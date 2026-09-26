/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PropFindContext, PropFindItem};
use crate::common::ArchivedResource;
use common::{Server, auth::AccessToken};
use dav_proto::schema::property::{CalDavProperty, CardDavProperty, DavProperty, WebDavProperty};
use groupware::{
    calendar::{
        CalendarEvent, EVENT_HAS_ALARMS, EVENT_HAS_DEAD_PROPERTIES, EVENT_PRIVATE, EVENT_SECRET,
    },
    contact::{CARD_HAS_DEAD_PROPERTIES, ContactCard},
};
use store::{
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    collection::Collection,
    field::{CalendarEventField, CalendarNotificationField, ContactField, Field},
};

pub(super) const PROPFIND_BATCH_SIZE: usize = 256;

type ArchiveKey = (u32, u8, u32);

pub(super) struct ArchiveLoader {
    collection_container: Collection,
    collection_children: Collection,
    is_scheduling: bool,
    needs_content: bool,
    needs_dead_properties: bool,
    needs_content_length: bool,
    content_field: Option<Field>,
}

pub(super) struct BatchArchives {
    metadata: AHashMap<ArchiveKey, Archive<ArchiveBytes>>,
    contents: AHashMap<ArchiveKey, Archive<ArchiveBytes>>,
}

struct ContentDemand {
    dead_properties: bool,
    event_content_length: bool,
    is_owner: bool,
}

impl ArchiveLoader {
    pub fn new(ctx: &PropFindContext<'_>, has_filter: bool) -> Self {
        let properties = ctx.properties;
        ArchiveLoader {
            collection_container: ctx.collection_container,
            collection_children: ctx.collection_children,
            is_scheduling: ctx.is_scheduling,
            needs_content: has_filter
                || properties.iter().any(|property| {
                    matches!(
                        property,
                        DavProperty::CardDav(CardDavProperty::AddressData { .. })
                            | DavProperty::CalDav(CalDavProperty::CalendarData(_))
                    )
                }),
            needs_dead_properties: ctx.skip_not_found
                || properties
                    .iter()
                    .any(|property| matches!(property, DavProperty::DeadProperty(_))),
            needs_content_length: ctx.collection_children == Collection::CalendarEvent
                && properties.iter().any(|property| {
                    matches!(
                        property,
                        DavProperty::WebDav(WebDavProperty::GetContentLength)
                    )
                }),
            content_field: match ctx.collection_children {
                Collection::CalendarEvent => Some(CalendarEventField::Content.field()),
                Collection::CalendarEventNotification => {
                    Some(CalendarNotificationField::Content.field())
                }
                Collection::ContactCard => Some(ContactField::Content.field()),
                _ => None,
            },
        }
    }

    pub fn needs_event_view(&self) -> bool {
        self.collection_children == Collection::CalendarEvent
            && (self.needs_content || self.needs_content_length)
    }

    pub fn collection_of(&self, item: &PropFindItem) -> Collection {
        if item.is_container {
            self.collection_container
        } else {
            self.collection_children
        }
    }

    pub async fn load(
        &self,
        server: &Server,
        access_token: &AccessToken,
        batch: &[PropFindItem],
    ) -> trc::Result<BatchArchives> {
        let mut groups: AHashMap<(u32, Collection), RoaringBitmap> = AHashMap::with_capacity(4);
        for item in batch {
            if !(self.is_scheduling && item.is_container) {
                groups
                    .entry((item.account_id, self.collection_of(item)))
                    .or_default()
                    .insert(item.document_id);
            }
        }

        let track_carriers = self.content_field.is_some()
            && (self.needs_dead_properties || self.needs_content_length)
            && !self.needs_content;
        let mut metadata = AHashMap::with_capacity(batch.len());
        let mut carriers: AHashMap<(u32, Collection), RoaringBitmap> = AHashMap::new();
        for (&(account_id, collection), documents) in &groups {
            let content_demand = ContentDemand {
                dead_properties: self.needs_dead_properties,
                event_content_length: self.needs_content_length,
                is_owner: access_token.is_member(account_id),
            };
            let mut group_carriers = RoaringBitmap::new();
            server
                .archives(
                    account_id,
                    collection,
                    Field::ARCHIVE,
                    documents,
                    |document_id, archive| {
                        if track_carriers
                            && collection == self.collection_children
                            && content_demand
                                .is_met_by(&archive, collection)
                                .caused_by(trc::location!())?
                        {
                            group_carriers.insert(document_id);
                        }
                        metadata.insert((account_id, collection.into(), document_id), archive);
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;

            if !group_carriers.is_empty() {
                carriers.insert((account_id, collection), group_carriers);
            }
        }

        let mut contents = AHashMap::new();
        if let Some(content_field) = self.content_field
            && (self.needs_content || self.needs_dead_properties || self.needs_content_length)
        {
            for (&(account_id, collection), documents) in &groups {
                if collection != self.collection_children {
                    continue;
                }

                let documents = if self.needs_content {
                    documents
                } else if let Some(carriers) = carriers.get(&(account_id, collection)) {
                    carriers
                } else {
                    continue;
                };

                if !documents.is_empty() {
                    server
                        .archives(
                            account_id,
                            collection,
                            content_field,
                            documents,
                            |document_id, archive| {
                                contents
                                    .insert((account_id, collection.into(), document_id), archive);
                                Ok(true)
                            },
                        )
                        .await
                        .caused_by(trc::location!())?;
                }
            }
        }

        Ok(BatchArchives { metadata, contents })
    }
}

impl BatchArchives {
    pub fn resource(
        &self,
        collection: Collection,
        item: &PropFindItem,
    ) -> trc::Result<Option<ArchivedResource<'_>>> {
        let key = (item.account_id, collection.into(), item.document_id);
        self.metadata
            .get(&key)
            .map(|archive| {
                ArchivedResource::from_archive(archive, self.contents.get(&key), collection)
            })
            .transpose()
    }
}

impl ContentDemand {
    fn view_flags(&self) -> u16 {
        if self.is_owner {
            EVENT_HAS_ALARMS
        } else {
            EVENT_HAS_ALARMS | EVENT_PRIVATE | EVENT_SECRET
        }
    }

    fn is_met_by(
        &self,
        archive: &Archive<ArchiveBytes>,
        collection: Collection,
    ) -> trc::Result<bool> {
        match collection {
            Collection::CalendarEvent => {
                let flags = archive.unarchive::<CalendarEvent>()?.flags.to_native();
                Ok(
                    (self.dead_properties && flags & EVENT_HAS_DEAD_PROPERTIES != 0)
                        || (self.event_content_length && flags & self.view_flags() != 0),
                )
            }
            Collection::ContactCard => Ok(self.dead_properties
                && archive.unarchive::<ContactCard>()?.flags.to_native()
                    & CARD_HAS_DEAD_PROPERTIES
                    != 0),
            _ => Ok(false),
        }
    }
}
