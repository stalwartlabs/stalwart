/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MAX_EMBED_DEPTH, attach_row::merge_attachment_properties, fill_conversation_index,
    object_row::merge_properties, save::meeting_message,
};
use crate::{
    identity::org_dn,
    mail::fetch_raw_message,
    mapi::{
        emsmdb::{
            cache::MessageKey,
            execute::{MailboxView, RopContext, RopError},
            staged::RowBaseline,
            state::MessageObject,
            store::StoreGuids,
        },
        ids::{IdSpace, MapiId},
    },
    rules::map::FORWARDED_BY_HEADER,
    store::{
        alias::GroupwareKind,
        object::{
            ArchivedConflictState, ArchivedExchangeObject, ExchangeObject, ExchangeObjectStore,
        },
    },
};
use calcard::icalendar::{ICalendarComponentType, ICalendarProperty};
use common::Server;
use email::cache::email::MessageCacheAccess;
use exchange_proto::{
    common::time::{FileTime, UtcSeconds},
    convert::{
        ConvertError, clear_received_representing,
        context::{BodyPreference, ConvertOptions, NoDirectory, StoreIds, TnefPolicy},
        ical::{event_to_message, set_meeting_state, task_to_message},
        mime::mime_to_message,
        model::{AttachData, MessageContent},
        set_received_representing,
        vcard::{contact_to_message, is_contact_group},
    },
    ids::essdn::OrgDn,
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropKey, PropKeyRef, tags},
    },
};
use groupware::cache::GroupwareCache;
use groupware::{
    calendar::{
        CalendarEvent, CalendarEventContent,
        privacy::{EventPrivacy, ICalendarPrivacy},
    },
    contact::{ContactCard, ContactCardContent},
};
use mail_parser::MessageParser;
use std::sync::Arc;
use store::write::{Archive, ArchiveBytes, ArchiveVersion};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::{CalendarEventField, ContactField},
    type_state::DataType,
};

pub const MAX_DECODED: u32 = 64 * 1024 * 1024;
const OBJECT_VERSION: u64 = 1 << 63;
const SHAREE_VIEW_VERSION: u64 = 1 << 62;
const ROW_HASH_MASK: u32 = 0x7FFF_FFFF;
const DECODED_PER_SOURCE_BYTE: u64 = 2;
const GROUPWARE_ITEM_SIZE: u32 = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadDepth {
    Envelope,
    Full,
}

#[derive(Clone)]
pub struct LoadedContent {
    pub key: MessageKey,
    pub origin: u64,
    pub change: Option<u64>,
    pub row: RowBaseline,
    pub content: Arc<MessageContent>,
    pub client: Option<ClientVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientVersion {
    pub change_key: Box<[u8]>,
    pub pcl: Box<[u8]>,
    pub current: bool,
}

impl ClientVersion {
    pub fn read(archive: &Archive<ArchiveBytes>, change_id: u64) -> trc::Result<Option<Self>> {
        Ok(Self::of(
            archive.unarchive::<ExchangeObject>()?,
            archive.version.change_id() == Some(change_id),
        ))
    }

    fn of(object: &ArchivedExchangeObject, current: bool) -> Option<Self> {
        object
            .conflict
            .as_ref()
            .map(|conflict| Self::from_conflict(conflict, current))
    }

    pub fn from_conflict(conflict: &ArchivedConflictState, current: bool) -> Self {
        ClientVersion {
            change_key: conflict.change_key.as_slice().into(),
            pcl: conflict.pcl.as_slice().into(),
            current,
        }
    }
}

impl RopContext<'_, '_> {
    pub fn loaded_for(&self, message: &MessageObject) -> Option<&LoadedContent> {
        self.loaded.as_ref().filter(|loaded| {
            loaded.key.mailbox_id == message.mailbox_id && loaded.key.message == message.message
        })
    }

    pub async fn message_root(
        &mut self,
        message: &MessageObject,
    ) -> Result<Arc<MessageContent>, RopError> {
        if let Some(id) = message.staged {
            return self.staged_root(id);
        }
        self.require_folder_items(message.mailbox_id, message.folder)
            .await?;
        if let Some(loaded) = self.loaded_for(message) {
            return Ok(loaded.content.clone());
        }
        let id = message.id().ok_or(ErrorCode::NOT_FOUND)?;
        let (key, origin, change, row, content, client) = if id.space == IdSpace::Fai {
            let (change, content, client) = self.load_fai(message, id.id).await?;
            (
                MessageKey {
                    mailbox_id: message.mailbox_id,
                    message: message.message,
                    version: change,
                },
                change,
                None,
                RowBaseline::Untracked,
                Arc::new(content),
                client,
            )
        } else {
            let id = self
                .mailbox(message.mailbox_id)
                .await?
                .stored_item(message.folder, id)
                .ok_or(ErrorCode::NOT_FOUND)?;
            let (version, size) = self.message_version(message.mailbox_id, id).await?;
            let object = match id.space {
                IdSpace::Email => self.object_row(message.mailbox_id, id.id).await?,
                _ => None,
            };
            let archived = object
                .as_ref()
                .map(|archive| {
                    archive
                        .unarchive::<ExchangeObject>()
                        .map(|row| (archive, row))
                })
                .transpose()?;
            let client = match archived {
                Some((archive, row)) => self
                    .mailbox(message.mailbox_id)
                    .await?
                    .messages
                    .as_ref()
                    .and_then(|messages| messages.email_by_id(&id.id))
                    .and_then(|item| {
                        ClientVersion::of(
                            row,
                            archive.version.change_id() == Some(item.change_id()),
                        )
                    }),
                None => None,
            };
            let row = match id.space {
                IdSpace::Email => RowBaseline::of(object.as_ref().map(|object| &object.version)),
                _ => RowBaseline::Untracked,
            };
            let row_hash = object.as_ref().map(|object| object.version.hash());
            let cacheable = row_hash.is_none_or(|hash| hash.is_some());
            let key = MessageKey {
                mailbox_id: message.mailbox_id,
                message: message.message,
                version: match row_hash {
                    Some(Some(hash)) => merged_version(version, hash),
                    _ if id.space == IdSpace::Event
                        && !self.event_viewer(message.mailbox_id).is_owner() =>
                    {
                        version | SHAREE_VIEW_VERSION
                    }
                    _ => version,
                },
            };
            let (content, change) = match self.cached_message(key) {
                Some(cached) if cacheable => cached,
                cached => {
                    let (mut content, change) = match cached {
                        Some((content, change)) => (Arc::unwrap_or_clone(content), change),
                        None => {
                            let (content, change) = self
                                .load_versioned(message.mailbox_id, id, LoadDepth::Full)
                                .await?;
                            (content, id.space.groupware().map(|_| change))
                        }
                    };
                    if let Some((_, row)) = archived {
                        merge_properties(row.properties.iter(), &mut content.props);
                        merge_attachment_properties(row, &mut content);
                    }
                    let content = Arc::new(content);
                    if cacheable {
                        self.cache_message(key, (content.clone(), change), size);
                    }
                    (content, change)
                }
            };
            (key, version, change, row, content, client)
        };
        self.loaded = Some(LoadedContent {
            key,
            origin,
            change,
            row,
            content: content.clone(),
            client,
        });
        Ok(content)
    }

    pub(in crate::mapi::emsmdb) async fn object_row(
        &mut self,
        mailbox_id: u32,
        document_id: u32,
    ) -> Result<Option<Archive<ArchiveBytes>>, RopError> {
        if !self
            .mailbox(mailbox_id)
            .await?
            .exchange
            .has_object(Collection::Email, document_id)
        {
            return Ok(None);
        }
        self.request
            .server
            .exchange_object(mailbox_id, Collection::Email, document_id)
            .await
            .caused_by(trc::location!())
            .map_err(Into::into)
    }

    pub(in crate::mapi::emsmdb) async fn groupware_client(
        &self,
        view: &MailboxView,
        (kind, document_id): (GroupwareKind, u32),
        change_id: u64,
    ) -> Result<Option<ClientVersion>, RopError> {
        let collection = kind.collection();
        if !view.exchange.has_object(collection, document_id) {
            return Ok(None);
        }
        match self
            .request
            .server
            .exchange_object(view.id, collection, document_id)
            .await
            .caused_by(trc::location!())?
        {
            Some(archive) => ClientVersion::read(&archive, change_id).map_err(Into::into),
            None => Ok(None),
        }
    }

    async fn message_version(
        &mut self,
        mailbox_id: u32,
        id: MapiId,
    ) -> Result<(u64, u64), RopError> {
        let collection = match id.space {
            IdSpace::Email => {
                let mailbox = self.mailbox(mailbox_id).await?;
                let item = mailbox
                    .messages
                    .as_ref()
                    .and_then(|messages| messages.email_by_id(&id.id))
                    .ok_or(ErrorCode::NOT_FOUND)?;
                return Ok((
                    u64::from(id.id),
                    u64::from(item.size()).saturating_mul(DECODED_PER_SOURCE_BYTE),
                ));
            }
            IdSpace::Event if self.types.contains(DataType::CalendarEvent) => {
                SyncCollection::Calendar
            }
            IdSpace::Contact if self.types.contains(DataType::ContactCard) => {
                SyncCollection::AddressBook
            }
            _ => return Err(RopError::Code(ErrorCode::NOT_FOUND)),
        };
        let resources = self
            .request
            .server
            .fetch_groupware_resources(mailbox_id, mailbox_id, collection)
            .await
            .caused_by(trc::location!())?;
        let item = resources.item_by_id(id.id).ok_or(ErrorCode::NOT_FOUND)?;
        Ok((
            u64::from(item.etag()),
            u64::from(item.size().unwrap_or(GROUPWARE_ITEM_SIZE))
                .saturating_mul(DECODED_PER_SOURCE_BYTE),
        ))
    }

    pub async fn load_message(
        &mut self,
        mailbox_id: u32,
        id: MapiId,
        depth: LoadDepth,
    ) -> Result<MessageContent, RopError> {
        self.load_versioned(mailbox_id, id, depth)
            .await
            .map(|(content, _)| content)
    }

    pub async fn load_versioned(
        &mut self,
        mailbox_id: u32,
        id: MapiId,
        depth: LoadDepth,
    ) -> Result<(MessageContent, u64), RopError> {
        let server = self.request.server;
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let org = org_dn().ok_or(ErrorCode::ERROR)?;
        let opts = convert_options(&org, guids);
        let (converted, change_id, modified) = match id.space {
            IdSpace::Email => {
                let item = mailbox
                    .messages
                    .as_ref()
                    .and_then(|messages| messages.email_by_id(&id.id))
                    .ok_or(ErrorCode::NOT_FOUND)?;
                let (raw, _reservation) = fetch_raw_message(server, mailbox_id, id.id)
                    .await?
                    .ok_or(ErrorCode::NOT_FOUND)?;
                let parsed = MessageParser::new()
                    .parse(&raw)
                    .ok_or(ErrorCode::NOT_FOUND)?;
                let mut converted = mime_to_message(&parsed, &NoDirectory, &opts);
                if let Ok(message) = &mut converted {
                    fill_conversation_index(&mut message.props, item);
                    clear_received_representing(&mut message.props);
                    if let LoadDepth::Full = depth
                        && meeting_message(message).is_some()
                        && let Some(marker) = parsed
                            .headers()
                            .all(FORWARDED_BY_HEADER)
                            .last()
                            .and_then(|header| str::from_utf8(header.raw_value()).ok())
                        && let Some(delegator) = self
                            .representing
                            .principal(
                                server,
                                mailbox_id,
                                marker.trim_ascii(),
                                [parsed.to(), parsed.cc()]
                                    .into_iter()
                                    .flatten()
                                    .flat_map(|addresses| addresses.mailboxes())
                                    .filter_map(|mailbox| mailbox.address()),
                            )
                            .await
                            .unwrap_or_else(|err| {
                                trc::error!(
                                    err.account_id(mailbox_id)
                                        .details("Delegate marker check failed")
                                        .caused_by(trc::location!())
                                );
                                self.representing
                                    .remember_none(mailbox_id, marker.trim_ascii());
                                None
                            })
                    {
                        set_received_representing(
                            &mut message.props,
                            &delegator.name,
                            &delegator.address,
                        );
                    }
                }
                (converted, item.change_id(), None)
            }
            IdSpace::Event if self.types.contains(DataType::CalendarEvent) => {
                let (content, change_id, archive) = load_field::<CalendarEventContent>(
                    server,
                    mailbox_id,
                    Collection::CalendarEvent,
                    id.id,
                    CalendarEventField::Content.into(),
                )
                .await?;
                let modified = archive
                    .as_ref()
                    .map(|archive| {
                        archive
                            .unarchive::<CalendarEvent>()
                            .map(|event| event.modified.to_native())
                    })
                    .transpose()
                    .caused_by(trc::location!())?;
                let content = if self.event_viewer(mailbox_id).is_owner() {
                    content
                } else {
                    match content.data.event.privacy() {
                        EventPrivacy::Public => content,
                        EventPrivacy::Private => content.into_private_view(),
                        EventPrivacy::Secret => return Err(RopError::Code(ErrorCode::NOT_FOUND)),
                    }
                };
                let ical = &content.data.event;
                let converted = if ical
                    .components
                    .iter()
                    .any(|component| component.component_type == ICalendarComponentType::VTodo)
                {
                    task_to_message(ical, &opts)
                } else {
                    let mut converted = event_to_message(ical, None, &NoDirectory, &opts);
                    if let (Ok(message), LoadDepth::Full) = (&mut converted, depth)
                        && ical.components.iter().any(|component| {
                            component.property(&ICalendarProperty::Organizer).is_some()
                        })
                    {
                        let account_info = self
                            .cached_account_info(mailbox_id)
                            .await
                            .caused_by(trc::location!())?;
                        set_meeting_state(&mut message.props, ical, account_info.addresses());
                    }
                    converted
                };
                (converted, change_id, modified)
            }
            IdSpace::Contact if self.types.contains(DataType::ContactCard) => {
                let (content, change_id, archive) = load_field::<ContactCardContent>(
                    server,
                    mailbox_id,
                    Collection::ContactCard,
                    id.id,
                    ContactField::Content.into(),
                )
                .await?;
                let modified = archive
                    .as_ref()
                    .map(|archive| {
                        archive
                            .unarchive::<ContactCard>()
                            .map(|card| card.modified.to_native())
                    })
                    .transpose()
                    .caused_by(trc::location!())?;
                let converted = if is_contact_group(&content.card) {
                    self.group_message(mailbox_id, guids, &content.card, depth)
                        .await?
                } else {
                    contact_to_message(&content.card, &opts)
                };
                (converted, change_id, modified)
            }
            _ => return Err(RopError::Code(ErrorCode::NOT_FOUND)),
        };
        converted
            .map(|mut content| {
                if let Some(modified) = modified {
                    default_modified(&mut content, modified);
                }
                (content, change_id)
            })
            .map_err(|err| RopError::Code(convert_error(err)))
    }
}

pub(super) fn convert_options(org_dn: &OrgDn, guids: StoreGuids) -> ConvertOptions<'_> {
    ConvertOptions {
        org_dn,
        store: Some(StoreIds {
            store_guid: guids.mailbox,
            replguid: guids.replica,
        }),
        body_preference: BodyPreference::Html,
        tnef: TnefPolicy::Decode,
        max_decoded: MAX_DECODED,
    }
}

pub(super) async fn load_field<T>(
    server: &Server,
    account_id: u32,
    collection: Collection,
    document_id: u32,
    field: types::field::Field,
) -> Result<(T, u64, Option<Archive<ArchiveBytes>>), RopError>
where
    T: rkyv::Archive,
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    let (archive, content) = server
        .archive_and_field(account_id, collection, document_id, field)
        .await
        .caused_by(trc::location!())?;
    let change_id = match archive.as_ref().map(|archive| archive.version) {
        Some(ArchiveVersion::Versioned { change_id, .. }) => change_id,
        _ => 0,
    };
    Ok((
        content
            .ok_or(ErrorCode::NOT_FOUND)?
            .deserialize::<T>()
            .caused_by(trc::location!())?,
        change_id,
        archive,
    ))
}

fn default_modified(content: &mut MessageContent, modified: i64) {
    if content
        .props
        .get_any(PropKeyRef::Tag(tags::LAST_MODIFICATION_TIME.id()))
        .is_none()
    {
        content.props.set(
            PropKey::tag(tags::LAST_MODIFICATION_TIME.id()),
            OwnedPropValue::Time(FileTime::from_utc(UtcSeconds(modified), 0)),
        );
    }
}

pub fn convert_error(err: ConvertError) -> ErrorCode {
    match err {
        ConvertError::TooLarge => ErrorCode::TOO_BIG,
        _ => ErrorCode::ERROR,
    }
}

pub fn embedded<'c>(content: &'c MessageContent, path: &[u32]) -> Option<&'c MessageContent> {
    if path.len() > MAX_EMBED_DEPTH {
        return None;
    }
    path.iter().try_fold(content, |content, number| {
        match &super::attachment_at(content, *number)?.data {
            AttachData::Embedded(message) => Some(message.as_ref()),
            _ => None,
        }
    })
}

pub fn embedded_mut<'c>(
    content: &'c mut MessageContent,
    path: &[u32],
) -> Option<&'c mut MessageContent> {
    if path.len() > MAX_EMBED_DEPTH {
        return None;
    }
    path.iter()
        .try_fold(
            content,
            |content, number| match &mut super::attachment_mut(content, *number)?.data {
                AttachData::Embedded(message) => Some(message.as_mut()),
                _ => None,
            },
        )
}

fn merged_version(document_version: u64, row_hash: u32) -> u64 {
    OBJECT_VERSION | u64::from(row_hash & ROW_HASH_MASK) << 32 | document_version
}
