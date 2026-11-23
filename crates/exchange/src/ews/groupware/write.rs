/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    GroupwareFields, VersionedArchives, change_id_of,
    items::{GroupwareItems, GroupwareRef},
};
use crate::{
    ews::{context::EwsCaller, item::ItemError},
    groupware_write::{
        EventEdit, WriteFailure, assert_event_room, event_failure, event_name, ical_size,
        store_failure,
    },
};
use calcard::icalendar::ICalendar;
use common::Server;
use exchange_proto::ews::types::ids::ItemId;
use groupware::calendar::{
    ArchivedCalendarEvent,
    privacy::{EventViewer, ICalendarPrivacy},
    rights::EventAcl,
    write::{EventCreate, EventWrite, EventWriter, ItipMode},
};
use store::{roaring::RoaringBitmap, write::now};
use types::acl::Acl;

const MAX_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scheduling {
    pub tag: Option<u32>,
    range_end: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Committed {
    pub before: Scheduling,
    pub after: Option<u32>,
}

impl Scheduling {
    pub fn of(event: &ArchivedCalendarEvent) -> Self {
        Scheduling {
            tag: event.schedule_tag.as_ref().map(|tag| tag.to_native()),
            range_end: event.event_range_end(),
        }
    }

    pub fn is_upcoming(self) -> bool {
        self.range_end > now() as i64
    }
}

pub(crate) struct CalendarWriter<'x, F> {
    pub server: &'x Server,
    pub caller: EwsCaller<'x>,
    pub items: &'x GroupwareItems<F>,
    created: usize,
}

impl<'x, F: GroupwareFields> CalendarWriter<'x, F> {
    pub fn new(server: &'x Server, caller: EwsCaller<'x>, items: &'x GroupwareItems<F>) -> Self {
        CalendarWriter {
            server,
            caller,
            items,
            created: 0,
        }
    }

    pub async fn create_ical(
        &mut self,
        container: u32,
        uid: &str,
        ical: ICalendar,
        itip: ItipMode,
    ) -> trc::Result<Result<(ItemId<'static>, Option<u32>), ItemError>> {
        let Some(size) = ical_size(self.server, &ical) else {
            return Ok(Err(ItemError::ItemSave));
        };
        if let Err(err) = assert_event_room(
            self.server,
            self.items.account_id,
            &self.items.resources,
            self.created,
        )
        .await
        {
            return store_failure(err).map(|failure| Err(failure_error(failure)));
        }
        let writer = self.event_writer().await?;
        let written = match writer.prepare_create(container, &ical).await {
            Ok(new) => {
                writer
                    .create(
                        new,
                        EventCreate {
                            name: event_name(uid),
                            ical,
                            size: Some(size),
                            itip,
                        },
                    )
                    .await
            }
            Err(err) => Err(err),
        };
        match written {
            Ok(written) => {
                self.created += 1;
                self.current_id(GroupwareRef {
                    container,
                    document_id: written.document_id,
                })
                .await
                .map(|id| Ok((id, written.schedule_tag)))
            }
            Err(err) => event_failure(err).map(|failure| Err(failure_error(failure))),
        }
    }

    pub async fn update_ical(
        &self,
        item: GroupwareRef,
        expected_change: Option<u64>,
        itip: ItipMode,
        apply: impl FnMut(&mut ICalendar) -> Result<(), ItemError>,
    ) -> trc::Result<Result<(u64, Committed), ItemError>> {
        match self.commit_ical(item, expected_change, itip, apply).await? {
            Ok(committed) => self
                .current_change(item)
                .await
                .map(|change_id| Ok((change_id, committed))),
            Err(err) => Ok(Err(err)),
        }
    }

    pub async fn commit_ical(
        &self,
        item: GroupwareRef,
        expected_change: Option<u64>,
        itip: ItipMode,
        mut apply: impl FnMut(&mut ICalendar) -> Result<(), ItemError>,
    ) -> trc::Result<Result<Committed, ItemError>> {
        let writer = self.event_writer().await?;
        for _ in 0..MAX_ATTEMPTS {
            let edit = match EventEdit::open(&writer, item.container, item.document_id).await {
                Ok(edit) => edit,
                Err(err) => return event_failure(err).map(|failure| Err(failure_error(failure))),
            };
            let (version, before) = match edit.event() {
                Ok(event) => (event.version, Scheduling::of(event.inner)),
                Err(err) => return Ok(Err(unreadable(err))),
            };
            if expected_change.is_some_and(|expected| expected != change_id_of(version)) {
                return Ok(Err(ItemError::Stale));
            }
            let mut ical = match edit.to_ical() {
                Ok(ical) => ical,
                Err(err) => return Ok(Err(unreadable(err))),
            };
            if let Err(err) = apply(&mut ical) {
                return Ok(Err(err));
            }
            if ical_size(self.server, &ical).is_none() {
                return Ok(Err(ItemError::ItemSave));
            }
            match edit.commit(ical, itip).await {
                Ok(EventWrite::Written(written)) => {
                    return Ok(Ok(Committed {
                        before,
                        after: written.schedule_tag,
                    }));
                }
                Ok(EventWrite::Unchanged) => {
                    return Ok(Ok(Committed {
                        before,
                        after: before.tag,
                    }));
                }
                Err(err) => match event_failure(err)? {
                    WriteFailure::Conflict => continue,
                    failure => return Ok(Err(failure_error(failure))),
                },
            }
        }
        Ok(Err(ItemError::Stale))
    }

    pub async fn delete(
        &self,
        item: GroupwareRef,
        itip: ItipMode,
    ) -> trc::Result<Result<(), ItemError>> {
        let Some(path) = self
            .items
            .resources
            .format_resource_path_by_parent(item.document_id, item.container)
        else {
            return Ok(Err(ItemError::NotFound));
        };
        let writer = self.event_writer().await?;
        for _ in 0..MAX_ATTEMPTS {
            let deleted = match writer
                .prepare_delete(item.container, item.document_id)
                .await
            {
                Ok(deletion) => {
                    writer
                        .delete(deletion, None, itip, Some(path.clone()))
                        .await
                }
                Err(err) => Err(err),
            };
            match deleted {
                Ok(()) => return Ok(Ok(())),
                Err(err) => match event_failure(err)? {
                    WriteFailure::Conflict => continue,
                    failure => return Ok(Err(failure_error(failure))),
                },
            }
        }
        Ok(Err(ItemError::Stale))
    }

    pub fn may_create(&self, container: u32, ical: &ICalendar) -> bool {
        let access_token = self.caller.access_token;
        let resources = &self.items.resources;
        let is_owner = access_token.is_member(self.items.account_id);
        (is_owner
            || resources.has_access_to_container(access_token, container, Acl::AddItems)
            || EventAcl::for_calendar(resources, access_token, container).may_manage_own_items())
            && ical.privacy().may_be_set_by(EventViewer::new(is_owner))
    }

    async fn current_id(&self, item: GroupwareRef) -> trc::Result<ItemId<'static>> {
        let change_id = self.current_change(item).await?;
        Ok(self.items.item_id(item, change_id))
    }

    pub(crate) async fn current_change(&self, item: GroupwareRef) -> trc::Result<u64> {
        let mut documents = RoaringBitmap::new();
        documents.insert(item.document_id);
        Ok(VersionedArchives::read(
            self.server,
            self.items.account_id,
            F::KIND.collection(),
            F::KIND.content(),
            &documents,
            false,
        )
        .await?
        .change_id(item.document_id)
        .unwrap_or_default())
    }

    pub(crate) async fn event_writer(&self) -> trc::Result<EventWriter<'_>> {
        let account_info = self.items.account_info(self.server).await?;
        Ok(EventWriter {
            server: self.server,
            access_token: self.caller.access_token,
            account_id: self.items.account_id,
            resources: &self.items.resources,
            account_info,
        })
    }
}

pub(crate) fn unreadable(err: trc::Error) -> ItemError {
    trc::error!(err.caused_by(trc::location!()));
    ItemError::Unparsable
}

pub(crate) fn failure_error(failure: WriteFailure) -> ItemError {
    match failure {
        WriteFailure::NotFound => ItemError::NotFound,
        WriteFailure::Forbidden => ItemError::AccessDenied,
        WriteFailure::Invalid => ItemError::InvalidPropertySet,
        WriteFailure::UidConflict => ItemError::UidConflict,
        WriteFailure::Quota => ItemError::Quota,
        WriteFailure::Conflict => ItemError::Stale,
    }
}
