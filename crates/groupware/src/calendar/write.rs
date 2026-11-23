/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendarEvent, ArchivedCalendarEventContent, Calendar, CalendarEvent,
    CalendarEventContent, CalendarEventData, SupportedComponent,
    alerts::{DefaultAlertsResolver, DefaultAlertsView, ICalendarDefaultAlerts},
    compare::ComparisonScope,
    identity::ParticipantIdentityAddresses,
    itip::ItipSendStatus,
    notification::{NotificationAudience, may_have_viewers},
    privacy::{EventPrivacy, EventViewer, ICalendarPrivacy, PrivacyDenied},
    rights::{EventAcl, EventChanges},
    schedule::{AlarmTasks, EventAlarmScheduler, EventAlarmUsers},
    storage::{DirectChange, DirectChangeNotification, NotificationQuota},
    user::{
        ICalendarUserData, UpdatedPolicy, UserDataError, UserDataSplit, UserDataUpdate,
        UserDataView,
    },
};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::SizeWriter;
// SPDX-SnippetEnd
use crate::{
    DestroyArchive,
    scheduling::{
        ItipError, ItipMessages,
        event_create::{itip_create, itip_unscheduled_update},
        event_update::{itip_retain_changed, itip_update},
        itip::itip_set_unreachable_status,
        recipient::RecipientPolicy,
    },
};
use calcard::{
    common::timezone::Tz,
    icalendar::{ArchivedICalendar, ArchivedICalendarProperty, ICalendar, ICalendarComponentType},
};
use common::{
    ArchivedDavName, DavName, GroupwareResources, Server,
    auth::{AccessToken, AccountInfo},
};
use compact_str::ToCompactString;
use registry::schema::enums::{Permission, StorageQuota};
use std::{future::Future, sync::Arc};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder, now},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
};
use utils::map::bitmap::Bitmap;

pub struct EventWriter<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub account_id: u32,
    pub resources: &'x Arc<GroupwareResources>,
    pub account_info: &'x AccountInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItipMode {
    Send,
    SendToChanged,
    Suppress,
}

impl ItipMode {
    pub fn sends(self) -> bool {
        self != ItipMode::Suppress
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UidChange {
    Refuse,
    AllowUnscheduled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingPrecondition {
    SameOrganizerInAllComponents,
    ValidOrganizer,
    AllowedAttendeeObjectChange,
    ValidSchedulingMessage,
    MaxAttendeesPerInstance,
}

#[derive(Debug)]
pub enum EventWriteError {
    NotFound,
    Forbidden,
    InvalidObject,
    UidChanged(Option<String>),
    UidConflict {
        document_id: u32,
        href: Option<String>,
    },
    UnsupportedComponent,
    ScheduleTagMismatch,
    UserData(UserDataError),
    TooManyRecipients,
    Scheduling(SchedulingPrecondition, ItipError),
    Store(trc::Error),
}

pub struct StoredEvent {
    document_id: u32,
    calendar_id: u32,
    event: Archive<ArchiveBytes>,
    content: Archive<ArchiveBytes>,
}

pub struct NewEvent {
    calendar_id: u32,
}

pub struct EventCreate {
    pub name: String,
    pub ical: ICalendar,
    pub size: Option<usize>,
    pub itip: ItipMode,
}

struct Replacement {
    deletion: EventDeletion,
    delete_path: Option<String>,
    freed: Option<u32>,
    schedule_tag: Option<u32>,
}

pub struct EventDeletion {
    document_id: u32,
    calendar_id: u32,
    event: Archive<ArchiveBytes>,
    content: Option<Archive<ArchiveBytes>>,
    previous: Option<ICalendar>,
}

pub enum EventWrite {
    Unchanged,
    Written(WrittenEvent),
}

pub struct WrittenEvent {
    pub document_id: u32,
    pub etag: String,
    pub change_id: Option<u64>,
    pub schedule_tag: Option<u32>,
    pub serves_submitted: bool,
}

pub struct SupportedComponents(Bitmap<SupportedComponent>);

pub type EventWriteResult<T> = Result<T, EventWriteError>;

impl EventWriter<'_> {
    pub fn sends_itip(&self, mode: ItipMode) -> bool {
        mode.sends()
            && self.server.core.groupware.itip_enabled
            && !self.account_info.addresses().is_empty()
            && self
                .access_token
                .has_permission(Permission::CalendarSchedulingSend)
    }

    fn assert_privacy_access(&self, document_id: u32, viewer: EventViewer) -> EventWriteResult<()> {
        assert_privacy_access(
            self.resources
                .item_by_id(document_id)
                .and_then(|resource| resource.event_flags()),
            viewer,
        )
    }

    pub async fn prepare_update(
        &self,
        calendar_id: u32,
        document_id: u32,
        ical: &ICalendar,
    ) -> EventWriteResult<StoredEvent> {
        let account_id = self.account_id;
        let is_owner = self.access_token.is_member(account_id);
        if !is_owner
            && !self.resources.has_access_to_container(
                self.access_token,
                calendar_id,
                Bitmap::from_iter([
                    Acl::ModifyItems,
                    Acl::ModifyItemsOwn,
                    Acl::ModifyPrivateProperties,
                    Acl::ModifyRSVP,
                ]),
            )
        {
            return Err(EventWriteError::Forbidden);
        }
        let viewer = EventViewer::new(is_owner);
        self.assert_privacy_access(document_id, viewer)?;
        if !ical.privacy().may_be_set_by(viewer) {
            return Err(EventWriteError::Forbidden);
        }

        let (event, content) = self
            .server
            .archive_and_field(
                account_id,
                Collection::CalendarEvent,
                document_id,
                CalendarEventField::Content.field(),
            )
            .await
            .caused_by(trc::location!())?;
        Ok(StoredEvent {
            document_id,
            calendar_id,
            event: event.ok_or(EventWriteError::NotFound)?,
            content: content.ok_or(EventWriteError::NotFound)?,
        })
    }

    pub fn update(
        &self,
        stored: StoredEvent,
        ical: ICalendar,
        if_schedule_tag: Option<u32>,
        itip: ItipMode,
    ) -> impl Future<Output = EventWriteResult<EventWrite>> + Send + '_ {
        self.update_with(stored, ical, if_schedule_tag, itip, UidChange::Refuse)
    }

    pub async fn update_with(
        &self,
        stored: StoredEvent,
        mut ical: ICalendar,
        if_schedule_tag: Option<u32>,
        itip: ItipMode,
        uid_change: UidChange,
    ) -> EventWriteResult<EventWrite> {
        let server = self.server;
        let access_token = self.access_token;
        let account_id = self.account_id;
        let resources = self.resources;
        let account_info = self.account_info;
        let document_id = stored.document_id;
        let is_owner = access_token.is_member(account_id);
        let personal_id = access_token.personal_id(account_id, Collection::Calendar);
        let event = stored.event()?;
        let content = stored.content()?;

        if ical == content.inner.data.event {
            return Ok(EventWrite::Unchanged);
        }

        let (uid, component) = validate_ical(&ical)?;
        if event.inner.uid.as_str() != uid {
            if uid_change == UidChange::Refuse
                || itip != ItipMode::Suppress
                || event.inner.schedule_tag.is_some()
                || has_participants(&content.inner.data.event)
            {
                return Err(EventWriteError::UidChanged(
                    resources.format_resource_path_by_parent(document_id, stored.calendar_id),
                ));
            }
            for calendar_id in event.inner.names.iter().map(ArchivedDavName::parent_id) {
                assert_unique_uid(resources, access_token, account_id, calendar_id, Some(uid))?;
            }
        }
        SupportedComponents::fetch(server, account_id, stored.calendar_id)
            .await?
            .assert_supports(component)?;

        if if_schedule_tag.is_some()
            && event.inner.schedule_tag.as_ref().map(|t| t.to_native()) != if_schedule_tag
        {
            return Err(EventWriteError::ScheduleTagMismatch);
        }

        let now = now() as i64;
        let calendar_ids = event
            .inner
            .names
            .iter()
            .map(ArchivedDavName::parent_id)
            .collect::<Vec<_>>();
        let mut default_alerts_resolver =
            DefaultAlertsResolver::with_resources(account_id, resources.clone());
        let prev_email_alarms = server
            .next_event_alarms(
                account_id,
                &EventAlarmUsers::new(account_id, content.inner)?
                    .with_event_flags(event.inner.flags.to_native()),
                &content.inner.data,
                &calendar_ids,
                now,
                &mut default_alerts_resolver,
            )
            .await
            .caused_by(trc::location!())?;

        let mut new_event = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        let mut new_content = content
            .deserialize::<CalendarEventContent>()
            .caused_by(trc::location!())?;

        let writer_default_alerts = default_alerts_resolver
            .resolve_for_content(
                server,
                account_id,
                personal_id,
                &new_content,
                event.inner.names.iter().map(ArchivedDavName::parent_id),
            )
            .await
            .caused_by(trc::location!())?;
        let has_default_alerts = writer_default_alerts.is_enabled();
        let submitted_ical = ical.clone();
        ical.strip_default_alerts(&writer_default_alerts);
        let sharee_alerts_view = |content: &CalendarEventContent| {
            let mut view = content.data.event.clone();
            view.apply_user_data(content.preferences(personal_id), UserDataView::AlertsOnly);
            view
        };
        let mut sharee_view = None;
        if has_default_alerts {
            if is_owner {
                ical.restore_hidden_alerts(&new_content.data.event, &writer_default_alerts);
            } else {
                ical.restore_hidden_alerts(
                    sharee_view.insert(sharee_alerts_view(&new_content)),
                    &writer_default_alerts,
                );
            }
        }
        let changes_shared_user_data =
            !is_owner && !ical.has_same_user_data(&new_content.data.event);
        if is_owner || changes_shared_user_data {
            ical.validate_user_data_changes(&new_content.data.event)
                .map_err(EventWriteError::UserData)?;
        }

        if !is_owner {
            let identities = server
                .account_identity_addresses(access_token.account_id())
                .await
                .caused_by(trc::location!())?;
            let ownership = identities.event_ownership(&new_content.data.event);
            let acl = EventAcl::for_calendars(
                resources,
                access_token,
                event.inner.names.iter().map(ArchivedDavName::parent_id),
            );
            if !acl.may_write(ownership) {
                if changes_shared_user_data {
                    return Err(EventWriteError::Forbidden);
                }
                let event_flags = event.inner.flags.to_native();
                let sharee_view = sharee_view.unwrap_or_else(|| sharee_alerts_view(&new_content));
                let mut changes = EventChanges::between(
                    &sharee_view.into_jscalendar(),
                    &ical.clone().into_jscalendar(),
                    event_flags,
                    event_flags,
                    &identities,
                );
                changes.classify_recurrence_sets(&new_content.data.event, &ical);
                changes
                    .assert_allowed(&acl, ownership, event_flags)
                    .map_err(|_| EventWriteError::Forbidden)?;
            }
        }

        let is_user_data_only = if is_owner {
            false
        } else {
            let stored_preferences = new_content
                .preferences
                .iter()
                .find(|p| p.account_id == personal_id);
            let (preferences, split) = ical
                .split_user_data(
                    &new_content.data.event,
                    UserDataUpdate {
                        account_id: personal_id,
                        view: UserDataView::AlertsOnly,
                        previous: stored_preferences,
                        current: stored_preferences,
                        updated: UpdatedPolicy::Server(now),
                    },
                )
                .map_err(EventWriteError::UserData)?;
            new_content.set_preferences(preferences);
            split == UserDataSplit::UserDataOnly
        };
        let old_ical = if is_user_data_only {
            None
        } else {
            let old_ical = std::mem::take(&mut new_content.data.event);
            let owner_default_alerts = default_alerts_resolver
                .resolve_for_content(
                    server,
                    account_id,
                    account_id,
                    &new_content,
                    event.inner.names.iter().map(ArchivedDavName::parent_id),
                )
                .await
                .caused_by(trc::location!())?;
            new_content.data = CalendarEventData::new_with_default_alerts(
                ical,
                Tz::Floating,
                server.core.groupware.max_ical_instances,
                &owner_default_alerts,
            );
            Some(old_ical)
        };
        let next_email_alarms = server
            .next_event_alarms(
                account_id,
                &EventAlarmUsers::new(account_id, &new_content)?.with_event_flags(new_event.flags),
                &new_content.data,
                &calendar_ids,
                now,
                &mut default_alerts_resolver,
            )
            .await
            .caused_by(trc::location!())?;

        let mut itip_messages = None;
        let itip_status = if is_user_data_only || itip == ItipMode::Suppress {
            ItipSendStatus::NotRequested
        } else {
            ItipSendStatus::resolve(
                server,
                access_token,
                account_info,
                new_content
                    .data
                    .event_range_end()
                    .max(event.inner.event_range_end()),
            )
        };
        if itip_status.is_send() {
            let policy = RecipientPolicy::new(&server.core.groupware, new_event.flags);
            let mut result = match (&old_ical, new_event.schedule_tag) {
                (Some(old_ical), Some(_)) => itip_update(
                    &mut new_content.data.event,
                    old_ical,
                    account_info.addresses(),
                    policy,
                ),
                (Some(old_ical), None) => itip_unscheduled_update(
                    &mut new_content.data.event,
                    old_ical,
                    account_info.addresses(),
                    policy,
                ),
                (None, _) => itip_create(
                    &mut new_content.data.event,
                    account_info.addresses(),
                    policy,
                ),
            };
            if let (ItipMode::SendToChanged, Some(old_ical)) = (itip, &old_ical) {
                result = result.and_then(|messages| {
                    itip_retain_changed(
                        messages,
                        old_ical,
                        &new_content.data.event,
                        account_info.addresses(),
                    )
                });
            }

            match result {
                Ok(messages) => {
                    let mut is_organizer = false;
                    if messages
                        .iter()
                        .map(|r| {
                            is_organizer = r.from_organizer;
                            r.to.len()
                        })
                        .sum::<usize>()
                        < server.core.groupware.itip_outbound_max_recipients
                    {
                        match &mut new_event.schedule_tag {
                            Some(schedule_tag) if is_organizer => *schedule_tag += 1,
                            Some(_) => {}
                            None => new_event.schedule_tag = Some(1),
                        }

                        itip_messages = Some(ItipMessages::new(messages));
                    } else {
                        return Err(EventWriteError::TooManyRecipients);
                    }
                }
                Err(err) => {
                    if let Some(precondition) = SchedulingPrecondition::of(&err) {
                        return Err(EventWriteError::Scheduling(precondition, err));
                    }

                    trc::event!(
                        Calendar(trc::CalendarEvent::ItipMessageError),
                        AccountId = account_id,
                        DocumentId = document_id,
                        Reason = err.to_compact_string(),
                    );

                    if let Some(schedule_tag) = &mut new_event.schedule_tag {
                        *schedule_tag += 1;
                    }
                }
            }

            itip_set_unreachable_status(&mut new_content.data.event, account_info.addresses());
        } else if let Some(reason) = itip_status.reason() {
            trc::event!(
                Calendar(trc::CalendarEvent::ItipMessageError),
                AccountId = account_id,
                DocumentId = document_id,
                Reason = reason,
            );
        }

        let account = server.account(account_id).await?;
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let extra_bytes = (SizeWriter::ical(&new_content.data.event) as u64)
            .saturating_sub(u32::from(event.inner.size) as u64);
        #[cfg(feature = "enterprise")]
        if extra_bytes > 0 {
            server
                .has_available_tenant_quota(&account, extra_bytes)
                .await?;
        }
        // SPDX-SnippetEnd

        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        server.limit_disk_quota(&mut batch, &account);
        let notify_event_flags = new_event.flags | event.inner.flags.to_native();
        if let Some(old_ical) = old_ical.filter(|_| {
            may_have_viewers(
                access_token,
                account_id,
                resources,
                &calendar_ids,
                NotificationAudience::of_event(notify_event_flags),
            )
        }) {
            server
                .notify_direct_change(
                    access_token,
                    account_id,
                    DirectChange::Updated {
                        event_id: document_id,
                        previous: old_ical,
                        current: new_content.data.event.clone(),
                        calendar_ids: calendar_ids.clone(),
                        event_flags: notify_event_flags,
                    },
                    Some(resources),
                    &mut NotificationQuota::default(),
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }
        let serves_submitted = if is_owner && !has_default_alerts {
            serves_ical(&new_content.data.event, &submitted_ical)
        } else {
            let view_default_alerts = default_alerts_resolver
                .resolve_for_ical_view(
                    server,
                    account_id,
                    personal_id,
                    &new_content,
                    calendar_ids.iter().copied(),
                )
                .await
                .caused_by(trc::location!())?;
            let mut view = new_content.data.event.clone();
            if !is_owner {
                view.apply_user_data(
                    new_content.preferences(personal_id),
                    UserDataView::AlertsOnly,
                );
            }
            view.apply_default_alerts(&view_default_alerts, DefaultAlertsView::ICalendar);
            serves_ical(&view, &submitted_ical)
        };

        let schedule_tag = new_event.schedule_tag;
        let etag = new_event
            .update_full(
                new_content,
                access_token.changed_by(),
                event,
                content.inner,
                account_id,
                document_id,
                None,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        server
            .replace_event_alarms(
                account_id,
                document_id,
                prev_email_alarms,
                next_email_alarms,
                &mut AlarmTasks::None,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        if let Some(itip_messages) = itip_messages {
            itip_messages
                .queue(&mut batch)
                .caused_by(trc::location!())?;
        }
        let change_id = server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?
            .change_id(account_id, SyncCollection::Calendar);

        Ok(EventWrite::Written(WrittenEvent {
            document_id,
            etag,
            change_id,
            schedule_tag,
            serves_submitted,
        }))
    }

    pub async fn prepare_create(
        &self,
        calendar_id: u32,
        ical: &ICalendar,
    ) -> EventWriteResult<NewEvent> {
        let is_owner = self.access_token.is_member(self.account_id);
        if !is_owner
            && !self.resources.has_access_to_container(
                self.access_token,
                calendar_id,
                Acl::AddItems,
            )
            && !(EventAcl::for_calendar(self.resources, self.access_token, calendar_id)
                .may_manage_own_items()
                && self
                    .server
                    .account_identity_addresses(self.access_token.account_id())
                    .await
                    .caused_by(trc::location!())?
                    .event_ownership(ical)
                    .may_write_own())
        {
            return Err(EventWriteError::Forbidden);
        }
        if !ical.privacy().may_be_set_by(EventViewer::new(is_owner)) {
            return Err(EventWriteError::Forbidden);
        }
        ical.validate_user_data()
            .map_err(EventWriteError::UserData)?;
        Ok(NewEvent { calendar_id })
    }

    pub fn create(
        &self,
        new: NewEvent,
        input: EventCreate,
    ) -> impl Future<Output = EventWriteResult<WrittenEvent>> + Send + '_ {
        self.create_inner(new, input, None)
    }

    pub fn create_replacing(
        &self,
        new: NewEvent,
        input: EventCreate,
        replaced: EventDeletion,
        delete_path: Option<String>,
    ) -> impl Future<Output = EventWriteResult<WrittenEvent>> + Send + '_ {
        self.create_inner(new, input, Some((replaced, delete_path)))
    }

    async fn create_inner(
        &self,
        new: NewEvent,
        input: EventCreate,
        replaced: Option<(EventDeletion, Option<String>)>,
    ) -> EventWriteResult<WrittenEvent> {
        let server = self.server;
        let access_token = self.access_token;
        let account_id = self.account_id;
        let resources = self.resources;
        let account_info = self.account_info;
        let calendar_id = new.calendar_id;
        let is_owner = access_token.is_member(account_id);
        let personal_id = access_token.personal_id(account_id, Collection::Calendar);
        let mut ical = input.ical;
        let replaced = replaced
            .map(|(deletion, delete_path)| {
                Replacement::new(deletion, delete_path, calendar_id, &input.name)
            })
            .transpose()?;

        let (uid, component) = validate_ical(&ical)?;
        unique_uid_except(
            resources,
            access_token,
            account_id,
            calendar_id,
            uid,
            replaced
                .as_ref()
                .map(|replaced| replaced.deletion.document_id),
        )?;
        SupportedComponents::fetch(server, account_id, calendar_id)
            .await?
            .assert_supports(component)?;

        let account = server.account(account_id).await?;
        let requested = usize::from(
            replaced
                .as_ref()
                .is_none_or(|replaced| replaced.freed.is_none()),
        );
        server.assert_object_quota(&account, StorageQuota::MaxCalendarEvents, requested, || {
            resources.resources.count(false)
        })?;

        let submitted_ical = ical.clone();
        let mut preferences = Vec::new();
        if !is_owner {
            let extracted = ical
                .extract_user_data(personal_id)
                .map_err(EventWriteError::UserData)?;
            ical.apply_user_data(None, UserDataView::Full);
            if !extracted.is_empty() {
                preferences.push(extracted);
            }
        }

        let mut event = CalendarEvent {
            names: vec![DavName {
                name: input.name,
                parent_id: calendar_id,
            }],
            ..Default::default()
        };
        let mut content = CalendarEventContent {
            data: CalendarEventData::new(
                ical,
                Tz::Floating,
                server.core.groupware.max_ical_instances,
            ),
            preferences,
        };
        let next_email_alarms = server
            .next_event_alarms(
                account_id,
                &EventAlarmUsers::new(account_id, &content)?,
                &content.data,
                &[calendar_id],
                now() as i64,
                &mut DefaultAlertsResolver::with_resources(account_id, resources.clone()),
            )
            .await
            .caused_by(trc::location!())?;

        let mut itip_messages = None;
        let itip_status = if input.itip == ItipMode::Suppress {
            ItipSendStatus::NotRequested
        } else {
            ItipSendStatus::resolve(
                server,
                access_token,
                account_info,
                content.data.event_range_end(),
            )
        };
        if itip_status.is_send() {
            match itip_create(
                &mut content.data.event,
                account_info.addresses(),
                RecipientPolicy::new(&server.core.groupware, event.flags),
            ) {
                Ok(messages) => {
                    if messages.iter().map(|r| r.to.len()).sum::<usize>()
                        < server.core.groupware.itip_outbound_max_recipients
                    {
                        event.schedule_tag = Some(1);
                        itip_messages = Some(ItipMessages::new(messages));
                    } else {
                        return Err(EventWriteError::TooManyRecipients);
                    }
                }
                Err(err) => {
                    if let Some(precondition) = SchedulingPrecondition::of(&err) {
                        return Err(EventWriteError::Scheduling(precondition, err));
                    }

                    trc::event!(
                        Calendar(trc::CalendarEvent::ItipMessageError),
                        AccountId = account_id,
                        Reason = err.to_compact_string(),
                    );
                }
            }

            itip_set_unreachable_status(&mut content.data.event, account_info.addresses());
        } else if let Some(reason) = itip_status.reason() {
            trc::event!(
                Calendar(trc::CalendarEvent::ItipMessageError),
                AccountId = account_id,
                Reason = reason,
            );
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        {
            let size = input
                .size
                .unwrap_or_else(|| SizeWriter::ical(&content.data.event));
            let freed = replaced
                .as_ref()
                .and_then(|replaced| replaced.freed)
                .map_or(0, u64::from);
            let size = (size as u64).saturating_sub(freed);
            if size != 0 {
                server.has_available_tenant_quota(&account, size).await?;
            }
        }
        // SPDX-SnippetEnd

        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        server.limit_disk_quota(&mut batch, &account);
        let slot = batch.reserve_document_id(account_id, Collection::CalendarEvent);
        let notify_calendar_ids = event.calendar_ids().collect::<Vec<_>>();
        if may_have_viewers(
            access_token,
            account_id,
            resources,
            &notify_calendar_ids,
            NotificationAudience::of_event(event.flags),
        ) {
            server
                .notify_direct_change(
                    access_token,
                    account_id,
                    DirectChange::Created {
                        event_id: slot.into(),
                        current: content.data.event.clone(),
                        calendar_ids: notify_calendar_ids,
                        event_flags: event.flags,
                    },
                    Some(resources),
                    &mut NotificationQuota::default(),
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }
        let serves_submitted = if is_owner {
            serves_ical(&content.data.event, &submitted_ical)
        } else {
            let mut view = content.data.event.clone();
            view.apply_user_data(content.preferences(personal_id), UserDataView::AlertsOnly);
            serves_ical(&view, &submitted_ical)
        };

        if event.schedule_tag.is_none() {
            event.schedule_tag = replaced.as_ref().and_then(|replaced| replaced.schedule_tag);
        }
        let schedule_tag = event.schedule_tag;
        let etag = event
            .insert(
                content,
                access_token.changed_by(),
                account_id,
                slot,
                None,
                next_email_alarms,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        if let Some(itip_messages) = itip_messages {
            itip_messages
                .queue(&mut batch)
                .caused_by(trc::location!())?;
        }
        if let Some(replaced) = replaced {
            Box::pin(self.destroy_into(replaced.deletion, replaced.delete_path, false, &mut batch))
                .await?;
        }
        let assigned_ids = server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;

        Ok(WrittenEvent {
            document_id: assigned_ids.slot(slot),
            etag,
            change_id: assigned_ids.change_id(account_id, SyncCollection::Calendar),
            schedule_tag,
            serves_submitted,
        })
    }

    pub async fn prepare_delete(
        &self,
        calendar_id: u32,
        document_id: u32,
    ) -> EventWriteResult<EventDeletion> {
        let server = self.server;
        let access_token = self.access_token;
        let account_id = self.account_id;
        let resources = self.resources;
        let is_owner = access_token.is_member(account_id);
        self.assert_privacy_access(document_id, EventViewer::new(is_owner))?;
        let may_remove_items = is_owner
            || resources.has_access_to_container(access_token, calendar_id, Acl::RemoveItems);
        if !may_remove_items
            && !EventAcl::for_calendar(resources, access_token, calendar_id).may_manage_own_items()
        {
            return Err(EventWriteError::Forbidden);
        }

        let event_ = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::CalendarEvent,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(EventWriteError::NotFound)?;
        let event_flags = event_
            .unarchive::<CalendarEvent>()
            .caused_by(trc::location!())?
            .flags
            .to_native();
        let may_notify = may_have_viewers(
            access_token,
            account_id,
            resources,
            &[calendar_id],
            NotificationAudience::of_event(event_flags),
        );
        let content = if !may_remove_items || may_notify {
            server
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                    CalendarEventField::Content,
                ))
                .await
                .caused_by(trc::location!())?
        } else {
            None
        };
        let previous = content
            .as_ref()
            .map(|content| content.deserialize::<CalendarEventContent>())
            .transpose()
            .caused_by(trc::location!())?
            .map(|content| content.data.event);
        if !may_remove_items {
            let identities = server
                .account_identity_addresses(access_token.account_id())
                .await
                .caused_by(trc::location!())?;
            if !previous
                .as_ref()
                .is_some_and(|ical| identities.event_ownership(ical).may_write_own())
            {
                return Err(EventWriteError::Forbidden);
            }
        }

        Ok(EventDeletion {
            document_id,
            calendar_id,
            event: event_,
            content,
            previous,
        })
    }

    pub async fn delete(
        &self,
        deletion: EventDeletion,
        if_schedule_tag: Option<u32>,
        itip: ItipMode,
        delete_path: Option<String>,
    ) -> EventWriteResult<()> {
        if if_schedule_tag.is_some()
            && deletion
                .event()?
                .inner
                .schedule_tag
                .as_ref()
                .map(|t| t.to_native())
                != if_schedule_tag
        {
            return Err(EventWriteError::ScheduleTagMismatch);
        }
        let mut batch = BatchBuilder::new();
        self.destroy_into(deletion, delete_path, self.sends_itip(itip), &mut batch)
            .await?;
        self.server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
        Ok(())
    }

    async fn destroy_into(
        &self,
        deletion: EventDeletion,
        delete_path: Option<String>,
        send_itip: bool,
        batch: &mut BatchBuilder,
    ) -> EventWriteResult<()> {
        let server = self.server;
        let account_id = self.account_id;
        let EventDeletion {
            document_id,
            calendar_id,
            event: event_,
            content,
            previous,
        } = deletion;
        let event = event_
            .to_unarchived::<CalendarEvent>()
            .caused_by(trc::location!())?;
        if let Some(previous) = previous {
            server
                .notify_direct_change(
                    self.access_token,
                    account_id,
                    DirectChange::Destroyed {
                        event_id: document_id,
                        previous,
                        calendar_ids: vec![calendar_id],
                        event_flags: event.inner.flags.to_native(),
                    },
                    Some(self.resources),
                    &mut NotificationQuota::default(),
                    batch,
                )
                .await
                .caused_by(trc::location!())?;
        }
        DestroyArchive(event)
            .delete(
                server,
                self.account_info,
                account_id,
                document_id,
                calendar_id,
                content,
                delete_path,
                send_itip,
                batch,
            )
            .await
            .caused_by(trc::location!())?;
        Ok(())
    }
}

impl StoredEvent {
    pub fn document_id(&self) -> u32 {
        self.document_id
    }

    pub fn event(&self) -> trc::Result<Archive<&ArchivedCalendarEvent>> {
        self.event.to_unarchived::<CalendarEvent>()
    }

    pub fn content(&self) -> trc::Result<Archive<&ArchivedCalendarEventContent>> {
        self.content.to_unarchived::<CalendarEventContent>()
    }
}

impl Replacement {
    fn new(
        deletion: EventDeletion,
        delete_path: Option<String>,
        calendar_id: u32,
        name: &str,
    ) -> EventWriteResult<Self> {
        let stored = deletion.event()?;
        let names = &stored.inner.names;
        let freed = (names.len() == 1).then(|| stored.inner.size.to_native());
        let renamed = names
            .iter()
            .any(|entry| entry.parent_id == calendar_id && entry.name.as_str() != name);
        let schedule_tag = stored
            .inner
            .schedule_tag
            .as_ref()
            .map(|tag| tag.to_native());
        Ok(Replacement {
            deletion,
            delete_path: delete_path.filter(|_| renamed),
            freed,
            schedule_tag,
        })
    }
}

impl EventDeletion {
    pub fn event(&self) -> trc::Result<Archive<&ArchivedCalendarEvent>> {
        self.event.to_unarchived::<CalendarEvent>()
    }

    pub fn previous(&self) -> Option<&ICalendar> {
        self.previous.as_ref()
    }

    pub fn set_content(&mut self, content: Archive<ArchiveBytes>) {
        self.content = Some(content);
    }
}

impl SupportedComponents {
    pub async fn fetch(server: &Server, account_id: u32, calendar_id: u32) -> trc::Result<Self> {
        server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::Calendar,
                calendar_id,
            ))
            .await
            .caused_by(trc::location!())?
            .map(|archive| {
                archive
                    .unarchive::<Calendar>()
                    .map(|calendar| calendar.supported_components.to_native())
            })
            .transpose()
            .caused_by(trc::location!())
            .map(|supported_components| {
                SupportedComponents(Bitmap::from(supported_components.unwrap_or_default()))
            })
    }

    pub fn is_restricted(&self) -> bool {
        !self.0.is_empty()
    }

    pub fn assert_supports(&self, component: SupportedComponent) -> EventWriteResult<()> {
        if component.is_storable() && (!self.is_restricted() || self.0.contains(component)) {
            Ok(())
        } else {
            Err(EventWriteError::UnsupportedComponent)
        }
    }
}

impl SchedulingPrecondition {
    pub fn of(err: &ItipError) -> Option<Self> {
        match err {
            ItipError::MultipleOrganizer => Some(Self::SameOrganizerInAllComponents),
            ItipError::OrganizerIsLocalAddress
            | ItipError::SenderIsNotParticipant(_)
            | ItipError::OrganizerMismatch => Some(Self::ValidOrganizer),
            ItipError::CannotModifyProperty(_)
            | ItipError::CannotModifyInstance
            | ItipError::CannotModifyAddress => Some(Self::AllowedAttendeeObjectChange),
            ItipError::MissingUid
            | ItipError::MultipleUid
            | ItipError::MultipleObjectTypes
            | ItipError::MultipleObjectInstances
            | ItipError::MissingMethod
            | ItipError::InvalidComponentType
            | ItipError::OutOfSequence
            | ItipError::UnknownParticipant(_)
            | ItipError::UnsupportedMethod(_) => Some(Self::ValidSchedulingMessage),
            ItipError::TooManyRecipients => Some(Self::MaxAttendeesPerInstance),
            _ => None,
        }
    }
}

impl From<trc::Error> for EventWriteError {
    fn from(err: trc::Error) -> Self {
        EventWriteError::Store(err)
    }
}

pub fn assert_unique_uid(
    resources: &GroupwareResources,
    access_token: &AccessToken,
    account_id: u32,
    calendar_id: u32,
    uid: Option<&str>,
) -> EventWriteResult<()> {
    match uid {
        Some(uid) => unique_uid_except(resources, access_token, account_id, calendar_id, uid, None),
        None => Ok(()),
    }
}

fn unique_uid_except(
    resources: &GroupwareResources,
    access_token: &AccessToken,
    account_id: u32,
    calendar_id: u32,
    uid: &str,
    replaced: Option<u32>,
) -> EventWriteResult<()> {
    let is_owner = access_token.is_member(account_id);
    let mut hidden_conflict = None;
    for path in resources
        .children_with_uid(calendar_id, uid)
        .filter(|path| Some(path.document_id()) != replaced)
    {
        if is_owner
            || EventPrivacy::from_flags(path.resource.event_flags().unwrap_or_default())
                != EventPrivacy::Secret
        {
            return Err(EventWriteError::UidConflict {
                document_id: path.document_id(),
                href: Some(resources.format_resource(path)),
            });
        }
        hidden_conflict.get_or_insert(path.document_id());
    }

    match hidden_conflict {
        Some(document_id) => Err(EventWriteError::UidConflict {
            document_id,
            href: None,
        }),
        None => Ok(()),
    }
}

pub fn assert_privacy_access(flags: Option<u16>, viewer: EventViewer) -> EventWriteResult<()> {
    flags
        .map(EventPrivacy::from_flags)
        .unwrap_or_default()
        .check_access(viewer)
        .map_err(|denied| match denied {
            PrivacyDenied::Forbidden => EventWriteError::Forbidden,
            PrivacyDenied::NotFound => EventWriteError::NotFound,
        })
}

fn has_participants(ical: &ArchivedICalendar) -> bool {
    ical.components
        .iter()
        .filter(|component| component.component_type.is_scheduling_object())
        .flat_map(|component| component.entries.iter())
        .any(|entry| {
            matches!(
                entry.name,
                ArchivedICalendarProperty::Organizer | ArchivedICalendarProperty::Attendee
            )
        })
}

fn serves_ical(view: &ICalendar, submitted: &ICalendar) -> bool {
    view == submitted || ComparisonScope::SharedData.component_eq(view, 0, submitted, 0)
}

fn validate_ical(ical: &ICalendar) -> EventWriteResult<(&str, SupportedComponent)> {
    let mut uid = None;
    let mut has_mixed_uids = false;
    let mut object_type = None;
    let mut has_mixed_types = false;
    for comp in &ical.components {
        let component = match comp.component_type {
            ICalendarComponentType::VEvent => SupportedComponent::VEvent,
            ICalendarComponentType::VTodo => SupportedComponent::VTodo,
            ICalendarComponentType::VJournal => SupportedComponent::VJournal,
            ICalendarComponentType::VFreebusy => SupportedComponent::VFreebusy,
            ICalendarComponentType::VAvailability => SupportedComponent::VAvailability,
            _ => {
                continue;
            }
        };
        has_mixed_types |= object_type
            .replace(component)
            .is_some_and(|previous| previous != component);

        if let Some(comp_uid) = comp.uid() {
            has_mixed_uids |= uid
                .replace(comp_uid)
                .is_some_and(|previous| previous != comp_uid);
        }
    }

    match (uid.filter(|_| !has_mixed_uids), object_type) {
        (Some(uid), Some(object_type)) if !has_mixed_types => Ok((uid, object_type)),
        _ => Err(EventWriteError::InvalidObject),
    }
}
