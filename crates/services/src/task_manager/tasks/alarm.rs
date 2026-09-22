/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::timezone::Tz,
    icalendar::{
        ArchivedICalendarComponent, ArchivedICalendarEntry, ArchivedICalendarParameterName,
        ArchivedICalendarProperty, ICalendar, ICalendarComponentType,
    },
};
use common::{
    ArchivedDavName, DEFAULT_LOGO_BASE64, GroupwareResources, Server,
    auth::{AccessToken, AccountInfo, BuildAccessToken},
    config::groupware::CalendarTemplateVariable,
    ipc::{CalendarAlert, PushNotification},
    network::{ServerInstance, stream::NullIo},
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        ArchivedCalendarEvent, ArchivedCalendarEventContent, CalendarEvent, CalendarEventContent,
        EVENT_DRAFT, EVENT_HIDE_ATTENDEES,
        alarm::{AlarmId, AlarmTarget, EventAlarmData, TriggeredAlarm},
        alerts::{DefaultAlerts, DefaultAlertsResolver},
        expand::RecurrenceKey,
        identity::{CalendarAddresses, EventOwnership, ParticipantIdentityAddresses},
        index::ICalendarObjectUid,
        participants::ParticipantVisibility,
        privacy::EventPrivacy,
        schedule::{EventAlarmScheduler, EventAlarmUsers},
    },
    scheduling::{
        ItipTime, ItipValue,
        format::{DateStyle, TextFormatter, hyperlink},
    },
    strip_mailto_scheme,
};
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, content_type::ContentType},
    mime::{BodyPart, MimePart},
};
use mail_parser::decoders::html::html_to_text;
use registry::{
    schema::{
        enums::Permission,
        structs::{TaskCalendarAlarmEmail, TaskCalendarAlarmNotification, TaskStatus},
    },
    types::EnumImpl,
};
use smtp::core::{Session, SessionData};
use smtp_proto::{MailFrom, RcptTo};
use std::{sync::Arc, time::Duration};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, now, serialize::rkyv_deserialize},
};
use trc::{AddContext, TaskManagerEvent};
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
};
use utils::{sanitize_email, template::Variables};

use crate::task_manager::TaskResult;

pub(crate) trait SendAlarmTask: Sync + Send {
    fn send_display_alarm(
        &self,
        task: &TaskCalendarAlarmNotification,
    ) -> impl Future<Output = TaskResult> + Send;

    fn send_email_alarm(
        &self,
        task: &TaskCalendarAlarmEmail,
        server_instance: Arc<ServerInstance>,
    ) -> impl Future<Output = TaskResult> + Send;
}

impl SendAlarmTask for Server {
    async fn send_display_alarm(&self, task: &TaskCalendarAlarmNotification) -> TaskResult {
        match send_display_alarm(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .document_id(task.document_id.document_id())
                        .caused_by(trc::location!())
                        .details("Failed to process e-mail alarm")
                );
                result
            }
        }
    }

    async fn send_email_alarm(
        &self,
        task: &TaskCalendarAlarmEmail,
        server_instance: Arc<ServerInstance>,
    ) -> TaskResult {
        match send_email_alarm(self, task, server_instance).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .document_id(task.document_id.document_id())
                        .caused_by(trc::location!())
                        .details("Failed to process e-mail alarm")
                );
                result
            }
        }
    }
}

async fn send_email_alarm(
    server: &Server,
    task: &TaskCalendarAlarmEmail,
    server_instance: Arc<ServerInstance>,
) -> trc::Result<TaskResult> {
    let account_id = task.account_id.document_id();
    let document_id = task.document_id.document_id();
    let target_id = task
        .target_account_id
        .map_or(account_id, |id| id.document_id());
    let fired = FiredAlarm::new(&task.status);
    let Some((meta_, event_)) = fetch_alarm_event(server, account_id, document_id).await? else {
        return Ok(TaskResult::Success(vec![]));
    };
    let meta = meta_
        .unarchive::<CalendarEvent>()
        .caused_by(trc::location!())?;
    let event = event_
        .unarchive::<CalendarEventContent>()
        .caused_by(trc::location!())?;
    let mut alarm = AlarmContext::new(server, account_id, document_id, target_id, meta).await?;
    if let Some(reason) = alarm
        .skip_reason(server, Some(Permission::CalendarAlarmsSend))
        .await?
    {
        return alarm.skip(server, event, fired, reason).await;
    }
    let account_info = server
        .account_info(target_id)
        .await
        .caused_by(trc::location!())?;
    if account_info.name().is_empty() {
        trc::event!(
            Calendar(trc::CalendarEvent::AlarmFailed),
            Reason = "Account does not have any email addresses",
            AccountId = account_id,
            DocumentId = document_id,
        );
        return alarm.build_next(server, event, fired).await;
    }
    let recurrence_key = event
        .data
        .component_recurrence(
            task.event_id as u16,
            Tz::from_id(task.event_start_tz as u16).unwrap_or(Tz::Floating),
        )
        .recurrence_key(task.event_start.timestamp());
    let alarm_id = AlarmId::from_task_id(task.alarm_id);
    let defaults = alarm.defaults(server, event, alarm_id).await?;
    let Some(triggered) =
        alarm.triggered(event, &defaults, alarm_id, task.event_id, recurrence_key)
    else {
        return alarm.build_next(server, event, fired).await;
    };
    if triggered
        .acknowledged()
        .is_some_and(|acknowledged| acknowledged >= fired.alarm_time)
    {
        return alarm
            .skip(server, event, fired, "Alarm was acknowledged")
            .await;
    }
    let event_account_info = if target_id == account_id {
        None
    } else {
        Some(
            server
                .account_info(account_id)
                .await
                .caused_by(trc::location!())?,
        )
    };
    let attendees = alarm.attendee_list(server, &account_info, event).await?;

    // Build message body
    let account_main_email = account_info.name();
    let account_main_domain = account_main_email.rsplit('@').next().unwrap_or("localhost");
    let logo_cid = format!("logo.{}@{account_main_domain}", now());
    let Some(tpl) = build_template(
        server,
        &account_info,
        event_account_info.as_ref().unwrap_or(&account_info),
        task,
        meta,
        event,
        triggered.component(),
        &attendees,
        &logo_cid,
    )
    .await?
    else {
        return alarm.build_next(server, event, fired).await;
    };
    let txt_body = html_to_text(&tpl.body);

    // Obtain logo image
    let logo = match server.logo_resource(account_main_domain).await {
        Ok(logo) => logo,
        Err(err) => {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to fetch logo image")
            );
            None
        }
    };
    let logo = if let Some(logo) = &logo {
        MimePart::new(
            ContentType::new(logo.content_type.as_ref()),
            BodyPart::Binary(logo.contents.as_slice().into()),
        )
    } else {
        MimePart::new(
            ContentType::new("image/png"),
            BodyPart::Binary(DEFAULT_LOGO_BASE64.as_bytes().into()),
        )
        .transfer_encoding("base64")
    }
    .inline()
    .cid(&logo_cid);

    // Build message
    let mail_from = if let Some(from_email) = &server.core.groupware.alarms_from_email {
        from_email.to_string()
    } else {
        format!("calendar-notification@{account_main_domain}")
    };
    let message = MessageBuilder::new()
        .from((
            server.core.groupware.alarms_from_name.as_str(),
            mail_from.as_str(),
        ))
        .header("To", HeaderType::Text(tpl.to.as_str().into()))
        .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
        .header("Reply-To", HeaderType::Text(account_main_email.into()))
        .message_id(server.core.network.message_id())
        .subject(tpl.subject)
        .body(MimePart::new(
            ContentType::new("multipart/related"),
            BodyPart::Multipart(vec![
                MimePart::new(
                    ContentType::new("multipart/alternative"),
                    BodyPart::Multipart(vec![
                        MimePart::new(
                            ContentType::new("text/plain"),
                            BodyPart::Text(txt_body.into()),
                        ),
                        MimePart::new(
                            ContentType::new("text/html"),
                            BodyPart::Text(tpl.body.into()),
                        ),
                    ]),
                ),
                logo,
            ]),
        ))
        .write_to_vec()
        .unwrap_or_default();

    // Send message
    let server_ = server.clone();
    let mail_from = account_main_email.to_string();
    let to = tpl.to;
    let result = tokio::spawn(async move {
        let mut session = Session::<NullIo>::local(
            server_,
            server_instance,
            SessionData::local(account_info, None, vec![], vec![], 0),
        );

        // MAIL FROM
        let _ = session
            .handle_mail_from(MailFrom {
                address: mail_from.into(),
                ..Default::default()
            })
            .await;
        if let Some(error) = session.has_failed() {
            return Err(format!("Server rejected MAIL-FROM: {}", error.trim()));
        }

        // RCPT TO
        session.params.rcpt_errors_wait = Duration::from_secs(0);
        let _ = session
            .handle_rcpt_to(RcptTo {
                address: to.into(),
                ..Default::default()
            })
            .await;
        if let Some(error) = session.has_failed() {
            return Err(format!("Server rejected RCPT-TO: {}", error.trim()));
        }

        // DATA
        session.data.message = message;
        let response = session.queue_message().await;
        if let smtp::core::State::Accepted(queue_id) = session.state {
            Ok(queue_id)
        } else {
            Err(format!(
                "Server rejected DATA: {}",
                std::str::from_utf8(&response).unwrap().trim()
            ))
        }
    })
    .await;

    match result {
        Ok(Ok(queue_id)) => {
            trc::event!(
                Calendar(trc::CalendarEvent::AlarmSent),
                AccountId = account_id,
                DocumentId = document_id,
                QueueId = queue_id,
            );
        }
        Ok(Err(err)) => {
            trc::event!(
                Calendar(trc::CalendarEvent::AlarmFailed),
                AccountId = account_id,
                DocumentId = document_id,
                Reason = err,
            );
        }
        Err(_) => {
            trc::event!(
                Server(trc::ServerEvent::ThreadError),
                Details = "Join Error",
                AccountId = account_id,
                DocumentId = document_id,
                CausedBy = trc::location!(),
            );
            return Ok(TaskResult::temporary("Thread join error"));
        }
    }

    alarm.build_next(server, event, fired).await
}

async fn send_display_alarm(
    server: &Server,
    task: &TaskCalendarAlarmNotification,
) -> trc::Result<TaskResult> {
    let account_id = task.account_id.document_id();
    let document_id = task.document_id.document_id();
    let target_id = task
        .target_account_id
        .map_or(account_id, |id| id.document_id());
    let fired = FiredAlarm::new(&task.status);
    let Some((meta_, event_)) = fetch_alarm_event(server, account_id, document_id).await? else {
        return Ok(TaskResult::Success(vec![]));
    };
    let meta = meta_
        .unarchive::<CalendarEvent>()
        .caused_by(trc::location!())?;
    let event = event_
        .unarchive::<CalendarEventContent>()
        .caused_by(trc::location!())?;
    let mut alarm = AlarmContext::new(server, account_id, document_id, target_id, meta).await?;
    if let Some(reason) = alarm.skip_reason(server, None).await? {
        return alarm.skip(server, event, fired, reason).await;
    }
    let recurrence_key = task
        .recurrence_id
        .and_then(RecurrenceKey::from_recurrence_id)
        .map(RecurrenceKey::prefix);
    let alarm_id = AlarmId::from_task_id(task.alarm_id);
    let defaults = alarm.defaults(server, event, alarm_id).await?;
    let Some(triggered) =
        alarm.triggered(event, &defaults, alarm_id, task.event_id, recurrence_key)
    else {
        return alarm.build_next(server, event, fired).await;
    };
    if triggered
        .acknowledged()
        .is_some_and(|acknowledged| acknowledged >= fired.alarm_time)
    {
        return alarm
            .skip(server, event, fired, "Alarm was acknowledged")
            .await;
    }

    let alert_id = match triggered.alert_id() {
        Some(alert_id) => alert_id.to_string(),
        None => format!("k{}", alarm.alarm_position(event, task) + 1),
    };
    server
        .broadcast_push_notification(PushNotification::CalendarAlert(CalendarAlert {
            account_id: target_id,
            event_account_id: account_id,
            event_id: document_id,
            recurrence_id: task.recurrence_id,
            uid: event
                .data
                .event
                .object_uid()
                .unwrap_or_default()
                .to_string(),
            alert_id,
        }))
        .await;

    alarm.build_next(server, event, fired).await
}

struct AlarmContext<'x> {
    account_id: u32,
    document_id: u32,
    target_id: u32,
    target: AlarmTarget,
    meta: &'x ArchivedCalendarEvent,
    calendar_ids: Vec<u32>,
    access_token: AccessToken,
    shared_resources: Option<Arc<GroupwareResources>>,
    resolver: DefaultAlertsResolver,
}

impl<'x> AlarmContext<'x> {
    async fn new(
        server: &Server,
        account_id: u32,
        document_id: u32,
        target_id: u32,
        meta: &'x ArchivedCalendarEvent,
    ) -> trc::Result<Self> {
        let access_token = server
            .access_token(target_id)
            .await
            .caused_by(trc::location!())?
            .build();
        let shared_resources = if access_token.is_member(account_id) {
            None
        } else {
            Some(
                server
                    .fetch_groupware_resources(target_id, account_id, SyncCollection::Calendar)
                    .await
                    .caused_by(trc::location!())?,
            )
        };
        let resolver = shared_resources
            .as_ref()
            .map_or_else(DefaultAlertsResolver::default, |resources| {
                DefaultAlertsResolver::with_resources(account_id, resources.clone())
            });
        Ok(AlarmContext {
            account_id,
            document_id,
            target_id,
            target: AlarmTarget::for_account(account_id, target_id),
            meta,
            calendar_ids: meta.names.iter().map(ArchivedDavName::parent_id).collect(),
            access_token,
            shared_resources,
            resolver,
        })
    }

    async fn skip_reason(
        &mut self,
        server: &Server,
        permission: Option<Permission>,
    ) -> trc::Result<Option<&'static str>> {
        if !server.core.groupware.alarms_enabled {
            return Ok(Some("Calendar alarms are disabled"));
        }
        if self.meta.flags & EVENT_DRAFT != 0 {
            return Ok(Some("Calendar event is a draft"));
        }
        if !self
            .resolver
            .is_subscribed(
                server,
                self.account_id,
                self.target_id,
                self.calendar_ids.iter().copied(),
            )
            .await
            .caused_by(trc::location!())?
        {
            return Ok(Some("User is not subscribed to the calendar"));
        }
        if permission.is_some_and(|permission| !self.access_token.has_permission(permission)) {
            return Ok(Some(
                "Account does not have permission to send calendar alarms",
            ));
        }
        let Some(resources) = &self.shared_resources else {
            return Ok(None);
        };
        if EventPrivacy::from_flags(self.meta.flags.to_native()) != EventPrivacy::Public {
            return Ok(Some("Calendar event is not public"));
        }
        if self.calendar_ids.iter().any(|calendar_id| {
            resources.has_access_to_container(&self.access_token, *calendar_id, Acl::ReadItems)
        }) {
            Ok(None)
        } else {
            Ok(Some("User no longer has access to the calendar"))
        }
    }

    async fn skip(
        &mut self,
        server: &Server,
        event: &ArchivedCalendarEventContent,
        fired: FiredAlarm,
        reason: &'static str,
    ) -> trc::Result<TaskResult> {
        trc::event!(
            Calendar(trc::CalendarEvent::AlarmSkipped),
            Reason = reason,
            AccountId = self.account_id,
            DocumentId = self.document_id,
        );
        self.build_next(server, event, fired).await
    }

    async fn defaults(
        &mut self,
        server: &Server,
        event: &ArchivedCalendarEventContent,
        alarm_id: Option<AlarmId>,
    ) -> trc::Result<DefaultAlerts> {
        if alarm_id.is_some_and(AlarmId::is_default) {
            self.resolver
                .resolve_for_content(
                    server,
                    self.account_id,
                    self.target_id,
                    event,
                    self.calendar_ids.iter().copied(),
                )
                .await
                .caused_by(trc::location!())
        } else {
            Ok(DefaultAlerts::disabled())
        }
    }

    fn triggered<'y>(
        &self,
        event: &'y ArchivedCalendarEventContent,
        defaults: &'y DefaultAlerts,
        alarm_id: Option<AlarmId>,
        event_id: u64,
        recurrence_key: Option<u32>,
    ) -> Option<TriggeredAlarm<'y>> {
        let triggered = alarm_id.and_then(|alarm_id| {
            event.triggered_alarm(
                self.target,
                alarm_id,
                event_id as u16,
                recurrence_key,
                defaults,
            )
        });
        if triggered.is_none() {
            trc::event!(
                TaskManager(TaskManagerEvent::MetadataNotFound),
                Details = "Calendar Alarm component not found",
                AccountId = self.account_id,
                DocumentId = self.document_id,
            );
        }
        triggered
    }

    fn alarm_position(
        &self,
        event: &ArchivedCalendarEventContent,
        task: &TaskCalendarAlarmNotification,
    ) -> usize {
        match AlarmId::from_task_id(task.alarm_id) {
            Some(AlarmId::Stored(alarm_id)) => {
                let components = &event.data.event.components;
                components
                    .get(task.event_id as usize)
                    .into_iter()
                    .flat_map(|component| component.component_ids.iter())
                    .map(|id| id.to_native())
                    .filter(|id| {
                        components
                            .get(*id as usize)
                            .is_some_and(|c| c.component_type == ICalendarComponentType::VAlarm)
                    })
                    .position(|id| id == alarm_id as u32)
                    .unwrap_or_default()
            }
            Some(AlarmId::Personal(index)) => index as usize,
            Some(AlarmId::Default(_)) | None => 0,
        }
    }

    async fn attendee_list(
        &self,
        server: &Server,
        account_info: &AccountInfo,
        event: &ArchivedCalendarEventContent,
    ) -> trc::Result<AttendeeList> {
        if self.shared_resources.is_none()
            || self.meta.flags.to_native() & EVENT_HIDE_ATTENDEES == 0
        {
            return Ok(AttendeeList::All);
        }
        let identities = server
            .identity_addresses(self.target_id, account_info)
            .await
            .caused_by(trc::location!())?;
        let ical =
            rkyv_deserialize::<_, ICalendar>(&event.data.event).caused_by(trc::location!())?;
        Ok(
            if identities.event_ownership(&ical) == EventOwnership::Owner {
                AttendeeList::All
            } else {
                AttendeeList::OwnersAndSelf(identities)
            },
        )
    }

    async fn build_next(
        &mut self,
        server: &Server,
        event: &ArchivedCalendarEventContent,
        fired: FiredAlarm,
    ) -> trc::Result<TaskResult> {
        let users = EventAlarmUsers::for_target(self.account_id, event, self.target)?
            .with_event_flags(self.meta.flags.to_native());
        let now = now() as i64;
        let start_time = fired
            .alarm_time
            .min(now)
            .max(now + server.core.groupware.alarms_minimum_interval);
        let next_alarm = server
            .next_event_alarms(
                self.account_id,
                &users,
                &event.data,
                &self.calendar_ids,
                start_time,
                &mut self.resolver,
            )
            .await?
            .into_alarm();

        Ok(match next_alarm {
            Some(next_alarm) => {
                TaskResult::Update(next_alarm.build_write_ops(self.account_id, self.document_id))
            }
            None => TaskResult::Success(vec![]),
        })
    }
}

enum AttendeeList {
    All,
    OwnersAndSelf(CalendarAddresses),
}

impl AttendeeList {
    fn includes(&self, entry: &ArchivedICalendarEntry) -> bool {
        match self {
            AttendeeList::All => true,
            AttendeeList::OwnersAndSelf(identities) => entry.is_visible_participant(identities),
        }
    }
}

async fn fetch_alarm_event(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<(Archive<ArchiveBytes>, Archive<ArchiveBytes>)>> {
    let (Some(meta), Some(event)) = (
        server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::CalendarEvent,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?,
        server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                account_id,
                Collection::CalendarEvent,
                document_id,
                CalendarEventField::Content,
            ))
            .await
            .caused_by(trc::location!())?,
    ) else {
        trc::event!(
            TaskManager(TaskManagerEvent::MetadataNotFound),
            Details = "Calendar Event metadata not found",
            AccountId = account_id,
            DocumentId = document_id,
        );
        return Ok(None);
    };
    Ok(Some((meta, event)))
}

#[derive(Debug, Clone, Copy)]
struct FiredAlarm {
    alarm_time: i64,
}

impl FiredAlarm {
    fn new(status: &TaskStatus) -> Self {
        FiredAlarm {
            alarm_time: match status {
                TaskStatus::Pending(pending) => pending.due.timestamp(),
                _ => now() as i64,
            },
        }
    }
}

struct Details {
    to: String,
    subject: String,
    body: String,
}

#[allow(clippy::too_many_arguments)]
async fn build_template(
    server: &Server,
    account_info: &AccountInfo,
    event_account_info: &AccountInfo,
    alarm: &TaskCalendarAlarmEmail,
    meta: &ArchivedCalendarEvent,
    event: &ArchivedCalendarEventContent,
    alarm_component: Option<&ArchivedICalendarComponent>,
    attendees: &AttendeeList,
    logo_cid: &str,
) -> trc::Result<Option<Details>> {
    let account_id = alarm.account_id.document_id();
    let document_id = alarm.document_id.document_id();
    let Some(event_component) = event.data.event.components.get(alarm.event_id as usize) else {
        trc::event!(
            TaskManager(TaskManagerEvent::MetadataNotFound),
            Details = "Calendar Alarm component not found",
            AccountId = account_id,
            DocumentId = document_id,
        );
        return Ok(None);
    };

    // Build webcal URI
    let webcal_uri = match meta.webcal_uri(server, event_account_info).await {
        Ok(uri) => uri,
        Err(err) => {
            trc::error!(
                err.account_id(account_id)
                    .document_id(document_id)
                    .caused_by(trc::location!())
                    .details("Failed to generate webcal URI")
            );
            String::from("#")
        }
    };

    // Obtain alarm details
    let mut summary = None;
    let mut description = None;
    let mut rcpt_to = None;
    let mut location = None;
    let mut conference = None;
    let mut organizer = None;
    let mut guests = vec![];

    for entry in alarm_component
        .into_iter()
        .flat_map(|alarm_component| alarm_component.entries.iter())
    {
        match &entry.name {
            ArchivedICalendarProperty::Summary => {
                summary = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Description => {
                description = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Attendee => {
                rcpt_to = entry
                    .values
                    .first()
                    .and_then(|v| v.as_text())
                    .map(strip_mailto_scheme)
                    .and_then(sanitize_email);
            }
            _ => {}
        }
    }

    for entry in event_component.entries.iter() {
        match &entry.name {
            ArchivedICalendarProperty::Summary if summary.is_none() => {
                summary = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Description if description.is_none() => {
                description = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Location => {
                location = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Conference if conference.is_none() => {
                conference = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Attendee if !attendees.includes(entry) => {}
            ArchivedICalendarProperty::Organizer | ArchivedICalendarProperty::Attendee => {
                let email = entry
                    .values
                    .first()
                    .and_then(|v| v.as_text())
                    .map(strip_mailto_scheme);
                let name = entry.params.iter().find_map(|param| {
                    if let ArchivedICalendarParameterName::Cn = param.name {
                        param.value.as_text()
                    } else {
                        None
                    }
                });

                if email.is_some() || name.is_some() {
                    if matches!(entry.name, ArchivedICalendarProperty::Organizer) {
                        organizer = Some((email, name));
                    } else {
                        guests.push((email, name));
                    }
                }
            }
            _ => {}
        }
    }

    // Validate recipient
    let rcpt_to = if let Some(rcpt_to) = rcpt_to {
        if server.core.groupware.alarms_allow_external_recipients
            || account_info.addresses().contains(&rcpt_to)
        {
            rcpt_to
        } else {
            trc::event!(
                Calendar(trc::CalendarEvent::AlarmRecipientOverride),
                Reason = "External recipient not allowed for calendar alarms",
                Details = rcpt_to,
                AccountId = account_id,
                DocumentId = document_id,
            );

            account_info.name().to_string()
        }
    } else {
        account_info.name().to_string()
    };

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let template = server
        .core
        .enterprise
        .as_ref()
        .and_then(|e| e.template_calendar_alarm.as_ref())
        .unwrap_or(&server.core.groupware.alarms_template);
    // SPDX-SnippetEnd

    #[cfg(not(feature = "enterprise"))]
    let template = &server.core.groupware.alarms_template;
    let formatter = TextFormatter::new(account_info.locale().as_str())?;
    let locale = formatter.locale;

    let start = formatter.field_to_string(
        &ItipValue::Time(ItipTime {
            start: alarm.event_start.timestamp(),
            tz_id: alarm.event_start_tz as u16,
        }),
        DateStyle::Short,
    );
    let end = formatter.field_to_string(
        &ItipValue::Time(ItipTime {
            start: alarm.event_end.timestamp(),
            tz_id: alarm.event_end_tz as u16,
        }),
        DateStyle::Short,
    );
    let subject = format!(
        "{}: {} @ {}",
        locale.calendar_alarm_subject_prefix,
        summary.or(description).unwrap_or("No Subject"),
        start
    );
    let organizer = organizer
        .map(|(email, name)| match (email, name) {
            (Some(email), Some(name)) => format!("{} <{}>", name, email),
            (Some(email), None) => email.to_string(),
            (None, Some(name)) => name.to_string(),
            _ => unreachable!(),
        })
        .unwrap_or_else(|| account_info.name().to_string());
    let logo_cid = format!("cid:{logo_cid}");
    let mut variables = Variables::new();
    variables.insert_single(CalendarTemplateVariable::PageTitle, subject.as_str());
    variables.insert_single(CalendarTemplateVariable::Lang, locale.name);
    variables.insert_single(CalendarTemplateVariable::Dir, locale.direction);
    variables.insert_single(
        CalendarTemplateVariable::Header,
        locale.calendar_alarm_header,
    );
    variables.insert_single(
        CalendarTemplateVariable::Footer,
        locale.calendar_alarm_footer,
    );
    variables.insert_single(
        CalendarTemplateVariable::ActionName,
        locale.calendar_alarm_open,
    );
    variables.insert_single(CalendarTemplateVariable::ActionUrl, webcal_uri.as_str());
    variables.insert_single(
        CalendarTemplateVariable::AttendeesTitle,
        locale.calendar_attendees,
    );
    if let Some(summary) = summary.filter(|summary| !summary.is_empty()) {
        variables.insert_single(CalendarTemplateVariable::EventTitle, summary);
    }
    variables.insert_single(CalendarTemplateVariable::LogoCid, logo_cid.as_str());
    if let Some(description) = description {
        variables.insert_single(CalendarTemplateVariable::EventDescription, description);
    }
    variables.insert_block(
        CalendarTemplateVariable::EventDetails,
        [
            Some(vec![
                (CalendarTemplateVariable::Key, locale.calendar_start),
                (CalendarTemplateVariable::Value, start.as_str()),
            ]),
            Some(vec![
                (CalendarTemplateVariable::Key, locale.calendar_end),
                (CalendarTemplateVariable::Value, end.as_str()),
            ]),
            location.map(|location| {
                vec![
                    (CalendarTemplateVariable::Key, locale.calendar_location),
                    (CalendarTemplateVariable::Value, location),
                ]
            }),
            conference.map(|conference| {
                let mut detail = vec![
                    (CalendarTemplateVariable::Key, locale.calendar_conference),
                    (CalendarTemplateVariable::Value, conference),
                ];
                if let Some(link) = hyperlink(conference) {
                    detail.push((CalendarTemplateVariable::Link, link));
                }
                detail
            }),
            Some(vec![
                (CalendarTemplateVariable::Key, locale.calendar_organizer),
                (CalendarTemplateVariable::Value, organizer.as_str()),
            ]),
        ]
        .into_iter()
        .flatten(),
    );
    if !guests.is_empty() {
        variables.insert_block(
            CalendarTemplateVariable::Attendees,
            guests.into_iter().map(|(email, name)| {
                [
                    (CalendarTemplateVariable::Key, name.unwrap_or_default()),
                    (CalendarTemplateVariable::Value, email.unwrap_or_default()),
                ]
            }),
        );
    }
    Ok(Some(Details {
        to: rcpt_to,
        body: template.eval(&variables),
        subject,
    }))
}
