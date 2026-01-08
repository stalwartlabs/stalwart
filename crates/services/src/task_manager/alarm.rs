/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::timezone::Tz,
    icalendar::{ArchivedICalendarParameterName, ArchivedICalendarProperty, ICalendarProperty},
};
use chrono::{DateTime, Locale};
use common::{
    DEFAULT_LOGO_BASE64, Server,
    auth::AccessToken,
    config::groupware::CalendarTemplateVariable,
    i18n,
    ipc::{CalendarAlert, PushNotification},
    listener::{ServerInstance, stream::NullIo},
};
use directory::Permission;
use groupware::calendar::{
    ArchivedCalendarEvent, CalendarEvent,
    alarm::{CalendarAlarm, CalendarAlarmType},
};
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, content_type::ContentType},
    mime::{BodyPart, MimePart},
};
use mail_parser::decoders::html::html_to_text;
use smtp::core::{Session, SessionData};
use smtp_proto::{MailFrom, RcptTo};
use std::{str::FromStr, sync::Arc, time::Duration};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive, BatchBuilder, now},
};
use trc::{AddContext, TaskQueueEvent};
use types::collection::Collection;
use utils::{sanitize_email, template::Variables};

pub trait SendAlarmTask: Sync + Send {
    fn send_alarm(
        &self,
        account_id: u32,
        document_id: u32,
        alarm: &CalendarAlarm,
        server_instance: Arc<ServerInstance>,
    ) -> impl Future<Output = bool> + Send;
}

impl SendAlarmTask for Server {
    async fn send_alarm(
        &self,
        account_id: u32,
        document_id: u32,
        alarm: &CalendarAlarm,
        server_instance: Arc<ServerInstance>,
    ) -> bool {
        match &alarm.typ {
            CalendarAlarmType::Display { .. } => {
                match send_display_alarm(self, account_id, document_id, alarm).await {
                    Ok(result) => result,
                    Err(err) => {
                        trc::error!(
                            err.account_id(account_id)
                                .document_id(document_id)
                                .caused_by(trc::location!())
                                .details("Failed to process e-mail alarm")
                        );
                        false
                    }
                }
            }
            CalendarAlarmType::Email { .. } => {
                match send_email_alarm(self, account_id, document_id, alarm, server_instance).await
                {
                    Ok(result) => result,
                    Err(err) => {
                        trc::error!(
                            err.account_id(account_id)
                                .document_id(document_id)
                                .caused_by(trc::location!())
                                .details("Failed to process e-mail alarm")
                        );
                        false
                    }
                }
            }
        }
    }
}

async fn send_email_alarm(
    server: &Server,
    account_id: u32,
    document_id: u32,
    alarm: &CalendarAlarm,
    server_instance: Arc<ServerInstance>,
) -> trc::Result<bool> {
    // Obtain access token
    let access_token = server
        .get_access_token(account_id)
        .await
        .caused_by(trc::location!())?;

    if !access_token.has_permission(Permission::CalendarAlarms) {
        trc::event!(
            Calendar(trc::CalendarEvent::AlarmSkipped),
            Reason = "Account does not have permission to send calendar alarms",
            AccountId = account_id,
            DocumentId = document_id,
        );
        return Ok(true);
    } else if access_token.emails.is_empty() {
        trc::event!(
            Calendar(trc::CalendarEvent::AlarmFailed),
            Reason = "Account does not have any email addresses",
            AccountId = account_id,
            DocumentId = document_id,
        );
        return Ok(true);
    }

    // Fetch event
    let Some(event_) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::CalendarEvent,
            document_id,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        trc::event!(
            TaskQueue(TaskQueueEvent::MetadataNotFound),
            Details = "Calendar Event metadata not found",
            AccountId = account_id,
            DocumentId = document_id,
        );

        return Ok(true);
    };

    // Unarchive event
    let event = event_
        .unarchive::<CalendarEvent>()
        .caused_by(trc::location!())?;

    // Build message body
    let account_main_email = access_token.emails.first().unwrap();
    let account_main_domain = account_main_email.rsplit('@').next().unwrap_or("localhost");
    let logo_cid = format!("logo.{}@{account_main_domain}", now());
    let Some(tpl) = build_template(
        server,
        &access_token,
        account_id,
        document_id,
        alarm,
        event,
        &logo_cid,
    )
    .await?
    else {
        return Ok(true);
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
            SessionData::local(access_token, None, vec![], vec![], 0),
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
            return Ok(false);
        }
    }

    write_next_alarm(server, account_id, document_id, event).await
}

async fn send_display_alarm(
    server: &Server,
    account_id: u32,
    document_id: u32,
    alarm: &CalendarAlarm,
) -> trc::Result<bool> {
    // Fetch event
    let Some(event_) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::CalendarEvent,
            document_id,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        trc::event!(
            TaskQueue(TaskQueueEvent::MetadataNotFound),
            Details = "Calendar Event metadata not found",
            AccountId = account_id,
            DocumentId = document_id,
        );

        return Ok(true);
    };

    // Unarchive event
    let event = event_
        .unarchive::<CalendarEvent>()
        .caused_by(trc::location!())?;

    let recurrence_id = match &alarm.typ {
        CalendarAlarmType::Display { recurrence_id } => *recurrence_id,
        _ => None,
    };

    let ical = &event.data.event;
    server
        .broadcast_push_notification(PushNotification::CalendarAlert(CalendarAlert {
            account_id,
            event_id: document_id,
            recurrence_id,
            uid: ical.uids().next().unwrap_or_default().to_string(),
            alert_id: ical
                .components
                .get(alarm.alarm_id as usize)
                .and_then(|c| c.property(&ICalendarProperty::Jsid))
                .and_then(|v| v.values.first())
                .and_then(|v| v.as_text())
                .map(|v| v.to_string())
                .unwrap_or_else(|| {
                    format!(
                        "k{}",
                        ical.components
                            .get(alarm.event_id as usize)
                            .and_then(|c| c
                                .component_ids
                                .iter()
                                .position(|id| id.to_native() == alarm.alarm_id as u32))
                            .unwrap_or_default()
                            + 1
                    )
                }),
        }))
        .await;

    write_next_alarm(server, account_id, document_id, event).await
}

async fn write_next_alarm(
    server: &Server,
    account_id: u32,
    document_id: u32,
    event: &ArchivedCalendarEvent,
) -> trc::Result<bool> {
    // Find next alarm time and write to task queue
    let now = now() as i64;
    if let Some(next_alarm) =
        event
            .data
            .next_alarm(now, Default::default())
            .and_then(|next_alarm| {
                // Verify minimum interval
                let max_next_alarm = now + server.core.groupware.alarms_minimum_interval;
                if next_alarm.alarm_time < max_next_alarm {
                    trc::event!(
                        Calendar(trc::CalendarEvent::AlarmSkipped),
                        Reason = "Next alarm skipped due to minimum interval",
                        Details = next_alarm.alarm_time - now,
                        AccountId = account_id,
                        DocumentId = document_id,
                    );
                    event.data.next_alarm(max_next_alarm, Default::default())
                } else {
                    Some(next_alarm)
                }
            })
    {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id);
        next_alarm.write_task(&mut batch);
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        server.notify_task_queue();
    }

    Ok(true)
}

struct Details {
    to: String,
    subject: String,
    body: String,
}

async fn build_template(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    alarm: &CalendarAlarm,
    event: &ArchivedCalendarEvent,
    logo_cid: &str,
) -> trc::Result<Option<Details>> {
    let (Some(event_component), Some(alarm_component)) = (
        event.data.event.components.get(alarm.event_id as usize),
        event.data.event.components.get(alarm.alarm_id as usize),
    ) else {
        trc::event!(
            TaskQueue(TaskQueueEvent::MetadataNotFound),
            Details = "Calendar Alarm component not found",
            AccountId = account_id,
            DocumentId = document_id,
        );
        return Ok(None);
    };

    // Build webcal URI
    let webcal_uri = match event.webcal_uri(server, access_token).await {
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
    let mut organizer = None;
    let mut guests = vec![];

    for entry in alarm_component.entries.iter() {
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
                    .map(|v| v.strip_prefix("mailto:").unwrap_or(v))
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
            ArchivedICalendarProperty::Organizer | ArchivedICalendarProperty::Attendee => {
                let email = entry
                    .values
                    .first()
                    .and_then(|v| v.as_text())
                    .map(|v| v.strip_prefix("mailto:").unwrap_or(v));
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
            || access_token.emails.iter().any(|email| email == &rcpt_to)
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

            access_token.emails.first().unwrap().to_string()
        }
    } else {
        access_token.emails.first().unwrap().to_string()
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
    let locale = i18n::locale_or_default(access_token.locale.as_deref().unwrap_or("en"));
    let chrono_locale = access_token
        .locale
        .as_deref()
        .and_then(|locale| Locale::from_str(locale).ok())
        .unwrap_or(Locale::en_US);
    let (event_start, event_start_tz, event_end, event_end_tz) = match alarm.typ {
        CalendarAlarmType::Email {
            event_start,
            event_start_tz,
            event_end,
            event_end_tz,
        } => (event_start, event_start_tz, event_end, event_end_tz),
        CalendarAlarmType::Display { .. } => unreachable!(),
    };

    let start = format!(
        "{} ({})",
        DateTime::from_timestamp(event_start, 0)
            .unwrap_or_default()
            .format_localized(locale.calendar_date_template, chrono_locale),
        Tz::from_id(event_start_tz)
            .unwrap_or(Tz::UTC)
            .name()
            .unwrap_or_default()
    );
    let end = format!(
        "{} ({})",
        DateTime::from_timestamp(event_end, 0)
            .unwrap_or_default()
            .format_localized(locale.calendar_date_template, chrono_locale),
        Tz::from_id(event_end_tz)
            .unwrap_or(Tz::UTC)
            .name()
            .unwrap_or_default()
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
        .unwrap_or_else(|| access_token.name.clone());
    let mut variables = Variables::new();
    variables.insert_single(CalendarTemplateVariable::PageTitle, subject.as_str());
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
    variables.insert_single(
        CalendarTemplateVariable::EventTitle,
        summary.unwrap_or_default(),
    );
    variables.insert_single(CalendarTemplateVariable::LogoCid, logo_cid);
    if let Some(description) = description {
        variables.insert_single(CalendarTemplateVariable::EventDescription, description);
    }
    variables.insert_block(
        CalendarTemplateVariable::EventDetails,
        [
            Some([
                (CalendarTemplateVariable::Key, locale.calendar_start),
                (CalendarTemplateVariable::Value, start.as_str()),
            ]),
            Some([
                (CalendarTemplateVariable::Key, locale.calendar_end),
                (CalendarTemplateVariable::Value, end.as_str()),
            ]),
            location.map(|location| {
                [
                    (CalendarTemplateVariable::Key, locale.calendar_location),
                    (CalendarTemplateVariable::Value, location),
                ]
            }),
            Some([
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
