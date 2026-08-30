/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::TaskResult;
use calcard::icalendar::{ICalendarParticipationStatus, ICalendarProperty};
use common::{
    DEFAULT_LOGO_BASE64, Server,
    auth::AccountInfo,
    config::groupware::CalendarTemplateVariable,
    network::{ServerInstance, stream::NullIo},
};
use groupware::{
    calendar::itip::ItipIngest,
    scheduling::{
        ItipSummary, ItipValue,
        format::{DateStyle, TextFormatter, hyperlink},
    },
};
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, content_type::ContentType},
    mime::{BodyPart, MimePart},
};
use mail_parser::decoders::html::html_to_text;
use registry::{schema::structs::TaskCalendarItipMessage, types::EnumImpl};
use smtp::core::{Session, SessionData};
use smtp_proto::{MailFrom, RcptTo};
use std::{sync::Arc, time::Duration};
use store::{ahash::AHashMap, write::now};
use trc::AddContext;
use utils::template::{Variable, Variables};

pub(crate) trait SendImipTask: Sync + Send {
    fn send_imip(
        &self,
        task: &TaskCalendarItipMessage,
        server_instance: Arc<ServerInstance>,
    ) -> impl Future<Output = TaskResult> + Send;
}

impl SendImipTask for Server {
    async fn send_imip(
        &self,
        task: &TaskCalendarItipMessage,
        server_instance: Arc<ServerInstance>,
    ) -> TaskResult {
        match send_imip(self, task, server_instance).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .document_id(task.document_id.document_id())
                        .caused_by(trc::location!())
                        .details("Failed to send iMIP message")
                );
                result
            }
        }
    }
}

async fn send_imip(
    server: &Server,
    imip: &TaskCalendarItipMessage,
    server_instance: Arc<ServerInstance>,
) -> trc::Result<TaskResult> {
    // Obtain iMIP payload
    let account_id = imip.account_id.document_id();
    let document_id = imip.document_id.document_id();

    let sender_domain = imip
        .messages
        .iter()
        .next()
        .and_then(|msg| msg.from.rsplit('@').next())
        .unwrap_or("localhost");

    // Obtain logo image
    let logo = match server.logo_resource(sender_domain).await {
        Ok(logo) => logo,
        Err(err) => {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to fetch logo image")
            );
            None
        }
    };
    let logo_cid = format!("logo.{}@{sender_domain}", now());
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

    let account_info = server
        .account_info(account_id)
        .await
        .caused_by(trc::location!())?;

    for itip_message in imip.messages.iter() {
        let Ok(summary) = serde_json::from_str::<ItipSummary>(&itip_message.summary) else {
            return Ok(TaskResult::permanent(
                "Failed to parse iMIP message summary.",
            ));
        };

        let organizer_info = match server
            .account_id_from_email(itip_message.from.as_str(), true)
            .await
        {
            Ok(Some(sender_id)) if sender_id != account_id => {
                match server.account_info(sender_id).await {
                    Ok(info) => Some(info),
                    Err(err) => {
                        trc::error!(
                            err.account_id(account_id)
                                .document_id(document_id)
                                .caused_by(trc::location!())
                                .details("Failed to load organizer account for iMIP sender")
                        );
                        None
                    }
                }
            }
            Ok(_) => None,
            Err(err) => {
                trc::error!(
                    err.account_id(account_id)
                        .document_id(document_id)
                        .caused_by(trc::location!())
                        .details("Failed to resolve organizer account for iMIP sender")
                );
                None
            }
        };
        let sender_info = organizer_info.as_ref().unwrap_or(&account_info);

        for recipient in itip_message.to.iter() {
            // Build template
            let tpl = build_itip_template(
                server,
                &account_info,
                account_id,
                document_id,
                itip_message.from.as_str(),
                recipient.as_str(),
                &summary,
                &logo_cid,
            )
            .await?;
            let txt_body = html_to_text(&tpl.body);

            // Build message
            let message = MessageBuilder::new()
                .from((
                    sender_info.description().unwrap_or(sender_info.name()),
                    itip_message.from.as_str(),
                ))
                .to(recipient.as_str())
                .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
                .header(
                    "Reply-To",
                    HeaderType::Text(itip_message.from.as_str().into()),
                )
                .message_id(server.core.network.message_id())
                .subject(&tpl.subject)
                .body(MimePart::new(
                    ContentType::new("multipart/mixed"),
                    BodyPart::Multipart(vec![
                        MimePart::new(
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
                                            BodyPart::Text(tpl.body.as_str().into()),
                                        ),
                                        MimePart::new(
                                            ContentType::new("text/calendar")
                                                .attribute("method", summary.method())
                                                .attribute("charset", "utf-8"),
                                            BodyPart::Text(
                                                itip_message.i_calendar_data.as_str().into(),
                                            ),
                                        ),
                                    ]),
                                ),
                                logo.clone(),
                            ]),
                        ),
                        MimePart::new(
                            ContentType::new("application/ics").attribute("name", "event.ics"),
                            BodyPart::Text(itip_message.i_calendar_data.as_str().into()),
                        )
                        .attachment("event.ics"),
                    ]),
                ))
                .write_to_vec()
                .unwrap_or_default();

            // Send message
            let server_ = server.clone();
            let server_instance = server_instance.clone();
            let sender_info = sender_info.clone();
            let from = itip_message.from.to_string();
            let to = recipient.to_string();
            tokio::spawn(async move {
                let mut session = Session::<NullIo>::local(
                    server_,
                    server_instance,
                    SessionData::local(sender_info, None, vec![], vec![], 0),
                );

                // MAIL FROM
                let _ = session
                    .handle_mail_from(MailFrom {
                        address: from.as_str().into(),
                        ..Default::default()
                    })
                    .await;
                if let Some(error) = session.has_failed() {
                    trc::event!(
                        Calendar(trc::CalendarEvent::ItipMessageError),
                        AccountId = account_id,
                        DocumentId = document_id,
                        From = from,
                        To = to,
                        Reason = format!("Server rejected MAIL-FROM: {}", error.trim()),
                    );
                    return;
                }

                // RCPT TO
                session.params.rcpt_errors_wait = Duration::from_secs(0);
                let _ = session
                    .handle_rcpt_to(RcptTo {
                        address: to.as_str().into(),
                        ..Default::default()
                    })
                    .await;
                if let Some(error) = session.has_failed() {
                    trc::event!(
                        Calendar(trc::CalendarEvent::ItipMessageError),
                        AccountId = account_id,
                        DocumentId = document_id,
                        From = from,
                        To = to,
                        Reason = format!("Server rejected RCPT-TO: {}", error.trim()),
                    );
                    return;
                }

                // DATA
                session.data.message = message;
                let response = session.queue_message().await;
                if let smtp::core::State::Accepted(queue_id) = session.state {
                    trc::event!(
                        Calendar(trc::CalendarEvent::ItipMessageSent),
                        From = from,
                        To = to,
                        AccountId = account_id,
                        DocumentId = document_id,
                        QueueId = queue_id,
                    );
                } else {
                    trc::event!(
                        Calendar(trc::CalendarEvent::ItipMessageError),
                        From = from,
                        To = to,
                        AccountId = account_id,
                        DocumentId = document_id,
                        Reason = format!(
                            "Server rejected DATA: {}",
                            std::str::from_utf8(&response).unwrap().trim()
                        ),
                    );
                }
            })
            .await
            .map_err(|_| {
                trc::Error::new(trc::EventType::Server(trc::ServerEvent::ThreadError))
                    .caused_by(trc::location!())
            })?;
        }
    }

    Ok(TaskResult::Success(vec![]))
}

pub struct Details {
    pub subject: String,
    pub body: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn build_itip_template(
    server: &Server,
    account_info: &AccountInfo,
    account_id: u32,
    document_id: u32,
    from: &str,
    to: &str,
    summary: &ItipSummary,
    logo_cid: &str,
) -> trc::Result<Details> {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let template = server
        .core
        .enterprise
        .as_ref()
        .and_then(|e| e.template_scheduling_email.as_ref())
        .unwrap_or(&server.core.groupware.itip_template);
    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    let template = &server.core.groupware.itip_template;
    let formatter = TextFormatter::new(account_info.locale().as_str())?;
    let locale = formatter.locale;

    let mut variables = Variables::new();
    let mut subject;
    let (fields, old_fields) = match summary {
        ItipSummary::Invite(fields) => {
            subject = format!("{}: ", locale.calendar_invitation);

            (fields, None)
        }
        ItipSummary::Update {
            current, previous, ..
        } => {
            subject = format!("{}: ", locale.calendar_updated_invitation);
            variables.insert_single(
                CalendarTemplateVariable::Header,
                locale.calendar_event_updated.to_string(),
            );
            variables.insert_single(CalendarTemplateVariable::Color, "info".to_string());
            (current, Some(previous))
        }
        ItipSummary::Cancel(fields) => {
            subject = format!("{}: ", locale.calendar_cancelled);
            variables.insert_single(
                CalendarTemplateVariable::Header,
                locale.calendar_event_cancelled.to_string(),
            );
            variables.insert_single(CalendarTemplateVariable::Color, "danger".to_string());
            (fields, None)
        }
        ItipSummary::Rsvp { part_stat, current } => {
            let (color, value) = match part_stat {
                ICalendarParticipationStatus::Accepted => {
                    subject = format!("{}: ", locale.calendar_accepted);

                    (
                        "info",
                        locale.calendar_participant_accepted.replace("$name", from),
                    )
                }
                ICalendarParticipationStatus::Declined => {
                    subject = format!("{}: ", locale.calendar_declined);
                    (
                        "danger",
                        locale.calendar_participant_declined.replace("$name", from),
                    )
                }
                ICalendarParticipationStatus::Tentative => {
                    subject = format!("{}: ", locale.calendar_tentative);
                    (
                        "warning",
                        locale.calendar_participant_tentative.replace("$name", from),
                    )
                }
                ICalendarParticipationStatus::Delegated => {
                    subject = format!("{}: ", locale.calendar_delegated);
                    (
                        "warning",
                        locale.calendar_participant_delegated.replace("$name", from),
                    )
                }
                _ => {
                    subject = format!("{}: ", locale.calendar_reply);
                    (
                        "info",
                        locale.calendar_participant_reply.replace("$name", from),
                    )
                }
            };

            variables.insert_single(CalendarTemplateVariable::Header, value);
            variables.insert_single(CalendarTemplateVariable::Color, color.to_string());

            (current, None)
        }
    };

    let mut has_rrule = false;
    let mut details = Vec::with_capacity(4);
    for field in [
        ICalendarProperty::Summary,
        ICalendarProperty::Description,
        ICalendarProperty::Rrule,
        ICalendarProperty::Dtstart,
        ICalendarProperty::Location,
        ICalendarProperty::Conference,
    ] {
        let mut old_entries = old_fields.into_iter().flatten().filter(|e| e.name == field);

        for entry in fields.iter().filter(|e| e.name == field) {
            let field_name = match &field {
                ICalendarProperty::Summary => locale.calendar_summary,
                ICalendarProperty::Description => locale.calendar_description,
                ICalendarProperty::Rrule => {
                    has_rrule = true;
                    locale.calendar_when
                }
                ICalendarProperty::Dtstart if !has_rrule => locale.calendar_when,
                ICalendarProperty::Location => locale.calendar_location,
                ICalendarProperty::Conference => locale.calendar_conference,
                _ => continue,
            };
            let value = formatter.field_to_string(&entry.value, DateStyle::Long);

            let old_entry = old_entries.next();

            match &field {
                ICalendarProperty::Summary => {
                    subject.push_str(&value);
                }
                ICalendarProperty::Dtstart | ICalendarProperty::Rrule => {
                    subject.push_str(" @ ");
                    subject.push_str(&value);
                }
                _ => (),
            }

            if let ICalendarProperty::Summary | ICalendarProperty::Description = &field {
                let variable = if matches!(field, ICalendarProperty::Summary) {
                    CalendarTemplateVariable::EventTitle
                } else {
                    CalendarTemplateVariable::EventDescription
                };

                if old_entry.is_none() {
                    variables.insert_single(variable, value);
                    continue;
                }
                variables.insert_single(variable, value.clone());
            }

            let mut detail = AHashMap::with_capacity(4);
            detail.insert(CalendarTemplateVariable::Key, field_name.to_string());
            if matches!(field, ICalendarProperty::Conference)
                && let Some(link) = hyperlink(&value)
            {
                detail.insert(CalendarTemplateVariable::Link, link.to_string());
            }
            detail.insert(CalendarTemplateVariable::Value, value);
            if let Some(old_entry) = old_entry {
                detail.insert(
                    CalendarTemplateVariable::Changed,
                    locale.calendar_changed.to_string(),
                );
                detail.insert(
                    CalendarTemplateVariable::OldValue,
                    formatter.field_to_string(&old_entry.value, DateStyle::Short),
                );
            }
            details.push(detail);
        }
    }
    if !details.is_empty() {
        variables.items.insert(
            CalendarTemplateVariable::EventDetails,
            Variable::Block(details),
        );
    }
    variables.insert_single(CalendarTemplateVariable::PageTitle, subject.clone());
    variables.insert_single(CalendarTemplateVariable::Lang, locale.name.to_string());
    variables.insert_single(CalendarTemplateVariable::Dir, locale.direction.to_string());
    variables.insert_single(CalendarTemplateVariable::LogoCid, format!("cid:{logo_cid}"));

    if let Some(guests) = fields
        .iter()
        .find(|e| e.name == ICalendarProperty::Attendee)
        && let ItipValue::Participants(guests) = &guests.value
    {
        variables.insert_single(
            CalendarTemplateVariable::AttendeesTitle,
            locale.calendar_attendees.to_string(),
        );
        variables.insert_block(
            CalendarTemplateVariable::Attendees,
            guests.iter().map(|guest| {
                [
                    (
                        CalendarTemplateVariable::Key,
                        if guest.is_organizer {
                            if let Some(name) = guest.name.as_ref() {
                                format!("{name} - {}", locale.calendar_organizer)
                            } else {
                                locale.calendar_organizer.to_string()
                            }
                        } else {
                            guest.name.as_deref().unwrap_or_default().to_string()
                        },
                    ),
                    (CalendarTemplateVariable::Value, guest.email.to_string()),
                ]
            }),
        );
    }

    // Add RSVP buttons
    if matches!(summary, ItipSummary::Invite(_) | ItipSummary::Update { .. })
        && let Some(rsvp_url) = server
            .http_rsvp_url(account_id, account_info.name(), document_id, to)
            .await
    {
        variables.insert_single(
            CalendarTemplateVariable::Rsvp,
            locale.calendar_reply_as.replace("$name", to),
        );
        variables.insert_block(
            CalendarTemplateVariable::Actions,
            [
                (
                    ICalendarParticipationStatus::Accepted,
                    locale.calendar_yes.to_string(),
                    "info",
                ),
                (
                    ICalendarParticipationStatus::Declined,
                    locale.calendar_no.to_string(),
                    "danger",
                ),
                (
                    ICalendarParticipationStatus::Tentative,
                    locale.calendar_maybe.to_string(),
                    "warning",
                ),
            ]
            .into_iter()
            .map(|(status, title, color)| {
                [
                    (CalendarTemplateVariable::ActionName, title.to_string()),
                    (CalendarTemplateVariable::ActionUrl, rsvp_url.url(&status)),
                    (CalendarTemplateVariable::Color, color.to_string()),
                ]
            }),
        );
    }

    // Add footer
    variables.insert_block(
        CalendarTemplateVariable::Footer,
        [
            [(
                CalendarTemplateVariable::Key,
                locale.calendar_imip_footer_1.to_string(),
            )],
            [(
                CalendarTemplateVariable::Key,
                locale.calendar_imip_footer_2.to_string(),
            )],
        ],
    );

    Ok(Details {
        subject,
        body: template.eval(&variables),
    })
}
