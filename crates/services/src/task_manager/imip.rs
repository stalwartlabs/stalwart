/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::TaskResult;
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendarDay, ICalendarFrequency, ICalendarMonth, ICalendarParticipationStatus,
        ICalendarProperty, ICalendarRecurrenceRule, ICalendarWeekday,
    },
};
use chrono::{DateTime, Locale};
use common::{
    DEFAULT_LOGO_BASE64, Server,
    auth::AccountInfo,
    config::groupware::CalendarTemplateVariable,
    i18n,
    network::{ServerInstance, stream::NullIo},
};
use groupware::{
    calendar::itip::ItipIngest,
    scheduling::{ItipSummary, ItipValue},
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
use std::{str::FromStr, sync::Arc, time::Duration};
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
        .first()
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
            .await;
            let txt_body = html_to_text(&tpl.body);

            // Build message
            let message = MessageBuilder::new()
                .from((
                    account_info.description().unwrap_or(account_info.name()),
                    itip_message.from.as_str(),
                ))
                .to(recipient.as_str())
                .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
                .header(
                    "Reply-To",
                    HeaderType::Text(itip_message.from.as_str().into()),
                )
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
                                    ]),
                                ),
                                logo.clone(),
                            ]),
                        ),
                        MimePart::new(
                            ContentType::new("text/calendar")
                                .attribute("method", summary.method())
                                .attribute("charset", "utf-8"),
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
            let account_info = account_info.clone();
            let from = itip_message.from.to_string();
            let to = recipient.to_string();
            tokio::spawn(async move {
                let mut session = Session::<NullIo>::local(
                    server_,
                    server_instance,
                    SessionData::local(account_info, None, vec![], vec![], 0),
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

    Ok(TaskResult::Success)
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
) -> Details {
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
    let locale = i18n::locale_or_default(account_info.locale().as_str());
    let chrono_locale = Locale::from_str(account_info.locale().as_str()).unwrap_or(Locale::en_US);

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
    ] {
        let Some(entry) = fields.iter().find(|e| e.name == field) else {
            continue;
        };
        let field_name = match &field {
            ICalendarProperty::Summary => locale.calendar_summary,
            ICalendarProperty::Description => locale.calendar_description,
            ICalendarProperty::Rrule => {
                has_rrule = true;
                locale.calendar_when
            }
            ICalendarProperty::Dtstart if !has_rrule => locale.calendar_when,
            ICalendarProperty::Location => locale.calendar_location,
            _ => continue,
        };
        let value = format_field(
            &entry.value,
            locale.calendar_date_template_long,
            chrono_locale,
        );

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

        let mut fields = AHashMap::with_capacity(3);
        fields.insert(CalendarTemplateVariable::Key, field_name.to_string());
        fields.insert(CalendarTemplateVariable::Value, value);
        if let Some(old_entry) =
            old_fields.and_then(|fields| fields.iter().find(|e| e.name == field))
        {
            fields.insert(
                CalendarTemplateVariable::Changed,
                locale.calendar_changed.to_string(),
            );
            fields.insert(
                CalendarTemplateVariable::OldValue,
                format_field(
                    &old_entry.value,
                    locale.calendar_date_template,
                    chrono_locale,
                ),
            );
        }
        details.push(fields);
    }
    variables.items.insert(
        CalendarTemplateVariable::EventDetails,
        Variable::Block(details),
    );
    variables.insert_single(CalendarTemplateVariable::PageTitle, subject.clone());
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
        && let Some(rsvp_url) = server.http_rsvp_url(account_id, document_id, to).await
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
        ]
        .into_iter(),
    );

    Details {
        subject,
        body: template.eval(&variables),
    }
}

fn format_field(value: &ItipValue, template: &str, chrono_locale: Locale) -> String {
    match value {
        ItipValue::Text(text) => text.to_string(),
        ItipValue::Time(time) => {
            use chrono::TimeZone;
            let tz = Tz::from_id(time.tz_id).unwrap_or(Tz::UTC);
            format!(
                "{} ({})",
                tz.from_utc_datetime(
                    &DateTime::from_timestamp(time.start, 0)
                        .unwrap_or_default()
                        .naive_local()
                )
                .format_localized(template, chrono_locale),
                tz.name().unwrap_or_default()
            )
        }
        ItipValue::Rrule(rrule) => RecurrenceFormatter.format(rrule),
        ItipValue::Participants(_) => String::new(), // Handled separately
    }
}

#[derive(Default)]
pub struct RecurrenceFormatter;

impl RecurrenceFormatter {
    pub fn format(&self, rule: &ICalendarRecurrenceRule) -> String {
        let mut parts = Vec::new();

        // Format frequency and interval
        let freq_part = self.format_frequency(&rule.freq, rule.interval.unwrap_or(1));
        parts.push(freq_part);

        // Format day constraints
        if !rule.byday.is_empty() {
            parts.push(self.format_by_day(&rule.byday));
        }

        // Format time constraints
        if !rule.byhour.is_empty() || !rule.byminute.is_empty() {
            parts.push(self.format_time_constraints(&rule.byhour, &rule.byminute));
        }

        // Format month day constraints
        if !rule.bymonthday.is_empty() {
            parts.push(self.format_month_days(&rule.bymonthday));
        }

        // Format month constraints
        if !rule.bymonth.is_empty() {
            parts.push(self.format_months(&rule.bymonth));
        }

        // Format year day constraints
        if !rule.byyearday.is_empty() {
            parts.push(self.format_year_days(&rule.byyearday));
        }

        // Format week number constraints
        if !rule.byweekno.is_empty() {
            parts.push(self.format_week_numbers(&rule.byweekno));
        }

        // Format set position constraints
        if !rule.bysetpos.is_empty() {
            parts.push(self.format_set_positions(&rule.bysetpos));
        }

        // Format termination (until/count)
        /*if let Some(until) = &rule.until {
            parts.push(format!("until {}", self.format_datetime(until)));
        } else*/
        if let Some(count) = rule.count.as_ref() {
            let times = if *count == 1 { "time" } else { "times" };
            parts.push(format!("for {} {}", count, times));
        }

        parts.join(" ")
    }

    fn format_frequency(&self, freq: &ICalendarFrequency, interval: u16) -> String {
        let (singular, plural) = match freq {
            ICalendarFrequency::Daily => ("day", "days"),
            ICalendarFrequency::Weekly => ("week", "weeks"),
            ICalendarFrequency::Monthly => ("month", "months"),
            ICalendarFrequency::Yearly => ("year", "years"),
            ICalendarFrequency::Hourly => ("hour", "hours"),
            ICalendarFrequency::Minutely => ("minute", "minutes"),
            ICalendarFrequency::Secondly => ("second", "seconds"),
        };

        if interval == 1 {
            format!("Every {}", singular)
        } else {
            format!("Every {} {}", interval, plural)
        }
    }

    fn format_by_day(&self, days: &[ICalendarDay]) -> String {
        let day_names: Vec<String> = days.iter().map(|day| self.format_day(day)).collect();

        format!("on {}", self.format_list(&day_names))
    }

    fn format_day(&self, day: &ICalendarDay) -> String {
        let day_name = match day.weekday {
            ICalendarWeekday::Monday => "Monday",
            ICalendarWeekday::Tuesday => "Tuesday",
            ICalendarWeekday::Wednesday => "Wednesday",
            ICalendarWeekday::Thursday => "Thursday",
            ICalendarWeekday::Friday => "Friday",
            ICalendarWeekday::Saturday => "Saturday",
            ICalendarWeekday::Sunday => "Sunday",
        };

        if let Some(occurrence) = day.ordwk {
            if occurrence > 0 {
                format!("the {} {}", self.ordinal(occurrence as u32), day_name)
            } else {
                format!(
                    "the {} {} from the end",
                    self.ordinal((-occurrence) as u32),
                    day_name
                )
            }
        } else {
            day_name.to_string()
        }
    }

    fn format_time_constraints(&self, hours: &[u8], minutes: &[u8]) -> String {
        let mut time_parts = Vec::new();

        if !hours.is_empty() && !minutes.is_empty() {
            // Combine hours and minutes
            for &hour in hours {
                for &minute in minutes {
                    time_parts.push(format!("{}:{:02}", self.format_hour(hour), minute));
                }
            }
        } else if !hours.is_empty() {
            for &hour in hours {
                time_parts.push(self.format_hour(hour));
            }
        } else if !minutes.is_empty() {
            for &minute in minutes {
                time_parts.push(format!(":{:02}", minute));
            }
        }

        if !time_parts.is_empty() {
            format!("at {}", self.format_list(&time_parts))
        } else {
            String::new()
        }
    }

    fn format_hour(&self, hour: u8) -> String {
        match hour {
            0 => "12:00 AM".to_string(),
            1..=11 => format!("{}:00 AM", hour),
            12 => "12:00 PM".to_string(),
            13..=23 => format!("{}:00 PM", hour - 12),
            _ => format!("{:02}:00", hour),
        }
    }

    fn format_month_days(&self, days: &[i8]) -> String {
        let day_strings: Vec<String> = days
            .iter()
            .map(|&day| {
                if day > 0 {
                    self.ordinal(day as u32)
                } else {
                    format!("{} from the end", self.ordinal((-day) as u32))
                }
            })
            .collect();

        format!("on the {}", self.format_list(&day_strings))
    }

    fn format_months(&self, months: &[ICalendarMonth]) -> String {
        let month_names: Vec<String> = months
            .iter()
            .map(|month| self.month_name(month.month()))
            .collect();

        format!("in {}", self.format_list(&month_names))
    }

    fn format_year_days(&self, days: &[i16]) -> String {
        let day_strings: Vec<String> = days
            .iter()
            .map(|&day| {
                if day > 0 {
                    format!("day {} of the year", day)
                } else {
                    format!("day {} from the end of the year", -day)
                }
            })
            .collect();

        format!("on {}", self.format_list(&day_strings))
    }

    fn format_week_numbers(&self, weeks: &[i8]) -> String {
        let week_strings: Vec<String> = weeks
            .iter()
            .map(|&week| {
                if week > 0 {
                    format!("week {}", week)
                } else {
                    format!("week {} from the end", -week)
                }
            })
            .collect();

        format!("in {}", self.format_list(&week_strings))
    }

    fn format_set_positions(&self, positions: &[i32]) -> String {
        let pos_strings: Vec<String> = positions
            .iter()
            .map(|&pos| {
                if pos > 0 {
                    self.ordinal(pos as u32)
                } else {
                    format!("{} from the end", self.ordinal((-pos) as u32))
                }
            })
            .collect();

        format!(
            "limited to the {} occurrence",
            self.format_list(&pos_strings)
        )
    }

    fn format_list(&self, items: &[String]) -> String {
        match items.len() {
            0 => String::new(),
            1 => items[0].clone(),
            2 => format!("{} and {}", items[0], items[1]),
            _ => {
                let rest = &items[..items.len() - 1];
                format!("{}, and {}", rest.join(", "), items.last().unwrap())
            }
        }
    }

    fn ordinal(&self, n: u32) -> String {
        let suffix = match n % 100 {
            11..=13 => "th",
            _ => match n % 10 {
                1 => "st",
                2 => "nd",
                3 => "rd",
                _ => "th",
            },
        };
        format!("{}{}", n, suffix)
    }

    fn month_name(&self, month: u8) -> String {
        match month {
            1 => "January",
            2 => "February",
            3 => "March",
            4 => "April",
            5 => "May",
            6 => "June",
            7 => "July",
            8 => "August",
            9 => "September",
            10 => "October",
            11 => "November",
            12 => "December",
            _ => "Unknown",
        }
        .to_string()
    }

    /*fn format_datetime(&self, dt: &PartialDateTime) -> String {
        format!("{:?}", dt)
    }*/
}
