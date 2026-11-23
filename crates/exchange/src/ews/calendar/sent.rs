/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::groupware::write::Scheduling;
use calcard::icalendar::{
    ICalendar, ICalendarMethod, ICalendarParticipationStatus, ICalendarProperty,
};
use common::Server;
use groupware::{
    calendar::write::ItipMode,
    scheduling::{
        ItipField, ItipMessage, ItipSummary, ItipValue,
        event_cancel::itip_cancel,
        event_create::{itip_create, itip_unscheduled_update},
        event_update::{itip_retain_changed, itip_update},
        recipient::{AttendeeVisibility, RecipientPolicy},
    },
};
use mail_builder::{
    MessageBuilder,
    headers::content_type::ContentType,
    mime::{BodyPart, MimePart},
};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MeetingSend {
    Suppress,
    Send,
    SendAndSave,
    SendToChanged,
    SendToChangedAndSave,
}

impl MeetingSend {
    pub fn itip(self) -> ItipMode {
        match self {
            MeetingSend::Suppress => ItipMode::Suppress,
            MeetingSend::Send | MeetingSend::SendAndSave => ItipMode::Send,
            MeetingSend::SendToChanged | MeetingSend::SendToChangedAndSave => {
                ItipMode::SendToChanged
            }
        }
    }

    pub fn saves_copy(self) -> bool {
        matches!(
            self,
            MeetingSend::SendAndSave | MeetingSend::SendToChangedAndSave
        )
    }
}

#[derive(Default)]
pub(crate) struct SentCopies(Vec<ItipMessage<ICalendar>>);

pub(crate) struct CopyMaker<'x> {
    owner: &'x [String],
    policy: RecipientPolicy,
    itip: ItipMode,
}

impl<'x> CopyMaker<'x> {
    pub fn new(server: &Server, owner: &'x [String], itip: ItipMode) -> Self {
        let config = &server.core.groupware;
        CopyMaker {
            owner,
            policy: RecipientPolicy {
                visibility: AttendeeVisibility::All,
                max_recipients: config.itip_outbound_max_recipients,
                max_instances: config.max_ical_instances,
            },
            itip,
        }
    }

    pub fn owner(&self) -> &'x [String] {
        self.owner
    }

    pub fn created(&self, mut ical: ICalendar, tag: Option<u32>) -> SentCopies {
        if tag.is_none() {
            return SentCopies::default();
        }
        SentCopies(itip_create(&mut ical, self.owner, self.policy).unwrap_or_default())
    }

    pub fn updated(
        &self,
        mut ical: ICalendar,
        previous: &ICalendar,
        before: Scheduling,
        after: Option<u32>,
    ) -> SentCopies {
        let mut messages = match before.tag {
            Some(_) => itip_update(&mut ical, previous, self.owner, self.policy),
            None => itip_unscheduled_update(&mut ical, previous, self.owner, self.policy),
        };
        if self.itip == ItipMode::SendToChanged {
            messages = messages
                .and_then(|messages| itip_retain_changed(messages, previous, &ical, self.owner));
        }
        let messages = messages.unwrap_or_default();
        let sent = match messages.first() {
            Some(message) if message.from_organizer => after != before.tag,
            Some(_) => before.is_upcoming(),
            None => false,
        };
        if sent {
            SentCopies(messages)
        } else {
            SentCopies::default()
        }
    }

    pub fn deleted(&self, ical: &ICalendar, before: Scheduling) -> SentCopies {
        if before.tag.is_none() || !before.is_upcoming() {
            return SentCopies::default();
        }
        SentCopies(itip_cancel(ical, self.owner, true, self.policy).unwrap_or_default())
    }
}

impl SentCopies {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn messages(&self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.0.iter().filter_map(sent_message)
    }
}

fn sent_message(message: &ItipMessage<ICalendar>) -> Option<Vec<u8>> {
    let fields = match &message.summary {
        ItipSummary::Invite(fields) | ItipSummary::Cancel(fields) => fields,
        ItipSummary::Update { current, .. } | ItipSummary::Rsvp { current, .. } => current,
    };
    let summary = text_field(fields, &ICalendarProperty::Summary).unwrap_or_default();
    let subject = match subject_prefix(&message.summary) {
        Some(prefix) => Cow::Owned(format!("{prefix}: {summary}")),
        None => Cow::Borrowed(summary),
    };
    let description = text_field(fields, &ICalendarProperty::Description).unwrap_or_default();
    MessageBuilder::new()
        .from(message.from.as_str())
        .to(message.to.iter().map(String::as_str).collect::<Vec<_>>())
        .subject(subject)
        .body(MimePart::new(
            "multipart/alternative",
            BodyPart::Multipart(vec![
                MimePart::new(
                    ContentType::new("text/plain").attribute("charset", "utf-8"),
                    BodyPart::Text(description.into()),
                ),
                MimePart::new(
                    ContentType::new("text/calendar")
                        .attribute("method", message.summary.method())
                        .attribute("charset", "utf-8"),
                    BodyPart::Text(message.message.to_string().into()),
                ),
            ]),
        ))
        .write_to_vec()
        .ok()
}

fn text_field<'x>(fields: &'x [ItipField], name: &ICalendarProperty) -> Option<&'x str> {
    fields.iter().find_map(|field| match &field.value {
        ItipValue::Text(text) if field.name == *name => Some(text.as_str()),
        _ => None,
    })
}

fn subject_prefix(summary: &ItipSummary) -> Option<&'static str> {
    match summary {
        ItipSummary::Cancel(_)
        | ItipSummary::Update {
            method: ICalendarMethod::Cancel,
            ..
        } => Some("Canceled"),
        ItipSummary::Rsvp { part_stat, .. } => match part_stat {
            ICalendarParticipationStatus::Accepted => Some("Accepted"),
            ICalendarParticipationStatus::Declined => Some("Declined"),
            ICalendarParticipationStatus::Tentative => Some("Tentative"),
            _ => None,
        },
        ItipSummary::Invite(_) | ItipSummary::Update { .. } => None,
    }
}
