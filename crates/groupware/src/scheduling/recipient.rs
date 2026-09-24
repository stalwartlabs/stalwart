/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    calendar::EVENT_HIDE_ATTENDEES,
    scheduling::{ItipError, ItipMessage},
};
use calcard::icalendar::ICalendar;
use common::config::groupware::GroupwareConfig;
use split::RecipientSplit;

pub(crate) mod series;
mod split;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttendeeVisibility {
    #[default]
    All,
    RecipientOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientPolicy {
    pub visibility: AttendeeVisibility,
    pub max_recipients: usize,
    pub max_instances: usize,
}

impl AttendeeVisibility {
    pub fn from_event_flags(flags: u16) -> Self {
        if flags & EVENT_HIDE_ATTENDEES != 0 {
            AttendeeVisibility::RecipientOnly
        } else {
            AttendeeVisibility::All
        }
    }
}

impl RecipientPolicy {
    pub fn new(config: &GroupwareConfig, event_flags: u16) -> Self {
        RecipientPolicy {
            visibility: AttendeeVisibility::from_event_flags(event_flags),
            max_recipients: config.itip_outbound_max_recipients,
            max_instances: config.max_ical_instances,
        }
    }
}

pub(crate) fn itip_messages_per_recipient(
    messages: Vec<ItipMessage<ICalendar>>,
    policy: RecipientPolicy,
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    if messages
        .iter()
        .map(|message| message.to.len())
        .sum::<usize>()
        >= policy.max_recipients
    {
        return Err(ItipError::TooManyRecipients);
    }

    let mut result = Vec::with_capacity(messages.len());
    for message in messages {
        if message.from_organizer {
            RecipientSplit::split(message, policy, &mut result);
        } else {
            result.push(message);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduling::{ItipField, ItipSummary, ItipValue, snapshot::itip_snapshot};
    use calcard::icalendar::{ICalendarMethod, ICalendarProperty};
    use std::borrow::Cow;

    const MAX_INSTANCES: usize = 3000;
    const ORGANIZER: &str = "org@example.com";

    const BERLIN: &str = concat!(
        "BEGIN:VTIMEZONE\r\n",
        "TZID:Europe/Berlin\r\n",
        "BEGIN:STANDARD\r\n",
        "DTSTART:19701025T030000\r\n",
        "TZOFFSETFROM:+0200\r\n",
        "TZOFFSETTO:+0100\r\n",
        "RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\n",
        "END:STANDARD\r\n",
        "BEGIN:DAYLIGHT\r\n",
        "DTSTART:19700329T020000\r\n",
        "TZOFFSETFROM:+0100\r\n",
        "TZOFFSETTO:+0200\r\n",
        "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\n",
        "END:DAYLIGHT\r\n",
        "END:VTIMEZONE\r\n",
    );

    const SERIES: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "METHOD:REQUEST\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:series\r\n",
        "DTSTART:20260601T090000Z\r\n",
        "RRULE:FREQ=DAILY;COUNT=3\r\n",
        "ORGANIZER:mailto:org@example.com\r\n",
        "ATTENDEE:mailto:org@example.com\r\n",
        "ATTENDEE:mailto:a@example.com\r\n",
        "ATTENDEE:mailto:b@example.com\r\n",
        "JSPROP;JSPTR=participants/b/roles:{\"attendee\":true}\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:series\r\n",
        "RECURRENCE-ID:20260602T090000Z\r\n",
        "DTSTART:20260602T100000Z\r\n",
        "ORGANIZER:mailto:org@example.com\r\n",
        "ATTENDEE:mailto:org@example.com\r\n",
        "ATTENDEE:mailto:a@example.com\r\n",
        "ATTENDEE:mailto:c@example.com\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    fn policy(visibility: AttendeeVisibility) -> RecipientPolicy {
        RecipientPolicy {
            visibility,
            max_recipients: usize::MAX,
            max_instances: MAX_INSTANCES,
        }
    }

    fn itip(ical: &str, recipients: &[&str], summary: ItipSummary) -> ItipMessage<ICalendar> {
        ItipMessage {
            from: ORGANIZER.to_string(),
            from_organizer: true,
            to: recipients.iter().map(|r| r.to_string()).collect(),
            summary,
            message: ICalendar::parse(ical).expect("valid iCalendar"),
        }
    }

    fn message(recipients: &[&str]) -> ItipMessage<ICalendar> {
        itip(SERIES, recipients, ItipSummary::Invite(vec![]))
    }

    fn calendar(body: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\n{BERLIN}{body}END:VCALENDAR\r\n")
    }

    fn split_messages(
        message: ItipMessage<ICalendar>,
        visibility: AttendeeVisibility,
    ) -> Vec<ItipMessage<ICalendar>> {
        let mut messages = itip_messages_per_recipient(vec![message], policy(visibility))
            .expect("recipients within limit");
        messages.sort_by(|a, b| a.to.cmp(&b.to));
        messages
    }

    fn text(message: &ItipMessage<ICalendar>) -> String {
        message.message.to_string().replace("\r\n ", "")
    }

    fn split(recipients: &[&str], visibility: AttendeeVisibility) -> Vec<(Vec<String>, String)> {
        split_messages(message(recipients), visibility)
            .iter()
            .map(|message| (message.to.clone(), text(message)))
            .collect()
    }

    fn fields(summary: &ItipSummary) -> &[ItipField] {
        match summary {
            ItipSummary::Invite(fields)
            | ItipSummary::Cancel(fields)
            | ItipSummary::Update {
                current: fields, ..
            }
            | ItipSummary::Rsvp {
                current: fields, ..
            } => fields,
        }
    }

    fn participants(summary: &ItipSummary) -> Vec<&str> {
        fields(summary)
            .iter()
            .filter_map(|field| match &field.value {
                ItipValue::Participants(participants) => Some(participants),
                _ => None,
            })
            .flatten()
            .map(|participant| participant.email.as_str())
            .collect()
    }

    #[test]
    fn recipients_only_receive_their_instances() {
        let messages = split(
            &["a@example.com", "b@example.com", "c@example.com"],
            AttendeeVisibility::All,
        );
        assert_eq!(messages.len(), 3, "{messages:#?}");

        let (to, ical) = &messages[0];
        assert_eq!(to, &["a@example.com"]);
        assert!(ical.contains("RECURRENCE-ID:20260602T090000Z"), "{ical}");
        assert!(!ical.contains("EXDATE"), "{ical}");

        let (to, ical) = &messages[1];
        assert_eq!(to, &["b@example.com"]);
        assert!(!ical.contains("RECURRENCE-ID"), "{ical}");
        assert!(ical.contains("EXDATE:20260602T090000Z"), "{ical}");
        assert!(ical.contains("RRULE"), "{ical}");

        let (to, ical) = &messages[2];
        assert_eq!(to, &["c@example.com"]);
        assert!(ical.contains("RECURRENCE-ID:20260602T090000Z"), "{ical}");
        assert!(!ical.contains("RRULE"), "{ical}");
        assert_eq!(ical.matches("BEGIN:VEVENT").count(), 1, "{ical}");
    }

    #[test]
    fn recipients_with_the_same_view_share_a_message() {
        let messages = split_messages(
            message(&["a@example.com", "org@example.com"]),
            AttendeeVisibility::All,
        );
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].to, ["a@example.com", "org@example.com"]);
    }

    #[test]
    fn recipient_limit_is_checked_before_splitting() {
        let limited = |max_recipients| {
            itip_messages_per_recipient(
                vec![message(&[
                    "a@example.com",
                    "b@example.com",
                    "c@example.com",
                ])],
                RecipientPolicy {
                    max_recipients,
                    ..policy(AttendeeVisibility::RecipientOnly)
                },
            )
        };
        assert!(matches!(limited(3), Err(ItipError::TooManyRecipients)));
        assert_eq!(limited(4).map(|messages| messages.len()).ok(), Some(3));
    }

    #[test]
    fn hidden_attendees_are_removed() {
        let messages = split(
            &["a@example.com", "b@example.com"],
            AttendeeVisibility::RecipientOnly,
        );
        assert_eq!(messages.len(), 2, "{messages:#?}");
        for (to, ical) in &messages {
            let attendees = ical
                .lines()
                .filter(|line| line.starts_with("ATTENDEE"))
                .collect::<Vec<_>>();
            assert!(
                attendees.iter().all(|line| line.ends_with(to[0].as_str())),
                "{ical}"
            );
            assert!(!attendees.is_empty(), "{ical}");
            assert!(ical.contains("ORGANIZER:mailto:org@example.com"), "{ical}");
            assert!(!ical.contains("JSPROP"), "{ical}");
        }

        let ical = calendar(concat!(
            "BEGIN:VEVENT\r\n",
            "UID:hidden\r\n",
            "DTSTART:20260601T090000Z\r\n",
            "ORGANIZER;SENT-BY=\"mailto:assistant@example.com\":mailto:org@example.com\r\n",
            "ATTENDEE;PARTSTAT=DELEGATED;DELEGATED-TO=\"mailto:d@example.com\":mailto:a@example.com\r\n",
            "ATTENDEE;DELEGATED-FROM=\"mailto:a@example.com\";JSID=pd:mailto:d@example.com\r\n",
            "ATTENDEE:mailto:b@example.com\r\n",
            "X-CALENDARSERVER-ATTENDEE-COMMENT;X-CALENDARSERVER-ATTENDEE-REF=\"mailto:b@example.com\":see you\r\n",
            "JSPROP;JSPTR=\"recurrenceOverrides/2026-06-02T09:00:00\":{\"participants/pb/participationStatus\":\"declined\"}\r\n",
            "JSPROP;JSPTR=participants/pd/roles:{\"attendee\":true\\,\"informational\":true}\r\n",
            "JSPROP;JSPTR=participants/pb/roles:{\"attendee\":true}\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:EMAIL\r\n",
            "TRIGGER:-PT15M\r\n",
            "SUMMARY:x\r\n",
            "DESCRIPTION:y\r\n",
            "ATTENDEE:mailto:b@example.com\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
        ));
        let messages = split_messages(
            itip(
                &ical,
                &["b@example.com", "d@example.com"],
                ItipSummary::Invite(vec![]),
            ),
            AttendeeVisibility::RecipientOnly,
        );
        let [to_b, to_d] = messages.as_slice() else {
            panic!("expected two messages: {messages:#?}");
        };

        let ical = text(to_b);
        assert!(ical.contains("X-CALENDARSERVER-ATTENDEE-COMMENT"), "{ical}");
        assert!(ical.contains("BEGIN:VALARM"), "{ical}");
        assert!(!ical.contains("d@example.com"), "{ical}");
        assert!(!ical.contains("JSPROP"), "{ical}");

        let ical = text(to_d);
        assert!(!ical.contains("b@example.com"), "{ical}");
        assert!(!ical.contains("BEGIN:VALARM"), "{ical}");
        assert!(!ical.contains("recurrenceOverrides"), "{ical}");
        assert!(ical.contains("JSPTR=\"participants/pd/roles\""), "{ical}");
        assert!(ical.contains("mailto:assistant@example.com"), "{ical}");
        assert!(
            !ical
                .lines()
                .any(|line| line.starts_with("ATTENDEE") && line.ends_with("a@example.com")),
            "{ical}"
        );
    }

    #[test]
    fn hidden_attendees_keep_their_own_properties_without_jsid() {
        let event = |jsprops: &str| {
            calendar(&format!(
                concat!(
                    "BEGIN:VEVENT\r\n",
                    "UID:jsid-less\r\n",
                    "DTSTART:20260601T090000Z\r\n",
                    "ORGANIZER:mailto:org@example.com\r\n",
                    "ATTENDEE:mailto:b@example.com\r\n",
                    "ATTENDEE:mailto:d@example.com\r\n",
                    "{}",
                    "END:VEVENT\r\n",
                ),
                jsprops
            ))
        };
        let participant_ids = ICalendar::parse(event(""))
            .expect("valid iCalendar")
            .components
            .iter()
            .flat_map(|component| component.entries.iter())
            .filter(|entry| entry.name == ICalendarProperty::Attendee)
            .filter_map(|entry| entry.participant_id().map(Cow::into_owned))
            .collect::<Vec<_>>();
        let [b_id, d_id] = participant_ids.as_slice() else {
            panic!("expected two participant ids: {participant_ids:?}");
        };
        let ical = event(&format!(
            concat!(
                "JSPROP;JSPTR=\"participants/{}/roles\":{{\"attendee\":true}}\r\n",
                "JSPROP;JSPTR=\"participants/{}/roles\":{{\"chair\":true}}\r\n",
            ),
            b_id, d_id
        ));
        let messages = split_messages(
            itip(
                &ical,
                &["b@example.com", "d@example.com"],
                ItipSummary::Invite(vec![]),
            ),
            AttendeeVisibility::RecipientOnly,
        );
        let [to_b, to_d] = messages.as_slice() else {
            panic!("expected two messages: {messages:#?}");
        };

        let ical = text(to_b);
        assert!(
            ical.contains(&format!("participants/{b_id}/roles")),
            "{ical}"
        );
        assert!(!ical.contains(d_id.as_str()), "{ical}");

        let ical = text(to_d);
        assert!(
            ical.contains(&format!("participants/{d_id}/roles")),
            "{ical}"
        );
        assert!(!ical.contains(b_id.as_str()), "{ical}");
    }

    #[test]
    fn summaries_only_describe_visible_attendees_and_instances() {
        let ical = ICalendar::parse(SERIES).expect("valid iCalendar");
        let snapshots = itip_snapshot(&ical, &[ORGANIZER.to_string()], false).expect("snapshot");
        let summary = ItipSummary::Invite(
            snapshots
                .main_instance_or_default()
                .build_summary(Some(&snapshots.organizer), &[]),
        );
        let messages = split_messages(
            itip(
                SERIES,
                &["a@example.com", "b@example.com", "c@example.com"],
                summary,
            ),
            AttendeeVisibility::RecipientOnly,
        );
        let [to_a, to_b, to_c] = messages.as_slice() else {
            panic!("expected three messages: {messages:#?}");
        };

        assert_eq!(participants(&to_a.summary), [ORGANIZER, "a@example.com"]);
        assert_eq!(participants(&to_b.summary), [ORGANIZER, "b@example.com"]);
        assert!(
            fields(&to_b.summary)
                .iter()
                .any(|field| field.name == ICalendarProperty::Rrule),
            "{:?}",
            to_b.summary
        );

        assert_eq!(participants(&to_c.summary), [ORGANIZER, "c@example.com"]);
        assert!(
            fields(&to_c.summary).iter().any(|field| {
                field.name == ICalendarProperty::Dtstart
                    && matches!(&field.value, ItipValue::Time(time) if time.start == 1780394400)
            }),
            "{:?}",
            to_c.summary
        );
        assert!(
            !fields(&to_c.summary)
                .iter()
                .any(|field| field.name == ICalendarProperty::Rrule),
            "{:?}",
            to_c.summary
        );
    }

    #[test]
    fn excluded_instances_outside_the_rule_are_omitted() {
        let ical = calendar(concat!(
            "BEGIN:VEVENT\r\nUID:extra\r\nDTSTART:20260601T090000Z\r\nRRULE:FREQ=DAILY;COUNT=5\r\n",
            "RDATE:20260610T090000Z\r\nORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:a@example.com\r\nATTENDEE:mailto:b@example.com\r\nEND:VEVENT\r\n",
            "BEGIN:VEVENT\r\nUID:extra\r\nRECURRENCE-ID:20260610T090000Z\r\nDTSTART:20260610T090000Z\r\n",
            "ORGANIZER:mailto:org@example.com\r\nATTENDEE:mailto:a@example.com\r\n",
            "ATTENDEE:mailto:c@example.com\r\nEND:VEVENT\r\n",
            "BEGIN:VEVENT\r\nUID:extra\r\nRECURRENCE-ID:20260603T090000Z\r\nDTSTART:20260603T100000Z\r\n",
            "ORGANIZER:mailto:org@example.com\r\nATTENDEE:mailto:a@example.com\r\nEND:VEVENT\r\n",
            "BEGIN:VEVENT\r\nUID:extra\r\nRECURRENCE-ID:20260530T090000Z\r\nDTSTART:20260530T090000Z\r\n",
            "ORGANIZER:mailto:org@example.com\r\nATTENDEE:mailto:a@example.com\r\nEND:VEVENT\r\n",
        ));
        let messages = split_messages(
            itip(&ical, &["b@example.com"], ItipSummary::Invite(vec![])),
            AttendeeVisibility::All,
        );
        let [message] = messages.as_slice() else {
            panic!("expected one message: {messages:#?}");
        };
        let ical = text(message);
        assert!(ical.contains("EXDATE:20260603T090000Z"), "{ical}");
        assert!(ical.contains("RRULE:FREQ=DAILY;COUNT=5"), "{ical}");
        assert!(!ical.contains("20260610"), "{ical}");
        assert!(!ical.contains("20260530"), "{ical}");
        assert_eq!(ical.matches("BEGIN:VEVENT").count(), 1, "{ical}");
    }

    fn this_and_future(master: &str, recurrence_id: &str, summary: ItipSummary) -> Vec<String> {
        split_messages(
            itip(
                &calendar(&format!(
                    concat!(
                        "BEGIN:VEVENT\r\n",
                        "UID:future\r\n",
                        "{}",
                        "ORGANIZER:mailto:org@example.com\r\n",
                        "ATTENDEE:mailto:a@example.com\r\n",
                        "END:VEVENT\r\n",
                        "BEGIN:VEVENT\r\n",
                        "UID:future\r\n",
                        "{}",
                        "ORGANIZER:mailto:org@example.com\r\n",
                        "ATTENDEE:mailto:b@example.com\r\n",
                        "END:VEVENT\r\n",
                    ),
                    master, recurrence_id
                )),
                &["a@example.com"],
                summary,
            ),
            AttendeeVisibility::All,
        )
        .iter()
        .map(text)
        .collect()
    }

    fn truncated(master: &str, recurrence_id: &str) -> String {
        let messages = this_and_future(master, recurrence_id, ItipSummary::Invite(vec![]));
        let [ical] = messages.as_slice() else {
            panic!("expected one message: {messages:#?}");
        };
        assert!(!ical.contains("RECURRENCE-ID"), "{ical}");
        assert!(!ical.contains("COUNT=0"), "{ical}");
        ical.to_string()
    }

    #[test]
    fn this_and_future_exclusion_ends_the_series() {
        let ical = truncated(
            "DTSTART;TZID=Europe/Berlin:20260601T090000\r\nRRULE:FREQ=DAILY\r\nRDATE;TZID=Europe/Berlin:20260601T180000,20260610T180000\r\n",
            "RECURRENCE-ID;TZID=Europe/Berlin;RANGE=THISANDFUTURE:20260605T090000\r\nDTSTART;TZID=Europe/Berlin:20260605T100000\r\n",
        );
        assert!(ical.contains("UNTIL=20260605T065959Z"), "{ical}");
        assert!(
            ical.contains("RDATE;TZID=Europe/Berlin:20260601T180000\r\n"),
            "{ical}"
        );
        assert!(!ical.contains("20260610T180000"), "{ical}");
        assert!(!ical.contains("EXDATE"), "{ical}");

        let ical = truncated(
            "DTSTART;VALUE=DATE:20260601\r\nRRULE:FREQ=WEEKLY;UNTIL=20261231\r\n",
            "RECURRENCE-ID;VALUE=DATE;RANGE=THISANDFUTURE:20260615\r\nDTSTART;VALUE=DATE:20260616\r\n",
        );
        assert!(ical.contains("UNTIL=20260614\r\n"), "{ical}");

        let ical = truncated(
            "DTSTART;TZID=Europe/Berlin:20260601T090000\r\nRRULE:FREQ=DAILY;UNTIL=20260603T000000Z\r\n",
            "RECURRENCE-ID;TZID=Europe/Berlin;RANGE=THISANDFUTURE:20260605T090000\r\nDTSTART;TZID=Europe/Berlin:20260605T100000\r\n",
        );
        assert!(ical.contains("UNTIL=20260603T000000Z\r\n"), "{ical}");
    }

    #[test]
    fn count_rules_are_truncated_without_expansion() {
        let ical = truncated(
            "DTSTART;TZID=Europe/Berlin:20260601T090000\r\nRRULE:FREQ=DAILY;COUNT=10\r\n",
            "RECURRENCE-ID;TZID=Europe/Berlin;RANGE=THISANDFUTURE:20260605T090000\r\nDTSTART;TZID=Europe/Berlin:20260605T100000\r\n",
        );
        assert!(ical.contains("UNTIL=20260605T065959Z"), "{ical}");
        assert!(!ical.contains("COUNT"), "{ical}");

        let ical = truncated(
            "DTSTART:20260601T090000Z\r\nRRULE:FREQ=SECONDLY;COUNT=4000000000\r\n",
            "RECURRENCE-ID;RANGE=THISANDFUTURE:20260601T091000Z\r\nDTSTART:20260601T091500Z\r\n",
        );
        assert!(ical.contains("UNTIL=20260601T090959Z"), "{ical}");
        assert!(!ical.contains("COUNT"), "{ical}");

        let ical = truncated(
            "DTSTART;TZID=Europe/Berlin:20260601T090000\r\nRRULE:FREQ=WEEKLY;BYDAY=TU;COUNT=10\r\n",
            "RECURRENCE-ID;TZID=Europe/Berlin;RANGE=THISANDFUTURE:20260616T090000\r\nDTSTART;TZID=Europe/Berlin:20260616T100000\r\n",
        );
        assert!(ical.contains("UNTIL=20260616T065959Z"), "{ical}");
        assert!(!ical.contains("COUNT"), "{ical}");

        let ical = truncated(
            "DTSTART:20260601T090000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\n",
            "RECURRENCE-ID;RANGE=THISANDFUTURE:20260610T090000Z\r\nDTSTART:20260610T100000Z\r\n",
        );
        assert!(ical.contains("RRULE:FREQ=DAILY;COUNT=3\r\n"), "{ical}");
    }

    #[test]
    fn floating_series_end_in_local_time() {
        let ical = truncated(
            "DTSTART:20260601T090000\r\nRRULE:FREQ=DAILY\r\n",
            "RECURRENCE-ID;RANGE=THISANDFUTURE:20260605T090000\r\nDTSTART:20260605T100000\r\n",
        );
        assert!(ical.contains("UNTIL=20260605T085959\r\n"), "{ical}");
    }

    #[test]
    fn several_this_and_future_exclusions_truncate_once() {
        let ical = calendar(concat!(
            "BEGIN:VEVENT\r\nUID:f\r\nDTSTART;TZID=Europe/Berlin:20260601T090000\r\nRRULE:FREQ=DAILY\r\n",
            "RDATE;TZID=Europe/Berlin:20260610T180000\r\nORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:a@example.com\r\nATTENDEE:mailto:b@example.com\r\n",
            "RDATE;TZID=Europe/Berlin:20260603T180000\r\nEND:VEVENT\r\n",
            "BEGIN:VEVENT\r\nUID:f\r\nRECURRENCE-ID;TZID=Europe/Berlin;RANGE=THISANDFUTURE:20260604T090000\r\n",
            "DTSTART;TZID=Europe/Berlin:20260604T100000\r\nORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:a@example.com\r\nEND:VEVENT\r\n",
            "BEGIN:VEVENT\r\nUID:f\r\nRECURRENCE-ID;TZID=Europe/Berlin;RANGE=THISANDFUTURE:20260606T090000\r\n",
            "DTSTART;TZID=Europe/Berlin:20260606T100000\r\nORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:a@example.com\r\nEND:VEVENT\r\n",
        ));
        let messages = split_messages(
            itip(&ical, &["b@example.com"], ItipSummary::Invite(vec![])),
            AttendeeVisibility::All,
        );
        let [message] = messages.as_slice() else {
            panic!("expected one message: {messages:#?}");
        };
        let ical = text(message);
        assert!(
            ical.contains("ORGANIZER:mailto:org@example.com\r\n"),
            "{ical}"
        );
        assert!(ical.contains("ATTENDEE:mailto:a@example.com\r\n"), "{ical}");
        assert!(ical.contains("ATTENDEE:mailto:b@example.com\r\n"), "{ical}");
        assert!(
            ical.contains("RDATE;TZID=Europe/Berlin:20260603T180000\r\n"),
            "{ical}"
        );
        assert!(!ical.contains("20260610"), "{ical}");
        assert!(ical.contains("UNTIL=20260604T065959Z"), "{ical}");
        assert!(!ical.contains("RECURRENCE-ID"), "{ical}");
    }

    #[test]
    fn truncated_series_keep_their_first_instance() {
        let ical = truncated(
            "DTSTART;TZID=Europe/Berlin:20260601T090000\r\nRDATE;TZID=Europe/Berlin:20260605T090000,20260610T090000\r\n",
            "RECURRENCE-ID;TZID=Europe/Berlin;RANGE=THISANDFUTURE:20260605T090000\r\nDTSTART;TZID=Europe/Berlin:20260605T100000\r\n",
        );
        assert!(
            ical.contains("DTSTART;TZID=Europe/Berlin:20260601T090000\r\n"),
            "{ical}"
        );
        assert!(!ical.contains("RDATE"), "{ical}");

        let master = "DTSTART;TZID=Europe/Berlin:20260601T090000\r\nRRULE:FREQ=DAILY;COUNT=5\r\nRDATE;TZID=Europe/Berlin:20260530T090000\r\nSEQUENCE:3\r\n";
        let recurrence_id = "RECURRENCE-ID;TZID=Europe/Berlin;RANGE=THISANDFUTURE:20260601T090000\r\nDTSTART;TZID=Europe/Berlin:20260601T100000\r\n";
        let messages = this_and_future(master, recurrence_id, ItipSummary::Invite(vec![]));
        assert!(messages.is_empty(), "{messages:#?}");

        let messages = this_and_future(
            master,
            recurrence_id,
            ItipSummary::Update {
                method: ICalendarMethod::Request,
                current: vec![],
                previous: vec![],
            },
        );
        let [ical] = messages.as_slice() else {
            panic!("expected one message: {messages:#?}");
        };
        assert!(ical.contains("METHOD:CANCEL\r\n"), "{ical}");
        assert!(ical.contains("ATTENDEE:mailto:a@example.com\r\n"), "{ical}");
        assert!(ical.contains("SEQUENCE:3\r\n"), "{ical}");
        assert!(!ical.contains("STATUS"), "{ical}");
        assert!(!ical.contains("FREQ=DAILY"), "{ical}");
        assert!(!ical.contains("RECURRENCE-ID"), "{ical}");
    }

    #[test]
    fn replies_are_not_split() {
        let mut reply = message(&["org@example.com"]);
        reply.from_organizer = false;
        reply.to = vec!["a@example.com".to_string(), "b@example.com".to_string()];
        let messages =
            itip_messages_per_recipient(vec![reply], policy(AttendeeVisibility::RecipientOnly))
                .expect("recipients within limit");
        assert_eq!(messages.len(), 1);
    }
}
