/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CalendarEventContent, CalendarEventData, EVENT_PRIVATE, EVENT_SECRET,
    compare::RedundantOverrides,
};
use calcard::icalendar::{
    ICalendar, ICalendarClassification, ICalendarComponent, ICalendarComponentType, ICalendarEntry,
    ICalendarParameterName, ICalendarProperty, ICalendarValue,
};
use common::auth::AccessToken;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventPrivacy {
    #[default]
    Public,
    Private,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyDenied {
    Forbidden,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventViewer {
    Owner,
    Sharee,
}

impl EventViewer {
    pub fn new(is_owner: bool) -> Self {
        if is_owner {
            EventViewer::Owner
        } else {
            EventViewer::Sharee
        }
    }

    pub fn of(access_token: &AccessToken, account_id: u32) -> Self {
        EventViewer::new(access_token.is_member(account_id))
    }

    pub fn is_owner(self) -> bool {
        self == EventViewer::Owner
    }
}

impl EventPrivacy {
    pub fn from_flags(flags: u16) -> Self {
        if flags & EVENT_SECRET != 0 {
            EventPrivacy::Secret
        } else if flags & EVENT_PRIVATE != 0 {
            EventPrivacy::Private
        } else {
            EventPrivacy::Public
        }
    }

    pub fn apply_to_flags(self, flags: u16) -> u16 {
        let flags = flags & !(EVENT_PRIVATE | EVENT_SECRET);
        match self {
            EventPrivacy::Public => flags,
            EventPrivacy::Private => flags | EVENT_PRIVATE,
            EventPrivacy::Secret => flags | EVENT_SECRET,
        }
    }

    pub fn from_value(value: &ICalendarValue) -> Self {
        match value {
            ICalendarValue::Classification(ICalendarClassification::Public) => EventPrivacy::Public,
            ICalendarValue::Classification(ICalendarClassification::Confidential) => {
                EventPrivacy::Secret
            }
            _ => EventPrivacy::Private,
        }
    }

    pub fn is_public(self) -> bool {
        self == EventPrivacy::Public
    }

    pub fn check_access(self, viewer: EventViewer) -> Result<(), PrivacyDenied> {
        match self {
            _ if viewer.is_owner() => Ok(()),
            EventPrivacy::Public => Ok(()),
            EventPrivacy::Private => Err(PrivacyDenied::Forbidden),
            EventPrivacy::Secret => Err(PrivacyDenied::NotFound),
        }
    }

    pub fn may_be_set_by(self, viewer: EventViewer) -> bool {
        viewer.is_owner() || self.is_public()
    }

    fn classification(self) -> ICalendarClassification {
        match self {
            EventPrivacy::Public => ICalendarClassification::Public,
            EventPrivacy::Private => ICalendarClassification::Private,
            EventPrivacy::Secret => ICalendarClassification::Confidential,
        }
    }
}

impl CalendarEventContent {
    pub fn into_private_view(self) -> Self {
        CalendarEventContent {
            data: CalendarEventData {
                event: self.data.event.into_private_view(),
                alarms: Box::default(),
                ..self.data
            },
            preferences: vec![],
            dead_properties: Default::default(),
        }
    }
}

pub trait ICalendarPrivacy {
    fn privacy(&self) -> EventPrivacy;

    fn set_privacy(&mut self, privacy: EventPrivacy);

    fn into_private_view(self) -> ICalendar;
}

impl ICalendarPrivacy for ICalendar {
    fn privacy(&self) -> EventPrivacy {
        self.components
            .iter()
            .filter(|component| component.component_type.is_scheduling_object())
            .flat_map(|component| component.entries.iter())
            .filter(|entry| entry.name == ICalendarProperty::Class)
            .filter_map(|entry| entry.values.first())
            .map(EventPrivacy::from_value)
            .max()
            .unwrap_or_default()
    }

    fn set_privacy(&mut self, privacy: EventPrivacy) {
        for component in self
            .components
            .iter_mut()
            .filter(|component| component.component_type.is_scheduling_object())
        {
            component
                .entries
                .retain(|entry| entry.name != ICalendarProperty::Class);
            if !privacy.is_public() {
                component.entries.push(ICalendarEntry {
                    name: ICalendarProperty::Class,
                    params: vec![],
                    values: [ICalendarValue::Classification(privacy.classification())].into(),
                });
            }
        }
    }

    fn into_private_view(self) -> ICalendar {
        let is_visible = self
            .components
            .iter()
            .map(|component| is_private_component(&component.component_type))
            .collect::<Vec<_>>();
        let components = self
            .components
            .into_iter()
            .zip(&is_visible)
            .map(|(component, is_component_visible)| {
                if !is_component_visible {
                    return ICalendarComponent {
                        component_type: ICalendarComponentType::Other(Default::default()),
                        entries: vec![],
                        component_ids: vec![],
                    };
                }
                let entries = component
                    .entries
                    .into_iter()
                    .filter(|entry| is_private_entry(&component.component_type, &entry.name))
                    .map(|mut entry| {
                        entry.params.retain(|param| {
                            matches!(
                                param.name,
                                ICalendarParameterName::Tzid
                                    | ICalendarParameterName::Value
                                    | ICalendarParameterName::Range
                            )
                        });
                        entry
                    })
                    .collect();
                let component_ids = component
                    .component_ids
                    .into_iter()
                    .filter(|id| is_visible.get(*id as usize).copied().unwrap_or_default())
                    .collect();
                ICalendarComponent {
                    component_type: component.component_type,
                    entries,
                    component_ids,
                }
            })
            .collect();

        let mut view = ICalendar { components };
        view.remove_redundant_overrides();
        view
    }
}

trait RedundantOverrideRemoval {
    fn remove_redundant_overrides(&mut self);
}

impl RedundantOverrideRemoval for ICalendar {
    fn remove_redundant_overrides(&mut self) {
        let Some(overrides) = RedundantOverrides::new(self) else {
            return;
        };
        let redundant = self
            .components
            .iter()
            .enumerate()
            .filter(|(id, component)| {
                component.component_type.is_event_or_todo()
                    && component.is_recurrence_override()
                    && overrides.is_redundant(*id as u32)
            })
            .map(|(id, _)| id as u32)
            .collect::<Vec<_>>();
        if !redundant.is_empty() {
            for component in &mut self.components {
                component.component_ids.retain(|id| !redundant.contains(id));
            }
        }
    }
}

fn is_private_component(component_type: &ICalendarComponentType) -> bool {
    matches!(
        component_type,
        ICalendarComponentType::VCalendar
            | ICalendarComponentType::VEvent
            | ICalendarComponentType::VTodo
            | ICalendarComponentType::VTimezone
            | ICalendarComponentType::Standard
            | ICalendarComponentType::Daylight
    )
}

fn is_private_entry(component_type: &ICalendarComponentType, property: &ICalendarProperty) -> bool {
    match component_type {
        ICalendarComponentType::VCalendar => matches!(
            property,
            ICalendarProperty::Version | ICalendarProperty::Prodid | ICalendarProperty::Calscale
        ),
        ICalendarComponentType::VEvent | ICalendarComponentType::VTodo => matches!(
            property,
            ICalendarProperty::Uid
                | ICalendarProperty::Dtstamp
                | ICalendarProperty::Created
                | ICalendarProperty::Sequence
                | ICalendarProperty::Dtstart
                | ICalendarProperty::Dtend
                | ICalendarProperty::Duration
                | ICalendarProperty::Due
                | ICalendarProperty::EstimatedDuration
                | ICalendarProperty::Transp
                | ICalendarProperty::Class
                | ICalendarProperty::RecurrenceId
                | ICalendarProperty::Rrule
                | ICalendarProperty::Rdate
                | ICalendarProperty::Exdate
                | ICalendarProperty::ShowWithoutTime
        ),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "METHOD:REQUEST\r\n",
        "BEGIN:VTIMEZONE\r\n",
        "TZID:Europe/Berlin\r\n",
        "BEGIN:STANDARD\r\n",
        "DTSTART:19701025T030000\r\n",
        "TZOFFSETFROM:+0200\r\n",
        "TZOFFSETTO:+0100\r\n",
        "END:STANDARD\r\n",
        "END:VTIMEZONE\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:abc\r\n",
        "DTSTAMP:20240101T000000Z\r\n",
        "DTSTART;TZID=Europe/Berlin:20240101T100000\r\n",
        "DURATION:PT1H\r\n",
        "RRULE:FREQ=DAILY;COUNT=3\r\n",
        "SUMMARY:Secret meeting\r\n",
        "DESCRIPTION:Details\r\n",
        "LOCATION:Room 1\r\n",
        "CLASS:PRIVATE\r\n",
        "TRANSP:OPAQUE\r\n",
        "ORGANIZER:mailto:a@example.org\r\n",
        "ATTENDEE:mailto:b@example.org\r\n",
        "BEGIN:VALARM\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER:-PT15M\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:abc\r\n",
        "RECURRENCE-ID;TZID=Europe/Berlin:20240102T100000\r\n",
        "DTSTART;TZID=Europe/Berlin:20240102T110000\r\n",
        "SUMMARY:Moved\r\n",
        "CLASS:CONFIDENTIAL\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    fn parse(ical: &str) -> ICalendar {
        ICalendar::parse(ical).expect("valid iCalendar")
    }

    #[test]
    fn privacy_is_strictest_class() {
        assert_eq!(parse(EVENT).privacy(), EventPrivacy::Secret);
        assert_eq!(
            parse(&EVENT.replace("CLASS:CONFIDENTIAL\r\n", "")).privacy(),
            EventPrivacy::Private
        );
        assert_eq!(
            parse(
                &EVENT
                    .replace("CLASS:CONFIDENTIAL\r\n", "")
                    .replace("CLASS:PRIVATE\r\n", "")
            )
            .privacy(),
            EventPrivacy::Public
        );
        assert_eq!(
            parse(
                &EVENT
                    .replace("CLASS:CONFIDENTIAL\r\n", "")
                    .replace("PRIVATE", "X-UNKNOWN")
            )
            .privacy(),
            EventPrivacy::Private
        );
    }

    #[test]
    fn flags_round_trip() {
        for privacy in [
            EventPrivacy::Public,
            EventPrivacy::Private,
            EventPrivacy::Secret,
        ] {
            let flags = privacy.apply_to_flags(EVENT_PRIVATE | EVENT_SECRET | 1);
            assert_eq!(EventPrivacy::from_flags(flags), privacy);
            assert_eq!(flags & 1, 1);
        }
    }

    #[test]
    fn set_privacy_replaces_class() {
        let mut ical = parse(EVENT);
        ical.set_privacy(EventPrivacy::Public);
        assert_eq!(ical.privacy(), EventPrivacy::Public);
        ical.set_privacy(EventPrivacy::Private);
        assert_eq!(ical.privacy(), EventPrivacy::Private);
        assert!(
            ical.components
                .iter()
                .filter(|c| c.component_type.is_scheduling_object())
                .all(|c| c
                    .entries
                    .iter()
                    .filter(|e| e.name == ICalendarProperty::Class)
                    .count()
                    == 1)
        );
    }

    #[test]
    fn private_view_strips_details() {
        let ical = parse(EVENT);
        let view = ical.clone().into_private_view();
        assert_eq!(view.components.len(), ical.components.len());
        for (original, projected) in ical.components.iter().zip(view.components.iter()) {
            if projected.component_type == original.component_type {
                continue;
            }
            assert!(projected.entries.is_empty() && projected.component_ids.is_empty());
        }
        let view = view.to_string();
        for removed in [
            "METHOD",
            "SUMMARY",
            "DESCRIPTION",
            "LOCATION",
            "ORGANIZER",
            "ATTENDEE",
            "VALARM",
            "TRIGGER",
        ] {
            assert!(!view.contains(removed), "{removed} leaked:\n{view}");
        }
        for kept in [
            "TZID:Europe/Berlin",
            "BEGIN:STANDARD",
            "UID:abc",
            "RRULE:FREQ=DAILY;COUNT=3",
            "DTSTART;TZID=Europe/Berlin:20240101T100000",
            "RECURRENCE-ID;TZID=Europe/Berlin:20240102T100000",
            "DURATION:PT1H",
            "TRANSP:OPAQUE",
            "CLASS:PRIVATE",
        ] {
            assert!(view.contains(kept), "{kept} missing:\n{view}");
        }
        let reparsed = parse(&view);
        assert_eq!(reparsed.components.len(), 5);
    }

    #[test]
    fn private_view_hides_changes_to_hidden_properties() {
        let view = parse(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:-//Owner Client//EN\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:abc\r\n",
            "DTSTAMP:20240101T000000Z\r\n",
            "LAST-MODIFIED:20240102T000000Z\r\n",
            "DTSTART;X-NOTE=Lawyer about divorce;TZID=Europe/Berlin:20240506T090000\r\n",
            "DURATION:PT30M\r\n",
            "RRULE:FREQ=WEEKLY;COUNT=4\r\n",
            "EXRULE:FREQ=MONTHLY;COUNT=1\r\n",
            "SUMMARY:Lawyer\r\n",
            "CLASS:PRIVATE\r\n",
            "END:VEVENT\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:abc\r\n",
            "DTSTAMP:20240101T000000Z\r\n",
            "RECURRENCE-ID;TZID=Europe/Berlin:20240513T090000\r\n",
            "DTSTART;TZID=Europe/Berlin:20240513T090000\r\n",
            "DURATION:PT30M\r\n",
            "SUMMARY:Lawyer again\r\n",
            "CLASS:PRIVATE\r\n",
            "END:VEVENT\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:abc\r\n",
            "DTSTAMP:20240101T000000Z\r\n",
            "RECURRENCE-ID;TZID=Europe/Berlin:20240520T090000\r\n",
            "DTSTART;TZID=Europe/Berlin:20240520T100000\r\n",
            "DURATION:PT30M\r\n",
            "SUMMARY:Lawyer later\r\n",
            "CLASS:PRIVATE\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ))
        .into_private_view();

        let text = view.to_string();
        for removed in [
            "X-NOTE",
            "Lawyer",
            "LAST-MODIFIED",
            "EXRULE",
            "20240513T090000",
        ] {
            assert!(!text.contains(removed), "{removed} leaked:\n{text}");
        }
        assert!(
            text.contains("RECURRENCE-ID;TZID=Europe/Berlin:20240520T090000"),
            "{text}"
        );

        let json = serde_json::to_value(
            view.into_jscalendar_with::<String, String, calcard::common::blob::NoBlobIds>(
                calcard::jscalendar::import::ImportOptions::new()
                    .include_ical_components(true)
                    .return_first(true),
            )
            .expect("converts"),
        )
        .expect("serializable JSCalendar");
        assert!(json.get("iCalendar").is_none(), "{json:#}");
        assert_eq!(
            json["recurrenceOverrides"],
            serde_json::json!({ "2024-05-20T09:00:00": { "start": "2024-05-20T10:00:00" } }),
            "{json:#}"
        );
    }
}
