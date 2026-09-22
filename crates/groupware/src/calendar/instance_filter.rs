/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::strip_mailto_scheme;
use calcard::icalendar::{
    ArchivedICalendar, ArchivedICalendarComponent, ArchivedICalendarParameterValue,
    ArchivedICalendarProperty, ArchivedICalendarValue,
};
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use std::borrow::Cow;
use store::{
    ahash::AHashSet,
    search::{CalendarSearchField, SearchFilter, TextMatch, tokenize::tokenize},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttendeeSearch {
    Visible,
    Hidden,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct QueryWord {
    word: String,
    stem: Option<String>,
}

#[derive(Debug)]
struct TextCondition {
    fields: &'static [CalendarSearchField],
    op: TextMatch,
    language: Language,
    words: Vec<QueryWord>,
}

#[derive(Debug, Default)]
pub struct InstanceTextFilter {
    conditions: Vec<TextCondition>,
    ordered_fields: Vec<CalendarSearchField>,
}

pub struct EventTextFilter<'x> {
    conditions: &'x [TextCondition],
    ordered_fields: &'x [CalendarSearchField],
    language: Language,
    attendees: AttendeeSearch,
}

#[derive(Default)]
struct FieldTokens<'a> {
    words: AHashSet<Cow<'a, str>>,
    stemmed: AHashSet<Cow<'a, str>>,
    ordered: Vec<Cow<'a, str>>,
}

struct ComponentTokens<'a, 'x> {
    ordered_fields: &'x [CalendarSearchField],
    fields: Vec<(CalendarSearchField, FieldTokens<'a>)>,
}

impl InstanceTextFilter {
    pub fn add(&mut self, fields: &'static [CalendarSearchField], filter: &SearchFilter) {
        let SearchFilter::Text {
            op,
            value,
            language,
            ..
        } = filter
        else {
            return;
        };
        let words = match op {
            TextMatch::Prefix => vec![QueryWord {
                word: value.to_lowercase(),
                stem: None,
            }],
            TextMatch::Standard | TextMatch::Exact => {
                let mut words = Vec::new();
                tokenize(value, *language, |token| {
                    words.push(QueryWord {
                        word: token.word.into_owned(),
                        stem: token.stem.map(Cow::into_owned),
                    });
                    true
                });
                if *op == TextMatch::Standard {
                    words.sort_unstable();
                    words.dedup();
                }
                words
            }
        };
        if *op == TextMatch::Exact {
            for field in fields {
                if !self.ordered_fields.contains(field) {
                    self.ordered_fields.push(*field);
                }
            }
        }
        self.conditions.push(TextCondition {
            fields,
            op: *op,
            language: *language,
            words,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }

    pub fn for_event(
        &self,
        event: &ArchivedICalendar,
        default_language: Language,
        attendees: AttendeeSearch,
    ) -> EventTextFilter<'_> {
        let language = if self
            .conditions
            .iter()
            .flat_map(|condition| condition.fields)
            .any(|field| field.is_language_detected())
        {
            let mut detector = LanguageDetector::new();
            for value in event
                .components
                .iter()
                .filter(|component| component.component_type.is_scheduling_object())
                .flat_map(|component| {
                    field_values(component, CalendarSearchField::Title)
                        .chain(field_values(component, CalendarSearchField::Description))
                })
            {
                detector.detect(value, MIN_LANGUAGE_SCORE);
            }
            detector
                .most_frequent_language()
                .unwrap_or(default_language)
        } else {
            default_language
        };

        EventTextFilter {
            conditions: &self.conditions,
            ordered_fields: &self.ordered_fields,
            language,
            attendees,
        }
    }
}

impl EventTextFilter<'_> {
    pub fn matches(&self, component: &ArchivedICalendarComponent) -> bool {
        let mut tokens = ComponentTokens {
            ordered_fields: self.ordered_fields,
            fields: Vec::with_capacity(2),
        };
        self.conditions.iter().all(|condition| {
            condition.matches(component, self.language, self.attendees, &mut tokens)
        })
    }
}

impl<'a> ComponentTokens<'a, '_> {
    fn of(
        &mut self,
        component: &'a ArchivedICalendarComponent,
        field: CalendarSearchField,
        language: Language,
    ) -> &FieldTokens<'a> {
        if let Some(index) = self.fields.iter().position(|(cached, _)| *cached == field) {
            return &self.fields[index].1;
        }

        let keep_order = self.ordered_fields.contains(&field);
        let mut tokens = FieldTokens::default();
        for value in field_values(component, field) {
            tokenize(value, language, |token| {
                if keep_order {
                    tokens.ordered.push(token.word.clone());
                }
                if let Some(stem) = token.stem {
                    tokens.stemmed.insert(stem);
                }
                tokens.stemmed.insert(token.word.clone());
                tokens.words.insert(token.word);
                true
            });
        }
        self.fields.push((field, tokens));
        &self.fields.last().expect("token set was just inserted").1
    }
}

impl TextCondition {
    fn matches<'a>(
        &self,
        component: &'a ArchivedICalendarComponent,
        event_language: Language,
        attendees: AttendeeSearch,
        tokens: &mut ComponentTokens<'a, '_>,
    ) -> bool {
        !self.words.is_empty()
            && self
                .fields
                .iter()
                .filter(|field| {
                    attendees == AttendeeSearch::Visible || **field != CalendarSearchField::Attendee
                })
                .any(|field| {
                    let language = if field.is_language_detected() {
                        event_language
                    } else {
                        Language::None
                    };
                    self.matches_tokens(tokens.of(component, *field, language))
                })
    }

    fn matches_tokens(&self, tokens: &FieldTokens<'_>) -> bool {
        match self.op {
            TextMatch::Standard => {
                let is_stemmed = !matches!(self.language, Language::None | Language::Unknown);
                self.words
                    .iter()
                    .all(|word| word.matches(tokens, is_stemmed))
            }
            TextMatch::Exact => tokens.ordered.windows(self.words.len()).any(|window| {
                window
                    .iter()
                    .zip(&self.words)
                    .all(|(token, word)| *token == word.word)
            }),
            TextMatch::Prefix => self.words.iter().all(|word| {
                tokens
                    .stemmed
                    .iter()
                    .any(|token| token.starts_with(&word.word))
            }),
        }
    }
}

impl QueryWord {
    fn matches(&self, tokens: &FieldTokens<'_>, is_stemmed: bool) -> bool {
        if is_stemmed {
            tokens.stemmed.contains(self.word.as_str())
                || self
                    .stem
                    .as_deref()
                    .is_some_and(|stem| tokens.stemmed.contains(stem))
        } else {
            tokens.words.contains(self.word.as_str())
        }
    }
}

trait DetectedLanguage {
    fn is_language_detected(&self) -> bool;
}

impl DetectedLanguage for CalendarSearchField {
    fn is_language_detected(&self) -> bool {
        matches!(
            self,
            CalendarSearchField::Title | CalendarSearchField::Description
        )
    }
}

fn field_values(
    component: &ArchivedICalendarComponent,
    field: CalendarSearchField,
) -> impl Iterator<Item = &str> {
    component
        .entries
        .iter()
        .filter(move |entry| {
            matches!(
                (&entry.name, field),
                (
                    ArchivedICalendarProperty::Summary,
                    CalendarSearchField::Title
                ) | (
                    ArchivedICalendarProperty::Description,
                    CalendarSearchField::Description
                ) | (
                    ArchivedICalendarProperty::Location,
                    CalendarSearchField::Location
                ) | (
                    ArchivedICalendarProperty::Organizer,
                    CalendarSearchField::Owner
                ) | (
                    ArchivedICalendarProperty::Attendee,
                    CalendarSearchField::Attendee
                )
            )
        })
        .flat_map(|entry| {
            entry
                .values
                .iter()
                .filter_map(|value| match value {
                    ArchivedICalendarValue::Text(value) => Some(value.as_str()),
                    ArchivedICalendarValue::Uri(uri) => uri.as_str(),
                    _ => None,
                })
                .chain(entry.params.iter().filter_map(|param| match &param.value {
                    ArchivedICalendarParameterValue::Text(value) => Some(value.as_str()),
                    ArchivedICalendarParameterValue::Uri(uri) => uri.as_str(),
                    _ => None,
                }))
        })
        .map(strip_mailto_scheme)
}

#[cfg(test)]
mod tests {
    use super::*;
    use calcard::{Entry, Parser, icalendar::ICalendar};

    const EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n",
        "BEGIN:VEVENT\r\nUID:u@example.com\r\nDTSTAMP:20300101T000000Z\r\n",
        "DTSTART:20300301T090000Z\r\nDURATION:PT30M\r\nRRULE:FREQ=DAILY;COUNT=4\r\n",
        "SUMMARY:Quarterly reviews\r\n",
        "DESCRIPTION:Discuss the numbers of the quarter with the whole team\r\n",
        "LOCATION:Room 5\r\n",
        "ORGANIZER;CN=John Doe:mailto:jdoe@example.com\r\n",
        "ATTENDEE;CN=Bill Secret:mailto:bill@example.com\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:u@example.com\r\nDTSTAMP:20300101T000000Z\r\n",
        "RECURRENCE-ID:20300302T090000Z\r\nDTSTART:20300302T090000Z\r\nDURATION:PT30M\r\n",
        "SUMMARY:Sales calls\r\n",
        "ORGANIZER;CN=John Doe:mailto:jdoe@example.com\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:u@example.com\r\nDTSTAMP:20300101T000000Z\r\n",
        "RECURRENCE-ID:20300303T090000Z\r\nDTSTART:20300303T090000Z\r\nDURATION:PT30M\r\n",
        "SUMMARY:Meet the team\r\nLOCATION:Berlin office\r\n",
        "ORGANIZER;CN=John Doe:mailto:jdoe@example.com\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:u@example.com\r\nDTSTAMP:20300101T000000Z\r\n",
        "RECURRENCE-ID:20300304T090000Z\r\nDTSTART:20300304T090000Z\r\nDURATION:PT30M\r\n",
        "SUMMARY:Review planning\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    fn archive(ical: &str) -> rkyv::util::AlignedVec {
        let Entry::ICalendar(ical) = Parser::new(ical).entry() else {
            panic!("failed to parse iCalendar");
        };
        rkyv::to_bytes::<rkyv::rancor::Error>(&ical).expect("archive")
    }

    fn matching_summaries(
        bytes: &rkyv::util::AlignedVec,
        conditions: &[(&'static [CalendarSearchField], &str, Language)],
        attendees: AttendeeSearch,
    ) -> Vec<String> {
        let ical =
            rkyv::access::<<ICalendar as rkyv::Archive>::Archived, rkyv::rancor::Error>(bytes)
                .expect("access");
        let mut filter = InstanceTextFilter::default();
        for (fields, text, language) in conditions {
            filter.add(
                fields,
                &SearchFilter::has_text(fields[0], text.to_string(), *language),
            );
        }
        let filter = filter.for_event(ical, Language::English, attendees);
        ical.components
            .iter()
            .filter(|component| component.component_type.is_scheduling_object())
            .filter(|component| filter.matches(component))
            .filter_map(|component| {
                component
                    .property(&calcard::icalendar::ICalendarProperty::Summary)
                    .and_then(|entry| entry.values.first())
                    .and_then(|value| value.as_text())
                    .map(str::to_string)
            })
            .collect()
    }

    const TITLE: &[CalendarSearchField] = &[CalendarSearchField::Title];
    const LOCATION: &[CalendarSearchField] = &[CalendarSearchField::Location];
    const TEXT: &[CalendarSearchField] = &[
        CalendarSearchField::Title,
        CalendarSearchField::Description,
        CalendarSearchField::Location,
        CalendarSearchField::Owner,
        CalendarSearchField::Attendee,
    ];

    #[test]
    fn stems_match_like_the_index() {
        let event = archive(EVENT);
        for (condition, expected) in [
            (
                (TITLE, "review", Language::English),
                vec!["Quarterly reviews", "Review planning"],
            ),
            ((TITLE, "call", Language::English), vec!["Sales calls"]),
            (
                (TITLE, "meetings", Language::English),
                vec!["Meet the team"],
            ),
            (
                (LOCATION, "rooms", Language::English),
                vec!["Quarterly reviews"],
            ),
            ((TITLE, "review", Language::None), vec!["Review planning"]),
        ] {
            assert_eq!(
                matching_summaries(&event, &[condition], AttendeeSearch::Visible),
                expected,
                "{condition:?}"
            );
        }
    }

    #[test]
    fn missing_override_fields_do_not_fall_back_to_the_base() {
        let event = archive(EVENT);
        for (condition, expected) in [
            (
                (LOCATION, "room", Language::English),
                vec!["Quarterly reviews"],
            ),
            (
                (LOCATION, "berlin", Language::English),
                vec!["Meet the team"],
            ),
            (
                (TEXT, "numbers", Language::English),
                vec!["Quarterly reviews"],
            ),
            (
                (TEXT, "doe", Language::English),
                vec!["Quarterly reviews", "Sales calls", "Meet the team"],
            ),
        ] {
            assert_eq!(
                matching_summaries(&event, &[condition], AttendeeSearch::Visible),
                expected,
                "{condition:?}"
            );
        }
    }

    #[test]
    fn conditions_match_the_same_component() {
        let event = archive(EVENT);
        assert_eq!(
            matching_summaries(
                &event,
                &[
                    (TITLE, "meet", Language::English),
                    (LOCATION, "berlin", Language::English)
                ],
                AttendeeSearch::Visible
            ),
            ["Meet the team"]
        );
        assert_eq!(
            matching_summaries(
                &event,
                &[
                    (TITLE, "calls", Language::English),
                    (LOCATION, "berlin", Language::English)
                ],
                AttendeeSearch::Visible
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn phrases_and_prefixes() {
        let event = archive(EVENT);
        for (condition, expected) in [
            (
                (TITLE, "\"review planning\"", Language::English),
                vec!["Review planning"],
            ),
            (
                (TITLE, "\"planning review\"", Language::English),
                Vec::<&str>::new(),
            ),
            (
                (TITLE, "rev*", Language::English),
                vec!["Quarterly reviews", "Review planning"],
            ),
            (
                (LOCATION, "berl*", Language::English),
                vec!["Meet the team"],
            ),
        ] {
            assert_eq!(
                matching_summaries(&event, &[condition], AttendeeSearch::Visible),
                expected,
                "{condition:?}"
            );
        }

        let event = archive(concat!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n",
            "BEGIN:VEVENT\r\nUID:ja@example.com\r\nDTSTAMP:20300101T000000Z\r\n",
            "DTSTART:20300301T090000Z\r\nDURATION:PT30M\r\n",
            "SUMMARY:東京本社で四半期の会議を開きます\r\n",
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        ));
        assert_eq!(
            matching_summaries(
                &event,
                &[(TITLE, "会議*", Language::Japanese)],
                AttendeeSearch::Visible
            ),
            ["東京本社で四半期の会議を開きます"]
        );
    }

    #[test]
    fn several_conditions_share_one_tokenization_per_field() {
        let event = archive(EVENT);
        assert_eq!(
            matching_summaries(
                &event,
                &[
                    (TITLE, "\"review planning\"", Language::English),
                    (TITLE, "planning", Language::English),
                    (TITLE, "plan*", Language::English)
                ],
                AttendeeSearch::Visible
            ),
            ["Review planning"]
        );
        assert_eq!(
            matching_summaries(
                &event,
                &[
                    (TITLE, "\"quarterly reviews\"", Language::English),
                    (TITLE, "review", Language::English)
                ],
                AttendeeSearch::Visible
            ),
            ["Quarterly reviews"]
        );
    }

    #[test]
    fn hidden_attendees_are_not_searched() {
        let event = archive(EVENT);
        for (attendees, expected) in [
            (AttendeeSearch::Visible, vec!["Quarterly reviews"]),
            (AttendeeSearch::Hidden, vec![]),
        ] {
            assert_eq!(
                matching_summaries(&event, &[(TEXT, "bill", Language::English)], attendees),
                expected,
                "{attendees:?}"
            );
        }
    }
}
