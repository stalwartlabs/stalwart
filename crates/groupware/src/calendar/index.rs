/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendar, ArchivedCalendarEvent, ArchivedCalendarPreferences, ArchivedDefaultAlert,
    ArchivedTimezone, Calendar, CalendarEvent, CalendarPreferences, DefaultAlert, Timezone,
};
use crate::calendar::{
    ArchivedCalendarEventNotification, ArchivedChangedBy, ArchivedEventPreferences,
    CalendarEventNotification, ChangedBy, EventPreferences,
};
use ahash::AHashSet;
use calcard::icalendar::{
    ArchivedICalendarParameterValue, ArchivedICalendarProperty, ArchivedICalendarValue,
    ICalendarParameterValue, ICalendarProperty, ICalendarValue,
};
use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use store::{
    U32_LEN,
    search::{CalendarSearchField, IndexDocument, SearchField},
    write::{IndexPropertyClass, SearchIndex, ValueClass},
    xxhash_rust::xxh3,
};
use types::{
    acl::AclGrant,
    collection::SyncCollection,
    field::{CalendarEventField, CalendarNotificationField},
};

impl IndexableObject for Calendar {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Calendar,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedCalendar {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Calendar,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for Calendar {
    fn is_versioned() -> bool {
        true
    }
}

impl IndexableObject for CalendarEvent {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::SearchIndex {
                index: SearchIndex::Calendar,
                hash: self
                    .hashes()
                    .chain([self.data.event_range_start() as u64])
                    .fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Index {
                field: CalendarEventField::Uid.into(),
                value: self.data.event.uids().next().into(),
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Calendar,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedCalendarEvent {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::SearchIndex {
                index: SearchIndex::Calendar,
                hash: self
                    .hashes()
                    .chain([self.data.event_range_start() as u64])
                    .fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Index {
                field: CalendarEventField::Uid.into(),
                value: self.data.event.uids().next().into(),
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Calendar,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for CalendarEvent {
    fn is_versioned() -> bool {
        true
    }
}

impl IndexableObject for CalendarEventNotification {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Quota {
                used: self.size() as u32,
            },
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: CalendarNotificationField::CreatedToId.into(),
                    value: self.created as u64,
                }),
                value: self.event_id.unwrap_or(u32::MAX).into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::CalendarEventNotification,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedCalendarEventNotification {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Quota {
                used: self.size() as u32,
            },
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: CalendarNotificationField::CreatedToId.into(),
                    value: self.created.to_native() as u64,
                }),
                value: self
                    .event_id
                    .as_ref()
                    .map(|v| v.to_native())
                    .unwrap_or(u32::MAX)
                    .into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::CalendarEventNotification,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for CalendarEventNotification {
    fn is_versioned() -> bool {
        false
    }
}

impl Calendar {
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self.preferences.iter().map(|p| p.size()).sum::<usize>()
            + self.name.len()
            + std::mem::size_of::<Calendar>()
    }
}

impl ArchivedCalendar {
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self.preferences.iter().map(|p| p.size()).sum::<usize>()
            + self.name.len()
            + std::mem::size_of::<Calendar>()
    }
}

impl CalendarEvent {
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.names.iter().map(|n| n.name.len()).sum::<usize>()
            + self.preferences.iter().map(|p| p.size()).sum::<usize>()
            + self.size as usize
            + std::mem::size_of::<CalendarEvent>()
    }
}

impl ArchivedCalendarEvent {
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.names.iter().map(|n| n.name.len()).sum::<usize>()
            + self.preferences.iter().map(|p| p.size()).sum::<usize>()
            + self.size.to_native() as usize
            + std::mem::size_of::<CalendarEvent>()
    }
}

impl CalendarEventNotification {
    pub fn size(&self) -> usize {
        (match &self.changed_by {
            ChangedBy::PrincipalId(_) => U32_LEN,
            ChangedBy::CalendarAddress(v) => v.len(),
        }) + std::mem::size_of::<CalendarEventNotification>()
            + self.size as usize
    }
}

impl ArchivedCalendarEventNotification {
    pub fn size(&self) -> usize {
        (match &self.changed_by {
            ArchivedChangedBy::PrincipalId(_) => U32_LEN,
            ArchivedChangedBy::CalendarAddress(v) => v.len(),
        }) + std::mem::size_of::<CalendarEventNotification>()
            + self.size.to_native() as usize
    }
}

impl CalendarPreferences {
    pub fn size(&self) -> usize {
        self.name.len()
            + self.default_alerts.iter().map(|a| a.size()).sum::<usize>()
            + self.description.as_ref().map_or(0, |n| n.len())
            + self.color.as_ref().map_or(0, |n| n.len())
            + self.time_zone.size()
            + std::mem::size_of::<CalendarPreferences>()
    }
}

impl ArchivedCalendarPreferences {
    pub fn size(&self) -> usize {
        self.name.len()
            + self.default_alerts.iter().map(|a| a.size()).sum::<usize>()
            + self.description.as_ref().map_or(0, |n| n.len())
            + self.color.as_ref().map_or(0, |n| n.len())
            + self.time_zone.size()
            + std::mem::size_of::<CalendarPreferences>()
    }
}

impl EventPreferences {
    pub fn size(&self) -> usize {
        self.alerts.iter().map(|a| a.size()).sum::<usize>()
            + self.properties.iter().map(|p| p.size()).sum::<usize>()
            + std::mem::size_of::<EventPreferences>()
    }
}

impl ArchivedEventPreferences {
    pub fn size(&self) -> usize {
        self.alerts.iter().map(|a| a.size()).sum::<usize>()
            + self.properties.iter().map(|p| p.size()).sum::<usize>()
            + std::mem::size_of::<EventPreferences>()
    }
}

impl Timezone {
    pub fn size(&self) -> usize {
        match self {
            Timezone::IANA(_) => 2,
            Timezone::Custom(c) => c.size(),
            Timezone::Default => 0,
        }
    }
}

impl ArchivedTimezone {
    pub fn size(&self) -> usize {
        match self {
            ArchivedTimezone::IANA(_) => 2,
            ArchivedTimezone::Custom(c) => c.size(),
            ArchivedTimezone::Default => 0,
        }
    }
}

impl DefaultAlert {
    pub fn size(&self) -> usize {
        std::mem::size_of::<DefaultAlert>() + self.id.len()
    }
}

impl ArchivedDefaultAlert {
    pub fn size(&self) -> usize {
        std::mem::size_of::<DefaultAlert>() + self.id.len()
    }
}

impl CalendarEvent {
    pub fn hashes(&self) -> impl Iterator<Item = u64> {
        self.data
            .event
            .components
            .iter()
            .filter(|e| e.component_type.is_scheduling_object())
            .flat_map(|e| {
                e.entries.iter().filter(|e| {
                    matches!(
                        e.name,
                        ICalendarProperty::Summary
                            | ICalendarProperty::Location
                            | ICalendarProperty::Description
                            | ICalendarProperty::Categories
                            | ICalendarProperty::Comment
                            | ICalendarProperty::Attendee
                            | ICalendarProperty::Organizer
                            | ICalendarProperty::Uid
                    )
                })
            })
            .flat_map(|e| {
                e.values
                    .iter()
                    .filter_map(|v| match v {
                        ICalendarValue::Text(v) => Some(v.as_str()),
                        ICalendarValue::Uri(uri) => uri.as_str(),
                        _ => None,
                    })
                    .chain(e.params.iter().filter_map(|p| match &p.value {
                        ICalendarParameterValue::Text(v) => Some(v.as_str()),
                        ICalendarParameterValue::Uri(uri) => uri.as_str(),
                        _ => None,
                    }))
            })
            .map(|v| xxh3::xxh3_64(v.as_bytes()))
    }
}

impl ArchivedCalendarEvent {
    pub fn hashes(&self) -> impl Iterator<Item = u64> {
        self.data
            .event
            .components
            .iter()
            .filter(|e| e.component_type.is_scheduling_object())
            .flat_map(|e| {
                e.entries.iter().filter(|e| {
                    matches!(
                        e.name,
                        ArchivedICalendarProperty::Summary
                            | ArchivedICalendarProperty::Location
                            | ArchivedICalendarProperty::Description
                            | ArchivedICalendarProperty::Categories
                            | ArchivedICalendarProperty::Comment
                            | ArchivedICalendarProperty::Attendee
                            | ArchivedICalendarProperty::Organizer
                            | ArchivedICalendarProperty::Uid
                    )
                })
            })
            .flat_map(|e| {
                e.values
                    .iter()
                    .filter_map(|v| match v {
                        ArchivedICalendarValue::Text(v) => Some(v.as_str()),
                        ArchivedICalendarValue::Uri(uri) => uri.as_str(),
                        _ => None,
                    })
                    .chain(e.params.iter().filter_map(|p| match &p.value {
                        ArchivedICalendarParameterValue::Text(v) => Some(v.as_str()),
                        ArchivedICalendarParameterValue::Uri(uri) => uri.as_str(),
                        _ => None,
                    }))
            })
            .map(|v| xxh3::xxh3_64(v.as_bytes()))
    }
}

impl ArchivedCalendarEvent {
    pub fn index_document(
        &self,
        account_id: u32,
        document_id: u32,
        index_fields: &AHashSet<SearchField>,
        default_language: Language,
    ) -> IndexDocument {
        let mut document = IndexDocument::new(SearchIndex::Calendar)
            .with_account_id(account_id)
            .with_document_id(document_id);

        if index_fields.is_empty()
            || index_fields.contains(&SearchField::Calendar(CalendarSearchField::Start))
        {
            document.index_integer(CalendarSearchField::Start, self.data.event_range_start());
        }

        let mut detector = LanguageDetector::new();
        for component in self
            .data
            .event
            .components
            .iter()
            .filter(|e| e.component_type.is_scheduling_object())
        {
            for entry in component.entries.iter() {
                let (is_lang, is_keyword, field) = match entry.name {
                    ArchivedICalendarProperty::Summary => (true, false, CalendarSearchField::Title),
                    ArchivedICalendarProperty::Description => {
                        (true, false, CalendarSearchField::Description)
                    }
                    ArchivedICalendarProperty::Location => {
                        (false, false, CalendarSearchField::Location)
                    }
                    ArchivedICalendarProperty::Organizer => {
                        (false, false, CalendarSearchField::Owner)
                    }
                    ArchivedICalendarProperty::Attendee => {
                        (false, false, CalendarSearchField::Attendee)
                    }
                    ArchivedICalendarProperty::Uid => (false, true, CalendarSearchField::Uid),
                    _ => continue,
                };
                let field = SearchField::Calendar(field);

                if index_fields.is_empty() || index_fields.contains(&field) {
                    for value in entry
                        .values
                        .iter()
                        .filter_map(|v| match v {
                            ArchivedICalendarValue::Text(v) => Some(v.as_str()),
                            ArchivedICalendarValue::Uri(uri) => uri.as_str(),
                            _ => None,
                        })
                        .chain(entry.params.iter().filter_map(|p| match &p.value {
                            ArchivedICalendarParameterValue::Text(v) => Some(v.as_str()),
                            ArchivedICalendarParameterValue::Uri(uri) => uri.as_str(),
                            _ => None,
                        }))
                    {
                        let value = value.strip_prefix("mailto:").unwrap_or(value).trim();
                        let lang = if is_lang {
                            detector.detect(value, MIN_LANGUAGE_SCORE);
                            Language::Unknown
                        } else {
                            Language::None
                        };

                        if !is_keyword {
                            document.index_text(field.clone(), value, lang);
                        } else {
                            document.index_keyword(field.clone(), value);
                        }
                    }
                }
            }
        }

        document.set_unknown_language(
            detector
                .most_frequent_language()
                .unwrap_or(default_language),
        );

        document
    }
}
