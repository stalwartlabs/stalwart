/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendar, ArchivedCalendarEvent, ArchivedCalendarPreferences, ArchivedDefaultAlert,
    ArchivedTimezone, Calendar, CalendarEvent, CalendarPreferences, DefaultAlert, Timezone,
};
use crate::{
    MetaHasher, SizeWriter,
    calendar::{
        ArchivedCalendarEventContent, ArchivedCalendarEventNotification,
        ArchivedCalendarEventNotificationContent, ArchivedChangedBy, ArchivedEventPreferences,
        CalendarEventContent, CalendarEventNotification, CalendarEventNotificationContent,
        ChangedBy, EVENT_HAS_ALARMS, EVENT_HAS_DEAD_PROPERTIES, EventPreferences,
    },
    strip_mailto_scheme,
};
use ahash::AHashSet;
use calcard::icalendar::{
    ArchivedICalendarParameterValue, ArchivedICalendarProperty, ArchivedICalendarValue,
    ICalendarParameterValue, ICalendarProperty, ICalendarValue,
};
use common::storage::index::{
    ArchivedSplitObject, IndexValue, IndexableAndSerializableObject, IndexableObject,
    SEARCH_HASH_UNCHANGED, SerializableObject, SplitObject, serialize_object,
};
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use store::{
    U32_LEN,
    search::{CalendarSearchField, IndexDocument, SearchField},
    write::{ArchiveCompression, BatchBuilder, Compression, Dictionary, SearchIndex, Slot},
    xxhash_rust::xxh3,
};
use types::{
    acl::AclGrant,
    collection::SyncCollection,
    field::{CalendarEventField, CalendarNotificationField, Field},
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

impl SerializableObject for Calendar {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        serialize_object(self, batch, pending_id)
    }
}

impl IndexableObject for CalendarEvent {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::SearchIndex {
                index: SearchIndex::Calendar,
                hash: SEARCH_HASH_UNCHANGED,
            },
            IndexValue::Index {
                field: CalendarEventField::Uid.into(),
                value: self.uid.as_str().into(),
            },
            IndexValue::Quota { used: self.size },
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
        self.meta_index_values().into_iter()
    }
}

impl IndexableAndSerializableObject for CalendarEvent {
    fn is_versioned() -> bool {
        true
    }

    fn set_pending_id(&mut self, document_id: u32) {
        self.names
            .last_mut()
            .expect("a pending calendar id requires a name")
            .parent_id = document_id;
    }

    fn size_hint(&self) -> usize {
        self.meta_size_hint()
    }
}

impl SplitObject for CalendarEvent {
    type Content = CalendarEventContent;
    type Context = ();

    const CONTENT_FIELD: Field = CalendarEventField::Content.field();

    fn meta_hash(&self) -> u32 {
        let mut hasher = MetaHasher::new();
        hasher.u32(self.names.len() as u32);
        for name in &self.names {
            hasher.str(&name.name).u32(name.parent_id);
        }
        hasher
            .str(&self.uid)
            .opt_str(self.display_name.as_deref())
            .i64(self.start)
            .u32(self.duration)
            .i64(self.created)
            .i64(self.modified)
            .u32(self.size)
            .u16(self.flags)
            .opt_u32(self.schedule_tag)
            .finish()
    }

    fn set_etag(&mut self, etag: u32) {
        self.etag = etag;
    }

    fn etag_value(&self) -> u32 {
        self.etag
    }

    fn refresh_from_content(&mut self, content: &CalendarEventContent, _ctx: ()) {
        self.uid = content
            .data
            .event
            .uids()
            .next()
            .unwrap_or_default()
            .to_string();
        let (start, duration) = content.data.event_range().unwrap_or_default();
        self.start = start;
        self.duration = duration;
        self.size = SizeWriter::ical(&content.data.event) as u32;
        if content.dead_properties.is_empty() {
            self.flags &= !EVENT_HAS_DEAD_PROPERTIES;
        } else {
            self.flags |= EVENT_HAS_DEAD_PROPERTIES;
        }
        if content.data.alarms.is_empty() {
            self.flags &= !EVENT_HAS_ALARMS;
        } else {
            self.flags |= EVENT_HAS_ALARMS;
        }
    }

    fn full_index_values<'x>(&'x self, content: &'x CalendarEventContent) -> Vec<IndexValue<'x>> {
        vec![
            IndexValue::SearchIndex {
                index: SearchIndex::Calendar,
                hash: content
                    .hashes()
                    .chain([content.data.event_range_start() as u64])
                    .fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Index {
                field: CalendarEventField::Uid.into(),
                value: self.uid.as_str().into(),
            },
            IndexValue::Quota { used: self.size },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Calendar,
                prefix: None,
            },
        ]
    }
}

impl ArchivedSplitObject for ArchivedCalendarEvent {
    type ArchivedContent = ArchivedCalendarEventContent;

    const CONTENT_FIELD: Field = CalendarEventField::Content.field();

    fn meta_hash(&self) -> u32 {
        let mut hasher = MetaHasher::new();
        hasher.u32(self.names.len() as u32);
        for name in self.names.iter() {
            hasher.str(&name.name).u32(name.parent_id.to_native());
        }
        hasher
            .str(&self.uid)
            .opt_str(self.display_name.as_deref())
            .i64(self.start.to_native())
            .u32(self.duration.to_native())
            .i64(self.created.to_native())
            .i64(self.modified.to_native())
            .u32(self.size.to_native())
            .u16(self.flags.to_native())
            .opt_u32(self.schedule_tag.as_ref().map(|tag| tag.to_native()))
            .finish()
    }

    fn etag(&self) -> u32 {
        self.etag.to_native()
    }

    fn meta_index_values(&self) -> Vec<IndexValue<'_>> {
        vec![
            IndexValue::SearchIndex {
                index: SearchIndex::Calendar,
                hash: SEARCH_HASH_UNCHANGED,
            },
            IndexValue::Index {
                field: CalendarEventField::Uid.into(),
                value: self.uid.as_str().into(),
            },
            IndexValue::Quota {
                used: self.size.to_native(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Calendar,
                prefix: None,
            },
        ]
    }

    fn full_index_values<'x>(
        &'x self,
        content: &'x ArchivedCalendarEventContent,
    ) -> Vec<IndexValue<'x>> {
        vec![
            IndexValue::SearchIndex {
                index: SearchIndex::Calendar,
                hash: content
                    .hashes()
                    .chain([content.data.event_range_start() as u64])
                    .fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Index {
                field: CalendarEventField::Uid.into(),
                value: self.uid.as_str().into(),
            },
            IndexValue::Quota {
                used: self.size.to_native(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Calendar,
                prefix: None,
            },
        ]
    }
}

impl IndexableObject for CalendarEventNotification {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Quota { used: self.size },
            IndexValue::Index {
                field: CalendarNotificationField::Created.into(),
                value: self.created.into(),
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
        self.meta_index_values().into_iter()
    }
}

impl IndexableAndSerializableObject for CalendarEventNotification {
    fn is_versioned() -> bool {
        false
    }

    fn set_pending_id(&mut self, document_id: u32) {
        self.event_id = Some(document_id);
    }

    fn size_hint(&self) -> usize {
        self.meta_size_hint()
    }
}

impl SplitObject for CalendarEventNotification {
    type Content = CalendarEventNotificationContent;
    type Context = ();

    const CONTENT_FIELD: Field = CalendarNotificationField::Content.field();

    fn meta_hash(&self) -> u32 {
        let mut hasher = MetaHasher::new();
        match &self.changed_by {
            ChangedBy::PrincipalId(id) => {
                hasher.u16(0).u32(*id);
            }
            ChangedBy::CalendarAddress(address) => {
                hasher.u16(1).str(address);
            }
        }
        hasher
            .opt_u32(self.event_id)
            .i64(self.created)
            .i64(self.modified)
            .u32(self.size)
            .u16(self.flags)
            .finish()
    }

    fn set_etag(&mut self, etag: u32) {
        self.etag = etag;
    }

    fn etag_value(&self) -> u32 {
        self.etag
    }

    fn refresh_from_content(&mut self, content: &CalendarEventNotificationContent, _ctx: ()) {
        self.size = SizeWriter::ical(&content.event) as u32;
    }

    fn full_index_values<'x>(
        &'x self,
        _content: &'x CalendarEventNotificationContent,
    ) -> Vec<IndexValue<'x>> {
        self.index_values().collect()
    }
}

impl ArchivedSplitObject for ArchivedCalendarEventNotification {
    type ArchivedContent = ArchivedCalendarEventNotificationContent;

    const CONTENT_FIELD: Field = CalendarNotificationField::Content.field();

    fn meta_hash(&self) -> u32 {
        let mut hasher = MetaHasher::new();
        match &self.changed_by {
            ArchivedChangedBy::PrincipalId(id) => {
                hasher.u16(0).u32(id.to_native());
            }
            ArchivedChangedBy::CalendarAddress(address) => {
                hasher.u16(1).str(address);
            }
        }
        hasher
            .opt_u32(self.event_id.as_ref().map(|id| id.to_native()))
            .i64(self.created.to_native())
            .i64(self.modified.to_native())
            .u32(self.size.to_native())
            .u16(self.flags.to_native())
            .finish()
    }

    fn etag(&self) -> u32 {
        self.etag.to_native()
    }

    fn meta_index_values(&self) -> Vec<IndexValue<'_>> {
        vec![
            IndexValue::Quota {
                used: self.size.to_native(),
            },
            IndexValue::Index {
                field: CalendarNotificationField::Created.into(),
                value: self.created.to_native().into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::CalendarEventNotification,
                prefix: None,
            },
        ]
    }

    fn full_index_values<'x>(
        &'x self,
        _content: &'x ArchivedCalendarEventNotificationContent,
    ) -> Vec<IndexValue<'x>> {
        self.meta_index_values()
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
    pub fn meta_size_hint(&self) -> usize {
        self.uid.len()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.names.iter().map(|n| n.name.len()).sum::<usize>()
            + std::mem::size_of::<CalendarEvent>()
    }
}

impl ArchivedCalendarEvent {
    pub fn event_range_end(&self) -> i64 {
        self.start.to_native() + self.duration.to_native() as i64
    }

    pub fn meta_size_hint(&self) -> usize {
        self.uid.len()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.names.iter().map(|n| n.name.len()).sum::<usize>()
            + std::mem::size_of::<CalendarEvent>()
    }
}

impl CalendarEventNotification {
    pub fn meta_size_hint(&self) -> usize {
        (match &self.changed_by {
            ChangedBy::PrincipalId(_) => U32_LEN,
            ChangedBy::CalendarAddress(v) => v.len(),
        }) + std::mem::size_of::<CalendarEventNotification>()
    }
}

impl ArchivedCalendarEventNotification {
    pub fn meta_size_hint(&self) -> usize {
        (match &self.changed_by {
            ArchivedChangedBy::PrincipalId(_) => U32_LEN,
            ArchivedChangedBy::CalendarAddress(v) => v.len(),
        }) + std::mem::size_of::<CalendarEventNotification>()
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

impl CalendarEventContent {
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

impl ArchivedCalendarEventContent {
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

impl ArchivedCalendarEventContent {
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
                        let value = strip_mailto_scheme(value);
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

impl ArchiveCompression for Calendar {
    const COMPRESSION: Compression = Compression::None;
}

impl ArchiveCompression for CalendarEvent {
    const COMPRESSION: Compression = Compression::None;
}

impl ArchiveCompression for CalendarEventContent {
    const COMPRESSION: Compression = Compression::Zstd(Some(Dictionary::Calendar));
}

impl ArchiveCompression for CalendarEventNotification {
    const COMPRESSION: Compression = Compression::None;
}

impl ArchiveCompression for CalendarEventNotificationContent {
    const COMPRESSION: Compression = Compression::Zstd(Some(Dictionary::Calendar));
}
