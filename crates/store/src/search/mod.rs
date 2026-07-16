/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod document;
pub mod fields;
pub mod index;
pub mod local;
pub mod query;
pub mod split;

use crate::write::SearchIndex;
use ahash::AHashMap;
use nlp::language::Language;
use roaring::{RoaringBitmap, RoaringTreemap};
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::ops::{BitAndAssign, BitOrAssign, BitXorAssign};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SearchField {
    AccountId,
    DocumentId,
    Id,
    Email(EmailSearchField),
    Calendar(CalendarSearchField),
    Contact(ContactSearchField),
    File(FileSearchField),
    Tracing(TracingSearchField),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EmailSearchField {
    From,
    To,
    Cc,
    Bcc,
    Subject,
    Body,
    Attachment,
    Headers,
    _ReceivedAt,
    _SentAt,
    _Size,
    _HasAttachment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CalendarSearchField {
    Title,
    Description,
    Location,
    Owner,
    Attendee,
    Uid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContactSearchField {
    Member,
    Kind,
    Name,
    Nickname,
    Organization,
    Email,
    Phone,
    OnlineService,
    Address,
    Note,
    Uid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileSearchField {
    Name,
    Content,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TracingSearchField {
    EventType,
    QueueId,
    Keywords,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchValue {
    Text { value: String, language: Language },
    KeyValues(VecMap<String, String>),
    Int(i64),
    Uint(u64),
    Boolean(bool),
}

pub trait SearchResults: Sized + Default {
    fn insert(&mut self, id: u64);
    fn field() -> SearchField;
}

#[derive(Debug)]
pub struct SearchQuery {
    pub(crate) index: SearchIndex,
    pub(crate) filters: Vec<SearchFilter>,
    pub(crate) comparators: Vec<SearchComparator>,
    pub(crate) mask: RoaringBitmap,
}

#[derive(Debug, PartialEq, Clone, Default)]
pub enum SearchFilter {
    Text {
        field: SearchField,
        op: TextMatch,
        value: String,
        language: Language,
    },
    Integer {
        field: SearchField,
        op: Ordering,
        value: u64,
    },
    KeyValue {
        field: SearchField,
        key: String,
        op: KeyValueMatch,
    },
    DocumentSet(RoaringBitmap),
    And,
    Or,
    Not,
    #[default]
    End,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TextMatch {
    Keyword,
    Prefix,
    Phrase,
}

#[derive(Debug, PartialEq, Clone)]
pub enum KeyValueMatch {
    Equals(String),
    Contains(String),
    Exists,
}

#[derive(Debug)]
pub enum SearchComparator {
    DocumentSet {
        set: RoaringBitmap,
        ascending: bool,
    },
    SortedSet {
        set: AHashMap<u32, u32>,
        ascending: bool,
    },
}

#[derive(Debug)]
pub struct IndexDocument {
    pub(crate) index: SearchIndex,
    pub(crate) fields: AHashMap<SearchField, SearchValue>,
}

#[derive(Debug)]
pub struct QueryResults {
    results: RoaringBitmap,
    comparators: Vec<SearchComparator>,
}

impl From<EmailSearchField> for SearchField {
    fn from(field: EmailSearchField) -> Self {
        SearchField::Email(field)
    }
}

impl From<CalendarSearchField> for SearchField {
    fn from(field: CalendarSearchField) -> Self {
        SearchField::Calendar(field)
    }
}

impl From<ContactSearchField> for SearchField {
    fn from(field: ContactSearchField) -> Self {
        SearchField::Contact(field)
    }
}

impl From<FileSearchField> for SearchField {
    fn from(field: FileSearchField) -> Self {
        SearchField::File(field)
    }
}

impl From<TracingSearchField> for SearchField {
    fn from(field: TracingSearchField) -> Self {
        SearchField::Tracing(field)
    }
}

impl From<u64> for SearchValue {
    fn from(value: u64) -> Self {
        SearchValue::Uint(value)
    }
}

impl From<i64> for SearchValue {
    fn from(value: i64) -> Self {
        SearchValue::Int(value)
    }
}

impl From<u32> for SearchValue {
    fn from(value: u32) -> Self {
        SearchValue::Uint(value as u64)
    }
}

impl From<i32> for SearchValue {
    fn from(value: i32) -> Self {
        SearchValue::Int(value as i64)
    }
}

impl From<usize> for SearchValue {
    fn from(value: usize) -> Self {
        SearchValue::Uint(value as u64)
    }
}

impl From<bool> for SearchValue {
    fn from(value: bool) -> Self {
        SearchValue::Boolean(value)
    }
}

impl From<String> for SearchValue {
    fn from(value: String) -> Self {
        SearchValue::Text {
            value,
            language: Language::None,
        }
    }
}

impl SearchResults for RoaringBitmap {
    fn field() -> SearchField {
        SearchField::DocumentId
    }

    fn insert(&mut self, id: u64) {
        self.insert(id as u32);
    }
}

impl SearchResults for RoaringTreemap {
    fn field() -> SearchField {
        SearchField::Id
    }

    fn insert(&mut self, id: u64) {
        self.insert(id);
    }
}

pub trait SearchableField: Sized {
    fn index() -> SearchIndex;
    fn primary_keys() -> &'static [SearchField];
    fn all_fields() -> &'static [SearchField];
    fn is_indexed(&self) -> bool;
    fn is_text(&self) -> bool;
}

impl Eq for SearchFilter {}

impl SearchIndex {
    pub fn index_name(&self) -> &'static str {
        match self {
            SearchIndex::Email => "st_email",
            SearchIndex::Calendar => "st_calendar",
            SearchIndex::Contacts => "st_contact",
            SearchIndex::File => "st_file",
            SearchIndex::Tracing => "st_tracing",
            SearchIndex::InMemory => unreachable!(),
        }
    }
}

impl SearchIndex {
    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            SearchIndex::Email => 0,
            SearchIndex::Calendar => 1,
            SearchIndex::Contacts => 2,
            SearchIndex::File => 3,
            SearchIndex::Tracing => 4,
            SearchIndex::InMemory => unreachable!(),
        }
    }
}

impl SearchField {
    pub(crate) fn u8_id(&self) -> u8 {
        match self {
            SearchField::AccountId => 0,
            SearchField::DocumentId => 1,
            SearchField::Id => 2,
            SearchField::Email(field) => match field {
                EmailSearchField::From => 3,
                EmailSearchField::To => 4,
                EmailSearchField::Cc => 5,
                EmailSearchField::Bcc => 6,
                EmailSearchField::Subject => 7,
                EmailSearchField::Body => 8,
                EmailSearchField::Attachment => 9,
                EmailSearchField::_ReceivedAt => 10,
                EmailSearchField::_SentAt => 11,
                EmailSearchField::_Size => 12,
                EmailSearchField::_HasAttachment => 13,
                EmailSearchField::Headers => 14,
            },
            SearchField::Calendar(field) => match field {
                CalendarSearchField::Title => 3,
                CalendarSearchField::Description => 4,
                CalendarSearchField::Location => 5,
                CalendarSearchField::Owner => 6,
                CalendarSearchField::Attendee => 7,
                CalendarSearchField::Uid => 9,
            },
            SearchField::Contact(field) => match field {
                ContactSearchField::Member => 3,
                ContactSearchField::Kind => 4,
                ContactSearchField::Name => 5,
                ContactSearchField::Nickname => 6,
                ContactSearchField::Organization => 7,
                ContactSearchField::Email => 8,
                ContactSearchField::Phone => 9,
                ContactSearchField::OnlineService => 10,
                ContactSearchField::Address => 11,
                ContactSearchField::Note => 12,
                ContactSearchField::Uid => 13,
            },
            SearchField::File(field) => match field {
                FileSearchField::Name => 3,
                FileSearchField::Content => 4,
            },
            SearchField::Tracing(field) => match field {
                TracingSearchField::EventType => 3,
                TracingSearchField::QueueId => 4,
                TracingSearchField::Keywords => 5,
            },
        }
    }
}

impl SearchField {
    pub fn field_name(&self) -> &'static str {
        match self {
            SearchField::AccountId => "acc_id",
            SearchField::DocumentId => "doc_id",
            SearchField::Id => "id",
            SearchField::Email(field) => match field {
                EmailSearchField::From => "from",
                EmailSearchField::To => "to",
                EmailSearchField::Cc => "cc",
                EmailSearchField::Bcc => "bcc",
                EmailSearchField::Subject => "subj",
                EmailSearchField::Body => "body",
                EmailSearchField::Attachment => "attach",
                EmailSearchField::_ReceivedAt => "rcvd",
                EmailSearchField::_SentAt => "sent",
                EmailSearchField::_Size => "size",
                EmailSearchField::_HasAttachment => "has_att",
                EmailSearchField::Headers => "headers",
            },
            SearchField::Calendar(field) => match field {
                CalendarSearchField::Title => "title",
                CalendarSearchField::Description => "desc",
                CalendarSearchField::Location => "loc",
                CalendarSearchField::Owner => "owner",
                CalendarSearchField::Attendee => "attendee",
                CalendarSearchField::Uid => "uid",
            },
            SearchField::Contact(field) => match field {
                ContactSearchField::Member => "member",
                ContactSearchField::Kind => "kind",
                ContactSearchField::Name => "name",
                ContactSearchField::Nickname => "nick",
                ContactSearchField::Organization => "org",
                ContactSearchField::Email => "email",
                ContactSearchField::Phone => "phone",
                ContactSearchField::OnlineService => "online",
                ContactSearchField::Address => "addr",
                ContactSearchField::Note => "note",
                ContactSearchField::Uid => "uid",
            },
            SearchField::File(field) => match field {
                FileSearchField::Name => "name",
                FileSearchField::Content => "content",
            },
            SearchField::Tracing(field) => match field {
                TracingSearchField::EventType => "ev_type",
                TracingSearchField::QueueId => "queue_id",
                TracingSearchField::Keywords => "keywords",
            },
        }
    }
}
