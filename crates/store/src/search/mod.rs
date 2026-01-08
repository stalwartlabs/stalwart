/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bm_u32;
pub mod bm_u64;
pub mod document;
pub mod fields;
pub mod index;
pub mod local;
pub mod query;
pub mod split;
pub mod term;

use crate::write::SearchIndex;
use ahash::AHashMap;
use nlp::language::Language;
use roaring::RoaringBitmap;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::fmt::Display;
use std::ops::{BitAndAssign, BitOrAssign, BitXorAssign};
use utils::config::utils::ParseValue;
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchOperator {
    LowerThan,
    LowerEqualThan,
    GreaterThan,
    GreaterEqualThan,
    Equal,
    Contains,
}

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
    ReceivedAt,
    SentAt,
    Size,
    HasAttachment,
    Headers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CalendarSearchField {
    Title,
    Description,
    Location,
    Owner,
    Attendee,
    Start,
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

pub trait SearchDocumentId: Sized + Copy + Display {
    fn from_u64(id: u64) -> Self;
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
    Operator {
        field: SearchField,
        op: SearchOperator,
        value: SearchValue,
    },
    DocumentSet(RoaringBitmap),
    And,
    Or,
    Not,
    #[default]
    End,
}

#[derive(Debug)]
pub enum SearchComparator {
    Field {
        field: SearchField,
        ascending: bool,
    },
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

impl SearchDocumentId for u32 {
    fn from_u64(id: u64) -> Self {
        id as u32
    }

    fn field() -> SearchField {
        SearchField::DocumentId
    }
}

impl SearchDocumentId for u64 {
    fn from_u64(id: u64) -> Self {
        id
    }

    fn field() -> SearchField {
        SearchField::Id
    }
}

pub trait SearchableField: Sized {
    fn index() -> SearchIndex;
    fn primary_keys() -> &'static [SearchField];
    fn all_fields() -> &'static [SearchField];
    fn is_indexed(&self) -> bool;
    fn is_text(&self) -> bool;
}

impl ParseValue for SearchField {
    fn parse_value(value: &str) -> utils::config::Result<Self> {
        Ok(match value {
            // Email
            "email-from" => Self::Email(EmailSearchField::From),
            "email-to" => Self::Email(EmailSearchField::To),
            "email-cc" => Self::Email(EmailSearchField::Cc),
            "email-bcc" => Self::Email(EmailSearchField::Bcc),
            "email-subject" => Self::Email(EmailSearchField::Subject),
            "email-body" => Self::Email(EmailSearchField::Body),
            "email-attachment" => Self::Email(EmailSearchField::Attachment),
            "email-received-at" => Self::Email(EmailSearchField::ReceivedAt),
            "email-sent-at" => Self::Email(EmailSearchField::SentAt),
            "email-size" => Self::Email(EmailSearchField::Size),
            "email-has-attachment" => Self::Email(EmailSearchField::HasAttachment),
            "email-headers" => Self::Email(EmailSearchField::Headers),

            // Calendar
            "cal-title" => Self::Calendar(CalendarSearchField::Title),
            "cal-desc" => Self::Calendar(CalendarSearchField::Description),
            "cal-location" => Self::Calendar(CalendarSearchField::Location),
            "cal-owner" => Self::Calendar(CalendarSearchField::Owner),
            "cal-attendee" => Self::Calendar(CalendarSearchField::Attendee),
            "cal-start" => Self::Calendar(CalendarSearchField::Start),
            "cal-uid" => Self::Calendar(CalendarSearchField::Uid),

            // Contact
            "contact-member" => Self::Contact(ContactSearchField::Member),
            "contact-kind" => Self::Contact(ContactSearchField::Kind),
            "contact-name" => Self::Contact(ContactSearchField::Name),
            "contact-nickname" => Self::Contact(ContactSearchField::Nickname),
            "contact-org" => Self::Contact(ContactSearchField::Organization),
            "contact-email" => Self::Contact(ContactSearchField::Email),
            "contact-phone" => Self::Contact(ContactSearchField::Phone),
            "contact-online-service" => Self::Contact(ContactSearchField::OnlineService),
            "contact-address" => Self::Contact(ContactSearchField::Address),
            "contact-note" => Self::Contact(ContactSearchField::Note),
            "contact-uid" => Self::Contact(ContactSearchField::Uid),

            // File
            "file-name" => Self::File(FileSearchField::Name),
            "file-content" => Self::File(FileSearchField::Content),

            // Tracing
            "trace-event-type" => Self::Tracing(TracingSearchField::EventType),
            "trace-queue-id" => Self::Tracing(TracingSearchField::QueueId),
            "trace-keywords" => Self::Tracing(TracingSearchField::Keywords),

            _ => return Err(format!("Unknown search field: {value}")),
        })
    }
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
                EmailSearchField::ReceivedAt => "rcvd",
                EmailSearchField::SentAt => "sent",
                EmailSearchField::Size => "size",
                EmailSearchField::HasAttachment => "has_att",
                EmailSearchField::Headers => "headers",
            },
            SearchField::Calendar(field) => match field {
                CalendarSearchField::Title => "title",
                CalendarSearchField::Description => "desc",
                CalendarSearchField::Location => "loc",
                CalendarSearchField::Owner => "owner",
                CalendarSearchField::Attendee => "attendee",
                CalendarSearchField::Start => "start",
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
