/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, FileSearchField, SearchField,
        TracingSearchField,
    },
    write::SearchIndex,
};
use ahash::AHashSet;
use deadpool_postgres::Pool;
use nlp::language::Language;

pub mod blob;
pub mod lookup;
pub mod main;
pub mod read;
pub mod search;
pub mod tls;
pub mod write;

pub struct PostgresStore {
    pub(crate) conn_pool: Pool,
    pub(crate) languages: AHashSet<Language>,
}

#[inline(always)]
fn into_error(err: tokio_postgres::error::Error) -> trc::Error {
    let mut local_err = trc::StoreEvent::PostgresqlError.reason(err.to_string());
    if let Some(db_err) = err.as_db_error() {
        local_err = local_err.code(db_err.code().code().to_string());
        if let Some(detail) = db_err.detail() {
            local_err = local_err.details(detail.to_string());
        }

        if let Some(hint) = db_err.hint() {
            local_err = local_err.caused_by(hint.to_string());
        }
    }
    local_err
}

#[inline(always)]
fn into_pool_error(err: deadpool::managed::PoolError<tokio_postgres::Error>) -> trc::Error {
    trc::StoreEvent::PostgresqlError.reason(err)
}

impl SearchIndex {
    pub fn psql_table(&self) -> &'static str {
        match self {
            SearchIndex::Email => "s_email",
            SearchIndex::Calendar => "s_cal",
            SearchIndex::Contacts => "s_card",
            SearchIndex::File => "s_file",
            SearchIndex::Tracing => "s_trace",
            SearchIndex::InMemory => "",
        }
    }
}

trait PsqlSearchField {
    fn column(&self) -> &'static str;
    fn column_type(&self) -> &'static str;
    fn sort_column_type(&self) -> Option<&'static str>;
    fn sort_column(&self) -> Option<&'static str>;
}

impl PsqlSearchField for EmailSearchField {
    fn column(&self) -> &'static str {
        match self {
            EmailSearchField::From => "fadr",
            EmailSearchField::To => "tadr",
            EmailSearchField::Cc => "cc",
            EmailSearchField::Bcc => "bcc",
            EmailSearchField::Subject => "subj",
            EmailSearchField::Body => "body",
            EmailSearchField::Attachment => "atta",
            EmailSearchField::ReceivedAt => "rcvd",
            EmailSearchField::SentAt => "sent",
            EmailSearchField::Size => "size",
            EmailSearchField::HasAttachment => "hatt",
            EmailSearchField::Headers => "hdrs",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            EmailSearchField::ReceivedAt | EmailSearchField::SentAt => "BIGINT",
            EmailSearchField::Size => "INTEGER",
            EmailSearchField::HasAttachment => "BOOLEAN",
            EmailSearchField::Headers => "JSONB",
            _ => "TSVECTOR",
        }
    }

    fn sort_column_type(&self) -> Option<&'static str> {
        match self {
            EmailSearchField::From | EmailSearchField::To | EmailSearchField::Subject => {
                Some("TEXT")
            }
            #[cfg(feature = "test_mode")]
            EmailSearchField::Cc | EmailSearchField::Bcc => Some("TEXT"),
            _ => None,
        }
    }

    fn sort_column(&self) -> Option<&'static str> {
        match self {
            EmailSearchField::From => Some("s_fr"),
            EmailSearchField::To => Some("s_to"),
            EmailSearchField::Subject => Some("s_sj"),
            #[cfg(feature = "test_mode")]
            EmailSearchField::Bcc => Some("s_bc"),
            #[cfg(feature = "test_mode")]
            EmailSearchField::Cc => Some("s_cc"),
            _ => None,
        }
    }
}

impl PsqlSearchField for CalendarSearchField {
    fn column(&self) -> &'static str {
        match self {
            CalendarSearchField::Title => "titl",
            CalendarSearchField::Description => "dscd",
            CalendarSearchField::Location => "locn",
            CalendarSearchField::Owner => "ownr",
            CalendarSearchField::Attendee => "atnd",
            CalendarSearchField::Start => "strt",
            CalendarSearchField::Uid => "uid",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            CalendarSearchField::Start => "BIGINT",
            CalendarSearchField::Uid => "TEXT",
            _ => "TSVECTOR",
        }
    }

    fn sort_column_type(&self) -> Option<&'static str> {
        None
    }

    fn sort_column(&self) -> Option<&'static str> {
        None
    }
}

impl PsqlSearchField for ContactSearchField {
    fn column(&self) -> &'static str {
        match self {
            ContactSearchField::Member => "mmbr",
            ContactSearchField::Name => "name",
            ContactSearchField::Nickname => "nick",
            ContactSearchField::Organization => "orgn",
            ContactSearchField::Email => "eml",
            ContactSearchField::Phone => "phon",
            ContactSearchField::OnlineService => "olsv",
            ContactSearchField::Address => "addr",
            ContactSearchField::Note => "note",
            ContactSearchField::Kind => "kind",
            ContactSearchField::Uid => "uid",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            ContactSearchField::Kind | ContactSearchField::Uid => "TEXT",
            _ => "TSVECTOR",
        }
    }

    fn sort_column_type(&self) -> Option<&'static str> {
        None
    }

    fn sort_column(&self) -> Option<&'static str> {
        None
    }
}

impl PsqlSearchField for FileSearchField {
    fn column(&self) -> &'static str {
        match self {
            FileSearchField::Name => "name",
            FileSearchField::Content => "body",
        }
    }

    fn column_type(&self) -> &'static str {
        "TSVECTOR"
    }

    fn sort_column_type(&self) -> Option<&'static str> {
        None
    }

    fn sort_column(&self) -> Option<&'static str> {
        None
    }
}
impl PsqlSearchField for TracingSearchField {
    fn column(&self) -> &'static str {
        match self {
            TracingSearchField::QueueId => "qid",
            TracingSearchField::EventType => "etyp",
            TracingSearchField::Keywords => "kwds",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            TracingSearchField::EventType => "BIGINT",
            TracingSearchField::QueueId => "BIGINT",
            TracingSearchField::Keywords => "TSVECTOR",
        }
    }

    fn sort_column_type(&self) -> Option<&'static str> {
        None
    }

    fn sort_column(&self) -> Option<&'static str> {
        None
    }
}

impl PsqlSearchField for SearchField {
    fn column(&self) -> &'static str {
        match self {
            SearchField::AccountId => "accid",
            SearchField::DocumentId => "docid",
            SearchField::Id => "id",
            SearchField::Email(field) => field.column(),
            SearchField::Calendar(field) => field.column(),
            SearchField::Contact(field) => field.column(),
            SearchField::File(field) => field.column(),
            SearchField::Tracing(field) => field.column(),
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            SearchField::AccountId => "INTEGER NOT NULL",
            SearchField::DocumentId => "INTEGER NOT NULL",
            SearchField::Id => "BIGINT NOT NULL",
            SearchField::Email(field) => field.column_type(),
            SearchField::Calendar(field) => field.column_type(),
            SearchField::Contact(field) => field.column_type(),
            SearchField::File(field) => field.column_type(),
            SearchField::Tracing(field) => field.column_type(),
        }
    }

    fn sort_column_type(&self) -> Option<&'static str> {
        match self {
            SearchField::Email(field) => field.sort_column_type(),
            SearchField::Calendar(field) => field.sort_column_type(),
            SearchField::Contact(field) => field.sort_column_type(),
            SearchField::File(field) => field.sort_column_type(),
            SearchField::Tracing(field) => field.sort_column_type(),
            SearchField::AccountId | SearchField::DocumentId | SearchField::Id => None,
        }
    }

    fn sort_column(&self) -> Option<&'static str> {
        match self {
            SearchField::Email(field) => field.sort_column(),
            SearchField::Calendar(field) => field.sort_column(),
            SearchField::Contact(field) => field.sort_column(),
            SearchField::File(field) => field.sort_column(),
            SearchField::Tracing(field) => field.sort_column(),
            SearchField::AccountId | SearchField::DocumentId | SearchField::Id => None,
        }
    }
}
