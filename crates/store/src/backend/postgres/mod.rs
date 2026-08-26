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
use tokio_postgres::error::SqlState;

pub mod blob;
pub mod lookup;
pub mod main;
pub mod read;
pub mod search;
pub mod tls;
pub mod write;

pub struct PostgresStore {
    pub(crate) conn_pool: Pool,
    pub(crate) ts_configs: AHashSet<&'static str>,
}

#[inline(always)]
fn into_error(err: tokio_postgres::error::Error) -> trc::Error {
    let mut local_err = trc::StoreEvent::PostgresqlError.reason(error_chain(&err));
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

fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let cause_message = cause.to_string();
        if !cause_message.is_empty() && !message.ends_with(&cause_message) {
            message.push_str(": ");
            message.push_str(&cause_message);
        }
        source = cause.source();
    }
    message
}

pub(crate) const DELETE_CHUNK_SIZE: usize = 1000;
pub(crate) const MIN_DELETE_CHUNK_SIZE: usize = 10;

#[inline(always)]
pub(crate) fn is_timeout_error(err: &tokio_postgres::Error) -> bool {
    err.code().is_some_and(|code| {
        *code == SqlState::QUERY_CANCELED
            || *code == SqlState::IDLE_IN_TRANSACTION_SESSION_TIMEOUT
            || *code == SqlState::LOCK_NOT_AVAILABLE
    })
}

#[inline(always)]
fn into_pool_error(err: deadpool_postgres::PoolError) -> trc::Error {
    match err {
        deadpool_postgres::PoolError::Backend(err) => into_error(err),
        err => trc::StoreEvent::PostgresqlError.reason(error_chain(&err)),
    }
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
            EmailSearchField::Headers => "hdrs",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            EmailSearchField::Headers => "JSONB",
            _ => "TSVECTOR",
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
        }
    }

    fn column_type(&self) -> &'static str {
        "TSVECTOR"
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
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            ContactSearchField::Kind => "TEXT",
            _ => "TSVECTOR",
        }
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
}
