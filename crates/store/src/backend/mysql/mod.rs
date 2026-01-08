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
use mysql_async::Pool;
use std::fmt::Display;

pub mod blob;
pub mod lookup;
pub mod main;
pub mod read;
pub mod search;
pub mod write;

pub struct MysqlStore {
    pub(crate) conn_pool: Pool,
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::MysqlError.reason(err)
}

impl SearchIndex {
    pub fn mysql_table(&self) -> &'static str {
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

trait MysqlSearchField {
    fn column(&self) -> &'static str;
    fn column_type(&self) -> &'static str;
}

impl MysqlSearchField for EmailSearchField {
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
            EmailSearchField::Size => "INT",
            EmailSearchField::HasAttachment => "BOOLEAN",
            EmailSearchField::Headers => "JSON",
            EmailSearchField::From => "TEXT",
            EmailSearchField::To => "TEXT",
            EmailSearchField::Cc => "TEXT",
            EmailSearchField::Bcc => "TEXT",
            EmailSearchField::Subject => "TEXT",
            EmailSearchField::Body => "MEDIUMTEXT",
            EmailSearchField::Attachment => "MEDIUMTEXT",
        }
    }
}

impl MysqlSearchField for CalendarSearchField {
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
            CalendarSearchField::Start => "BIGINT NOT NULL",
            _ => "TEXT",
        }
    }
}

impl MysqlSearchField for ContactSearchField {
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
            _ => "TEXT",
        }
    }
}

impl MysqlSearchField for FileSearchField {
    fn column(&self) -> &'static str {
        match self {
            FileSearchField::Name => "name",
            FileSearchField::Content => "body",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            FileSearchField::Name => "TEXT",
            FileSearchField::Content => "MEDIUMTEXT",
        }
    }
}
impl MysqlSearchField for TracingSearchField {
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
            TracingSearchField::Keywords => "TEXT",
        }
    }
}

impl MysqlSearchField for SearchField {
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
            SearchField::AccountId => "INT NOT NULL",
            SearchField::DocumentId => "INT NOT NULL",
            SearchField::Id => "BIGINT NOT NULL",
            SearchField::Email(field) => field.column_type(),
            SearchField::Calendar(field) => field.column_type(),
            SearchField::Contact(field) => field.column_type(),
            SearchField::File(field) => field.column_type(),
            SearchField::Tracing(field) => field.column_type(),
        }
    }
}
