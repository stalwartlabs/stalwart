/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::search::*;

impl SearchableField for EmailSearchField {
    fn index() -> SearchIndex {
        SearchIndex::Email
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::AccountId, SearchField::DocumentId]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::Email(EmailSearchField::From),
            SearchField::Email(EmailSearchField::To),
            SearchField::Email(EmailSearchField::Cc),
            SearchField::Email(EmailSearchField::Bcc),
            SearchField::Email(EmailSearchField::Subject),
            SearchField::Email(EmailSearchField::Body),
            SearchField::Email(EmailSearchField::Attachment),
            SearchField::Email(EmailSearchField::ReceivedAt),
            SearchField::Email(EmailSearchField::SentAt),
            SearchField::Email(EmailSearchField::Size),
            SearchField::Email(EmailSearchField::HasAttachment),
            SearchField::Email(EmailSearchField::Headers),
        ]
    }

    fn is_indexed(&self) -> bool {
        #[cfg(not(feature = "test_mode"))]
        {
            matches!(
                self,
                EmailSearchField::From
                    | EmailSearchField::To
                    | EmailSearchField::Subject
                    | EmailSearchField::ReceivedAt
                    | EmailSearchField::SentAt
                    | EmailSearchField::Size
                    | EmailSearchField::HasAttachment,
            )
        }

        #[cfg(feature = "test_mode")]
        {
            matches!(
                self,
                EmailSearchField::From
                    | EmailSearchField::To
                    | EmailSearchField::Subject
                    | EmailSearchField::ReceivedAt
                    | EmailSearchField::SentAt
                    | EmailSearchField::Size
                    | EmailSearchField::HasAttachment
                    | EmailSearchField::Bcc
                    | EmailSearchField::Cc
            )
        }
    }

    fn is_text(&self) -> bool {
        matches!(
            self,
            EmailSearchField::From
                | EmailSearchField::To
                | EmailSearchField::Cc
                | EmailSearchField::Bcc
                | EmailSearchField::Subject
                | EmailSearchField::Body
                | EmailSearchField::Attachment,
        )
    }
}

impl SearchableField for CalendarSearchField {
    fn index() -> SearchIndex {
        SearchIndex::Calendar
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::AccountId, SearchField::DocumentId]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::Calendar(CalendarSearchField::Title),
            SearchField::Calendar(CalendarSearchField::Description),
            SearchField::Calendar(CalendarSearchField::Location),
            SearchField::Calendar(CalendarSearchField::Owner),
            SearchField::Calendar(CalendarSearchField::Attendee),
            SearchField::Calendar(CalendarSearchField::Start),
            SearchField::Calendar(CalendarSearchField::Uid),
        ]
    }

    fn is_indexed(&self) -> bool {
        matches!(self, CalendarSearchField::Start | CalendarSearchField::Uid)
    }

    fn is_text(&self) -> bool {
        !self.is_indexed()
    }
}

impl SearchableField for ContactSearchField {
    fn index() -> SearchIndex {
        SearchIndex::Contacts
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::AccountId, SearchField::DocumentId]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::Contact(ContactSearchField::Member),
            SearchField::Contact(ContactSearchField::Kind),
            SearchField::Contact(ContactSearchField::Name),
            SearchField::Contact(ContactSearchField::Nickname),
            SearchField::Contact(ContactSearchField::Organization),
            SearchField::Contact(ContactSearchField::Email),
            SearchField::Contact(ContactSearchField::Phone),
            SearchField::Contact(ContactSearchField::OnlineService),
            SearchField::Contact(ContactSearchField::Address),
            SearchField::Contact(ContactSearchField::Note),
            SearchField::Contact(ContactSearchField::Uid),
        ]
    }

    fn is_indexed(&self) -> bool {
        matches!(self, ContactSearchField::Uid | ContactSearchField::Kind)
    }

    fn is_text(&self) -> bool {
        !self.is_indexed()
    }
}

impl SearchableField for FileSearchField {
    fn index() -> SearchIndex {
        SearchIndex::File
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::AccountId, SearchField::DocumentId]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::File(FileSearchField::Name),
            SearchField::File(FileSearchField::Content),
        ]
    }

    fn is_indexed(&self) -> bool {
        false
    }

    fn is_text(&self) -> bool {
        true
    }
}

impl SearchableField for TracingSearchField {
    fn index() -> SearchIndex {
        SearchIndex::Tracing
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::Id]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::Tracing(TracingSearchField::EventType),
            SearchField::Tracing(TracingSearchField::QueueId),
            SearchField::Tracing(TracingSearchField::Keywords),
        ]
    }

    fn is_indexed(&self) -> bool {
        matches!(
            self,
            TracingSearchField::QueueId | TracingSearchField::EventType
        )
    }

    fn is_text(&self) -> bool {
        matches!(self, TracingSearchField::Keywords)
    }
}

impl SearchField {
    pub(crate) fn is_indexed(&self) -> bool {
        match self {
            SearchField::Email(field) => field.is_indexed(),
            SearchField::Calendar(field) => field.is_indexed(),
            SearchField::Contact(field) => field.is_indexed(),
            SearchField::File(field) => field.is_indexed(),
            SearchField::Tracing(field) => field.is_indexed(),
            SearchField::AccountId | SearchField::DocumentId | SearchField::Id => false,
        }
    }

    pub(crate) fn is_text(&self) -> bool {
        match self {
            SearchField::Email(field) => field.is_text(),
            SearchField::Calendar(field) => field.is_text(),
            SearchField::Contact(field) => field.is_text(),
            SearchField::File(field) => field.is_text(),
            SearchField::Tracing(field) => field.is_text(),
            SearchField::AccountId | SearchField::DocumentId | SearchField::Id => false,
        }
    }

    pub(crate) fn is_json(&self) -> bool {
        matches!(self, SearchField::Email(EmailSearchField::Headers))
    }
}

impl SearchIndex {
    pub fn all_fields(&self) -> &[SearchField] {
        match self {
            SearchIndex::Email => EmailSearchField::all_fields(),
            SearchIndex::Calendar => CalendarSearchField::all_fields(),
            SearchIndex::Contacts => ContactSearchField::all_fields(),
            SearchIndex::File => FileSearchField::all_fields(),
            SearchIndex::Tracing => TracingSearchField::all_fields(),
            SearchIndex::InMemory => unreachable!(),
        }
    }

    pub fn primary_keys(&self) -> &'static [SearchField] {
        match self {
            SearchIndex::Email => EmailSearchField::primary_keys(),
            SearchIndex::Calendar => CalendarSearchField::primary_keys(),
            SearchIndex::Contacts => ContactSearchField::primary_keys(),
            SearchIndex::File => FileSearchField::primary_keys(),
            SearchIndex::Tracing => TracingSearchField::primary_keys(),
            SearchIndex::InMemory => unreachable!(),
        }
    }
}
