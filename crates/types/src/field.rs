/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const ARCHIVE_FIELD: u8 = 50;

pub trait FieldType: Into<u8> + Copy + std::fmt::Debug + PartialEq + Eq {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Field(u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ContactField {
    Uid,
    Email,
    Created,
    Updated,
    Text,
    Archive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CalendarField {
    Uid,
    Created,
    Updated,
    Start,
    Text,
    EventId,
    Archive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EmailField {
    Archive,
    Metadata,
    Size,
    Subject,
    References,
    MailboxIds,
    ReceivedAt,
    SentAt,
    HasAttachment,
    From,
    To,
    Cc,
    Bcc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MailboxField {
    UidCounter,
    Archive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SieveField {
    Name,
    Ids,
    Archive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EmailSubmissionField {
    Archive,
    UndoStatus,
    EmailId,
    ThreadId,
    IdentityId,
    SendAt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PrincipalField {
    Archive,
    EncryptionKeys,
    ParticipantIdentities,
    DefaultCalendarId,
    DefaultAddressBookId,
    ActiveScriptId,
    PushSubscriptions,
}

impl From<ContactField> for u8 {
    fn from(value: ContactField) -> Self {
        match value {
            ContactField::Uid => 0,
            ContactField::Email => 1,
            ContactField::Created => 2,
            ContactField::Updated => 3,
            ContactField::Text => 4,
            ContactField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<CalendarField> for u8 {
    fn from(value: CalendarField) -> Self {
        match value {
            CalendarField::Uid => 0,
            CalendarField::Text => 1,
            CalendarField::Created => 2,
            CalendarField::Updated => 3,
            CalendarField::Start => 4,
            CalendarField::EventId => 5,
            CalendarField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<EmailField> for u8 {
    fn from(value: EmailField) -> Self {
        match value {
            EmailField::From => 87,
            EmailField::To => 35,
            EmailField::Cc => 74,
            EmailField::Bcc => 69,
            EmailField::Subject => 29,
            EmailField::Size => 27,
            EmailField::Metadata => 71,
            EmailField::References => 20,
            EmailField::MailboxIds => 7,
            EmailField::ReceivedAt => 19,
            EmailField::SentAt => 26,
            EmailField::HasAttachment => 89,
            EmailField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<MailboxField> for u8 {
    fn from(value: MailboxField) -> Self {
        match value {
            MailboxField::UidCounter => 84,
            MailboxField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<SieveField> for u8 {
    fn from(value: SieveField) -> Self {
        match value {
            SieveField::Name => 13,
            SieveField::Ids => 84,
            SieveField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<EmailSubmissionField> for u8 {
    fn from(value: EmailSubmissionField) -> Self {
        match value {
            EmailSubmissionField::UndoStatus => 41,
            EmailSubmissionField::EmailId => 83,
            EmailSubmissionField::ThreadId => 33,
            EmailSubmissionField::IdentityId => 95,
            EmailSubmissionField::SendAt => 24,
            EmailSubmissionField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<PrincipalField> for u8 {
    fn from(value: PrincipalField) -> Self {
        match value {
            PrincipalField::ParticipantIdentities => 45,
            PrincipalField::EncryptionKeys => 46,
            PrincipalField::DefaultCalendarId => 47,
            PrincipalField::DefaultAddressBookId => 48,
            PrincipalField::ActiveScriptId => 49,
            PrincipalField::PushSubscriptions => 44,
            PrincipalField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<Field> for u8 {
    fn from(value: Field) -> Self {
        value.0
    }
}

impl From<ContactField> for Field {
    fn from(value: ContactField) -> Self {
        Field(u8::from(value))
    }
}

impl From<CalendarField> for Field {
    fn from(value: CalendarField) -> Self {
        Field(u8::from(value))
    }
}

impl From<EmailField> for Field {
    fn from(value: EmailField) -> Self {
        Field(u8::from(value))
    }
}

impl From<MailboxField> for Field {
    fn from(value: MailboxField) -> Self {
        Field(u8::from(value))
    }
}

impl From<PrincipalField> for Field {
    fn from(value: PrincipalField) -> Self {
        Field(u8::from(value))
    }
}

impl From<SieveField> for Field {
    fn from(value: SieveField) -> Self {
        Field(u8::from(value))
    }
}

impl From<EmailSubmissionField> for Field {
    fn from(value: EmailSubmissionField) -> Self {
        Field(u8::from(value))
    }
}

impl Field {
    pub const ARCHIVE: Field = Field(ARCHIVE_FIELD);

    pub fn new(value: u8) -> Self {
        Field(value)
    }
}

impl FieldType for Field {}
impl FieldType for ContactField {}
impl FieldType for CalendarField {}
impl FieldType for EmailField {}
impl FieldType for MailboxField {}
impl FieldType for PrincipalField {}
impl FieldType for SieveField {}
impl FieldType for EmailSubmissionField {}
