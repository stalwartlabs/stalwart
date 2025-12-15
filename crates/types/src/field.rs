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
    Archive,
    CreatedToUpdated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CalendarEventField {
    Uid,
    Archive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CalendarNotificationField {
    CreatedToId,
    Archive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EmailField {
    Archive,
    Metadata,
    Threading,
    DeletedAt,
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
    Metadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IdentityField {
    Archive,
    DocumentId,
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
            ContactField::CreatedToUpdated => 2,
            ContactField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<CalendarEventField> for u8 {
    fn from(value: CalendarEventField) -> Self {
        match value {
            CalendarEventField::Uid => 0,
            CalendarEventField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<CalendarNotificationField> for u8 {
    fn from(value: CalendarNotificationField) -> Self {
        match value {
            CalendarNotificationField::CreatedToId => 0,
            CalendarNotificationField::Archive => ARCHIVE_FIELD,
        }
    }
}

impl From<EmailField> for u8 {
    fn from(value: EmailField) -> Self {
        match value {
            EmailField::Metadata => 71,
            EmailField::Threading => 90,
            EmailField::DeletedAt => 91,
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
            EmailSubmissionField::Metadata => 49,
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

impl From<IdentityField> for u8 {
    fn from(value: IdentityField) -> Self {
        match value {
            IdentityField::Archive => ARCHIVE_FIELD,
            IdentityField::DocumentId => 51,
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

impl From<CalendarEventField> for Field {
    fn from(value: CalendarEventField) -> Self {
        Field(u8::from(value))
    }
}

impl From<CalendarNotificationField> for Field {
    fn from(value: CalendarNotificationField) -> Self {
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

impl From<IdentityField> for Field {
    fn from(value: IdentityField) -> Self {
        Field(u8::from(value))
    }
}

impl Field {
    pub const ARCHIVE: Field = Field(ARCHIVE_FIELD);

    pub fn new(value: u8) -> Self {
        Field(value)
    }

    pub fn inner(&self) -> u8 {
        self.0
    }
}

impl FieldType for Field {}
impl FieldType for ContactField {}
impl FieldType for CalendarEventField {}
impl FieldType for CalendarNotificationField {}
impl FieldType for EmailField {}
impl FieldType for MailboxField {}
impl FieldType for PrincipalField {}
impl FieldType for SieveField {}
impl FieldType for EmailSubmissionField {}
impl FieldType for IdentityField {}
