/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(feature = "convert")]
mod contact;

#[cfg(feature = "convert")]
pub use contact::persona_text;

use crate::{
    ews::{
        schema::{BaseShape, UnindexedField},
        types::{
            address::EmailAddress,
            ids::ItemId,
            path::Path,
            persona::PersonaShape,
            value::{EwsValue, T},
        },
    },
    xml::XmlWriter,
};
use std::borrow::Cow;

const ROUTING_SMTP: &str = "SMTP";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PersonaFieldSet(u16);

impl PersonaFieldSet {
    pub const KIND: u16 = 1;
    pub const DISPLAY_NAME: u16 = 1 << 1;
    pub const FILE_AS: u16 = 1 << 2;
    pub const GIVEN_NAME: u16 = 1 << 3;
    pub const SURNAME: u16 = 1 << 4;
    pub const TITLE: u16 = 1 << 5;
    pub const DEPARTMENT: u16 = 1 << 6;
    pub const COMPANY_NAME: u16 = 1 << 7;
    pub const EMAIL_ADDRESS: u16 = 1 << 8;
    pub const EMAIL_ADDRESSES: u16 = 1 << 9;

    const DEFAULT: u16 = Self::KIND
        | Self::DISPLAY_NAME
        | Self::FILE_AS
        | Self::GIVEN_NAME
        | Self::SURNAME
        | Self::EMAIL_ADDRESS
        | Self::EMAIL_ADDRESSES;
    const ALL: u16 = Self::DEFAULT | Self::TITLE | Self::DEPARTMENT | Self::COMPANY_NAME;

    pub fn from_shape(shape: Option<&PersonaShape<'_>>) -> Self {
        let Some(shape) = shape else {
            return PersonaFieldSet(Self::DEFAULT);
        };
        let mut fields = match shape.base {
            BaseShape::IdOnly => 0,
            BaseShape::Default => Self::DEFAULT,
            BaseShape::AllProperties | BaseShape::PcxPeopleSearch => Self::ALL,
        };
        for path in shape.additional.iter().flat_map(|paths| &paths.0) {
            if let Path::Field(field) = path {
                fields |= Self::of_field(*field);
            }
        }
        PersonaFieldSet(fields)
    }

    pub const fn all() -> Self {
        PersonaFieldSet(Self::ALL)
    }

    pub const fn has(self, field: u16) -> bool {
        self.0 & field != 0
    }

    fn of_field(field: UnindexedField) -> u16 {
        match field {
            UnindexedField::PersonaPersonaType => Self::KIND,
            UnindexedField::PersonaDisplayName => Self::DISPLAY_NAME,
            UnindexedField::PersonaFileAs => Self::FILE_AS,
            UnindexedField::PersonaGivenName => Self::GIVEN_NAME,
            UnindexedField::PersonaSurname => Self::SURNAME,
            UnindexedField::PersonaTitle => Self::TITLE,
            UnindexedField::PersonaCompanyName => Self::COMPANY_NAME,
            UnindexedField::PersonaEmailAddress => Self::EMAIL_ADDRESS,
            UnindexedField::PersonaEmailAddresses => Self::EMAIL_ADDRESSES,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonaKind {
    Person,
    DistributionList,
}

impl PersonaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PersonaKind::Person => "Person",
            PersonaKind::DistributionList => "DistributionList",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PersonaEntry<'x> {
    pub fields: PersonaFieldSet,
    pub id: ItemId<'x>,
    pub kind: PersonaKind,
    pub display_name: Option<Cow<'x, str>>,
    pub file_as: Option<Cow<'x, str>>,
    pub given_name: Option<Cow<'x, str>>,
    pub surname: Option<Cow<'x, str>>,
    pub title: Option<Cow<'x, str>>,
    pub department: Option<Cow<'x, str>>,
    pub company_name: Option<Cow<'x, str>>,
    pub email_addresses: Vec<EmailAddress<'x>>,
}

impl<'x> PersonaEntry<'x> {
    pub fn new(fields: PersonaFieldSet, id: ItemId<'x>, kind: PersonaKind) -> Self {
        PersonaEntry {
            fields,
            id,
            kind,
            display_name: None,
            file_as: None,
            given_name: None,
            surname: None,
            title: None,
            department: None,
            company_name: None,
            email_addresses: Vec::new(),
        }
    }

    pub fn wants_addresses(&self) -> bool {
        self.fields
            .has(PersonaFieldSet::EMAIL_ADDRESS | PersonaFieldSet::EMAIL_ADDRESSES)
    }

    pub fn smtp_address(name: Option<&'x str>, address: &'x str) -> EmailAddress<'x> {
        EmailAddress {
            name: Some(Cow::Borrowed(name.unwrap_or(address))),
            email_address: Some(Cow::Borrowed(address)),
            routing_type: Some(Cow::Borrowed(ROUTING_SMTP)),
            ..Default::default()
        }
    }

    pub fn write_children(&self, w: &mut XmlWriter<'_>) {
        self.id.write(w, "PersonaId");
        if self.fields.has(PersonaFieldSet::KIND) {
            w.leaf(T, "PersonaType", self.kind.as_str());
        }
        for (bit, local, value) in [
            (
                PersonaFieldSet::DISPLAY_NAME,
                "DisplayName",
                &self.display_name,
            ),
            (PersonaFieldSet::FILE_AS, "FileAs", &self.file_as),
            (PersonaFieldSet::GIVEN_NAME, "GivenName", &self.given_name),
            (PersonaFieldSet::SURNAME, "Surname", &self.surname),
            (PersonaFieldSet::TITLE, "Title", &self.title),
            (PersonaFieldSet::DEPARTMENT, "Department", &self.department),
            (
                PersonaFieldSet::COMPANY_NAME,
                "CompanyName",
                &self.company_name,
            ),
        ] {
            if let Some(value) = value.as_deref().filter(|_| self.fields.has(bit)) {
                w.leaf(T, local, value);
            }
        }
        if self.fields.has(PersonaFieldSet::EMAIL_ADDRESS)
            && let Some(first) = self.email_addresses.first()
        {
            first.write(w, "EmailAddress");
        }
        if self.fields.has(PersonaFieldSet::EMAIL_ADDRESSES) && !self.email_addresses.is_empty() {
            w.start(T, "EmailAddresses");
            for address in &self.email_addresses {
                address.write(w, "Address");
            }
            w.end(T, "EmailAddresses");
        }
    }

    pub fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        self.write_children(w);
        w.end(T, local);
    }
}
