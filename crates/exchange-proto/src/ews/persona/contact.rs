/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PersonaEntry, PersonaFieldSet, PersonaKind};
use crate::ews::{
    contact::{ContactProps, ContactText},
    schema::{EmailAddressKey, UnindexedField},
    types::{ids::ItemId, path::Path},
};
use std::borrow::Cow;

const CONTACT_EMAILS: [EmailAddressKey; 3] = [
    EmailAddressKey::EmailAddress1,
    EmailAddressKey::EmailAddress2,
    EmailAddressKey::EmailAddress3,
];

pub fn persona_text(path: &Path<'_>) -> Option<ContactText> {
    match path {
        Path::Field(field) => match field {
            UnindexedField::PersonaDisplayName => Some(ContactText::DisplayName),
            UnindexedField::PersonaFileAs => Some(ContactText::FileAs),
            UnindexedField::PersonaGivenName => Some(ContactText::GivenName),
            UnindexedField::PersonaSurname => Some(ContactText::Surname),
            UnindexedField::PersonaTitle => Some(ContactText::JobTitle),
            UnindexedField::PersonaCompanyName => Some(ContactText::CompanyName),
            UnindexedField::PersonaEmailAddress => {
                Some(ContactText::Email(EmailAddressKey::EmailAddress1))
            }
            _ => None,
        },
        _ => None,
    }
}

impl<'p> ContactProps<'p> {
    pub fn persona(self, fields: PersonaFieldSet, id: ItemId<'p>) -> PersonaEntry<'p> {
        let kind = if self.is_distlist() {
            PersonaKind::DistributionList
        } else {
            PersonaKind::Person
        };
        let mut persona = PersonaEntry::new(fields, id, kind);
        let text = |bit: u16, field: ContactText| {
            self.field_text(field)
                .filter(|_| fields.has(bit))
                .map(Cow::Borrowed)
        };
        persona.display_name = text(PersonaFieldSet::DISPLAY_NAME, ContactText::DisplayName);
        persona.file_as = text(PersonaFieldSet::FILE_AS, ContactText::FileAs);
        persona.given_name = text(PersonaFieldSet::GIVEN_NAME, ContactText::GivenName);
        persona.surname = text(PersonaFieldSet::SURNAME, ContactText::Surname);
        persona.title = text(PersonaFieldSet::TITLE, ContactText::JobTitle);
        persona.department = text(PersonaFieldSet::DEPARTMENT, ContactText::Department);
        persona.company_name = text(PersonaFieldSet::COMPANY_NAME, ContactText::CompanyName);
        if persona.wants_addresses() {
            let name = self.field_text(ContactText::DisplayName);
            persona.email_addresses.extend(
                CONTACT_EMAILS
                    .into_iter()
                    .filter_map(|key| self.field_text(ContactText::Email(key)))
                    .filter(|address| !address.is_empty())
                    .map(|address| PersonaEntry::smtp_address(name, address)),
            );
        }
        persona
    }
}
