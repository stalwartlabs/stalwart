/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ADDRESSES, EMAIL_KEYS, PHONES, file_as_id};
use crate::{
    common::FileTime,
    convert::{
        model::PropBag,
        tags::KEYWORDS_NAME,
        vcard::{
            patch_contact_from_message,
            props::{
                ASSISTANT, BIRTHDAY, BODY, BUSINESS_HOME_PAGE, CHILDRENS_NAMES, COMPANY_NAME,
                DEPARTMENT_NAME, DISPLAY_NAME, DISPLAY_NAME_PREFIX, EMAIL_SLOTS, GENERATION,
                GIVEN_NAME, HOME_ADDRESS, INITIALS, LID_BIRTHDAY_LOCAL, LID_FILE_UNDER,
                LID_FILE_UNDER_ID, LID_INSTANT_MESSAGING_ADDRESS, LID_POSTAL_ADDRESS_ID,
                LID_WEDDING_ANNIVERSARY_LOCAL, LID_YOMI_FIRST_NAME, LID_YOMI_LAST_NAME,
                MANAGER_NAME, MIDDLE_NAME, NICKNAME, OFFICE_LOCATION, OTHER_ADDRESS, PROFESSION,
                SENSITIVITY, SPOUSE_NAME, SURNAME, TITLE, WEDDING_ANNIVERSARY, WORK_ADDRESS,
                address_lid,
            },
        },
    },
    ews::{
        item_edit::with_appended_category_names,
        schema::{
            BodyType, DictionaryField, EmailAddressKey, ImAddressKey, PhoneNumberKey,
            PhysicalAddressIndex, PhysicalAddressKey, Sensitivity, UnindexedField,
        },
        types::{
            change::ItemChange,
            item::{
                ContactItem, Item,
                contact::{ContactFields, PhysicalAddressFields},
            },
            path::Path,
            value::DateTime,
            xprop::ExtendedProperty,
        },
    },
    mapi::prop::{OwnedPropValue, PropId, PropKey, PropKeyRef, PropType, sets::PS_PUBLIC_STRINGS},
};
use calcard::vcard::{VCard, VCardEntry, VCardProperty, VCardValue};
use mail_parser::html_to_text;
use smallvec::smallvec;
use std::borrow::Cow;

const CONTACTS_PREFIX: &str = "contacts:";
const N_FAMILY: usize = 0;
const N_GIVEN: usize = 1;
const N_ADDITIONAL: usize = 2;

type TextOf = for<'a> fn(&'a ContactFields<'_>) -> Option<&'a str>;
type AddressPart = for<'a> fn(&'a PhysicalAddressFields<'_>) -> Option<&'a str>;

const TEXT_FIELDS: [(UnindexedField, PropKeyRef<'static>, TextOf); 17] = [
    (
        UnindexedField::ContactsFileAs,
        address_lid(LID_FILE_UNDER),
        |c| c.file_as.as_deref(),
    ),
    (
        UnindexedField::ContactsDisplayName,
        PropKeyRef::Tag(DISPLAY_NAME),
        |c| c.display_name.as_deref(),
    ),
    (
        UnindexedField::ContactsGivenName,
        PropKeyRef::Tag(GIVEN_NAME),
        |c| c.given_name.as_deref(),
    ),
    (
        UnindexedField::ContactsInitials,
        PropKeyRef::Tag(INITIALS),
        |c| c.initials.as_deref(),
    ),
    (
        UnindexedField::ContactsMiddleName,
        PropKeyRef::Tag(MIDDLE_NAME),
        |c| c.middle_name.as_deref(),
    ),
    (
        UnindexedField::ContactsNickname,
        PropKeyRef::Tag(NICKNAME),
        |c| c.nickname.as_deref(),
    ),
    (
        UnindexedField::ContactsCompanyName,
        PropKeyRef::Tag(COMPANY_NAME),
        |c| c.company_name.as_deref(),
    ),
    (
        UnindexedField::ContactsAssistantName,
        PropKeyRef::Tag(ASSISTANT),
        |c| c.assistant_name.as_deref(),
    ),
    (
        UnindexedField::ContactsBusinessHomePage,
        PropKeyRef::Tag(BUSINESS_HOME_PAGE),
        |c| c.business_home_page.as_deref(),
    ),
    (
        UnindexedField::ContactsDepartment,
        PropKeyRef::Tag(DEPARTMENT_NAME),
        |c| c.department.as_deref(),
    ),
    (
        UnindexedField::ContactsGeneration,
        PropKeyRef::Tag(GENERATION),
        |c| c.generation.as_deref(),
    ),
    (
        UnindexedField::ContactsJobTitle,
        PropKeyRef::Tag(TITLE),
        |c| c.job_title.as_deref(),
    ),
    (
        UnindexedField::ContactsManager,
        PropKeyRef::Tag(MANAGER_NAME),
        |c| c.manager.as_deref(),
    ),
    (
        UnindexedField::ContactsOfficeLocation,
        PropKeyRef::Tag(OFFICE_LOCATION),
        |c| c.office_location.as_deref(),
    ),
    (
        UnindexedField::ContactsProfession,
        PropKeyRef::Tag(PROFESSION),
        |c| c.profession.as_deref(),
    ),
    (
        UnindexedField::ContactsSpouseName,
        PropKeyRef::Tag(SPOUSE_NAME),
        |c| c.spouse_name.as_deref(),
    ),
    (
        UnindexedField::ContactsSurname,
        PropKeyRef::Tag(SURNAME),
        |c| c.surname.as_deref(),
    ),
];

const CREATE_ONLY_TEXT: [(PropKeyRef<'static>, TextOf); 3] = [
    (PropKeyRef::Tag(DISPLAY_NAME_PREFIX), |c| {
        c.display_name_prefix.as_deref()
    }),
    (address_lid(LID_YOMI_FIRST_NAME), |c| {
        c.yomi_given_name.as_deref()
    }),
    (address_lid(LID_YOMI_LAST_NAME), |c| {
        c.yomi_surname.as_deref()
    }),
];

const ADDRESS_PARTS: [(DictionaryField, AddressPart); 5] = [
    (DictionaryField::ContactsPhysicalAddressStreet, |a| {
        a.street.as_deref()
    }),
    (DictionaryField::ContactsPhysicalAddressCity, |a| {
        a.city.as_deref()
    }),
    (DictionaryField::ContactsPhysicalAddressState, |a| {
        a.state.as_deref()
    }),
    (
        DictionaryField::ContactsPhysicalAddressCountryOrRegion,
        |a| a.country_or_region.as_deref(),
    ),
    (DictionaryField::ContactsPhysicalAddressPostalCode, |a| {
        a.postal_code.as_deref()
    }),
];

const WRITABLE: [UnindexedField; 10] = [
    UnindexedField::ItemBody,
    UnindexedField::ContactsEmailAddresses,
    UnindexedField::ContactsPhoneNumbers,
    UnindexedField::ContactsPhysicalAddresses,
    UnindexedField::ItemCategories,
    UnindexedField::ItemSensitivity,
    UnindexedField::ContactsFileAsMapping,
    UnindexedField::ContactsChildren,
    UnindexedField::ContactsPostalAddressIndex,
    UnindexedField::ContactsImAddresses,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactEditError {
    NotAContact,
    InvalidPropertySet,
    InvalidPropertyAppend,
    Conversion,
}

#[derive(Debug, Default)]
pub struct ContactEdit {
    props: PropBag,
    appended_categories: Vec<Box<str>>,
    subject: Option<Box<str>>,
}

enum Source<'v, 'x> {
    Set(&'v ContactItem<'x>),
    Delete,
}

impl ContactEdit {
    pub fn from_item(item: &ContactItem<'_>) -> Result<Self, ContactEditError> {
        if item.contact.has_picture.is_some() {
            return Err(ContactEditError::InvalidPropertySet);
        }
        let mut edit = ContactEdit {
            subject: item.item.subject.as_deref().map(Box::from),
            ..Default::default()
        };
        let source = Source::Set(item);
        for (_, key, text_of) in TEXT_FIELDS {
            if let Some(value) = text_of(&item.contact) {
                edit.text(key, value);
            }
        }
        for (key, text_of) in CREATE_ONLY_TEXT {
            if let Some(value) = text_of(&item.contact) {
                edit.text(key, value);
            }
        }
        for field in WRITABLE {
            edit.field(field, &source)?;
        }
        edit.dates(
            item.contact.birthday_local.as_ref(),
            item.contact.birthday.as_ref(),
            LID_BIRTHDAY_LOCAL,
            BIRTHDAY,
        )?;
        edit.dates(
            item.contact.wedding_anniversary_local.as_ref(),
            item.contact.wedding_anniversary.as_ref(),
            LID_WEDDING_ANNIVERSARY_LOCAL,
            WEDDING_ANNIVERSARY,
        )?;
        for property in item.item.extended_property.iter().flat_map(|list| &list.0) {
            edit.extended_value(property)?;
        }
        Ok(edit)
    }

    pub fn change(&mut self, change: &ItemChange<'_>) -> Result<(), ContactEditError> {
        let (path, source) = match change {
            ItemChange::Set { path, value } => (path, Source::Set(contact_of(value)?)),
            ItemChange::Append { path, value } => {
                return match path {
                    Path::Field(UnindexedField::ItemCategories) => {
                        let names = contact_of(value)?
                            .item
                            .categories
                            .as_ref()
                            .ok_or(ContactEditError::InvalidPropertySet)?;
                        self.appended_categories
                            .extend(names.0.iter().map(|name| Box::from(name.as_ref())));
                        Ok(())
                    }
                    _ => Err(ContactEditError::InvalidPropertyAppend),
                };
            }
            ItemChange::Delete(path) => (path, Source::Delete),
        };
        match path {
            Path::Field(field) => self.unindexed(*field, &source),
            Path::Indexed { field, index } => self.indexed(*field, index.as_bytes(), &source),
            Path::Extended(uri) => {
                let (key, ptype) = uri
                    .to_prop()
                    .map_err(|_| ContactEditError::InvalidPropertySet)?;
                match source {
                    Source::Set(item) => {
                        let property = item
                            .item
                            .extended_property
                            .iter()
                            .flat_map(|list| &list.0)
                            .find(|property| property.uri == *uri)
                            .ok_or(ContactEditError::InvalidPropertySet)?;
                        self.extended_value(property)
                    }
                    Source::Delete => {
                        let value = if ptype == PropType::Unicode {
                            OwnedPropValue::Unicode(Box::from(""))
                        } else {
                            OwnedPropValue::Null
                        };
                        self.props.set(key, value);
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn apply(&self, card: &mut VCard) -> Result<(), ContactEditError> {
        let props = with_appended_category_names(
            &self.props,
            &self.appended_categories,
            card.entries
                .iter()
                .filter(|entry| entry.name == VCardProperty::Categories)
                .flat_map(|entry| entry.values.iter())
                .filter_map(|value| value.as_text()),
        );
        patch_contact_from_message(card, &props).map_err(|_| ContactEditError::Conversion)?;
        if card
            .property(&VCardProperty::Fn)
            .and_then(|entry| entry.values.first())
            .and_then(VCardValue::as_text)
            .is_none_or(str::is_empty)
        {
            let mut name = fallback_name(card);
            if let (true, Some(subject)) = (name.is_empty(), self.subject.as_deref()) {
                name.push_str(subject);
            }
            card.entries.retain(|entry| entry.name != VCardProperty::Fn);
            card.entries.push(VCardEntry {
                group: None,
                name: VCardProperty::Fn,
                params: Vec::new(),
                values: smallvec![VCardValue::Text(name)],
            });
        }
        Ok(())
    }

    fn unindexed(
        &mut self,
        field: UnindexedField,
        source: &Source<'_, '_>,
    ) -> Result<(), ContactEditError> {
        if let Some((_, key, text_of)) = TEXT_FIELDS.iter().find(|(known, ..)| *known == field) {
            return match source {
                Source::Set(item) => {
                    let value =
                        text_of(&item.contact).ok_or(ContactEditError::InvalidPropertySet)?;
                    self.text(*key, value);
                    Ok(())
                }
                Source::Delete => {
                    self.text(*key, "");
                    Ok(())
                }
            };
        }
        match field {
            UnindexedField::ContactsBirthday => {
                self.date(PropKeyRef::Tag(BIRTHDAY), source, |c| c.birthday.as_ref())
            }
            UnindexedField::ContactsWeddingAnniversary => {
                self.date(PropKeyRef::Tag(WEDDING_ANNIVERSARY), source, |c| {
                    c.wedding_anniversary.as_ref()
                })
            }
            UnindexedField::ContactsCompleteName
            | UnindexedField::ContactsHasPicture
            | UnindexedField::ContactsContactSource => Err(ContactEditError::InvalidPropertySet),
            UnindexedField::ContactsEmailAddresses
            | UnindexedField::ContactsPhoneNumbers
            | UnindexedField::ContactsPhysicalAddresses
                if matches!(source, Source::Delete) =>
            {
                Err(ContactEditError::InvalidPropertySet)
            }
            UnindexedField::ItemSubject => {
                if let Source::Set(item) = source {
                    self.subject = item.item.subject.as_deref().map(Box::from);
                }
                Ok(())
            }
            UnindexedField::ItemItemClass => Ok(()),
            field if field.is_unstored_groupware_field() => Ok(()),
            field => {
                if self.field(field, source)? || field.as_str().starts_with(CONTACTS_PREFIX) {
                    Ok(())
                } else {
                    Err(ContactEditError::InvalidPropertySet)
                }
            }
        }
    }

    fn field(
        &mut self,
        field: UnindexedField,
        source: &Source<'_, '_>,
    ) -> Result<bool, ContactEditError> {
        let item = match source {
            Source::Set(item) => Some(*item),
            Source::Delete => None,
        };
        match field {
            UnindexedField::ItemBody => match item {
                Some(item) => {
                    if let Some(body) = &item.item.body {
                        let text = match body.body_type {
                            BodyType::Html => Cow::Owned(html_to_text(&body.text)),
                            BodyType::Text => Cow::Borrowed(body.text.as_ref()),
                        };
                        self.text(PropKeyRef::Tag(BODY), &text);
                    }
                }
                None => self.text(PropKeyRef::Tag(BODY), ""),
            },
            UnindexedField::ItemCategories => {
                let names = item
                    .and_then(|item| item.item.categories.as_ref())
                    .map(|names| {
                        names
                            .0
                            .iter()
                            .map(|name| Box::from(name.as_ref()))
                            .collect::<Box<[Box<str>]>>()
                    });
                if item.is_none() || names.is_some() {
                    self.props.set(
                        PropKey::name(PS_PUBLIC_STRINGS, KEYWORDS_NAME),
                        OwnedPropValue::MvUnicode(names.unwrap_or_default()),
                    );
                }
            }
            UnindexedField::ItemSensitivity => {
                let level = match item.map(|item| item.item.sensitivity) {
                    Some(None) => return Ok(true),
                    Some(Some(Sensitivity::Personal)) => 1,
                    Some(Some(Sensitivity::Private)) => 2,
                    Some(Some(Sensitivity::Confidential)) => 3,
                    Some(Some(Sensitivity::Normal)) | None => 0,
                };
                self.props
                    .set(PropKey::tag(SENSITIVITY), OwnedPropValue::I32(level));
            }
            UnindexedField::ContactsFileAsMapping => {
                let value = match item.map(|item| item.contact.file_as_mapping) {
                    Some(None) => return Ok(true),
                    Some(Some(mapping)) => {
                        file_as_id(mapping).map_or(OwnedPropValue::Null, OwnedPropValue::I32)
                    }
                    None => OwnedPropValue::Null,
                };
                self.props
                    .set(address_lid(LID_FILE_UNDER_ID).to_key(), value);
            }
            UnindexedField::ContactsEmailAddresses => {
                for entry in item
                    .and_then(|item| item.contact.email_addresses.as_ref())
                    .into_iter()
                    .flat_map(|list| &list.0)
                {
                    if let Some(key) = email_key(entry.key) {
                        self.text(key, &entry.address);
                    }
                }
            }
            UnindexedField::ContactsPhoneNumbers => {
                for entry in item
                    .and_then(|item| item.contact.phone_numbers.as_ref())
                    .into_iter()
                    .flat_map(|list| &list.0)
                {
                    if let Some(key) = phone_key(entry.key) {
                        self.text(key, &entry.value);
                    }
                }
            }
            UnindexedField::ContactsPhysicalAddresses => {
                for entry in item
                    .and_then(|item| item.contact.physical_addresses.as_ref())
                    .into_iter()
                    .flat_map(|list| &list.0)
                {
                    for (part, value_of) in ADDRESS_PARTS {
                        if let (Some(key), Some(value)) =
                            (address_key(entry.key, part), value_of(&entry.fields))
                        {
                            self.text(key, value);
                        }
                    }
                }
            }
            UnindexedField::ContactsChildren => {
                let names = item.and_then(|item| item.contact.children.as_ref());
                if item.is_none() || names.is_some() {
                    self.props.set(
                        PropKey::tag(CHILDRENS_NAMES),
                        OwnedPropValue::MvUnicode(
                            names
                                .into_iter()
                                .flat_map(|names| &names.0)
                                .map(|name| Box::from(name.as_ref()))
                                .collect(),
                        ),
                    );
                }
            }
            UnindexedField::ContactsPostalAddressIndex => {
                let value = match item.map(|item| item.contact.postal_address_index) {
                    Some(None) => return Ok(true),
                    Some(Some(index)) => OwnedPropValue::I32(postal_address_id(index)),
                    None => OwnedPropValue::Null,
                };
                self.props
                    .set(address_lid(LID_POSTAL_ADDRESS_ID).to_key(), value);
            }
            UnindexedField::ContactsImAddresses => match item {
                Some(item) => {
                    if let Some(address) = im_address1(&item.contact) {
                        self.text(address_lid(LID_INSTANT_MESSAGING_ADDRESS), address);
                    }
                }
                None => self.text(address_lid(LID_INSTANT_MESSAGING_ADDRESS), ""),
            },
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn indexed(
        &mut self,
        field: DictionaryField,
        index: &[u8],
        source: &Source<'_, '_>,
    ) -> Result<(), ContactEditError> {
        let item = match source {
            Source::Set(item) => Some(*item),
            Source::Delete => None,
        };
        let (key, value) = match field {
            DictionaryField::ContactsEmailAddress => {
                let entry_key =
                    EmailAddressKey::parse(index).ok_or(ContactEditError::InvalidPropertySet)?;
                let value = item
                    .map(|item| {
                        item.contact
                            .email_addresses
                            .iter()
                            .flat_map(|list| &list.0)
                            .find(|entry| entry.key == entry_key)
                            .map(|entry| entry.address.as_ref())
                            .ok_or(ContactEditError::InvalidPropertySet)
                    })
                    .transpose()?;
                (email_key(entry_key), value)
            }
            DictionaryField::ContactsPhoneNumber => {
                let entry_key =
                    PhoneNumberKey::parse(index).ok_or(ContactEditError::InvalidPropertySet)?;
                let value = item
                    .map(|item| {
                        item.contact
                            .phone_numbers
                            .iter()
                            .flat_map(|list| &list.0)
                            .find(|entry| entry.key == entry_key)
                            .map(|entry| entry.value.as_ref())
                            .ok_or(ContactEditError::InvalidPropertySet)
                    })
                    .transpose()?;
                (phone_key(entry_key), value)
            }
            DictionaryField::ContactsImAddress => {
                if ImAddressKey::parse(index).ok_or(ContactEditError::InvalidPropertySet)?
                    != ImAddressKey::ImAddress1
                {
                    return Ok(());
                }
                let value = item
                    .map(|item| {
                        im_address1(&item.contact).ok_or(ContactEditError::InvalidPropertySet)
                    })
                    .transpose()?;
                (Some(address_lid(LID_INSTANT_MESSAGING_ADDRESS)), value)
            }
            part => {
                let entry_key =
                    PhysicalAddressKey::parse(index).ok_or(ContactEditError::InvalidPropertySet)?;
                let value_of = ADDRESS_PARTS
                    .iter()
                    .find(|(known, _)| *known == part)
                    .map(|(_, value_of)| *value_of)
                    .ok_or(ContactEditError::InvalidPropertySet)?;
                let value = item
                    .map(|item| {
                        item.contact
                            .physical_addresses
                            .iter()
                            .flat_map(|list| &list.0)
                            .find(|entry| entry.key == entry_key)
                            .and_then(|entry| value_of(&entry.fields))
                            .ok_or(ContactEditError::InvalidPropertySet)
                    })
                    .transpose()?;
                (address_key(entry_key, part), value)
            }
        };
        if let Some(key) = key {
            self.text(key, value.unwrap_or_default());
        }
        Ok(())
    }

    fn date(
        &mut self,
        key: PropKeyRef<'static>,
        source: &Source<'_, '_>,
        date_of: for<'a> fn(&'a ContactFields<'_>) -> Option<&'a DateTime>,
    ) -> Result<(), ContactEditError> {
        let value = match source {
            Source::Set(item) => OwnedPropValue::Time(file_time(
                date_of(&item.contact).ok_or(ContactEditError::InvalidPropertySet)?,
            )?),
            Source::Delete => OwnedPropValue::Null,
        };
        self.props.set(key.to_key(), value);
        Ok(())
    }

    fn dates(
        &mut self,
        local: Option<&DateTime>,
        utc: Option<&DateTime>,
        local_lid: u32,
        utc_tag: PropId,
    ) -> Result<(), ContactEditError> {
        let (key, date) = match (local, utc) {
            (Some(date), _) => (address_lid(local_lid), date),
            (None, Some(date)) => (PropKeyRef::Tag(utc_tag), date),
            (None, None) => return Ok(()),
        };
        self.props
            .set(key.to_key(), OwnedPropValue::Time(file_time(date)?));
        Ok(())
    }

    fn extended_value(&mut self, property: &ExtendedProperty<'_>) -> Result<(), ContactEditError> {
        let (key, ptype) = property
            .uri
            .to_prop()
            .map_err(|_| ContactEditError::InvalidPropertySet)?;
        let value = property
            .value
            .to_owned_value(ptype)
            .map_err(|_| ContactEditError::InvalidPropertySet)?;
        self.props.set(key, value);
        Ok(())
    }

    fn text(&mut self, key: PropKeyRef<'_>, value: &str) {
        self.props
            .set(key.to_key(), OwnedPropValue::Unicode(Box::from(value)));
    }
}

fn fallback_name(card: &VCard) -> String {
    let mut name = String::new();
    if let Some(entry) = card.property(&VCardProperty::N) {
        for part in [N_GIVEN, N_ADDITIONAL, N_FAMILY]
            .into_iter()
            .filter_map(|index| entry.values.get(index).and_then(VCardValue::as_text))
            .filter(|part| !part.is_empty())
        {
            if !name.is_empty() {
                name.push(' ');
            }
            name.push_str(part);
        }
    }
    if name.is_empty()
        && let Some(fallback) =
            [VCardProperty::Org, VCardProperty::Email]
                .iter()
                .find_map(|property| {
                    card.property(property)
                        .and_then(|entry| entry.values.first())
                        .and_then(VCardValue::as_text)
                        .filter(|text| !text.is_empty())
                })
    {
        name.push_str(fallback);
    }
    name
}

fn contact_of<'v, 'x>(value: &'v Item<'x>) -> Result<&'v ContactItem<'x>, ContactEditError> {
    match value {
        Item::Contact(contact) => Ok(contact),
        _ => Err(ContactEditError::NotAContact),
    }
}

fn email_key(key: EmailAddressKey) -> Option<PropKeyRef<'static>> {
    let index = EMAIL_KEYS.iter().position(|known| *known == key)?;
    EMAIL_SLOTS.get(index).map(|slot| address_lid(slot.email))
}

fn phone_key(key: PhoneNumberKey) -> Option<PropKeyRef<'static>> {
    PHONES
        .iter()
        .find(|(known, _)| *known == key)
        .map(|(_, id)| PropKeyRef::Tag(*id))
}

fn address_key(key: PhysicalAddressKey, part: DictionaryField) -> Option<PropKeyRef<'static>> {
    let (_, group) = ADDRESSES.iter().find(|(known, _)| *known == key)?;
    let address = match part {
        DictionaryField::ContactsPhysicalAddressStreet => &group.street,
        DictionaryField::ContactsPhysicalAddressCity => &group.city,
        DictionaryField::ContactsPhysicalAddressState => &group.state,
        DictionaryField::ContactsPhysicalAddressCountryOrRegion => &group.country,
        DictionaryField::ContactsPhysicalAddressPostalCode => &group.postal_code,
        _ => return None,
    };
    Some(address.key())
}

fn im_address1<'a>(contact: &'a ContactFields<'_>) -> Option<&'a str> {
    contact
        .im_addresses
        .iter()
        .flat_map(|list| &list.0)
        .find(|entry| entry.key == ImAddressKey::ImAddress1)
        .map(|entry| entry.value.as_ref())
}

fn postal_address_id(index: PhysicalAddressIndex) -> i32 {
    match index {
        PhysicalAddressIndex::None => 0,
        PhysicalAddressIndex::Home => HOME_ADDRESS.postal_id,
        PhysicalAddressIndex::Business => WORK_ADDRESS.postal_id,
        PhysicalAddressIndex::Other => OTHER_ADDRESS.postal_id,
    }
}

fn file_time(date: &DateTime) -> Result<FileTime, ContactEditError> {
    date.to_utc()
        .map(|seconds| FileTime::from_utc(seconds, 0))
        .ok_or(ContactEditError::InvalidPropertySet)
}
