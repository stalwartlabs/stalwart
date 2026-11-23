/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod write;

use crate::{
    common::FileTime,
    convert::{
        model::PropBag,
        tags::MESSAGE_CLASS,
        vcard::DISTLIST_CLASS,
        vcard::props::{
            ASSISTANT, ASSISTANT_TELEPHONE_NUMBER, AddressGroup, BIRTHDAY, BODY,
            BUSINESS_FAX_NUMBER, BUSINESS_HOME_PAGE, BUSINESS_TELEPHONE_NUMBER,
            BUSINESS2_TELEPHONE_NUMBER, CALLBACK_TELEPHONE_NUMBER, CAR_TELEPHONE_NUMBER,
            CHILDRENS_NAMES, COMPANY_MAIN_PHONE_NUMBER, COMPANY_NAME, CONTACT_CLASS,
            DEPARTMENT_NAME, DISPLAY_NAME, DISPLAY_NAME_PREFIX, EMAIL_SLOTS, GENERATION,
            GIVEN_NAME, HOME_ADDRESS, HOME_FAX_NUMBER, HOME_TELEPHONE_NUMBER,
            HOME2_TELEPHONE_NUMBER, INITIALS, ISDN_NUMBER, LAST_MODIFICATION_TIME,
            LID_BIRTHDAY_LOCAL, LID_CATEGORIES, LID_FILE_UNDER, LID_FILE_UNDER_ID, LID_HAS_PICTURE,
            LID_INSTANT_MESSAGING_ADDRESS, LID_POSTAL_ADDRESS_ID, LID_WEDDING_ANNIVERSARY_LOCAL,
            LID_YOMI_FIRST_NAME, LID_YOMI_LAST_NAME, MANAGER_NAME, MIDDLE_NAME,
            MOBILE_TELEPHONE_NUMBER, NICKNAME, NORMALIZED_SUBJECT, OFFICE_LOCATION, OTHER_ADDRESS,
            OTHER_TELEPHONE_NUMBER, PAGER_TELEPHONE_NUMBER, PRIMARY_FAX_NUMBER,
            PRIMARY_TELEPHONE_NUMBER, PROFESSION, RADIO_TELEPHONE_NUMBER, SENSITIVITY, SPOUSE_NAME,
            SURNAME, TELEX_NUMBER, TITLE, TTY_TDD_PHONE_NUMBER, WEDDING_ANNIVERSARY, WORK_ADDRESS,
            address_lid,
        },
    },
    ews::{
        schema::{
            BaseShape, BodyType, BodyTypeResponse, ContactSource, DictionaryField, EmailAddressKey,
            FileAsMapping, ImAddressKey, PhoneNumberKey, PhysicalAddressIndex, PhysicalAddressKey,
            Sensitivity, UnindexedField,
        },
        types::{
            common::Body,
            item::{
                ContactItem, DistributionListItem, ItemFields,
                contact::{
                    CompleteName, ContactFields, DistributionListFields, EmailAddressEntry,
                    ImAddressEntry, PhoneNumberEntry, PhysicalAddressEntry, PhysicalAddressFields,
                },
            },
            path::Path,
            shape::ItemShape,
            value::{DateTime, List, Strings},
        },
    },
    mapi::prop::{OwnedPropValue, PropId, PropKeyRef, PropType, sets::PS_PUBLIC_STRINGS},
};
use mail_parser::text_to_html;
use std::borrow::Cow;

pub use write::{ContactEdit, ContactEditError};

const PHONES: [(PhoneNumberKey, PropId); 19] = [
    (PhoneNumberKey::AssistantPhone, ASSISTANT_TELEPHONE_NUMBER),
    (PhoneNumberKey::BusinessFax, BUSINESS_FAX_NUMBER),
    (PhoneNumberKey::BusinessPhone, BUSINESS_TELEPHONE_NUMBER),
    (PhoneNumberKey::BusinessPhone2, BUSINESS2_TELEPHONE_NUMBER),
    (PhoneNumberKey::Callback, CALLBACK_TELEPHONE_NUMBER),
    (PhoneNumberKey::CarPhone, CAR_TELEPHONE_NUMBER),
    (PhoneNumberKey::CompanyMainPhone, COMPANY_MAIN_PHONE_NUMBER),
    (PhoneNumberKey::HomeFax, HOME_FAX_NUMBER),
    (PhoneNumberKey::HomePhone, HOME_TELEPHONE_NUMBER),
    (PhoneNumberKey::HomePhone2, HOME2_TELEPHONE_NUMBER),
    (PhoneNumberKey::Isdn, ISDN_NUMBER),
    (PhoneNumberKey::MobilePhone, MOBILE_TELEPHONE_NUMBER),
    (PhoneNumberKey::OtherFax, PRIMARY_FAX_NUMBER),
    (PhoneNumberKey::OtherTelephone, OTHER_TELEPHONE_NUMBER),
    (PhoneNumberKey::Pager, PAGER_TELEPHONE_NUMBER),
    (PhoneNumberKey::PrimaryPhone, PRIMARY_TELEPHONE_NUMBER),
    (PhoneNumberKey::RadioPhone, RADIO_TELEPHONE_NUMBER),
    (PhoneNumberKey::Telex, TELEX_NUMBER),
    (PhoneNumberKey::TtyTddPhone, TTY_TDD_PHONE_NUMBER),
];

const FILE_AS_IDS: [(FileAsMapping, i32); 18] = [
    (FileAsMapping::None, -1),
    (FileAsMapping::Empty, 0x0000),
    (FileAsMapping::DisplayName, 0x3001),
    (FileAsMapping::FirstName, 0x3A06),
    (FileAsMapping::LastName, 0x3A11),
    (FileAsMapping::Company, 0x3A16),
    (FileAsMapping::LastCommaFirst, 0x8017),
    (FileAsMapping::CompanyLastCommaFirst, 0x8018),
    (FileAsMapping::LastCommaFirstCompany, 0x8019),
    (FileAsMapping::LastFirst, 0x8030),
    (FileAsMapping::LastSpaceFirst, 0x8031),
    (FileAsMapping::CompanyLastFirst, 0x8032),
    (FileAsMapping::CompanyLastSpaceFirst, 0x8033),
    (FileAsMapping::LastFirstCompany, 0x8034),
    (FileAsMapping::LastSpaceFirstCompany, 0x8035),
    (FileAsMapping::LastFirstMiddleSuffix, 0x8036),
    (FileAsMapping::FirstSpaceLast, 0x8037),
    (FileAsMapping::LastFirstSuffix, 0x8038),
];

pub(crate) fn file_as_mapping(id: i32) -> Option<FileAsMapping> {
    FILE_AS_IDS
        .iter()
        .find(|(_, known)| *known == id)
        .map(|(mapping, _)| *mapping)
}

pub(crate) fn file_as_id(mapping: FileAsMapping) -> Option<i32> {
    FILE_AS_IDS
        .iter()
        .find(|(known, _)| *known == mapping)
        .map(|(_, id)| *id)
}

const EMAIL_KEYS: [EmailAddressKey; 3] = [
    EmailAddressKey::EmailAddress1,
    EmailAddressKey::EmailAddress2,
    EmailAddressKey::EmailAddress3,
];

const ADDRESSES: [(PhysicalAddressKey, &AddressGroup); 3] = [
    (PhysicalAddressKey::Home, &HOME_ADDRESS),
    (PhysicalAddressKey::Business, &WORK_ADDRESS),
    (PhysicalAddressKey::Other, &OTHER_ADDRESS),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ContactFieldSet(u64);

impl ContactFieldSet {
    pub const ID: u64 = 1;
    pub const PARENT: u64 = 1 << 1;
    pub const CLASS: u64 = 1 << 2;
    pub const SUBJECT: u64 = 1 << 3;
    pub const SENSITIVITY: u64 = 1 << 4;
    pub const BODY: u64 = 1 << 5;
    pub const CATEGORIES: u64 = 1 << 6;
    pub const LAST_MODIFIED: u64 = 1 << 7;
    pub const HAS_ATTACHMENTS: u64 = 1 << 8;
    pub const FILE_AS: u64 = 1 << 9;
    pub const DISPLAY_NAME: u64 = 1 << 10;
    pub const GIVEN_NAME: u64 = 1 << 11;
    pub const INITIALS: u64 = 1 << 12;
    pub const MIDDLE_NAME: u64 = 1 << 13;
    pub const NICKNAME: u64 = 1 << 14;
    pub const COMPLETE_NAME: u64 = 1 << 15;
    pub const COMPANY_NAME: u64 = 1 << 16;
    pub const EMAIL_ADDRESSES: u64 = 1 << 17;
    pub const PHYSICAL_ADDRESSES: u64 = 1 << 18;
    pub const PHONE_NUMBERS: u64 = 1 << 19;
    pub const ASSISTANT_NAME: u64 = 1 << 20;
    pub const BIRTHDAY: u64 = 1 << 21;
    pub const BUSINESS_HOME_PAGE: u64 = 1 << 22;
    pub const CHILDREN: u64 = 1 << 23;
    pub const CONTACT_SOURCE: u64 = 1 << 24;
    pub const DEPARTMENT: u64 = 1 << 25;
    pub const GENERATION: u64 = 1 << 26;
    pub const IM_ADDRESSES: u64 = 1 << 27;
    pub const JOB_TITLE: u64 = 1 << 28;
    pub const MANAGER: u64 = 1 << 29;
    pub const OFFICE_LOCATION: u64 = 1 << 30;
    pub const POSTAL_ADDRESS_INDEX: u64 = 1 << 31;
    pub const PROFESSION: u64 = 1 << 32;
    pub const SPOUSE_NAME: u64 = 1 << 33;
    pub const SURNAME: u64 = 1 << 34;
    pub const WEDDING_ANNIVERSARY: u64 = 1 << 35;
    pub const HAS_PICTURE: u64 = 1 << 36;
    pub const LOCAL_DATES: u64 = 1 << 37;
    pub const DISPLAY_NAME_PREFIX: u64 = 1 << 38;
    pub const YOMI_NAMES: u64 = 1 << 39;
    pub const FILE_AS_MAPPING: u64 = 1 << 40;
    pub const BODY_HTML: u64 = 1 << 41;
    pub const MEMBERS: u64 = 1 << 42;
    pub const KIND: u64 = 1 << 43;
    const DEFAULT_SHAPE: u64 = 1 << 44;

    const LAST: u64 = Self::FILE_AS_MAPPING;
    const ALL: u64 = ((Self::LAST << 1) - 1) | Self::MEMBERS;
    const GET_ONLY: u64 = Self::BODY | Self::MEMBERS;
    const NOT_IN_DEFAULT: u64 = Self::PARENT
        | Self::CLASS
        | Self::SUBJECT
        | Self::SENSITIVITY
        | Self::LAST_MODIFIED
        | Self::COMPLETE_NAME
        | Self::CONTACT_SOURCE
        | Self::POSTAL_ADDRESS_INDEX
        | Self::HAS_PICTURE
        | Self::FILE_AS_MAPPING;
    const DEFAULT: u64 = Self::ALL & !Self::GET_ONLY & !Self::NOT_IN_DEFAULT;
    const DISTLIST_DEFAULT: u64 = Self::SUBJECT;

    pub fn from_shape(shape: &ItemShape<'_>) -> Self {
        let mut fields = match shape.base {
            BaseShape::IdOnly => Self::ID,
            BaseShape::Default => Self::DEFAULT | Self::DEFAULT_SHAPE,
            BaseShape::AllProperties | BaseShape::PcxPeopleSearch => Self::ALL,
        };
        for path in &shape.additional {
            fields |= match path {
                Path::Field(field) => Self::of_field(*field),
                Path::Indexed { field, .. } => Self::of_indexed(*field),
                Path::Extended(_) => 0,
            };
        }
        if shape.body_type == Some(BodyTypeResponse::Html) {
            fields |= Self::BODY_HTML;
        }
        ContactFieldSet(fields)
    }

    pub const fn id_only() -> Self {
        ContactFieldSet(Self::ID)
    }

    pub const fn all() -> Self {
        ContactFieldSet(Self::ALL)
    }

    pub const fn for_list(self) -> Self {
        ContactFieldSet((self.0 & !Self::GET_ONLY) | Self::KIND)
    }

    const fn for_distlist(self) -> Self {
        if self.has(Self::DEFAULT_SHAPE) {
            ContactFieldSet(self.0 | Self::DISTLIST_DEFAULT)
        } else {
            self
        }
    }

    pub const fn with_kind(self) -> Self {
        ContactFieldSet(self.0 | Self::KIND)
    }

    pub const fn has(self, field: u64) -> bool {
        self.0 & field != 0
    }

    pub const fn needs_content(self) -> bool {
        self.0 & !(Self::ID | Self::PARENT | Self::BODY_HTML | Self::KIND) != 0
    }

    fn of_field(field: UnindexedField) -> u64 {
        match field {
            UnindexedField::ItemItemId => Self::ID,
            UnindexedField::ItemParentFolderId => Self::PARENT,
            UnindexedField::ItemItemClass => Self::CLASS,
            UnindexedField::ItemSubject => Self::SUBJECT,
            UnindexedField::ItemSensitivity => Self::SENSITIVITY,
            UnindexedField::ItemBody => Self::BODY,
            UnindexedField::ItemCategories => Self::CATEGORIES,
            UnindexedField::ItemLastModifiedTime => Self::LAST_MODIFIED,
            UnindexedField::ItemHasAttachments => Self::HAS_ATTACHMENTS,
            UnindexedField::ContactsFileAs => Self::FILE_AS,
            UnindexedField::ContactsFileAsMapping => Self::FILE_AS_MAPPING,
            UnindexedField::ContactsDisplayName => Self::DISPLAY_NAME,
            UnindexedField::ContactsGivenName => Self::GIVEN_NAME,
            UnindexedField::ContactsInitials => Self::INITIALS,
            UnindexedField::ContactsMiddleName => Self::MIDDLE_NAME,
            UnindexedField::ContactsNickname => Self::NICKNAME,
            UnindexedField::ContactsCompleteName => Self::COMPLETE_NAME,
            UnindexedField::ContactsCompanyName => Self::COMPANY_NAME,
            UnindexedField::ContactsEmailAddresses => Self::EMAIL_ADDRESSES,
            UnindexedField::ContactsPhysicalAddresses => Self::PHYSICAL_ADDRESSES,
            UnindexedField::ContactsPhoneNumbers => Self::PHONE_NUMBERS,
            UnindexedField::ContactsAssistantName => Self::ASSISTANT_NAME,
            UnindexedField::ContactsBirthday => Self::BIRTHDAY,
            UnindexedField::ContactsBusinessHomePage => Self::BUSINESS_HOME_PAGE,
            UnindexedField::ContactsChildren => Self::CHILDREN,
            UnindexedField::ContactsContactSource => Self::CONTACT_SOURCE,
            UnindexedField::ContactsDepartment => Self::DEPARTMENT,
            UnindexedField::ContactsGeneration => Self::GENERATION,
            UnindexedField::ContactsImAddresses => Self::IM_ADDRESSES,
            UnindexedField::ContactsJobTitle => Self::JOB_TITLE,
            UnindexedField::ContactsManager => Self::MANAGER,
            UnindexedField::ContactsOfficeLocation => Self::OFFICE_LOCATION,
            UnindexedField::ContactsPostalAddressIndex => Self::POSTAL_ADDRESS_INDEX,
            UnindexedField::ContactsProfession => Self::PROFESSION,
            UnindexedField::ContactsSpouseName => Self::SPOUSE_NAME,
            UnindexedField::ContactsSurname => Self::SURNAME,
            UnindexedField::ContactsWeddingAnniversary => Self::WEDDING_ANNIVERSARY,
            UnindexedField::ContactsHasPicture => Self::HAS_PICTURE,
            UnindexedField::DistributionlistMembers => Self::MEMBERS,
            _ => 0,
        }
    }

    fn of_indexed(field: DictionaryField) -> u64 {
        match field {
            DictionaryField::ContactsEmailAddress => Self::EMAIL_ADDRESSES,
            DictionaryField::ContactsPhoneNumber => Self::PHONE_NUMBERS,
            DictionaryField::ContactsImAddress => Self::IM_ADDRESSES,
            DictionaryField::ContactsPhysicalAddressStreet
            | DictionaryField::ContactsPhysicalAddressCity
            | DictionaryField::ContactsPhysicalAddressState
            | DictionaryField::ContactsPhysicalAddressCountryOrRegion
            | DictionaryField::ContactsPhysicalAddressPostalCode => Self::PHYSICAL_ADDRESSES,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactText {
    ItemClass,
    Subject,
    FileAs,
    DisplayName,
    GivenName,
    Surname,
    CompanyName,
    JobTitle,
    Department,
    Email(EmailAddressKey),
}

impl ContactText {
    pub fn of_path(path: &Path<'_>) -> Option<Self> {
        match path {
            Path::Field(field) => match field {
                UnindexedField::ItemItemClass => Some(ContactText::ItemClass),
                UnindexedField::ItemSubject => Some(ContactText::Subject),
                UnindexedField::ContactsFileAs => Some(ContactText::FileAs),
                UnindexedField::ContactsDisplayName => Some(ContactText::DisplayName),
                UnindexedField::ContactsGivenName => Some(ContactText::GivenName),
                UnindexedField::ContactsSurname => Some(ContactText::Surname),
                UnindexedField::ContactsCompanyName => Some(ContactText::CompanyName),
                UnindexedField::ContactsJobTitle => Some(ContactText::JobTitle),
                UnindexedField::ContactsDepartment => Some(ContactText::Department),
                _ => None,
            },
            Path::Indexed {
                field: DictionaryField::ContactsEmailAddress,
                index,
            } => EmailAddressKey::parse(index.as_bytes()).map(ContactText::Email),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ContactProps<'p>(&'p PropBag);

impl<'p> ContactProps<'p> {
    pub fn new(props: &'p PropBag) -> Self {
        ContactProps(props)
    }

    pub fn is_distlist(self) -> bool {
        self.str(PropKeyRef::Tag(MESSAGE_CLASS))
            .is_some_and(|class| class.starts_with(DISTLIST_CLASS))
    }

    pub fn render_distlist(self, fields: ContactFieldSet) -> DistributionListItem<'p> {
        let fields = fields.for_distlist();
        let display_name = self.tag_text(DISPLAY_NAME);
        let item = self.item_fields(fields, DISTLIST_CLASS, display_name.as_ref());
        let mut list = DistributionListFields::default();
        if fields.has(ContactFieldSet::FILE_AS) {
            list.file_as = self.file_as(display_name.as_ref());
        }
        if fields.has(ContactFieldSet::DISPLAY_NAME) {
            list.display_name = Some(display_name.unwrap_or_default());
        }
        if fields.has(ContactFieldSet::CONTACT_SOURCE) {
            list.contact_source = Some(ContactSource::Store);
        }
        DistributionListItem { item, list }
    }

    pub fn render(self, fields: ContactFieldSet) -> ContactItem<'p> {
        let mut contact = ContactFields::default();
        let display_name = self.tag_text(DISPLAY_NAME);
        let item = self.item_fields(fields, CONTACT_CLASS, display_name.as_ref());
        if fields.has(ContactFieldSet::FILE_AS) {
            contact.file_as = self.file_as(display_name.as_ref());
        }
        if fields.has(ContactFieldSet::FILE_AS_MAPPING) {
            contact.file_as_mapping =
                match self.0.get(address_lid(LID_FILE_UNDER_ID), PropType::I32) {
                    Some(OwnedPropValue::I32(id)) => file_as_mapping(*id),
                    _ => None,
                };
        }
        if fields.has(ContactFieldSet::DISPLAY_NAME) {
            contact.display_name = Some(display_name.clone().unwrap_or_default());
        }
        let text_fields: [(u64, PropId, &mut Option<Cow<'p, str>>); 16] = [
            (
                ContactFieldSet::GIVEN_NAME,
                GIVEN_NAME,
                &mut contact.given_name,
            ),
            (ContactFieldSet::INITIALS, INITIALS, &mut contact.initials),
            (
                ContactFieldSet::MIDDLE_NAME,
                MIDDLE_NAME,
                &mut contact.middle_name,
            ),
            (ContactFieldSet::NICKNAME, NICKNAME, &mut contact.nickname),
            (
                ContactFieldSet::COMPANY_NAME,
                COMPANY_NAME,
                &mut contact.company_name,
            ),
            (
                ContactFieldSet::ASSISTANT_NAME,
                ASSISTANT,
                &mut contact.assistant_name,
            ),
            (
                ContactFieldSet::BUSINESS_HOME_PAGE,
                BUSINESS_HOME_PAGE,
                &mut contact.business_home_page,
            ),
            (
                ContactFieldSet::DEPARTMENT,
                DEPARTMENT_NAME,
                &mut contact.department,
            ),
            (
                ContactFieldSet::GENERATION,
                GENERATION,
                &mut contact.generation,
            ),
            (ContactFieldSet::JOB_TITLE, TITLE, &mut contact.job_title),
            (ContactFieldSet::MANAGER, MANAGER_NAME, &mut contact.manager),
            (
                ContactFieldSet::OFFICE_LOCATION,
                OFFICE_LOCATION,
                &mut contact.office_location,
            ),
            (
                ContactFieldSet::PROFESSION,
                PROFESSION,
                &mut contact.profession,
            ),
            (
                ContactFieldSet::SPOUSE_NAME,
                SPOUSE_NAME,
                &mut contact.spouse_name,
            ),
            (ContactFieldSet::SURNAME, SURNAME, &mut contact.surname),
            (
                ContactFieldSet::DISPLAY_NAME_PREFIX,
                DISPLAY_NAME_PREFIX,
                &mut contact.display_name_prefix,
            ),
        ];
        for (bit, id, slot) in text_fields {
            if fields.has(bit) {
                *slot = self.tag_text(id);
            }
        }
        if fields.has(ContactFieldSet::YOMI_NAMES) {
            contact.yomi_given_name = self.text(address_lid(LID_YOMI_FIRST_NAME));
            contact.yomi_surname = self.text(address_lid(LID_YOMI_LAST_NAME));
        }
        if fields.has(ContactFieldSet::COMPLETE_NAME) {
            contact.complete_name = Some(self.complete_name(display_name));
        }
        if fields.has(ContactFieldSet::EMAIL_ADDRESSES) {
            contact.email_addresses = self.email_addresses();
        }
        if fields.has(ContactFieldSet::PHYSICAL_ADDRESSES) {
            contact.physical_addresses = self.physical_addresses();
        }
        if fields.has(ContactFieldSet::PHONE_NUMBERS) {
            contact.phone_numbers = self.phone_numbers();
        }
        if fields.has(ContactFieldSet::IM_ADDRESSES) {
            contact.im_addresses =
                self.text(address_lid(LID_INSTANT_MESSAGING_ADDRESS))
                    .map(|value| {
                        List(vec![ImAddressEntry {
                            key: ImAddressKey::ImAddress1,
                            value,
                        }])
                    });
        }
        if fields.has(ContactFieldSet::BIRTHDAY) {
            contact.birthday = self.time(PropKeyRef::Tag(BIRTHDAY));
        }
        if fields.has(ContactFieldSet::WEDDING_ANNIVERSARY) {
            contact.wedding_anniversary = self.time(PropKeyRef::Tag(WEDDING_ANNIVERSARY));
        }
        if fields.has(ContactFieldSet::LOCAL_DATES) {
            contact.birthday_local = self.time(address_lid(LID_BIRTHDAY_LOCAL));
            contact.wedding_anniversary_local =
                self.time(address_lid(LID_WEDDING_ANNIVERSARY_LOCAL));
        }
        if fields.has(ContactFieldSet::CHILDREN) {
            contact.children = self.multi_text(PropKeyRef::Tag(CHILDRENS_NAMES));
        }
        if fields.has(ContactFieldSet::CONTACT_SOURCE) {
            contact.contact_source = Some(ContactSource::Store);
        }
        if fields.has(ContactFieldSet::POSTAL_ADDRESS_INDEX) {
            contact.postal_address_index = self.postal_address_index();
        }
        if fields.has(ContactFieldSet::HAS_PICTURE) {
            contact.has_picture = Some(matches!(
                self.0.get(address_lid(LID_HAS_PICTURE), PropType::Bool),
                Some(OwnedPropValue::Bool(true))
            ));
        }
        ContactItem { item, contact }
    }

    fn item_fields(
        self,
        fields: ContactFieldSet,
        class: &'static str,
        display_name: Option<&Cow<'p, str>>,
    ) -> ItemFields<'p> {
        let mut item = ItemFields::default();
        if fields.has(ContactFieldSet::CLASS) {
            item.item_class = Some(self.tag_text(MESSAGE_CLASS).unwrap_or(Cow::Borrowed(class)));
        }
        if fields.has(ContactFieldSet::SUBJECT) {
            item.subject = self
                .tag_text(NORMALIZED_SUBJECT)
                .or_else(|| display_name.cloned());
        }
        if fields.has(ContactFieldSet::SENSITIVITY) {
            item.sensitivity = Some(self.sensitivity());
        }
        if fields.has(ContactFieldSet::BODY) {
            let text = self.tag_text(BODY).unwrap_or_default();
            item.body = Some(if fields.has(ContactFieldSet::BODY_HTML) {
                Body {
                    body_type: BodyType::Html,
                    is_truncated: None,
                    text: Cow::Owned(text_to_html(&text)),
                }
            } else {
                Body {
                    body_type: BodyType::Text,
                    is_truncated: None,
                    text,
                }
            });
        }
        if fields.has(ContactFieldSet::CATEGORIES) {
            item.categories = self.multi_text(PropKeyRef::Lid {
                set: PS_PUBLIC_STRINGS,
                lid: LID_CATEGORIES,
            });
        }
        if fields.has(ContactFieldSet::LAST_MODIFIED) {
            item.last_modified_time = self.time(PropKeyRef::Tag(LAST_MODIFICATION_TIME));
        }
        if fields.has(ContactFieldSet::HAS_ATTACHMENTS) {
            item.has_attachments = Some(false);
        }
        item
    }

    fn file_as(self, display_name: Option<&Cow<'p, str>>) -> Option<Cow<'p, str>> {
        self.text(address_lid(LID_FILE_UNDER))
            .or_else(|| display_name.cloned())
            .or(Some(Cow::Borrowed("")))
    }

    pub fn field_text(self, field: ContactText) -> Option<&'p str> {
        let key = match field {
            ContactText::ItemClass => PropKeyRef::Tag(MESSAGE_CLASS),
            ContactText::Subject => {
                return self
                    .str(PropKeyRef::Tag(NORMALIZED_SUBJECT))
                    .or_else(|| self.field_text(ContactText::DisplayName));
            }
            ContactText::FileAs => {
                return self
                    .str(address_lid(LID_FILE_UNDER))
                    .or_else(|| self.field_text(ContactText::DisplayName));
            }
            ContactText::DisplayName => PropKeyRef::Tag(DISPLAY_NAME),
            ContactText::GivenName => PropKeyRef::Tag(GIVEN_NAME),
            ContactText::Surname => PropKeyRef::Tag(SURNAME),
            ContactText::CompanyName => PropKeyRef::Tag(COMPANY_NAME),
            ContactText::JobTitle => PropKeyRef::Tag(TITLE),
            ContactText::Department => PropKeyRef::Tag(DEPARTMENT_NAME),
            ContactText::Email(key) => {
                let index = EMAIL_KEYS.iter().position(|candidate| *candidate == key)?;
                address_lid(EMAIL_SLOTS.get(index)?.email)
            }
        };
        self.str(key)
    }

    pub fn last_modified(self) -> Option<FileTime> {
        match self
            .0
            .get(PropKeyRef::Tag(LAST_MODIFICATION_TIME), PropType::Time)
        {
            Some(OwnedPropValue::Time(time)) => Some(*time),
            _ => None,
        }
    }

    fn str(self, key: PropKeyRef<'_>) -> Option<&'p str> {
        match self.0.get(key, PropType::Unicode) {
            Some(OwnedPropValue::Unicode(text)) => Some(text),
            _ => None,
        }
    }

    fn complete_name(self, display_name: Option<Cow<'p, str>>) -> CompleteName<'p> {
        CompleteName {
            title: self.tag_text(DISPLAY_NAME_PREFIX),
            first_name: self.tag_text(GIVEN_NAME),
            middle_name: self.tag_text(MIDDLE_NAME),
            last_name: self.tag_text(SURNAME),
            suffix: self.tag_text(GENERATION),
            initials: self.tag_text(INITIALS),
            full_name: display_name,
            nickname: self.tag_text(NICKNAME),
            yomi_first_name: self.text(address_lid(LID_YOMI_FIRST_NAME)),
            yomi_last_name: self.text(address_lid(LID_YOMI_LAST_NAME)),
        }
    }

    fn email_addresses(self) -> Option<List<EmailAddressEntry<'p>>> {
        let entries = EMAIL_KEYS
            .into_iter()
            .zip(EMAIL_SLOTS.iter())
            .filter_map(|(key, slot)| {
                Some(EmailAddressEntry {
                    key,
                    name: slot
                        .display_name
                        .and_then(|lid| self.text(address_lid(lid))),
                    routing_type: None,
                    mailbox_type: None,
                    address: self.text(address_lid(slot.email))?,
                })
            })
            .collect::<Vec<_>>();
        (!entries.is_empty()).then_some(List(entries))
    }

    fn physical_addresses(self) -> Option<List<PhysicalAddressEntry<'p>>> {
        let entries = ADDRESSES
            .into_iter()
            .filter_map(|(key, group)| {
                let fields = PhysicalAddressFields {
                    street: self.text(group.street.key()),
                    city: self.text(group.city.key()),
                    state: self.text(group.state.key()),
                    country_or_region: self.text(group.country.key()),
                    postal_code: self.text(group.postal_code.key()),
                };
                (fields != PhysicalAddressFields::default())
                    .then_some(PhysicalAddressEntry { key, fields })
            })
            .collect::<Vec<_>>();
        (!entries.is_empty()).then_some(List(entries))
    }

    fn phone_numbers(self) -> Option<List<PhoneNumberEntry<'p>>> {
        let entries = PHONES
            .into_iter()
            .filter_map(|(key, id)| {
                Some(PhoneNumberEntry {
                    key,
                    value: self.tag_text(id)?,
                })
            })
            .collect::<Vec<_>>();
        (!entries.is_empty()).then_some(List(entries))
    }

    fn postal_address_index(self) -> Option<PhysicalAddressIndex> {
        let Some(OwnedPropValue::I32(id)) = self
            .0
            .get(address_lid(LID_POSTAL_ADDRESS_ID), PropType::I32)
        else {
            return None;
        };
        Some(match *id {
            id if id == HOME_ADDRESS.postal_id => PhysicalAddressIndex::Home,
            id if id == WORK_ADDRESS.postal_id => PhysicalAddressIndex::Business,
            id if id == OTHER_ADDRESS.postal_id => PhysicalAddressIndex::Other,
            _ => PhysicalAddressIndex::None,
        })
    }

    fn sensitivity(self) -> Sensitivity {
        match self.0.get(PropKeyRef::Tag(SENSITIVITY), PropType::I32) {
            Some(OwnedPropValue::I32(1)) => Sensitivity::Personal,
            Some(OwnedPropValue::I32(2)) => Sensitivity::Private,
            Some(OwnedPropValue::I32(3)) => Sensitivity::Confidential,
            _ => Sensitivity::Normal,
        }
    }

    fn tag_text(self, id: PropId) -> Option<Cow<'p, str>> {
        self.text(PropKeyRef::Tag(id))
    }

    fn text(self, key: PropKeyRef<'_>) -> Option<Cow<'p, str>> {
        self.str(key).map(Cow::Borrowed)
    }

    fn multi_text(self, key: PropKeyRef<'_>) -> Option<Strings<'p>> {
        match self.0.get(key, PropType::MvUnicode) {
            Some(OwnedPropValue::MvUnicode(list)) if !list.is_empty() => Some(Strings(
                list.iter().map(|text| Cow::Borrowed(&**text)).collect(),
            )),
            _ => None,
        }
    }

    fn time(self, key: PropKeyRef<'_>) -> Option<DateTime> {
        match self.0.get(key, PropType::Time) {
            Some(OwnedPropValue::Time(time)) => Some(DateTime::utc(time.to_utc().0)),
            _ => None,
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ews/contact/tests.rs"]
mod tests;
