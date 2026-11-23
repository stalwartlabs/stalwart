/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::mapi::prop::{PropId, PropKeyRef, sets::PSETID_ADDRESS};

pub(crate) const CONTACT_CLASS: &str = "IPM.Contact";
pub(crate) const PHOTO_FILE_STEM: &str = "ContactPicture";

pub(crate) const SENSITIVITY: PropId = PropId(0x0036);
pub(crate) const CONVERSATION_TOPIC: PropId = PropId(0x0070);
pub(crate) const NORMALIZED_SUBJECT: PropId = PropId(0x0E1D);
pub(crate) const BODY: PropId = PropId(0x1000);
pub(crate) const LAST_MODIFICATION_TIME: PropId = PropId(0x3008);
pub(crate) const DISPLAY_NAME: PropId = PropId(0x3001);
pub(crate) const ATTACH_EXTENSION: PropId = PropId(0x3703);
pub(crate) const ATTACH_FILENAME: PropId = PropId(0x3704);
pub(crate) const ATTACH_LONG_FILENAME: PropId = PropId(0x3707);
pub(crate) const ATTACH_METHOD: PropId = PropId(0x3705);
pub(crate) const ATTACHMENT_CONTACT_PHOTO: PropId = PropId(0x7FFF);
pub(crate) const ACCOUNT: PropId = PropId(0x3A00);
pub(crate) const CALLBACK_TELEPHONE_NUMBER: PropId = PropId(0x3A02);
pub(crate) const GENERATION: PropId = PropId(0x3A05);
pub(crate) const GIVEN_NAME: PropId = PropId(0x3A06);
pub(crate) const BUSINESS_TELEPHONE_NUMBER: PropId = PropId(0x3A08);
pub(crate) const HOME_TELEPHONE_NUMBER: PropId = PropId(0x3A09);
pub(crate) const SURNAME: PropId = PropId(0x3A11);
pub(crate) const COMPANY_NAME: PropId = PropId(0x3A16);
pub(crate) const TITLE: PropId = PropId(0x3A17);
pub(crate) const DEPARTMENT_NAME: PropId = PropId(0x3A18);
pub(crate) const PRIMARY_TELEPHONE_NUMBER: PropId = PropId(0x3A1A);
pub(crate) const BUSINESS2_TELEPHONE_NUMBER: PropId = PropId(0x3A1B);
pub(crate) const MOBILE_TELEPHONE_NUMBER: PropId = PropId(0x3A1C);
pub(crate) const RADIO_TELEPHONE_NUMBER: PropId = PropId(0x3A1D);
pub(crate) const CAR_TELEPHONE_NUMBER: PropId = PropId(0x3A1E);
pub(crate) const OTHER_TELEPHONE_NUMBER: PropId = PropId(0x3A1F);
pub(crate) const PAGER_TELEPHONE_NUMBER: PropId = PropId(0x3A21);
pub(crate) const PRIMARY_FAX_NUMBER: PropId = PropId(0x3A23);
pub(crate) const BUSINESS_FAX_NUMBER: PropId = PropId(0x3A24);
pub(crate) const HOME_FAX_NUMBER: PropId = PropId(0x3A25);
pub(crate) const COUNTRY: PropId = PropId(0x3A26);
pub(crate) const LOCALITY: PropId = PropId(0x3A27);
pub(crate) const STATE_OR_PROVINCE: PropId = PropId(0x3A28);
pub(crate) const STREET_ADDRESS: PropId = PropId(0x3A29);
pub(crate) const POSTAL_CODE: PropId = PropId(0x3A2A);
pub(crate) const POST_OFFICE_BOX: PropId = PropId(0x3A2B);
pub(crate) const TELEX_NUMBER: PropId = PropId(0x3A2C);
pub(crate) const ISDN_NUMBER: PropId = PropId(0x3A2D);
pub(crate) const ASSISTANT_TELEPHONE_NUMBER: PropId = PropId(0x3A2E);
pub(crate) const HOME2_TELEPHONE_NUMBER: PropId = PropId(0x3A2F);
pub(crate) const ASSISTANT: PropId = PropId(0x3A30);
pub(crate) const WEDDING_ANNIVERSARY: PropId = PropId(0x3A41);
pub(crate) const BIRTHDAY: PropId = PropId(0x3A42);
pub(crate) const HOBBIES: PropId = PropId(0x3A43);
pub(crate) const MIDDLE_NAME: PropId = PropId(0x3A44);
pub(crate) const DISPLAY_NAME_PREFIX: PropId = PropId(0x3A45);
pub(crate) const PROFESSION: PropId = PropId(0x3A46);
pub(crate) const SPOUSE_NAME: PropId = PropId(0x3A48);
pub(crate) const TTY_TDD_PHONE_NUMBER: PropId = PropId(0x3A4B);
pub(crate) const MANAGER_NAME: PropId = PropId(0x3A4E);
pub(crate) const NICKNAME: PropId = PropId(0x3A4F);
pub(crate) const PERSONAL_HOME_PAGE: PropId = PropId(0x3A50);
pub(crate) const BUSINESS_HOME_PAGE: PropId = PropId(0x3A51);
pub(crate) const COMPANY_MAIN_PHONE_NUMBER: PropId = PropId(0x3A57);
pub(crate) const CHILDRENS_NAMES: PropId = PropId(0x3A58);
pub(crate) const USER_X509_CERTIFICATE: PropId = PropId(0x3A70);
pub(crate) const INITIALS: PropId = PropId(0x3A0A);
pub(crate) const OFFICE_LOCATION: PropId = PropId(0x3A19);

pub(crate) const LID_FILE_UNDER: u32 = 0x8005;
pub(crate) const LID_FILE_UNDER_ID: u32 = 0x8006;
pub(crate) const LID_HAS_PICTURE: u32 = 0x8015;
pub(crate) const LID_POSTAL_ADDRESS_ID: u32 = 0x8022;
pub(crate) const LID_ADDRESS_BOOK_PROVIDER_EMAIL_LIST: u32 = 0x8028;
pub(crate) const LID_ADDRESS_BOOK_PROVIDER_ARRAY_TYPE: u32 = 0x8029;
pub(crate) const LID_YOMI_FIRST_NAME: u32 = 0x802C;
pub(crate) const LID_YOMI_LAST_NAME: u32 = 0x802D;
pub(crate) const LID_BUSINESS_CARD_DISPLAY_DEFINITION: u32 = 0x8040;
pub(crate) const LID_CONTACT_USER_FIELDS: [u32; 4] = [0x804F, 0x8050, 0x8051, 0x8052];
pub(crate) const LID_INSTANT_MESSAGING_ADDRESS: u32 = 0x8062;
pub(crate) const LID_FREE_BUSY_LOCATION: u32 = 0x80D8;
pub(crate) const LID_BIRTHDAY_LOCAL: u32 = 0x80DE;
pub(crate) const LID_WEDDING_ANNIVERSARY_LOCAL: u32 = 0x80DF;
pub(crate) const LID_CATEGORIES: u32 = 0x2328;

pub(crate) const HOME_ADDRESS_STREET: PropId = PropId(0x3A5D);
pub(crate) const HOME_ADDRESS_CITY: PropId = PropId(0x3A59);
pub(crate) const HOME_ADDRESS_STATE: PropId = PropId(0x3A5C);
pub(crate) const HOME_ADDRESS_POSTAL_CODE: PropId = PropId(0x3A5B);
pub(crate) const HOME_ADDRESS_COUNTRY: PropId = PropId(0x3A5A);
pub(crate) const OTHER_ADDRESS_STREET: PropId = PropId(0x3A63);
pub(crate) const OTHER_ADDRESS_CITY: PropId = PropId(0x3A5F);
pub(crate) const OTHER_ADDRESS_STATE: PropId = PropId(0x3A62);
pub(crate) const OTHER_ADDRESS_POSTAL_CODE: PropId = PropId(0x3A61);
pub(crate) const OTHER_ADDRESS_COUNTRY: PropId = PropId(0x3A60);
pub(crate) const LID_WORK_ADDRESS_STREET: u32 = 0x8045;
pub(crate) const LID_WORK_ADDRESS_CITY: u32 = 0x8046;
pub(crate) const LID_WORK_ADDRESS_STATE: u32 = 0x8047;
pub(crate) const LID_WORK_ADDRESS_POSTAL_CODE: u32 = 0x8048;
pub(crate) const LID_WORK_ADDRESS_COUNTRY: u32 = 0x8049;

pub(crate) const fn address_lid(lid: u32) -> PropKeyRef<'static> {
    PropKeyRef::Lid {
        set: PSETID_ADDRESS,
        lid,
    }
}

pub(crate) enum AddressKey {
    Tag(PropId),
    Lid(u32),
}

impl AddressKey {
    pub(crate) const fn key(&self) -> PropKeyRef<'static> {
        match self {
            AddressKey::Tag(id) => PropKeyRef::Tag(*id),
            AddressKey::Lid(lid) => address_lid(*lid),
        }
    }
}

pub(crate) struct AddressGroup {
    pub postal_id: i32,
    pub po_box: AddressKey,
    pub street: AddressKey,
    pub city: AddressKey,
    pub state: AddressKey,
    pub postal_code: AddressKey,
    pub country: AddressKey,
}

impl AddressGroup {
    pub(crate) const fn keys(&self) -> [&AddressKey; 6] {
        [
            &self.po_box,
            &self.street,
            &self.city,
            &self.state,
            &self.postal_code,
            &self.country,
        ]
    }
}

pub(crate) const HOME_ADDRESS: AddressGroup = AddressGroup {
    postal_id: 1,
    po_box: AddressKey::Tag(PropId(0x3A5E)),
    street: AddressKey::Tag(HOME_ADDRESS_STREET),
    city: AddressKey::Tag(HOME_ADDRESS_CITY),
    state: AddressKey::Tag(HOME_ADDRESS_STATE),
    postal_code: AddressKey::Tag(HOME_ADDRESS_POSTAL_CODE),
    country: AddressKey::Tag(HOME_ADDRESS_COUNTRY),
};
pub(crate) const WORK_ADDRESS: AddressGroup = AddressGroup {
    postal_id: 2,
    po_box: AddressKey::Lid(0x804A),
    street: AddressKey::Lid(LID_WORK_ADDRESS_STREET),
    city: AddressKey::Lid(LID_WORK_ADDRESS_CITY),
    state: AddressKey::Lid(LID_WORK_ADDRESS_STATE),
    postal_code: AddressKey::Lid(LID_WORK_ADDRESS_POSTAL_CODE),
    country: AddressKey::Lid(LID_WORK_ADDRESS_COUNTRY),
};
pub(crate) const OTHER_ADDRESS: AddressGroup = AddressGroup {
    postal_id: 3,
    po_box: AddressKey::Tag(PropId(0x3A64)),
    street: AddressKey::Tag(OTHER_ADDRESS_STREET),
    city: AddressKey::Tag(OTHER_ADDRESS_CITY),
    state: AddressKey::Tag(OTHER_ADDRESS_STATE),
    postal_code: AddressKey::Tag(OTHER_ADDRESS_POSTAL_CODE),
    country: AddressKey::Tag(OTHER_ADDRESS_COUNTRY),
};
pub(crate) const POSTAL_ADDRESS_GROUPS: [&AddressGroup; 3] =
    [&HOME_ADDRESS, &WORK_ADDRESS, &OTHER_ADDRESS];

pub(crate) fn known_postal_address_id(id: i32) -> bool {
    id == 0
        || POSTAL_ADDRESS_GROUPS
            .iter()
            .any(|group| group.postal_id == id)
}

pub(crate) const MAILING_ADDRESS: [PropId; 6] = [
    POST_OFFICE_BOX,
    STREET_ADDRESS,
    LOCALITY,
    STATE_OR_PROVINCE,
    POSTAL_CODE,
    COUNTRY,
];

pub(crate) struct ElectronicSlot {
    pub index: i32,
    pub display_name: Option<u32>,
    pub address_type: u32,
    pub email: u32,
    pub original_display_name: u32,
    pub original_entry_id: u32,
}

const fn email_slot(index: i32, base: u32) -> ElectronicSlot {
    ElectronicSlot {
        index,
        display_name: Some(base),
        address_type: base + 2,
        email: base + 3,
        original_display_name: base + 4,
        original_entry_id: base + 5,
    }
}

const fn fax_slot(index: i32, base: u32) -> ElectronicSlot {
    ElectronicSlot {
        index,
        display_name: None,
        address_type: base,
        email: base + 1,
        original_display_name: base + 2,
        original_entry_id: base + 3,
    }
}

pub(crate) const EMAIL_SLOTS: [ElectronicSlot; 3] = [
    email_slot(0, 0x8080),
    email_slot(1, 0x8090),
    email_slot(2, 0x80A0),
];
pub(crate) const EMAIL_PROP_IDS: [&str; 3] = ["email1", "email2", "email3"];
pub(crate) const BUSINESS2_PROP_ID: &str = "business2";
pub(crate) const HOME2_PROP_ID: &str = "home2";
pub(crate) const BUSINESS_FAX_SLOT: ElectronicSlot = fax_slot(3, 0x80C2);
pub(crate) const HOME_FAX_SLOT: ElectronicSlot = fax_slot(4, 0x80D2);
pub(crate) const PRIMARY_FAX_SLOT: ElectronicSlot = fax_slot(5, 0x80B2);
