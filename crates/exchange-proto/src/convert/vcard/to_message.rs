/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, collections::HashSet, ops::Range};

use bytes::Bytes;
use calcard::{
    common::PartialDateTime,
    vcard::{
        VCard, VCardEntry, VCardParameterName, VCardParameterValue, VCardProperty, VCardType,
        VCardValue,
    },
};
use jiff::{
    civil::{Date, Time},
    tz::TimeZone,
};
use smallvec::SmallVec;

use super::{
    patch::impp_handle,
    props::*,
    related::{Form, Labels, OtherName, Relation, related_name, relation_property},
    sink::{ContactSink, MessageSink, OriginSink},
};
use crate::{
    common::time::{FileTime, UtcSeconds},
    convert::{ConvertError, context::ConvertOptions, model::MessageContent, tags},
    mapi::{
        prop::{OwnedPropValue, PropId, PropKey, PropKeyRef},
        recipient::one_off,
    },
};

const SMTP: &str = "SMTP";
const FAX: &str = "FAX";
const TEL_URI_PREFIX: &str = "tel:";
const STREET_SEPARATOR: &str = "\r\n";
const UNIT_SEPARATOR: &str = ", ";
const BIRTHDAY_UTC_HOUR: i8 = 11;
const BIRTHDAY_UTC_MINUTE: i8 = 59;
const LINEAR_SCAN_MAX: usize = 16;

#[derive(Clone, Copy, Default)]
struct Types(u32);

impl Types {
    const WORK: u32 = 1 << 0;
    const HOME: u32 = 1 << 1;
    const PREF: u32 = 1 << 2;
    const FAX: u32 = 1 << 3;
    const CELL: u32 = 1 << 4;
    const PAGER: u32 = 1 << 5;
    const CAR: u32 = 1 << 6;
    const ISDN: u32 = 1 << 7;
    const VOICE: u32 = 1 << 8;
    const OTHER_LINE: u32 = 1 << 9;
    const POSTAL: u32 = 1 << 10;
    const TEXTPHONE: u32 = 1 << 11;
    const MAIN: u32 = 1 << 12;
    const ASSISTANT: u32 = 1 << 13;
    const CALLBACK: u32 = 1 << 14;
    const RADIO: u32 = 1 << 15;
    const TELEX: u32 = 1 << 16;

    fn of(entry: &VCardEntry) -> Self {
        let mut types = 0;
        for param in &entry.params {
            types |= match (&param.name, &param.value) {
                (VCardParameterName::Pref, _) => Self::PREF,
                (VCardParameterName::Type, VCardParameterValue::Type(typ)) => match typ {
                    VCardType::Work => Self::WORK,
                    VCardType::Home => Self::HOME,
                    VCardType::Fax => Self::FAX,
                    VCardType::Cell => Self::CELL,
                    VCardType::Pager => Self::PAGER,
                    VCardType::Voice => Self::VOICE,
                    VCardType::Video => Self::OTHER_LINE,
                    VCardType::Textphone => Self::TEXTPHONE,
                    VCardType::MainNumber => Self::MAIN,
                    _ => 0,
                },
                (VCardParameterName::Type, VCardParameterValue::Text(text)) => {
                    hashify::map_ignore_case!(text.as_bytes(), u32,
                        "pref" => Types::PREF,
                        "car" => Types::CAR,
                        "isdn" => Types::ISDN,
                        "msg" => Types::OTHER_LINE,
                        "bbs" => Types::OTHER_LINE,
                        "modem" => Types::OTHER_LINE,
                        "postal" => Types::POSTAL,
                        "dom" => Types::POSTAL,
                        "intl" => Types::POSTAL,
                        "parcel" => Types::POSTAL,
                        "assistant" => Types::ASSISTANT,
                        "callback" => Types::CALLBACK,
                        "company" => Types::MAIN,
                        "radio" => Types::RADIO,
                        "tlx" => Types::TELEX,
                        "ttytdd" => Types::TEXTPHONE,
                        "ttyttd" => Types::TEXTPHONE,
                    )
                    .copied()
                    .unwrap_or_default()
                }
                _ => 0,
            };
        }
        Types(types)
    }

    fn has(self, bits: u32) -> bool {
        self.0 & bits != 0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EmailKind {
    Internet,
    Im,
    Telex,
}

impl EmailKind {
    fn of(entry: &VCardEntry) -> Self {
        Self::from_types(
            entry
                .params
                .iter()
                .filter(|param| param.name == VCardParameterName::Type)
                .filter_map(|param| match &param.value {
                    VCardParameterValue::Text(text) => Some(text.as_str()),
                    _ => None,
                }),
        )
    }

    fn from_types<'x>(mut types: impl Iterator<Item = &'x str>) -> Self {
        types.find_map(Self::parse).unwrap_or(EmailKind::Internet)
    }

    fn parse(text: &str) -> Option<Self> {
        hashify::map_ignore_case!(text.as_bytes(), EmailKind,
            "internet" => EmailKind::Internet,
            "im" => EmailKind::Im,
            "tlx" => EmailKind::Telex,
        )
        .copied()
    }
}

#[derive(Clone, Copy)]
enum SlotMarker {
    Email(usize),
    Phone(PropId),
}

impl SlotMarker {
    fn of(entry: &VCardEntry) -> Option<Self> {
        hashify::map!(entry.prop_id()?.as_bytes(), SlotMarker,
            "email1" => SlotMarker::Email(0),
            "email2" => SlotMarker::Email(1),
            "email3" => SlotMarker::Email(2),
            "business2" => SlotMarker::Phone(BUSINESS2_TELEPHONE_NUMBER),
            "home2" => SlotMarker::Phone(HOME2_TELEPHONE_NUMBER),
        )
        .copied()
    }
}

pub(super) fn is_internet_email_entry(entry: &VCardEntry) -> bool {
    EmailKind::of(entry) == EmailKind::Internet
}

pub(super) fn is_internet_email<'x>(types: impl Iterator<Item = &'x str>) -> bool {
    EmailKind::from_types(types) == EmailKind::Internet
}

#[derive(Clone, Copy)]
enum Extra {
    Class,
    UserText,
    ImAddress,
    Tel,
    Anniversary,
    Account,
    Interests,
    Design,
    FileAs,
    FileAsId,
    PostalAddressId,
    Initials,
    OfficeLocation,
    YomiFirstName,
    YomiLastName,
    Relation(OtherName),
}

struct Builder<'c, S> {
    sink: S,
    display_name: Option<&'c str>,
    emails: [Option<(&'c str, usize)>; EMAIL_SLOTS.len()],
    unslotted_emails: SmallVec<[(&'c str, usize); EMAIL_SLOTS.len()]>,
    faxes: Vec<(&'static ElectronicSlot, &'c str, usize)>,
    user_fields: usize,
    addresses: [bool; 3],
    address_entries: [Option<(&'c VCardEntry, usize)>; 3],
    postal_address_id: Option<i32>,
    preferred_postal_id: Option<i32>,
    has_url_home: bool,
    has_url_work: bool,
    has_photo: bool,
    max_decoded: u64,
    categories: Vec<Cow<'c, str>>,
    categories_origin: usize,
    children: Vec<Cow<'c, str>>,
    apple_children: SmallVec<[Range<usize>; 2]>,
    related_children: bool,
    legacy_children: Vec<Cow<'c, str>>,
    children_origin: usize,
    legacy_relations: SmallVec<[(Relation, &'c str, usize); 3]>,
    partner: Option<(&'c str, usize)>,
    labels: Labels<'c>,
    current: usize,
}

pub(super) fn contact(
    card: &VCard,
    opts: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    build(card, u64::from(opts.max_decoded), MessageSink::default()).map(|sink| sink.content)
}

pub(super) fn origins(card: &VCard) -> Result<Vec<(PropKey, usize)>, ConvertError> {
    build(card, u64::MAX, OriginSink::default()).map(|sink| sink.origins)
}

pub(super) fn build<'c, S: ContactSink<'c>>(
    card: &'c VCard,
    max_decoded: u64,
    sink: S,
) -> Result<S, ConvertError> {
    let mut builder = Builder::new(max_decoded, sink);
    builder.run(card)?;
    Ok(builder.sink)
}

impl<'c, S: ContactSink<'c>> Builder<'c, S> {
    fn new(max_decoded: u64, sink: S) -> Self {
        Builder {
            sink,
            display_name: None,
            emails: [None; EMAIL_SLOTS.len()],
            unslotted_emails: SmallVec::new(),
            faxes: Vec::new(),
            user_fields: 0,
            addresses: [false; 3],
            address_entries: [None; 3],
            postal_address_id: None,
            preferred_postal_id: None,
            has_url_home: false,
            has_url_work: false,
            has_photo: false,
            max_decoded,
            categories: Vec::new(),
            categories_origin: 0,
            children: Vec::new(),
            apple_children: SmallVec::new(),
            related_children: false,
            legacy_children: Vec::new(),
            children_origin: 0,
            legacy_relations: SmallVec::new(),
            partner: None,
            labels: Labels::default(),
            current: 0,
        }
    }

    fn run(&mut self, card: &'c VCard) -> Result<(), ConvertError> {
        self.labels = Labels::new(&card.entries);
        self.text(tags::MESSAGE_CLASS, CONTACT_CLASS);
        self.display_name = card
            .property(&VCardProperty::Fn)
            .and_then(|entry| entry.values.first())
            .and_then(VCardValue::as_text)
            .filter(|name| !name.is_empty());
        if let Some((index, name)) = card
            .entries
            .iter()
            .position(|entry| entry.name == VCardProperty::Fn)
            .zip(self.display_name)
        {
            self.current = index;
            self.text(DISPLAY_NAME, name);
            if S::FULL_MESSAGE {
                self.text(tags::SUBJECT, name);
                self.text(NORMALIZED_SUBJECT, name);
                self.text(CONVERSATION_TOPIC, name);
            }
        }
        for (index, entry) in card.entries.iter().enumerate() {
            self.current = index;
            self.entry(entry)?;
        }
        self.finish();
        Ok(())
    }

    fn entry(&mut self, entry: &'c VCardEntry) -> Result<(), ConvertError> {
        if !S::BINARY && matches!(entry.name, VCardProperty::Photo | VCardProperty::Key) {
            return Ok(());
        }
        match &entry.name {
            VCardProperty::N => {
                for (id, value) in [
                    SURNAME,
                    GIVEN_NAME,
                    MIDDLE_NAME,
                    DISPLAY_NAME_PREFIX,
                    GENERATION,
                ]
                .into_iter()
                .zip(&entry.values)
                {
                    if let Some(value) = component(value).filter(|value| !value.is_empty()) {
                        self.text(id, value);
                    }
                }
            }
            VCardProperty::Nickname => self.first_text(NICKNAME, entry),
            VCardProperty::Photo => self.photo(entry)?,
            VCardProperty::Bday => self.date_pair(BIRTHDAY, LID_BIRTHDAY_LOCAL, entry),
            VCardProperty::Anniversary => {
                self.date_pair(WEDDING_ANNIVERSARY, LID_WEDDING_ANNIVERSARY_LOCAL, entry)
            }
            VCardProperty::Adr => self.address(entry),
            VCardProperty::Tel => self.telephone(entry, Types::of(entry)),
            VCardProperty::Email => self.email(entry),
            VCardProperty::Impp => {
                if let Some(uri) = first_text(entry) {
                    self.lid_once(LID_INSTANT_MESSAGING_ADDRESS, impp_handle(uri));
                }
            }
            VCardProperty::Title => self.first_text(TITLE, entry),
            VCardProperty::Role => self.first_text(PROFESSION, entry),
            VCardProperty::Org => self.organization(entry),
            VCardProperty::Categories => self.categories(entry),
            VCardProperty::Note => self.first_text(BODY, entry),
            VCardProperty::Url => self.url(entry),
            VCardProperty::Key => {
                if let Some(data) = entry.values.first().and_then(VCardValue::as_binary) {
                    self.charge(data.data.len())?;
                    if S::FULL_MESSAGE {
                        self.value(
                            PropKeyRef::Tag(USER_X509_CERTIFICATE),
                            OwnedPropValue::MvBinary(Box::new([Bytes::copy_from_slice(
                                &data.data,
                            )])),
                        );
                    }
                }
            }
            VCardProperty::Rev if S::FULL_MESSAGE => {
                if let Some(time) = revision_time(entry) {
                    self.value(
                        PropKeyRef::Tag(LAST_MODIFICATION_TIME),
                        OwnedPropValue::Time(time),
                    );
                }
            }
            VCardProperty::Fburl => self.first_lid(LID_FREE_BUSY_LOCATION, entry),
            VCardProperty::Hobby | VCardProperty::Interest => self.first_text(HOBBIES, entry),
            VCardProperty::Related => {
                if let Some(relation) = related_name(entry) {
                    self.relation(relation, Form::Related, entry);
                }
            }
            VCardProperty::Other(name) => self.extra(name, entry)?,
            _ => {}
        }
        Ok(())
    }

    fn extra(&mut self, name: &str, entry: &'c VCardEntry) -> Result<(), ConvertError> {
        let Some(extra) = relation_property!(name, [Extra], [Extra::Relation],
            "CLASS" => Extra::Class,
            "X-MS-TEXT" => Extra::UserText,
            "X-CUSTOM" => Extra::UserText,
            "X-MS-IMADDRESS" => Extra::ImAddress,
            "X-MS-RM-IMACCOUNT" => Extra::ImAddress,
            "X-MS-TEL" => Extra::Tel,
            "X-MS-ANNIVERSARY" => Extra::Anniversary,
            "X-ANNIVERSARY" => Extra::Anniversary,
            "X-MS-ACCOUNT" => Extra::Account,
            "X-MS-INTERESTS" => Extra::Interests,
            "X-INTERESTS" => Extra::Interests,
            "X-MS-OL-DESIGN" => Extra::Design,
            "X-MS-FILE-AS" => Extra::FileAs,
            "X-EVOLUTION-FILE-AS" => Extra::FileAs,
            "X-MS-FILE-AS-ID" => Extra::FileAsId,
            "X-MS-POSTAL-ADDRESS-ID" => Extra::PostalAddressId,
            "X-MS-INITIALS" => Extra::Initials,
            "X-MS-OFFICE-LOCATION" => Extra::OfficeLocation,
            "X-PHONETIC-FIRST-NAME" => Extra::YomiFirstName,
            "X-PHONETIC-LAST-NAME" => Extra::YomiLastName,
        ) else {
            return Ok(());
        };
        match extra {
            Extra::Relation(other) => {
                if let Some((relation, form)) = other.classify(entry, &self.labels) {
                    self.relation(relation, form, entry);
                }
            }
            Extra::Class => {
                let sensitivity = entry
                    .values
                    .first()
                    .and_then(VCardValue::as_text)
                    .and_then(|value| {
                        hashify::map_ignore_case!(value.as_bytes(), i32,
                            "public" => 0,
                            "personal" => 1,
                            "private" => 2,
                            "confidential" => 3,
                        )
                        .copied()
                    })
                    .unwrap_or_default();
                self.value(
                    PropKeyRef::Tag(SENSITIVITY),
                    OwnedPropValue::I32(sensitivity),
                );
            }
            Extra::UserText => {
                if let Some(lid) = LID_CONTACT_USER_FIELDS.get(self.user_fields).copied()
                    && let Some(value) = first_text(entry)
                {
                    self.user_fields += 1;
                    self.lid_text(lid, value);
                }
            }
            Extra::ImAddress => self.first_lid(LID_INSTANT_MESSAGING_ADDRESS, entry),
            Extra::Tel => self.telephone(entry, Types::of(entry)),
            Extra::Anniversary => {
                self.date_pair(WEDDING_ANNIVERSARY, LID_WEDDING_ANNIVERSARY_LOCAL, entry)
            }
            Extra::Account => self.first_text(ACCOUNT, entry),
            Extra::Interests => self.first_text(HOBBIES, entry),
            Extra::FileAs
            | Extra::FileAsId
            | Extra::PostalAddressId
            | Extra::Initials
            | Extra::OfficeLocation
            | Extra::YomiFirstName
            | Extra::YomiLastName
                if !S::FULL_MESSAGE => {}
            Extra::FileAs => self.first_lid(LID_FILE_UNDER, entry),
            Extra::FileAsId => {
                if let Some(id) = first_text(entry).and_then(|text| text.parse::<i32>().ok())
                    && !self.sink.has(address_lid(LID_FILE_UNDER_ID))
                {
                    self.value(address_lid(LID_FILE_UNDER_ID), OwnedPropValue::I32(id));
                }
            }
            Extra::PostalAddressId => {
                if self.postal_address_id.is_none() {
                    self.postal_address_id = first_text(entry)
                        .and_then(|text| text.trim().parse::<i32>().ok())
                        .filter(|id| known_postal_address_id(*id));
                }
            }
            Extra::Initials => self.first_text(INITIALS, entry),
            Extra::OfficeLocation => self.first_text(OFFICE_LOCATION, entry),
            Extra::YomiFirstName => self.first_lid(LID_YOMI_FIRST_NAME, entry),
            Extra::YomiLastName => self.first_lid(LID_YOMI_LAST_NAME, entry),
            Extra::Design if !S::BINARY => {}
            Extra::Design => {
                if let Some(data) = entry.values.first().and_then(VCardValue::as_binary) {
                    self.charge(data.data.len())?;
                    if S::FULL_MESSAGE {
                        self.value(
                            address_lid(LID_BUSINESS_CARD_DISPLAY_DEFINITION),
                            OwnedPropValue::Binary(Bytes::copy_from_slice(&data.data)),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn photo(&mut self, entry: &'c VCardEntry) -> Result<(), ConvertError> {
        if self.has_photo {
            return Ok(());
        }
        let Some(data) = entry.values.first().and_then(VCardValue::as_binary) else {
            return Ok(());
        };
        let media = data
            .content_type
            .as_deref()
            .and_then(|ctype| ctype.split_once('/'))
            .map(|(_, subtype)| subtype)
            .into_iter()
            .chain(entry.params.iter().filter_map(|param| match &param.value {
                VCardParameterValue::Text(text) if param.name == VCardParameterName::Type => {
                    Some(text.as_str())
                }
                _ => None,
            }))
            .find_map(|token| {
                hashify::map_ignore_case!(token.as_bytes(), &'static str,
                    "jpeg" => "jpg",
                    "jpg" => "jpg",
                    "png" => "png",
                    "gif" => "gif",
                    "bmp" => "bmp",
                )
                .copied()
            });
        let Some(extension) = media else {
            return Ok(());
        };
        self.charge(data.data.len())?;
        self.has_photo = true;
        self.sink.photo(extension, &data.data);
        if S::FULL_MESSAGE {
            self.value(address_lid(LID_HAS_PICTURE), OwnedPropValue::Bool(true));
        }
        Ok(())
    }

    fn date_pair(&mut self, utc: PropId, local: u32, entry: &VCardEntry) {
        let Some(date) = entry.values.first().and_then(|value| match value {
            VCardValue::PartialDateTime(value) => civil_date(value),
            value => value.as_text().and_then(text_date),
        }) else {
            return;
        };
        if let Some(time) = file_time(date, BIRTHDAY_UTC_HOUR, BIRTHDAY_UTC_MINUTE) {
            self.value(PropKeyRef::Tag(utc), OwnedPropValue::Time(time));
        }
        if S::FULL_MESSAGE
            && let Some(time) = file_time(date, 0, 0)
        {
            self.value(address_lid(local), OwnedPropValue::Time(time));
        }
    }

    fn address(&mut self, entry: &'c VCardEntry) {
        let types = Types::of(entry);
        let explicit = types.has(Types::WORK | Types::HOME | Types::POSTAL);
        let groups = [
            (&HOME_ADDRESS, types.has(Types::HOME)),
            (&WORK_ADDRESS, types.has(Types::WORK) || !explicit),
            (&OTHER_ADDRESS, types.has(Types::POSTAL) || !explicit),
        ];
        let values = address_values(entry);
        if values.iter().all(|value| value.is_empty()) {
            return;
        }
        let mut addresses = self.addresses;
        for (((group, wanted), used), stored) in groups
            .into_iter()
            .zip(&mut addresses)
            .zip(&mut self.address_entries)
        {
            if !wanted || *used {
                continue;
            }
            *used = true;
            let keys = [
                &group.po_box,
                &group.street,
                &group.city,
                &group.state,
                &group.postal_code,
                &group.country,
            ];
            for (key, value) in keys.into_iter().zip(&values) {
                if !value.is_empty() {
                    self.sink.text(key.key(), value.clone(), self.current);
                }
            }
            if S::FULL_MESSAGE {
                *stored = Some((entry, self.current));
                if types.has(Types::PREF) && self.preferred_postal_id.is_none() {
                    self.preferred_postal_id = Some(group.postal_id);
                }
            }
        }
        self.addresses = addresses;
    }

    fn telephone(&mut self, entry: &'c VCardEntry, types: Types) {
        let Some(number) = first_text(entry).map(|number| {
            number
                .get(..TEL_URI_PREFIX.len())
                .filter(|prefix| prefix.eq_ignore_ascii_case(TEL_URI_PREFIX))
                .and_then(|_| number.get(TEL_URI_PREFIX.len()..))
                .unwrap_or(number)
        }) else {
            return;
        };
        if types.has(Types::FAX) {
            let (id, slot) = if types.has(Types::HOME) {
                (HOME_FAX_NUMBER, &HOME_FAX_SLOT)
            } else if types.has(Types::WORK) {
                (BUSINESS_FAX_NUMBER, &BUSINESS_FAX_SLOT)
            } else {
                (PRIMARY_FAX_NUMBER, &PRIMARY_FAX_SLOT)
            };
            if self.set_once(id, number) && S::FULL_MESSAGE {
                self.faxes.push((slot, number, self.current));
            }
            return;
        }
        let marked = match SlotMarker::of(entry) {
            Some(SlotMarker::Phone(id)) => Some(id),
            _ => None,
        };
        let mut matched = false;
        for (bits, ids) in [
            (
                Types::HOME,
                &[HOME_TELEPHONE_NUMBER, HOME2_TELEPHONE_NUMBER][..],
            ),
            (
                Types::WORK,
                &[BUSINESS_TELEPHONE_NUMBER, BUSINESS2_TELEPHONE_NUMBER][..],
            ),
            (Types::CELL, &[MOBILE_TELEPHONE_NUMBER][..]),
            (Types::PAGER, &[PAGER_TELEPHONE_NUMBER][..]),
            (Types::CAR, &[CAR_TELEPHONE_NUMBER][..]),
            (Types::ISDN, &[ISDN_NUMBER][..]),
            (Types::PREF, &[PRIMARY_TELEPHONE_NUMBER][..]),
            (Types::TEXTPHONE, &[TTY_TDD_PHONE_NUMBER][..]),
            (Types::MAIN, &[COMPANY_MAIN_PHONE_NUMBER][..]),
            (Types::ASSISTANT, &[ASSISTANT_TELEPHONE_NUMBER][..]),
            (Types::CALLBACK, &[CALLBACK_TELEPHONE_NUMBER][..]),
            (Types::RADIO, &[RADIO_TELEPHONE_NUMBER][..]),
            (Types::TELEX, &[TELEX_NUMBER][..]),
        ] {
            if types.has(bits) {
                matched = true;
                let id = marked
                    .filter(|id| ids.contains(id) && !self.has_tag(*id))
                    .or_else(|| ids.iter().copied().find(|id| !self.has_tag(*id)));
                if let Some(id) = id {
                    self.text(id, number);
                }
            }
        }
        if types.has(Types::OTHER_LINE) || (!matched && types.has(Types::VOICE)) || types.0 == 0 {
            self.set_once(OTHER_TELEPHONE_NUMBER, number);
        }
    }

    fn email(&mut self, entry: &'c VCardEntry) {
        let Some(address) = first_text(entry) else {
            return;
        };
        match EmailKind::of(entry) {
            EmailKind::Internet => {
                let email = (address, self.current);
                let slot = match SlotMarker::of(entry) {
                    Some(SlotMarker::Email(slot)) => {
                        self.emails.get_mut(slot).filter(|slot| slot.is_none())
                    }
                    _ => None,
                };
                match slot {
                    Some(slot) => *slot = Some(email),
                    None if self.unslotted_emails.len() < EMAIL_SLOTS.len() => {
                        self.unslotted_emails.push(email);
                    }
                    None => {}
                }
            }
            EmailKind::Im => self.lid_once(LID_INSTANT_MESSAGING_ADDRESS, address),
            EmailKind::Telex => {
                self.set_once(TELEX_NUMBER, address);
            }
        }
    }

    fn organization(&mut self, entry: &'c VCardEntry) {
        let mut parts = entry.values.iter().filter_map(component);
        if let Some(company) = parts.next().filter(|company| !company.is_empty()) {
            self.text(COMPANY_NAME, company);
        }
        let mut units: Option<Cow<'c, str>> = None;
        for unit in parts.filter(|unit| !unit.is_empty()) {
            match &mut units {
                Some(joined) => {
                    let joined = joined.to_mut();
                    joined.push_str(UNIT_SEPARATOR);
                    joined.push_str(&unit);
                }
                None => units = Some(unit),
            }
        }
        if let Some(units) = units {
            self.text(DEPARTMENT_NAME, units);
        }
    }

    fn categories(&mut self, entry: &'c VCardEntry) {
        let count = self.categories.len();
        self.categories.extend(
            entry
                .values
                .iter()
                .flat_map(|value| {
                    let (items, text) = match value {
                        VCardValue::Component(items) => (items.as_slice(), None),
                        value => (&[][..], value.as_text()),
                    };
                    items.iter().map(String::as_str).chain(text)
                })
                .map(str::trim)
                .filter(|category| !category.is_empty())
                .map(Cow::Borrowed),
        );
        if self.categories.len() > count {
            self.categories_origin = self.current;
        }
    }

    fn url(&mut self, entry: &'c VCardEntry) {
        let Some(url) = first_text(entry) else {
            return;
        };
        let types = Types::of(entry);
        let home = if types.has(Types::WORK) {
            false
        } else if types.has(Types::HOME) {
            true
        } else {
            !self.has_url_home
        };
        let (id, used) = if home {
            (PERSONAL_HOME_PAGE, &mut self.has_url_home)
        } else {
            (BUSINESS_HOME_PAGE, &mut self.has_url_work)
        };
        if !*used {
            *used = true;
            self.text(id, url);
        }
    }

    fn finish(&mut self) {
        if !self.categories.is_empty() {
            self.current = self.categories_origin;
            let categories = std::mem::take(&mut self.categories);
            self.sink.categories(categories, self.current);
        }
        if self.related_children && !self.apple_children.is_empty() {
            drop_apple_duplicates(&mut self.children, &self.apple_children);
        }
        let legacy = std::mem::take(&mut self.legacy_children);
        merge_names(&mut self.children, legacy);
        if !self.children.is_empty() {
            self.current = self.children_origin;
            let children = std::mem::take(&mut self.children);
            self.sink
                .list(PropKeyRef::Tag(CHILDRENS_NAMES), children, self.current);
        }
        if let Some((value, origin)) = self.partner.take() {
            self.current = origin;
            self.set_once(SPOUSE_NAME, value);
        }
        for (relation, value, origin) in std::mem::take(&mut self.legacy_relations) {
            self.current = origin;
            self.set_once(relation.prop(), value);
        }
        if S::FULL_MESSAGE {
            self.mailing_address();
        }
        let mut indexes = Vec::new();
        let display_name = self.display_name;
        let mut unslotted = std::mem::take(&mut self.unslotted_emails).into_iter();
        let emails =
            std::mem::take(&mut self.emails).map(|email| email.or_else(|| unslotted.next()));
        for (slot, (address, origin)) in EMAIL_SLOTS
            .iter()
            .zip(emails)
            .filter_map(|(slot, email)| Some((slot, email?)))
        {
            self.current = origin;
            if !S::FULL_MESSAGE {
                self.lid_text(slot.email, address);
                continue;
            }
            let name = match display_name {
                Some(name) => Cow::Owned(format!("{name} ({address})")),
                None => Cow::Borrowed(address),
            };
            self.electronic(slot, name, SMTP, Cow::Borrowed(address), address);
            indexes.push(slot.index);
        }
        for (slot, number, origin) in std::mem::take(&mut self.faxes) {
            self.current = origin;
            let name = display_name.unwrap_or(number);
            let address = format!("{name}@{number}");
            self.electronic(slot, Cow::Borrowed(name), FAX, Cow::Owned(address), name);
            indexes.push(slot.index);
        }
        if indexes.is_empty() {
            return;
        }
        indexes.sort_unstable();
        let array_type = indexes.iter().fold(0, |bits, index| bits | (1 << index));
        self.value(
            address_lid(LID_ADDRESS_BOOK_PROVIDER_ARRAY_TYPE),
            OwnedPropValue::I32(array_type),
        );
        self.value(
            address_lid(LID_ADDRESS_BOOK_PROVIDER_EMAIL_LIST),
            OwnedPropValue::MvI32(indexes.into_boxed_slice()),
        );
    }

    fn electronic(
        &mut self,
        slot: &ElectronicSlot,
        name: Cow<'c, str>,
        address_type: &'static str,
        address: Cow<'c, str>,
        original_name: &'c str,
    ) {
        if let Some(lid) = slot.display_name {
            self.lid_text(lid, name);
        }
        self.lid_text(slot.address_type, address_type);
        let entry_id = one_off(original_name, address_type, &address);
        self.lid_text(slot.email, address);
        self.lid_text(slot.original_display_name, original_name);
        if let Some(entry_id) = entry_id {
            self.value(
                address_lid(slot.original_entry_id),
                OwnedPropValue::Binary(entry_id),
            );
        }
    }

    fn charge(&mut self, len: usize) -> Result<(), ConvertError> {
        let len = u64::try_from(len).map_err(|_| ConvertError::TooLarge)?;
        self.max_decoded = self
            .max_decoded
            .checked_sub(len)
            .ok_or(ConvertError::TooLarge)?;
        Ok(())
    }

    fn has_tag(&self, id: PropId) -> bool {
        self.sink.has(PropKeyRef::Tag(id))
    }

    fn set_once(&mut self, id: PropId, value: &'c str) -> bool {
        if self.has_tag(id) {
            return false;
        }
        self.text(id, value);
        true
    }

    fn relation(&mut self, relation: Relation, form: Form, entry: &'c VCardEntry) {
        match (relation, form) {
            (Relation::Child, _) => self.child(entry, form),
            (_, Form::Partner) => {
                if self.partner.is_none()
                    && let Some(value) = first_text(entry)
                {
                    self.partner = Some((value, self.current));
                }
            }
            (_, Form::Legacy) => {
                if let Some(value) = first_text(entry)
                    && !self
                        .legacy_relations
                        .iter()
                        .any(|(known, _, _)| *known == relation)
                {
                    self.legacy_relations.push((relation, value, self.current));
                }
            }
            _ => self.first_text(relation.prop(), entry),
        }
    }

    fn child(&mut self, entry: &'c VCardEntry, form: Form) {
        if self.children.is_empty() && self.legacy_children.is_empty() {
            self.children_origin = self.current;
        }
        let names = entry
            .values
            .iter()
            .filter_map(component)
            .filter(|name| !name.is_empty());
        match form {
            Form::Legacy => self.legacy_children.extend(names),
            Form::Related => {
                self.related_children = true;
                self.children.extend(names);
            }
            Form::Apple | Form::Partner => {
                let start = self.children.len();
                self.children.extend(names);
                self.apple_children.push(start..self.children.len());
            }
        }
    }

    fn mailing_address(&mut self) {
        let stored = |id: i32| {
            POSTAL_ADDRESS_GROUPS
                .iter()
                .zip(self.address_entries)
                .find_map(|(group, entry)| entry.filter(|_| group.postal_id == id))
        };
        let id = self
            .postal_address_id
            .filter(|id| *id == 0 || stored(*id).is_some())
            .or(self.preferred_postal_id)
            .or(self.postal_address_id);
        let Some(id) = id else {
            return;
        };
        let mailing = stored(id);
        self.value(address_lid(LID_POSTAL_ADDRESS_ID), OwnedPropValue::I32(id));
        if let Some((entry, origin)) = mailing {
            self.current = origin;
            for (prop, value) in MAILING_ADDRESS.into_iter().zip(address_values(entry)) {
                if !value.is_empty() {
                    self.text(prop, value);
                }
            }
        }
    }

    fn lid_once(&mut self, lid: u32, value: &'c str) {
        if !self.sink.has(address_lid(lid)) {
            self.lid_text(lid, value);
        }
    }

    fn first_text(&mut self, id: PropId, entry: &'c VCardEntry) {
        if let Some(value) = first_text(entry) {
            self.set_once(id, value);
        }
    }

    fn first_lid(&mut self, lid: u32, entry: &'c VCardEntry) {
        if let Some(value) = first_text(entry) {
            self.lid_once(lid, value);
        }
    }

    fn text(&mut self, id: PropId, value: impl Into<Cow<'c, str>>) {
        self.sink
            .text(PropKeyRef::Tag(id), value.into(), self.current);
    }

    fn lid_text(&mut self, lid: u32, value: impl Into<Cow<'c, str>>) {
        self.sink.text(address_lid(lid), value.into(), self.current);
    }

    fn value(&mut self, key: PropKeyRef<'static>, value: OwnedPropValue) {
        self.sink.value(key, value, self.current);
    }
}

#[cold]
fn drop_apple_duplicates(children: &mut Vec<Cow<'_, str>>, apple: &[Range<usize>]) {
    let mut is_apple = vec![false; children.len()];
    for range in apple {
        if let Some(flags) = is_apple.get_mut(range.clone()) {
            flags.fill(true);
        }
    }
    let keep: Vec<bool> = {
        let related: HashSet<&str> = children
            .iter()
            .zip(&is_apple)
            .filter(|(_, apple)| !**apple)
            .map(|(name, _)| name.as_ref())
            .collect();
        children
            .iter()
            .zip(&is_apple)
            .map(|(name, apple)| !*apple || !related.contains(name.as_ref()))
            .collect()
    };
    let mut keep = keep.into_iter();
    children.retain(|_| keep.next().unwrap_or(true));
}

fn merge_names<'c>(names: &mut Vec<Cow<'c, str>>, mut extra: Vec<Cow<'c, str>>) {
    if extra.is_empty() {
        return;
    }
    if names.is_empty() {
        *names = extra;
        return;
    }
    if names.len() <= LINEAR_SCAN_MAX {
        extra.retain(|name| !names.contains(name));
    } else {
        let known: HashSet<&str> = names.iter().map(AsRef::as_ref).collect();
        extra.retain(|name| !known.contains(name.as_ref()));
    }
    names.append(&mut extra);
}

fn first_text(entry: &VCardEntry) -> Option<&str> {
    entry
        .values
        .first()
        .and_then(VCardValue::as_text)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn component(value: &VCardValue) -> Option<Cow<'_, str>> {
    match value {
        VCardValue::Component(items) => Some(Cow::Owned(items.join(","))),
        value => value.as_text().map(Cow::Borrowed),
    }
}

fn address_values(entry: &VCardEntry) -> [Cow<'_, str>; 6] {
    let part = |index: usize| {
        entry
            .values
            .get(index)
            .and_then(component)
            .map(trimmed)
            .unwrap_or_default()
    };
    let street = match (part(1), part(2)) {
        (extended, street) if extended.is_empty() => street,
        (extended, street) if street.is_empty() => extended,
        (extended, street) => Cow::Owned(format!("{extended}{STREET_SEPARATOR}{street}")),
    };
    [part(0), street, part(3), part(4), part(5), part(6)]
}

fn trimmed(value: Cow<'_, str>) -> Cow<'_, str> {
    match value {
        Cow::Borrowed(text) => Cow::Borrowed(text.trim()),
        Cow::Owned(text) if text.trim().len() == text.len() => Cow::Owned(text),
        Cow::Owned(text) => Cow::Owned(text.trim().into()),
    }
}

fn civil_date(value: &PartialDateTime) -> Option<Date> {
    let year = i16::try_from(value.year?).ok()?;
    let month = i8::try_from(value.month?).ok()?;
    let day = i8::try_from(value.day?).ok()?;
    Date::new(year, month, day).ok()
}

fn text_date(text: &str) -> Option<Date> {
    let date = text.trim();
    let date = date.split_once('T').map_or(date, |(date, _)| date);
    date.parse().ok()
}

fn file_time(date: Date, hour: i8, minute: i8) -> Option<FileTime> {
    let seconds = date
        .to_datetime(Time::new(hour, minute, 0, 0).ok()?)
        .to_zoned(TimeZone::UTC)
        .ok()?
        .timestamp()
        .as_second();
    Some(FileTime::from_utc(UtcSeconds(seconds), 0))
}

pub(super) fn revision_time(entry: &VCardEntry) -> Option<FileTime> {
    entry
        .values
        .first()
        .and_then(VCardValue::as_partial_date_time)
        .and_then(utc_time)
}

fn utc_time(value: &PartialDateTime) -> Option<FileTime> {
    let date = civil_date(value)?;
    let time = Time::new(
        i8::try_from(value.hour.unwrap_or_default()).ok()?,
        i8::try_from(value.minute.unwrap_or_default()).ok()?,
        i8::try_from(value.second.unwrap_or_default()).ok()?,
        0,
    )
    .ok()?;
    let local = date
        .to_datetime(time)
        .to_zoned(TimeZone::UTC)
        .ok()?
        .timestamp()
        .as_second();
    let offset = i64::from(value.tz_hour.unwrap_or_default()) * 3600
        + i64::from(value.tz_minute.unwrap_or_default()) * 60;
    let seconds = if value.tz_minus {
        local.checked_add(offset)?
    } else {
        local.checked_sub(offset)?
    };
    Some(FileTime::from_utc(UtcSeconds(seconds), 0))
}
