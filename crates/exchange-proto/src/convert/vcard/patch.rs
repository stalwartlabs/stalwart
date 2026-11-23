/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use calcard::{
    common::{Data, PartialDateTime},
    vcard::{
        VCard, VCardEntry, VCardParameter, VCardParameterName, VCardParameterValue, VCardProperty,
        VCardType, VCardValue,
    },
};
use jiff::Timestamp;
use smallvec::smallvec;

use super::{
    props::*,
    related::{self, Change, Dialect, Relation},
    to_message::{is_internet_email_entry, origins},
};
use crate::{
    common::time::FileTime,
    convert::{
        ConvertError,
        model::{LossKind, PatchReport, PropBag},
        tags::{self, KEYWORDS_NAME},
    },
    mapi::prop::{
        OwnedPropValue, PropId, PropKey, PropKeyRef,
        sets::{PS_PUBLIC_STRINGS, PSETID_ADDRESS},
    },
};

const CLASS_PROPERTY: &str = "CLASS";
const ACCOUNT_PROPERTY: &str = "X-MS-ACCOUNT";
const INTERESTS_PROPERTY: &str = "X-MS-INTERESTS";
const MS_TEL_PROPERTY: &str = "X-MS-TEL";
const MS_ANNIVERSARY_PROPERTY: &str = "X-MS-ANNIVERSARY";
const FILE_AS_PROPERTY: &str = "X-MS-FILE-AS";
const FILE_AS_ID_PROPERTY: &str = "X-MS-FILE-AS-ID";
const POSTAL_ADDRESS_ID_PROPERTY: &str = "X-MS-POSTAL-ADDRESS-ID";
const IM_URI_SCHEME: &str = "im";
const INITIALS_PROPERTY: &str = "X-MS-INITIALS";
const OFFICE_LOCATION_PROPERTY: &str = "X-MS-OFFICE-LOCATION";
const PHONETIC_FIRST_NAME_PROPERTY: &str = "X-PHONETIC-FIRST-NAME";
const PHONETIC_LAST_NAME_PROPERTY: &str = "X-PHONETIC-LAST-NAME";
const N_COMPONENTS: usize = 5;
const ADR_EXTENDED: usize = 1;
const ADR_STREET: usize = 2;
const ORG_DEPARTMENT: usize = 1;
const ADDRESS_SLOTS: usize = 3;

#[derive(Clone, Copy)]
enum Ty {
    Known(&'static VCardType),
    Text(&'static str),
    PropId(&'static str),
}

#[derive(Clone, Copy)]
enum Create {
    Property(fn() -> VCardProperty),
    Other(&'static str),
}

#[derive(Clone, Copy)]
enum Target {
    Text(Create, &'static [Ty]),
    Component(fn() -> VCardProperty, usize),
    Address(&'static [Ty], usize, usize),
    Email(usize),
    Categories,
    LegacyCategories,
    Sensitivity,
    Date(Create),
    Integer(Create),
    Impp,
    Relation(Relation),
    Children,
    PostalAddressId,
    Derived,
}

const WORK_VOICE: &[Ty] = &[Ty::Known(&VCardType::Work), Ty::Known(&VCardType::Voice)];
const HOME_VOICE: &[Ty] = &[Ty::Known(&VCardType::Home), Ty::Known(&VCardType::Voice)];
const WORK_VOICE_SECOND: &[Ty] = &[
    Ty::Known(&VCardType::Work),
    Ty::Known(&VCardType::Voice),
    Ty::PropId(BUSINESS2_PROP_ID),
];
const HOME_VOICE_SECOND: &[Ty] = &[
    Ty::Known(&VCardType::Home),
    Ty::Known(&VCardType::Voice),
    Ty::PropId(HOME2_PROP_ID),
];
const TELEX: &[Ty] = &[Ty::Text("TLX")];
const INTERNET: &[Ty] = &[Ty::Text("INTERNET")];
const EMAIL_TYPES: [&[Ty]; 3] = [
    &[Ty::Text("INTERNET"), Ty::PropId(EMAIL_PROP_IDS[0])],
    &[Ty::Text("INTERNET"), Ty::PropId(EMAIL_PROP_IDS[1])],
    &[Ty::Text("INTERNET"), Ty::PropId(EMAIL_PROP_IDS[2])],
];
const TEL: Create = Create::Property(|| VCardProperty::Tel);
const MS_TEL: Create = Create::Other(MS_TEL_PROPERTY);

fn target(key: PropKeyRef<'_>) -> Option<Target> {
    match key {
        PropKeyRef::Tag(id) => tag_target(id),
        PropKeyRef::Lid { set, lid } if set == PSETID_ADDRESS => lid_target(lid),
        PropKeyRef::Lid { set, lid } if set == PS_PUBLIC_STRINGS && lid == LID_CATEGORIES => {
            Some(Target::LegacyCategories)
        }
        PropKeyRef::Name { set, name } if set == PS_PUBLIC_STRINGS && name == KEYWORDS_NAME => {
            Some(Target::Categories)
        }
        _ => None,
    }
}

fn tag_target(id: PropId) -> Option<Target> {
    if let Some(index) = [
        SURNAME,
        GIVEN_NAME,
        MIDDLE_NAME,
        DISPLAY_NAME_PREFIX,
        GENERATION,
    ]
    .iter()
    .position(|known| *known == id)
    {
        return Some(Target::Component(|| VCardProperty::N, index));
    }
    if let Some(field) = address_field(|key| matches!(key, AddressKey::Tag(tag) if *tag == id)) {
        return Some(field);
    }
    if MAILING_ADDRESS.contains(&id) {
        return Some(Target::Derived);
    }
    Some(match id {
        DISPLAY_NAME => Target::Text(Create::Property(|| VCardProperty::Fn), &[]),
        NICKNAME => Target::Text(Create::Property(|| VCardProperty::Nickname), &[]),
        TITLE => Target::Text(Create::Property(|| VCardProperty::Title), &[]),
        PROFESSION => Target::Text(Create::Property(|| VCardProperty::Role), &[]),
        BODY => Target::Text(Create::Property(|| VCardProperty::Note), &[]),
        COMPANY_NAME => Target::Component(|| VCardProperty::Org, 0),
        DEPARTMENT_NAME => Target::Component(|| VCardProperty::Org, ORG_DEPARTMENT),
        SPOUSE_NAME => Target::Relation(Relation::Spouse),
        MANAGER_NAME => Target::Relation(Relation::Manager),
        ACCOUNT => Target::Text(Create::Other(ACCOUNT_PROPERTY), &[]),
        ASSISTANT => Target::Relation(Relation::Assistant),
        HOBBIES => Target::Text(Create::Other(INTERESTS_PROPERTY), &[]),
        INITIALS => Target::Text(Create::Other(INITIALS_PROPERTY), &[]),
        OFFICE_LOCATION => Target::Text(Create::Other(OFFICE_LOCATION_PROPERTY), &[]),
        PERSONAL_HOME_PAGE => Target::Text(
            Create::Property(|| VCardProperty::Url),
            &[Ty::Known(&VCardType::Home)],
        ),
        BUSINESS_HOME_PAGE => Target::Text(
            Create::Property(|| VCardProperty::Url),
            &[Ty::Known(&VCardType::Work)],
        ),
        BUSINESS_TELEPHONE_NUMBER => Target::Text(TEL, WORK_VOICE),
        BUSINESS2_TELEPHONE_NUMBER => Target::Text(TEL, WORK_VOICE_SECOND),
        HOME_TELEPHONE_NUMBER => Target::Text(TEL, HOME_VOICE),
        HOME2_TELEPHONE_NUMBER => Target::Text(TEL, HOME_VOICE_SECOND),
        TELEX_NUMBER => Target::Text(MS_TEL, TELEX),
        MOBILE_TELEPHONE_NUMBER => Target::Text(TEL, &[Ty::Known(&VCardType::Cell)]),
        PAGER_TELEPHONE_NUMBER => Target::Text(TEL, &[Ty::Known(&VCardType::Pager)]),
        CAR_TELEPHONE_NUMBER => Target::Text(TEL, &[Ty::Text("CAR")]),
        ISDN_NUMBER => Target::Text(TEL, &[Ty::Text("ISDN")]),
        PRIMARY_TELEPHONE_NUMBER => Target::Text(TEL, &[Ty::Text("PREF")]),
        OTHER_TELEPHONE_NUMBER => Target::Text(TEL, &[Ty::Known(&VCardType::Voice)]),
        BUSINESS_FAX_NUMBER => Target::Text(
            TEL,
            &[Ty::Known(&VCardType::Work), Ty::Known(&VCardType::Fax)],
        ),
        HOME_FAX_NUMBER => Target::Text(
            TEL,
            &[Ty::Known(&VCardType::Home), Ty::Known(&VCardType::Fax)],
        ),
        PRIMARY_FAX_NUMBER => Target::Text(TEL, &[Ty::Known(&VCardType::Fax)]),
        TTY_TDD_PHONE_NUMBER => Target::Text(MS_TEL, &[Ty::Text("TTYTDD")]),
        COMPANY_MAIN_PHONE_NUMBER => Target::Text(MS_TEL, &[Ty::Text("COMPANY")]),
        ASSISTANT_TELEPHONE_NUMBER => Target::Text(MS_TEL, &[Ty::Text("ASSISTANT")]),
        CALLBACK_TELEPHONE_NUMBER => Target::Text(MS_TEL, &[Ty::Text("CALLBACK")]),
        RADIO_TELEPHONE_NUMBER => Target::Text(MS_TEL, &[Ty::Text("RADIO")]),
        SENSITIVITY => Target::Sensitivity,
        BIRTHDAY => Target::Date(Create::Property(|| VCardProperty::Bday)),
        WEDDING_ANNIVERSARY => Target::Date(Create::Other(MS_ANNIVERSARY_PROPERTY)),
        CHILDRENS_NAMES => Target::Children,
        tags::MESSAGE_CLASS
        | tags::SUBJECT
        | NORMALIZED_SUBJECT
        | CONVERSATION_TOPIC
        | LAST_MODIFICATION_TIME => Target::Derived,
        _ => return None,
    })
}

fn has_local_date(changes: &PropBag, key: PropKeyRef<'_>) -> bool {
    let local = match key {
        PropKeyRef::Tag(BIRTHDAY) => LID_BIRTHDAY_LOCAL,
        PropKeyRef::Tag(WEDDING_ANNIVERSARY) => LID_WEDDING_ANNIVERSARY_LOCAL,
        _ => return false,
    };
    changes.get_any(address_lid(local)).is_some()
}

fn lid_target(lid: u32) -> Option<Target> {
    if let Some(field) = address_field(|key| matches!(key, AddressKey::Lid(known) if *known == lid))
    {
        return Some(field);
    }
    if let Some(slot) = EMAIL_SLOTS.iter().position(|slot| slot.email == lid) {
        return Some(Target::Email(slot));
    }
    let derived = EMAIL_SLOTS
        .iter()
        .chain([&BUSINESS_FAX_SLOT, &HOME_FAX_SLOT, &PRIMARY_FAX_SLOT])
        .any(|slot| {
            slot.display_name == Some(lid)
                || slot.address_type == lid
                || slot.email == lid
                || slot.original_display_name == lid
                || slot.original_entry_id == lid
        });
    Some(match lid {
        _ if derived => Target::Derived,
        LID_HAS_PICTURE
        | LID_ADDRESS_BOOK_PROVIDER_EMAIL_LIST
        | LID_ADDRESS_BOOK_PROVIDER_ARRAY_TYPE => Target::Derived,
        LID_BIRTHDAY_LOCAL => Target::Date(Create::Property(|| VCardProperty::Bday)),
        LID_WEDDING_ANNIVERSARY_LOCAL => Target::Date(Create::Other(MS_ANNIVERSARY_PROPERTY)),
        LID_FILE_UNDER => Target::Text(Create::Other(FILE_AS_PROPERTY), &[]),
        LID_FILE_UNDER_ID => Target::Integer(Create::Other(FILE_AS_ID_PROPERTY)),
        LID_YOMI_FIRST_NAME => Target::Text(Create::Other(PHONETIC_FIRST_NAME_PROPERTY), &[]),
        LID_YOMI_LAST_NAME => Target::Text(Create::Other(PHONETIC_LAST_NAME_PROPERTY), &[]),
        LID_INSTANT_MESSAGING_ADDRESS => Target::Impp,
        LID_POSTAL_ADDRESS_ID => Target::PostalAddressId,
        _ => return None,
    })
}

const ADDRESS_GROUPS: [(&AddressGroup, &[Ty]); ADDRESS_SLOTS] = [
    (&HOME_ADDRESS, &[Ty::Known(&VCardType::Home)]),
    (&WORK_ADDRESS, &[Ty::Known(&VCardType::Work)]),
    (&OTHER_ADDRESS, &[Ty::Text("POSTAL")]),
];

fn address_field(matches: impl Fn(&AddressKey) -> bool) -> Option<Target> {
    const INDEXES: [usize; 6] = [0, ADR_STREET, 3, 4, 5, 6];
    for (slot, (group, types)) in ADDRESS_GROUPS.into_iter().enumerate() {
        if let Some(index) = group.keys().iter().position(|key| matches(key)) {
            return INDEXES
                .get(index)
                .map(|index| Target::Address(types, *index, slot));
        }
    }
    None
}

struct Patcher<'c> {
    card: &'c mut VCard,
    origins: Vec<(PropKey, usize)>,
    report: PatchReport,
    removed: Vec<usize>,
    created_addresses: [Option<usize>; ADDRESS_SLOTS],
    keywords_changed: bool,
}

pub(super) fn contact(card: &mut VCard, changes: &PropBag) -> Result<PatchReport, ConvertError> {
    let origins = origins(card)?;
    let mut patcher = Patcher {
        card,
        origins,
        report: PatchReport::default(),
        removed: Vec::new(),
        created_addresses: [None; ADDRESS_SLOTS],
        keywords_changed: changes
            .get_any(PropKey::name(PS_PUBLIC_STRINGS, KEYWORDS_NAME).as_ref())
            .is_some(),
    };
    for (key, value) in changes.iter() {
        let key_ref = key.as_ref();
        let applied = has_local_date(changes, key_ref)
            || target(key_ref).is_some_and(|target| patcher.apply(key_ref, target, value));
        if !applied {
            patcher.report.unmapped.set(key.clone(), value.clone());
        }
    }
    let Patcher {
        card,
        report,
        removed,
        ..
    } = patcher;
    remove_entries(&mut card.entries, removed);
    Ok(report)
}

pub(super) fn remove_entries(entries: &mut Vec<VCardEntry>, mut removed: Vec<usize>) {
    if removed.is_empty() {
        return;
    }
    removed.sort_unstable();
    let mut removed = removed.into_iter().peekable();
    let mut index = 0;
    entries.retain(|_| {
        let current = index;
        index += 1;
        let mut drop = false;
        while let Some(next) = removed.next_if(|next| *next <= current) {
            drop |= next == current;
        }
        !drop
    });
}

impl Patcher<'_> {
    fn origin(&self, key: PropKeyRef<'_>) -> Option<usize> {
        self.origins
            .iter()
            .find(|(known, _)| known.as_ref() == key)
            .map(|(_, index)| *index)
    }

    fn address_origin(&self, slot: usize) -> Option<usize> {
        let (group, _) = ADDRESS_GROUPS.get(slot)?;
        group
            .keys()
            .into_iter()
            .find_map(|key| self.origin(key.key()))
    }

    fn apply(&mut self, key: PropKeyRef<'_>, target: Target, value: &OwnedPropValue) -> bool {
        match (target, value) {
            (Target::Derived, _) => true,
            (Target::Text(create, types), OwnedPropValue::Unicode(text)) => {
                match self.origin(key) {
                    Some(index) if text.is_empty() => self.removed.push(index),
                    Some(index) => self.set_component(index, 0, text),
                    None if text.is_empty() => {}
                    None => {
                        self.push(create, types, VCardValue::Text(text.to_string()));
                    }
                }
                true
            }
            (Target::Component(property, index), OwnedPropValue::Unicode(text)) => {
                let entry = self.origin(key).or_else(|| {
                    let property = property();
                    self.card
                        .entries
                        .iter()
                        .position(|entry| entry.name == property)
                });
                let entry = match entry {
                    Some(entry) => entry,
                    None if text.is_empty() => return true,
                    None => self.push(
                        Create::Property(property),
                        &[],
                        VCardValue::Text(String::new()),
                    ),
                };
                match property() {
                    VCardProperty::N => self.pad(entry, N_COMPONENTS),
                    VCardProperty::Org if index == ORG_DEPARTMENT => {
                        self.truncate(entry, ORG_DEPARTMENT + 1)
                    }
                    _ => {}
                }
                self.set_component(entry, index, text);
                true
            }
            (Target::Address(types, index, slot), OwnedPropValue::Unicode(text)) => {
                let created = self.created_addresses.get(slot).copied().flatten();
                let entry = match self.address_origin(slot).or(created) {
                    Some(entry) => entry,
                    None if text.is_empty() => return true,
                    None => {
                        let entry = self.push(
                            Create::Property(|| VCardProperty::Adr),
                            types,
                            VCardValue::Text(String::new()),
                        );
                        if let Some(created) = self.created_addresses.get_mut(slot) {
                            *created = Some(entry);
                        }
                        entry
                    }
                };
                self.pad(entry, 7);
                if index == ADR_STREET
                    && self
                        .text_at(entry, ADR_EXTENDED)
                        .is_some_and(|extended| !extended.is_empty())
                {
                    self.report.lossy.insert(LossKind::ContactField);
                    self.set_component(entry, ADR_EXTENDED, "");
                }
                self.set_component(entry, index, text);
                true
            }
            (Target::Email(slot), OwnedPropValue::Unicode(text)) => {
                if self
                    .card
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.name == VCardProperty::Email && is_internet_email_entry(entry)
                    })
                    .count()
                    > EMAIL_SLOTS.len()
                {
                    self.report.lossy.insert(LossKind::ContactField);
                }
                match self.origin(key) {
                    Some(index) if text.is_empty() => self.removed.push(index),
                    Some(index) => self.set_component(index, 0, text),
                    None if text.is_empty() => {}
                    None => {
                        self.push(
                            Create::Property(|| VCardProperty::Email),
                            EMAIL_TYPES.get(slot).copied().unwrap_or(INTERNET),
                            VCardValue::Text(text.to_string()),
                        );
                    }
                }
                true
            }
            (Target::LegacyCategories, _) if self.keywords_changed => true,
            (Target::Categories | Target::LegacyCategories, OwnedPropValue::MvUnicode(values)) => {
                self.removed.extend(
                    self.card
                        .entries
                        .iter()
                        .enumerate()
                        .filter(|(_, entry)| entry.name == VCardProperty::Categories)
                        .map(|(index, _)| index),
                );
                if !values.is_empty() {
                    self.card.entries.push(VCardEntry {
                        group: None,
                        name: VCardProperty::Categories,
                        params: Vec::new(),
                        values: values
                            .iter()
                            .map(|value| VCardValue::Text(value.to_string()))
                            .collect(),
                    });
                }
                true
            }
            (Target::Impp, OwnedPropValue::Unicode(text)) => {
                match self.origin(key) {
                    Some(index) if text.is_empty() => self.removed.push(index),
                    Some(index) => self.set_impp(index, text),
                    None if text.is_empty() => {}
                    None => {
                        self.push(
                            Create::Property(|| VCardProperty::Impp),
                            &[],
                            VCardValue::Text(impp_uri(text).into_owned()),
                        );
                    }
                }
                true
            }
            (Target::Relation(relation), OwnedPropValue::Unicode(text)) => {
                let change = if text.is_empty() {
                    Change::Clear
                } else {
                    Change::Set
                };
                match related::remove_relation(
                    &self.card.entries,
                    relation,
                    self.origin(key),
                    change,
                    &mut self.removed,
                ) {
                    Some(index) => {
                        self.set_component(index, 0, text);
                        if let Some(entry) = self.card.entries.get_mut(index) {
                            related::mark_text(entry);
                        }
                    }
                    None if text.is_empty() => {}
                    None => Dialect::of(self.card).push(
                        &mut self.card.entries,
                        relation,
                        text.to_string(),
                    ),
                }
                true
            }
            (Target::Children, OwnedPropValue::MvUnicode(names)) => {
                let names = names
                    .iter()
                    .filter(|name| !name.is_empty())
                    .map(|name| name.to_string())
                    .collect();
                related::rewrite_children(self.card, names, &mut self.removed);
                true
            }
            (Target::Children, OwnedPropValue::Null) => {
                related::rewrite_children(self.card, Vec::new(), &mut self.removed);
                true
            }
            (
                Target::Text(..)
                | Target::Component(..)
                | Target::Address(..)
                | Target::Email(_)
                | Target::Impp
                | Target::Relation(_),
                OwnedPropValue::Null,
            ) => self.apply(key, target, &OwnedPropValue::Unicode(Box::default())),
            (Target::Categories | Target::LegacyCategories, OwnedPropValue::Null) => {
                self.apply(key, target, &OwnedPropValue::MvUnicode(Box::default()))
            }
            (Target::PostalAddressId, OwnedPropValue::I32(id)) => {
                if known_postal_address_id(*id) {
                    self.remove_where(is_postal_address_id_entry);
                    self.push(
                        Create::Other(POSTAL_ADDRESS_ID_PROPERTY),
                        &[],
                        VCardValue::Text(id.to_string()),
                    );
                } else {
                    self.report.lossy.insert(LossKind::ContactField);
                }
                true
            }
            (Target::PostalAddressId, OwnedPropValue::Null) => {
                self.remove_where(is_postal_address_id_entry);
                true
            }
            (Target::Sensitivity, OwnedPropValue::I32(level)) => {
                let text = match *level {
                    1 => "PERSONAL",
                    2 => "PRIVATE",
                    3 => "CONFIDENTIAL",
                    _ => "PUBLIC",
                };
                match self.origin(key) {
                    Some(index) => self.set_component(index, 0, text),
                    None => {
                        self.push(
                            Create::Other(CLASS_PROPERTY),
                            &[],
                            VCardValue::Text(text.into()),
                        );
                    }
                }
                true
            }
            (Target::Date(_) | Target::Integer(_), OwnedPropValue::Null) => {
                if let Some(index) = self.origin(key) {
                    self.removed.push(index);
                }
                true
            }
            (Target::Integer(create), OwnedPropValue::I32(number)) => {
                let text = number.to_string();
                match self.origin(key) {
                    Some(index) => self.set_component(index, 0, &text),
                    None => {
                        self.push(create, &[], VCardValue::Text(text));
                    }
                }
                true
            }
            (Target::Date(create), OwnedPropValue::Time(time)) => {
                let Some(date) = utc_date(*time) else {
                    return false;
                };
                match self.origin(key) {
                    Some(index) => {
                        let Some(entry) = self.card.entries.get_mut(index) else {
                            return false;
                        };
                        let value = match entry.values.first() {
                            Some(VCardValue::Text(_)) => VCardValue::Text(date_text(&date)),
                            _ => VCardValue::PartialDateTime(date),
                        };
                        entry.values = smallvec![value];
                    }
                    None => {
                        let value = match create {
                            Create::Other(_) => VCardValue::Text(date_text(&date)),
                            Create::Property(_) => VCardValue::PartialDateTime(date),
                        };
                        self.push(create, &[], value);
                    }
                }
                true
            }
            _ => false,
        }
    }

    fn push(&mut self, create: Create, types: &[Ty], value: VCardValue) -> usize {
        let name = match create {
            Create::Property(property) => property(),
            Create::Other(name) => VCardProperty::Other(name.into()),
        };
        let params = types
            .iter()
            .map(|ty| match ty {
                Ty::Known(known) => VCardParameter {
                    name: VCardParameterName::Type,
                    value: VCardParameterValue::Type((*known).clone()),
                },
                Ty::Text(text) => VCardParameter {
                    name: VCardParameterName::Type,
                    value: VCardParameterValue::Text((*text).into()),
                },
                Ty::PropId(id) => VCardParameter::prop_id((*id).to_string()),
            })
            .collect();
        self.card.entries.push(VCardEntry {
            group: None,
            name,
            params,
            values: smallvec![value],
        });
        self.card.entries.len().saturating_sub(1)
    }

    fn remove_where(&mut self, matches: impl Fn(&VCardEntry) -> bool) {
        self.removed.extend(
            self.card
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| matches(entry))
                .map(|(index, _)| index),
        );
    }

    fn set_impp(&mut self, index: usize, text: &str) {
        let Some(entry) = self.card.entries.get_mut(index) else {
            return;
        };
        if !matches!(entry.name, VCardProperty::Impp) {
            self.set_component(index, 0, text);
            return;
        }
        let uri = impp_uri(text);
        let same_scheme = match (
            entry
                .values
                .first()
                .and_then(VCardValue::as_text)
                .and_then(uri_scheme),
            uri_scheme(&uri),
        ) {
            (Some(old), Some(new)) => old.eq_ignore_ascii_case(new),
            _ => false,
        };
        if !same_scheme {
            entry.params.retain(|param| !is_service_type(&param.name));
        }
        self.set_component(index, 0, &uri);
    }

    fn pad(&mut self, entry: usize, len: usize) {
        if let Some(entry) = self.card.entries.get_mut(entry) {
            while entry.values.len() < len {
                entry.values.push(VCardValue::Text(String::new()));
            }
        }
    }

    fn truncate(&mut self, entry: usize, len: usize) {
        if let Some(entry) = self.card.entries.get_mut(entry)
            && entry.values.len() > len
        {
            entry.values.truncate(len);
            self.report.lossy.insert(LossKind::ContactField);
        }
    }

    fn text_at(&self, entry: usize, index: usize) -> Option<&str> {
        self.card.entries.get(entry)?.values.get(index)?.as_text()
    }

    fn set_component(&mut self, entry: usize, index: usize, text: &str) {
        let Some(entry) = self.card.entries.get_mut(entry) else {
            return;
        };
        while entry.values.len() <= index {
            entry.values.push(VCardValue::Text(String::new()));
        }
        if let Some(slot) = entry.values.get_mut(index) {
            if matches!(slot, VCardValue::Component(items) if items.len() > 1) {
                self.report.lossy.insert(LossKind::ContactField);
            }
            *slot = VCardValue::Text(text.into());
        }
    }
}

fn is_postal_address_id_entry(entry: &VCardEntry) -> bool {
    matches!(&entry.name, VCardProperty::Other(name)
        if hashify::set_ignore_case!(name.as_bytes(), "X-MS-POSTAL-ADDRESS-ID"))
}

fn is_service_type(name: &VCardParameterName) -> bool {
    match name {
        VCardParameterName::ServiceType => true,
        VCardParameterName::Other(name) => {
            hashify::set_ignore_case!(name.as_bytes(), "X-SERVICE-TYPE")
        }
        _ => false,
    }
}

pub(super) fn uri_scheme(text: &str) -> Option<&str> {
    let (scheme, _) = text.split_once(':')?;
    let (first, rest) = scheme.as_bytes().split_first()?;
    (first.is_ascii_alphabetic()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')))
    .then_some(scheme)
}

fn impp_uri(text: &str) -> Cow<'_, str> {
    if uri_scheme(text).is_some() {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(format!("{IM_URI_SCHEME}:{text}"))
    }
}

pub(super) fn impp_handle(uri: &str) -> &str {
    match uri.split_once(':') {
        Some((scheme, handle)) if scheme.eq_ignore_ascii_case(IM_URI_SCHEME) => handle,
        _ => uri,
    }
}

fn utc_date(time: FileTime) -> Option<PartialDateTime> {
    let date = Timestamp::from_second(time.to_utc().0.0)
        .ok()?
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date();
    Some(PartialDateTime {
        year: u16::try_from(date.year()).ok(),
        month: u8::try_from(date.month()).ok(),
        day: u8::try_from(date.day()).ok(),
        ..PartialDateTime::default()
    })
}

fn date_text(date: &PartialDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year.unwrap_or_default(),
        date.month.unwrap_or_default(),
        date.day.unwrap_or_default()
    )
}

pub(super) fn image_type(data: &[u8]) -> Option<&'static str> {
    match data {
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        [0x89, b'P', b'N', b'G', ..] => Some("image/png"),
        [b'G', b'I', b'F', b'8', ..] => Some("image/gif"),
        [b'B', b'M', ..] => Some("image/bmp"),
        _ => None,
    }
}

pub(super) fn set_photo(card: &mut VCard, photo: Option<Box<Data>>) {
    card.entries
        .retain(|entry| entry.name != VCardProperty::Photo);
    if let Some(data) = photo {
        card.entries.push(VCardEntry {
            group: None,
            name: VCardProperty::Photo,
            params: Vec::new(),
            values: smallvec![VCardValue::Binary(data)],
        });
    }
}
