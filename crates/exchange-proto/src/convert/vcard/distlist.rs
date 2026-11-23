/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, iter};

use bytes::Bytes;
use calcard::vcard::{VCard, VCardEntry, VCardKind, VCardProperty, VCardValue};
use smallvec::smallvec;

use super::{
    props::{DISPLAY_NAME, LID_FILE_UNDER, LID_FILE_UNDER_ID, NORMALIZED_SUBJECT, address_lid},
    sink::{CATEGORIES, KEYWORDS},
    to_message::revision_time,
};
use crate::{
    common::Guid,
    convert::{
        ConvertError,
        model::{MessageContent, PropBag},
        rtf::crc32_update,
        tags,
    },
    ids::entryid::{AddressBookEntryId, EntryId, MessageEntryId, OneOffEntryId, one_off_flags},
    mapi::{
        nspi::tags::{DT_DISTLIST, DT_MAILUSER},
        prop::{OwnedPropValue, PropKey, PropKeyRef, sets::PSETID_ADDRESS},
    },
};

pub const DISTLIST_CLASS: &str = "IPM.DistList";
const DIST_CHECKSUM: u32 = 0x804C;
const DIST_NAME: u32 = 0x8053;
const DIST_ONE_OFF_MEMBERS: u32 = 0x8054;
const DIST_MEMBERS: u32 = 0x8055;
const DIST_STREAM: u32 = 0x8064;
const FILE_UNDER_NONE: i32 = -1;
const MAX_MEMBERS_SIZE: usize = 15_000;
const SMTP: &str = "SMTP";
const EX: &str = "EX";
const MEMBER_ONE_OFF_FLAGS: u16 = one_off_flags::NO_RICH_INFO | one_off_flags::UNICODE;
const WRAPPED_PROVIDER: Guid = Guid::from_wire([
    0xC0, 0x91, 0xAD, 0xD3, 0x51, 0x9D, 0xCF, 0x11, 0xA4, 0xA9, 0x00, 0xAA, 0x00, 0x47, 0xFA, 0xA4,
]);
const WRAPPED_HEADER_LEN: usize = 21;
const STREAM_VERSION: u16 = 1;
const STREAM_BUILD_VERSION: u32 = 30_000;
const STREAM_HEADER_LEN: usize = 28;
const STREAM_COUNT_OFFSET: usize = 12;
const STREAM_TERMINATOR_LEN: usize = 8;
const MEMBER_KEYS: [u32; 4] = [
    DIST_CHECKSUM,
    DIST_ONE_OFF_MEMBERS,
    DIST_MEMBERS,
    DIST_STREAM,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    Contact,
    PersonalList,
    DirectoryUser,
    DirectoryList,
}

impl MemberKind {
    const fn wrapped_type(self) -> u8 {
        match self {
            MemberKind::Contact => 0xC3,
            MemberKind::PersonalList => 0xB4,
            MemberKind::DirectoryUser => 0xB5,
            MemberKind::DirectoryList => 0xB6,
        }
    }

    const fn from_wrapped_type(byte: u8) -> Option<Self> {
        match byte & 0x0F {
            3 => Some(MemberKind::Contact),
            4 => Some(MemberKind::PersonalList),
            5 => Some(MemberKind::DirectoryUser),
            6 => Some(MemberKind::DirectoryList),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistTarget<'a> {
    OneOff,
    Message {
        kind: MemberKind,
        entry: MessageEntryId,
    },
    Directory {
        kind: MemberKind,
        dn: Cow<'a, [u8]>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    Smtp,
    LegacyDn,
    Other,
}

impl AddressType {
    fn parse(value: &str) -> Self {
        hashify::map_ignore_case!(value.as_bytes(), AddressType,
            "SMTP" => AddressType::Smtp,
            "EX" => AddressType::LegacyDn,
        )
        .copied()
        .unwrap_or(AddressType::Other)
    }

    const fn as_str(self) -> Option<&'static str> {
        match self {
            AddressType::Smtp => Some(SMTP),
            AddressType::LegacyDn => Some(EX),
            AddressType::Other => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistMember<'a> {
    pub target: DistTarget<'a>,
    pub name: Cow<'a, str>,
    pub address_type: AddressType,
    pub email: Cow<'a, str>,
}

pub(super) fn is_member_key(key: PropKeyRef<'_>) -> bool {
    matches!(key, PropKeyRef::Lid { set, lid } if set == PSETID_ADDRESS && MEMBER_KEYS.contains(&lid))
}

pub(super) fn is_name_key(key: PropKeyRef<'_>) -> bool {
    match key {
        PropKeyRef::Tag(id) => id == DISPLAY_NAME || id == tags::SUBJECT,
        PropKeyRef::Lid { set, lid } => set == PSETID_ADDRESS && lid == DIST_NAME,
        _ => false,
    }
}

pub(super) fn is_group(card: &VCard) -> bool {
    card.property(&VCardProperty::Kind)
        .and_then(|entry| entry.values.first())
        .is_some_and(|value| matches!(value, VCardValue::Kind(VCardKind::Group)))
}

pub(super) fn group_members(card: &VCard) -> impl Iterator<Item = &str> {
    card.entries
        .iter()
        .filter(|entry| entry.name == VCardProperty::Member)
        .filter_map(|entry| entry.values.first())
        .filter_map(VCardValue::as_text)
}

pub(super) fn to_message(
    card: &VCard,
    members: Option<&[DistMember<'_>]>,
) -> Result<MessageContent, ConvertError> {
    let mut content = MessageContent::default();
    let props = &mut content.props;
    props.set(
        PropKey::tag(tags::MESSAGE_CLASS),
        OwnedPropValue::Unicode(DISTLIST_CLASS.into()),
    );
    let name = first_text(card, &VCardProperty::Fn).unwrap_or_default();
    for id in [DISPLAY_NAME, NORMALIZED_SUBJECT, tags::SUBJECT] {
        props.set(PropKey::tag(id), OwnedPropValue::Unicode(name.into()));
    }
    for lid in [DIST_NAME, LID_FILE_UNDER] {
        props.set(lid_key(lid), OwnedPropValue::Unicode(name.into()));
    }
    props.set(
        lid_key(LID_FILE_UNDER_ID),
        OwnedPropValue::I32(FILE_UNDER_NONE),
    );
    if let Some(note) = first_text(card, &VCardProperty::Note) {
        props.set(
            PropKey::tag(tags::BODY),
            OwnedPropValue::Unicode(note.into()),
        );
    }
    let categories = categories(card);
    if !categories.is_empty() {
        props.set(
            KEYWORDS.to_key(),
            OwnedPropValue::MvUnicode(categories.clone()),
        );
        props.set(CATEGORIES.to_key(), OwnedPropValue::MvUnicode(categories));
    }
    if let Some(time) = card.property(&VCardProperty::Rev).and_then(revision_time) {
        props.set(
            PropKey::tag(tags::LAST_MODIFICATION_TIME),
            OwnedPropValue::Time(time),
        );
    }
    let Some(members) = members else {
        return Ok(content);
    };
    let mut entries = Vec::with_capacity(members.len());
    let mut one_offs = Vec::with_capacity(members.len());
    for member in members {
        let Some(card) = member
            .address_type
            .as_str()
            .and_then(|address_type| member_one_off(&member.name, address_type, &member.email))
        else {
            continue;
        };
        let entry = match &member.target {
            DistTarget::OneOff => card.clone(),
            DistTarget::Message { kind, entry } => {
                wrapped(*kind, &EntryId::Message(entry.clone()))?
            }
            DistTarget::Directory { kind, dn } => wrapped(
                *kind,
                &EntryId::AddressBook(AddressBookEntryId {
                    flags: 0,
                    display_type: if *kind == MemberKind::DirectoryList {
                        DT_DISTLIST
                    } else {
                        DT_MAILUSER
                    },
                    dn: Cow::Borrowed(dn),
                }),
            )?,
        };
        entries.push(entry);
        one_offs.push(card);
    }
    let size = |values: &[Bytes]| values.iter().map(Bytes::len).sum::<usize>();
    if size(&entries) >= MAX_MEMBERS_SIZE || size(&one_offs) >= MAX_MEMBERS_SIZE {
        props.set(
            lid_key(DIST_STREAM),
            OwnedPropValue::Binary(stream(&entries, &one_offs)?.into()),
        );
    } else {
        props.set(
            lid_key(DIST_CHECKSUM),
            OwnedPropValue::I32(i32::from_le_bytes(checksum(&entries).to_le_bytes())),
        );
        props.set(
            lid_key(DIST_MEMBERS),
            OwnedPropValue::MvBinary(entries.into()),
        );
        props.set(
            lid_key(DIST_ONE_OFF_MEMBERS),
            OwnedPropValue::MvBinary(one_offs.into()),
        );
    }
    Ok(content)
}

pub(super) fn name(props: &PropBag) -> Option<&str> {
    [
        PropKeyRef::Tag(DISPLAY_NAME),
        address_lid(DIST_NAME),
        PropKeyRef::Tag(tags::SUBJECT),
    ]
    .into_iter()
    .find_map(|key| match props.get_any(key) {
        Some(OwnedPropValue::Unicode(text)) if !text.is_empty() => Some(&**text),
        _ => None,
    })
}

pub(super) fn members<'x>(
    props: &'x PropBag,
    changes: Option<&PropBag>,
) -> Result<Vec<DistMember<'x>>, ConvertError> {
    let changed = |lid| changes.is_none_or(|changes| changes.get_any(address_lid(lid)).is_some());
    if (changed(DIST_STREAM) || !changed(DIST_MEMBERS))
        && let Some(OwnedPropValue::Binary(stream)) = props.get_any(address_lid(DIST_STREAM))
        && !stream.is_empty()
    {
        return parse_stream(stream);
    }
    let entries = match props.get_any(address_lid(DIST_MEMBERS)) {
        Some(OwnedPropValue::MvBinary(entries)) => &entries[..],
        _ => &[],
    };
    let one_offs = match props.get_any(address_lid(DIST_ONE_OFF_MEMBERS)) {
        Some(OwnedPropValue::MvBinary(one_offs))
            if changed(DIST_ONE_OFF_MEMBERS) || !changed(DIST_MEMBERS) =>
        {
            &one_offs[..]
        }
        _ => &[],
    };
    let cards = one_offs
        .iter()
        .map(|card| Some(&card[..]))
        .chain(iter::repeat(None));
    Ok(entries
        .iter()
        .zip(cards)
        .filter_map(|(entry, card)| member(entry, card))
        .collect())
}

pub(super) fn patch(
    card: &mut VCard,
    name: Option<&str>,
    members: Option<&[String]>,
    hidden: &dyn Fn(&str) -> bool,
) {
    if !is_group(card) {
        card.entries
            .retain(|entry| entry.name != VCardProperty::Kind);
        card.entries.push(entry(
            VCardProperty::Kind,
            VCardValue::Kind(VCardKind::Group),
        ));
    }
    if let Some(name) = name {
        card.entries.retain(|entry| entry.name != VCardProperty::Fn);
        card.entries
            .push(entry(VCardProperty::Fn, VCardValue::Text(name.into())));
    } else if card.property(&VCardProperty::Fn).is_none() {
        card.entries
            .push(entry(VCardProperty::Fn, VCardValue::Text(String::new())));
    }
    if let Some(members) = members {
        card.entries.retain(|entry| {
            entry.name != VCardProperty::Member
                || entry
                    .values
                    .first()
                    .and_then(VCardValue::as_text)
                    .is_some_and(hidden)
        });
        card.entries.extend(
            members
                .iter()
                .map(|uri| entry(VCardProperty::Member, VCardValue::Text(uri.clone()))),
        );
    }
}

fn entry(name: VCardProperty, value: VCardValue) -> VCardEntry {
    VCardEntry {
        group: None,
        name,
        params: Vec::new(),
        values: smallvec![value],
    }
}

fn lid_key(lid: u32) -> PropKey {
    PropKey::lid(PSETID_ADDRESS, lid)
}

fn first_text<'x>(card: &'x VCard, property: &VCardProperty) -> Option<&'x str> {
    card.property(property)
        .and_then(|entry| entry.values.first())
        .and_then(VCardValue::as_text)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn categories(card: &VCard) -> Box<[Box<str>]> {
    card.entries
        .iter()
        .filter(|entry| entry.name == VCardProperty::Categories)
        .flat_map(|entry| entry.values.iter())
        .flat_map(|value| {
            let (items, text) = match value {
                VCardValue::Component(items) => (items.as_slice(), None),
                value => (&[][..], value.as_text()),
            };
            items.iter().map(String::as_str).chain(text)
        })
        .map(str::trim)
        .filter(|category| !category.is_empty())
        .map(Box::from)
        .collect()
}

fn member_one_off(name: &str, address_type: &str, email: &str) -> Option<Bytes> {
    let mut out = Vec::new();
    EntryId::OneOff(OneOffEntryId {
        flags: MEMBER_ONE_OFF_FLAGS,
        display_name: Cow::Borrowed(name),
        address_type: Cow::Borrowed(address_type),
        email: Cow::Borrowed(email),
    })
    .encode(&mut out)
    .ok()?;
    Some(out.into())
}

fn wrapped(kind: MemberKind, embedded: &EntryId<'_>) -> Result<Bytes, ConvertError> {
    let mut out = Vec::with_capacity(WRAPPED_HEADER_LEN + 70);
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(WRAPPED_PROVIDER.as_bytes());
    out.push(kind.wrapped_type());
    embedded
        .encode(&mut out)
        .map_err(|_| ConvertError::Unsupported)?;
    Ok(out.into())
}

pub(super) fn checksum(entries: &[Bytes]) -> u32 {
    entries
        .iter()
        .fold(0, |crc, entry| crc32_update(crc, entry))
}

fn stream(entries: &[Bytes], one_offs: &[Bytes]) -> Result<Vec<u8>, ConvertError> {
    let len = |value: usize| u32::try_from(value).map_err(|_| ConvertError::TooLarge);
    let entry_size = entries.iter().map(Bytes::len).sum::<usize>();
    let one_off_size = one_offs.iter().map(Bytes::len).sum::<usize>();
    let mut out = Vec::with_capacity(
        STREAM_HEADER_LEN
            + STREAM_TERMINATOR_LEN
            + entry_size
            + one_off_size
            + entries.len().saturating_mul(12),
    );
    out.extend_from_slice(&STREAM_VERSION.to_le_bytes());
    out.extend_from_slice(&[0; 2]);
    out.extend_from_slice(&STREAM_BUILD_VERSION.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&len(entries.len())?.to_le_bytes());
    out.extend_from_slice(&len(entry_size)?.to_le_bytes());
    out.extend_from_slice(&len(one_off_size)?.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for (entry, card) in entries.iter().zip(one_offs) {
        out.extend_from_slice(&len(entry.len())?.to_le_bytes());
        out.extend_from_slice(entry);
        out.extend_from_slice(&len(card.len())?.to_le_bytes());
        out.extend_from_slice(card);
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    out.extend_from_slice(&[0; STREAM_TERMINATOR_LEN]);
    Ok(out)
}

fn parse_stream(stream: &[u8]) -> Result<Vec<DistMember<'_>>, ConvertError> {
    let malformed = || ConvertError::Unsupported;
    let (header, mut rest) = stream
        .split_first_chunk::<STREAM_HEADER_LEN>()
        .ok_or_else(malformed)?;
    let count = header
        .get(STREAM_COUNT_OFFSET..)
        .and_then(<[u8]>::first_chunk::<4>)
        .and_then(|count| usize::try_from(u32::from_le_bytes(*count)).ok())
        .ok_or_else(malformed)?;
    let mut members = Vec::with_capacity(count.min(rest.len() / 8));
    for _ in 0..count {
        let (entry, after) = sized(rest).ok_or_else(malformed)?;
        let (card, after) = sized(after).ok_or_else(malformed)?;
        let (_, after) = sized(after).ok_or_else(malformed)?;
        rest = after;
        members.extend(member(entry, Some(card).filter(|card| !card.is_empty())));
    }
    Ok(members)
}

fn sized(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
    rest.split_at_checked(len)
}

fn member<'a>(entry: &'a [u8], card: Option<&'a [u8]>) -> Option<DistMember<'a>> {
    let card = card.and_then(|card| match EntryId::decode(card) {
        Ok(EntryId::OneOff(card)) => Some(card),
        _ => None,
    });
    let (target, own) = match EntryId::decode(entry) {
        Ok(EntryId::OneOff(own)) => (DistTarget::OneOff, Some(own)),
        _ => {
            let (header, embedded) = entry.split_at_checked(WRAPPED_HEADER_LEN)?;
            let (kind, provider) = header.get(4..)?.split_last()?;
            if provider != WRAPPED_PROVIDER.as_bytes() {
                return None;
            }
            match (
                MemberKind::from_wrapped_type(*kind),
                EntryId::decode(embedded).ok()?,
            ) {
                (None, EntryId::OneOff(own)) => (DistTarget::OneOff, Some(own)),
                (
                    Some(kind @ (MemberKind::Contact | MemberKind::PersonalList)),
                    EntryId::Message(entry),
                ) => (DistTarget::Message { kind, entry }, None),
                (
                    Some(kind @ (MemberKind::DirectoryUser | MemberKind::DirectoryList)),
                    EntryId::AddressBook(entry),
                ) => (DistTarget::Directory { kind, dn: entry.dn }, None),
                _ => return None,
            }
        }
    };
    let OneOffEntryId {
        display_name,
        address_type,
        email,
        ..
    } = own.or(card).unwrap_or(OneOffEntryId {
        flags: 0,
        display_name: Cow::Borrowed(""),
        address_type: Cow::Borrowed(SMTP),
        email: Cow::Borrowed(""),
    });
    Some(DistMember {
        target,
        name: display_name,
        address_type: AddressType::parse(&address_type),
        email,
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/vcard/distlist/tests.rs"]
mod tests;
