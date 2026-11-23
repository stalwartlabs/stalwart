/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use ahash::RandomState;
use hashbrown::{HashTable, hash_table::Entry};

use super::tag::PropId;
use crate::{
    common::{Guid, LeReader, Utf16Le},
    mapi::rop::RopDecodeError,
};

pub const FIRST_NAMED_ID: PropId = PropId(0x8001);
pub const MAX_NAMED_IDS: u16 = 32767;

pub mod sets {
    use crate::common::Guid;

    const MAPI_TAIL: [u8; 8] = [0xC0, 0, 0, 0, 0, 0, 0, 0x46];

    pub const PS_MAPI: Guid = Guid::from_fields(0x0002_0328, 0, 0, MAPI_TAIL);
    pub const PS_PUBLIC_STRINGS: Guid = Guid::from_fields(0x0002_0329, 0, 0, MAPI_TAIL);
    pub const PS_INTERNET_HEADERS: Guid = Guid::from_fields(0x0002_0386, 0, 0, MAPI_TAIL);
    pub const PSETID_COMMON: Guid = Guid::from_fields(0x0006_2008, 0, 0, MAPI_TAIL);
    pub const PSETID_APPOINTMENT: Guid = Guid::from_fields(0x0006_2002, 0, 0, MAPI_TAIL);
    pub const PSETID_ADDRESS: Guid = Guid::from_fields(0x0006_2004, 0, 0, MAPI_TAIL);
    pub const PSETID_TASK: Guid = Guid::from_fields(0x0006_2003, 0, 0, MAPI_TAIL);
    pub const PSETID_LOG: Guid = Guid::from_fields(0x0006_200A, 0, 0, MAPI_TAIL);
    pub const PSETID_NOTE: Guid = Guid::from_fields(0x0006_200E, 0, 0, MAPI_TAIL);
    pub const PSETID_SHARING: Guid = Guid::from_fields(0x0006_2040, 0, 0, MAPI_TAIL);
    pub const PSETID_POST_RSS: Guid = Guid::from_fields(0x0006_2041, 0, 0, MAPI_TAIL);
    pub const PSETID_MEETING: Guid = Guid::from_fields(
        0x6ED8_DA90,
        0x450B,
        0x101B,
        [0x98, 0xDA, 0x00, 0xAA, 0x00, 0x3F, 0x13, 0x05],
    );
    pub const PSETID_MESSAGING: Guid = Guid::from_fields(
        0x41F2_8F13,
        0x83F4,
        0x4114,
        [0xA5, 0x84, 0xEE, 0xDB, 0x5A, 0x6B, 0x0B, 0xFF],
    );
    pub const PSETID_CALENDAR_ASSISTANT: Guid = Guid::from_fields(
        0x1100_0E07,
        0xB51B,
        0x40D6,
        [0xAF, 0x21, 0xCA, 0xA8, 0x5E, 0xDA, 0xB1, 0xD0],
    );
    pub const PSETID_UNIFIED_MESSAGING: Guid = Guid::from_fields(
        0x4442_858E,
        0xA9E3,
        0x4E80,
        [0xB9, 0x00, 0x31, 0x7A, 0x21, 0x0C, 0xC1, 0x5B],
    );
    pub const PSETID_ATTACHMENT: Guid = Guid::from_fields(
        0x9635_7F7F,
        0x59E1,
        0x47D0,
        [0x99, 0xA7, 0x46, 0x51, 0x5C, 0x18, 0x3B, 0x54],
    );
    pub const PSETID_AIRSYNC: Guid = Guid::from_fields(
        0x7103_5549,
        0x0739,
        0x4DCB,
        [0x91, 0x63, 0x00, 0xF0, 0x58, 0x0D, 0xBB, 0xDF],
    );
    pub const PSETID_XML_EXTRACTED_ENTITIES: Guid = Guid::from_fields(
        0x2323_9608,
        0x685D,
        0x4732,
        [0x9C, 0x55, 0x4C, 0x95, 0xCB, 0x4E, 0x8E, 0x33],
    );
}

#[derive(Debug, Clone)]
struct NamedKey {
    set: Guid,
    name: Box<str>,
}

#[derive(Debug, Clone)]
enum KeyRepr {
    Tag(PropId),
    Lid { set: Guid, lid: u32 },
    Name(Box<NamedKey>),
}

#[derive(Debug, Clone)]
pub struct PropKey(KeyRepr);

const _: () = assert!(size_of::<PropKey>() <= 24);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PropKeyRef<'k> {
    Tag(PropId),
    Lid { set: Guid, lid: u32 },
    Name { set: Guid, name: &'k str },
}

impl PropKey {
    pub const fn tag(id: PropId) -> Self {
        PropKey(KeyRepr::Tag(id))
    }

    pub const fn lid(set: Guid, lid: u32) -> Self {
        PropKey(KeyRepr::Lid { set, lid })
    }

    pub fn name(set: Guid, name: &str) -> Self {
        let name = if set == sets::PS_INTERNET_HEADERS {
            name.to_ascii_lowercase().into_boxed_str()
        } else {
            Box::from(name)
        };
        PropKey(KeyRepr::Name(Box::new(NamedKey { set, name })))
    }

    pub fn internet_header(name: &str) -> Self {
        PropKey::name(sets::PS_INTERNET_HEADERS, name)
    }

    pub fn as_ref(&self) -> PropKeyRef<'_> {
        match &self.0 {
            KeyRepr::Tag(id) => PropKeyRef::Tag(*id),
            KeyRepr::Lid { set, lid } => PropKeyRef::Lid {
                set: *set,
                lid: *lid,
            },
            KeyRepr::Name(named) => PropKeyRef::Name {
                set: named.set,
                name: &named.name,
            },
        }
    }

    pub fn heap_size(&self) -> usize {
        match &self.0 {
            KeyRepr::Name(named) => size_of::<NamedKey>().saturating_add(named.name.len()),
            KeyRepr::Tag(_) | KeyRepr::Lid { .. } => 0,
        }
    }
}

impl PropKeyRef<'_> {
    pub fn to_key(&self) -> PropKey {
        match *self {
            PropKeyRef::Tag(id) => PropKey::tag(id),
            PropKeyRef::Lid { set, lid } => PropKey::lid(set, lid),
            PropKeyRef::Name { set, name } => PropKey::name(set, name),
        }
    }
}

impl PartialEq for PropKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for PropKey {}

impl Hash for PropKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialOrd for PropKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PropKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_ref().cmp(&other.as_ref())
    }
}

pub trait NamedPropMap {
    fn id(&self, key: PropKeyRef<'_>) -> Option<PropId>;
    fn key(&self, id: PropId) -> Option<PropKeyRef<'_>>;
}

#[derive(Debug, Clone, Default)]
pub struct StaticNamedPropMap {
    entries: Vec<(PropKey, PropId)>,
    by_key: HashTable<u32>,
    by_id: Vec<(PropId, u32)>,
    hasher: RandomState,
}

impl StaticNamedPropMap {
    pub fn new(entries: impl IntoIterator<Item = (PropKey, PropId)>) -> Self {
        let hasher = RandomState::new();
        let entries = entries.into_iter();
        let capacity = entries.size_hint().0;
        let mut kept: Vec<(PropKey, PropId)> = Vec::with_capacity(capacity);
        let mut by_key: HashTable<u32> = HashTable::with_capacity(capacity);
        for (key, id) in entries {
            let Ok(index) = u32::try_from(kept.len()) else {
                break;
            };
            let hash = hasher.hash_one(key.as_ref());
            if let Entry::Vacant(slot) = by_key.entry(
                hash,
                |at| key_at(&kept, *at) == Some(key.as_ref()),
                |at| key_at(&kept, *at).map_or(0, |key| hasher.hash_one(key)),
            ) {
                slot.insert(index);
                kept.push((key, id));
            }
        }
        let mut by_id: Vec<(PropId, u32)> = kept
            .iter()
            .zip(0u32..)
            .map(|((_, id), index)| (*id, index))
            .collect();
        by_id.sort_by_key(|(id, _)| *id);
        by_id.dedup_by_key(|(id, _)| *id);
        StaticNamedPropMap {
            entries: kept,
            by_key,
            by_id,
            hasher,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn key_at(entries: &[(PropKey, PropId)], index: u32) -> Option<PropKeyRef<'_>> {
    entries
        .get(usize::try_from(index).ok()?)
        .map(|(key, _)| key.as_ref())
}

impl NamedPropMap for StaticNamedPropMap {
    fn id(&self, key: PropKeyRef<'_>) -> Option<PropId> {
        let hash = self.hasher.hash_one(key);
        let index = self
            .by_key
            .find(hash, |at| key_at(&self.entries, *at) == Some(key))?;
        self.entries
            .get(usize::try_from(*index).ok()?)
            .map(|(_, id)| *id)
    }

    fn key(&self, id: PropId) -> Option<PropKeyRef<'_>> {
        let slot = self.by_id.binary_search_by_key(&id, |(id, _)| *id).ok()?;
        let (_, index) = self.by_id.get(slot)?;
        key_at(&self.entries, *index)
    }
}

const KIND_LID: u8 = 0x00;
const KIND_NAME: u8 = 0x01;
const KIND_NONE: u8 = 0xFF;
const NAME_MAX_UNITS: usize = 126;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyName<'a> {
    Lid { set: Guid, lid: u32 },
    Name { set: Guid, name: Utf16Le<'a> },
    None,
}

impl<'a> PropertyName<'a> {
    pub fn decode(r: &mut LeReader<'a>) -> Result<Self, RopDecodeError> {
        let offset = r.offset();
        let kind = r.u8()?;
        if kind == KIND_NONE {
            return Ok(PropertyName::None);
        }
        let set = r.guid()?;
        match kind {
            KIND_LID => Ok(PropertyName::Lid { set, lid: r.u32()? }),
            KIND_NAME => {
                let size = usize::from(r.u8()?);
                let bytes = r.bytes(size)?;
                let bad = || RopDecodeError::BadUtf16 {
                    offset: RopDecodeError::at(offset),
                };
                let units = bytes.strip_suffix(&[0, 0]).ok_or_else(bad)?;
                let name = Utf16Le::new(units).ok_or_else(bad)?;
                if name.units().any(|unit| unit == 0) {
                    return Err(bad());
                }
                Ok(PropertyName::Name { set, name })
            }
            other => Err(RopDecodeError::BadKind {
                offset: RopDecodeError::at(offset),
                kind: other,
            }),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            PropertyName::Lid { set, lid } => {
                out.push(KIND_LID);
                out.extend_from_slice(set.as_bytes());
                out.extend_from_slice(&lid.to_le_bytes());
            }
            PropertyName::Name { set, name } => {
                out.push(KIND_NAME);
                out.extend_from_slice(set.as_bytes());
                let units = name
                    .as_bytes()
                    .get(..NAME_MAX_UNITS.saturating_mul(2))
                    .unwrap_or(name.as_bytes());
                let units = trim_surrogate(units);
                out.push(u8::try_from(units.len().saturating_add(2)).unwrap_or(u8::MAX));
                out.extend_from_slice(units);
                out.extend_from_slice(&[0, 0]);
            }
            PropertyName::None => out.push(KIND_NONE),
        }
    }

    pub fn encode_key(key: PropKeyRef<'_>, out: &mut Vec<u8>) {
        match key {
            PropKeyRef::Tag(_) => PropertyName::None.encode(out),
            PropKeyRef::Lid { set, lid } => PropertyName::Lid { set, lid }.encode(out),
            PropKeyRef::Name { set, name } => {
                out.push(KIND_NAME);
                out.extend_from_slice(set.as_bytes());
                let size_at = out.len();
                out.push(0);
                let start = out.len();
                let mut units = 0usize;
                for ch in name.chars() {
                    let width = ch.len_utf16();
                    if units.saturating_add(width) > NAME_MAX_UNITS || ch == '\0' {
                        break;
                    }
                    units = units.saturating_add(width);
                    let mut buf = [0u16; 2];
                    for unit in ch.encode_utf16(&mut buf) {
                        out.extend_from_slice(&unit.to_le_bytes());
                    }
                }
                out.extend_from_slice(&[0, 0]);
                let size = u8::try_from(out.len().saturating_sub(start)).unwrap_or(u8::MAX);
                if let Some(slot) = out.get_mut(size_at) {
                    *slot = size;
                }
            }
        }
    }

    pub fn to_key_ref<'s>(&self, scratch: &'s mut String) -> Option<PropKeyRef<'s>>
    where
        'a: 's,
    {
        match self {
            PropertyName::Lid { set, lid } => Some(PropKeyRef::Lid {
                set: *set,
                lid: *lid,
            }),
            PropertyName::Name { set, name } => {
                scratch.clear();
                name.to_string_lossy(scratch);
                if *set == sets::PS_INTERNET_HEADERS {
                    scratch.make_ascii_lowercase();
                }
                Some(PropKeyRef::Name {
                    set: *set,
                    name: scratch.as_str(),
                })
            }
            PropertyName::None => None,
        }
    }
}

fn trim_surrogate(units: &[u8]) -> &[u8] {
    match units.last_chunk::<2>() {
        Some(last) if (0xD800..0xDC00).contains(&u16::from_le_bytes(*last)) => {
            units.get(..units.len().saturating_sub(2)).unwrap_or(units)
        }
        _ => units,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/prop/name/tests.rs"]
mod tests;
