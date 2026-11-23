/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    codec::{decode_value, encode_owned, encode_value},
    name::{PropKey, PropKeyRef},
    owned::OwnedPropValue,
    tag::{PropId, PropType},
    value::{CountWidth, PropValue},
};
use crate::{
    common::{Guid, LeReader},
    mapi::emsmdb::MapiLimits,
};

const KEY_TAG: u8 = 0;
const KEY_LID: u8 = 1;
const KEY_NAME: u8 = 2;

const STORED: MapiLimits = MapiLimits {
    mv_count_max: u32::MAX,
    ..MapiLimits::DEFAULT
};

impl PropId {
    pub const fn canonical_key(self) -> [u8; 3] {
        let [high, low] = self.0.to_be_bytes();
        [KEY_TAG, high, low]
    }
}

impl PropKeyRef<'_> {
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        match *self {
            PropKeyRef::Tag(id) => {
                out.push(KEY_TAG);
                out.extend_from_slice(&id.0.to_be_bytes());
            }
            PropKeyRef::Lid { set, lid } => {
                out.push(KEY_LID);
                out.extend_from_slice(set.as_bytes());
                out.extend_from_slice(&lid.to_be_bytes());
            }
            PropKeyRef::Name { set, name } => {
                out.push(KEY_NAME);
                out.extend_from_slice(set.as_bytes());
                let name = name
                    .get(..name.floor_char_boundary(usize::from(u16::MAX)))
                    .unwrap_or_default();
                out.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_be_bytes());
                out.extend_from_slice(name.as_bytes());
            }
        }
    }

    pub fn read_canonical(b: &[u8]) -> Option<(PropKeyRef<'_>, &[u8])> {
        let (kind, rest) = b.split_first()?;
        match *kind {
            KEY_TAG => {
                let (id, rest) = rest.split_first_chunk::<2>()?;
                Some((PropKeyRef::Tag(PropId(u16::from_be_bytes(*id))), rest))
            }
            KEY_LID => {
                let (set, rest) = rest.split_first_chunk::<16>()?;
                let (lid, rest) = rest.split_first_chunk::<4>()?;
                Some((
                    PropKeyRef::Lid {
                        set: Guid(*set),
                        lid: u32::from_be_bytes(*lid),
                    },
                    rest,
                ))
            }
            KEY_NAME => {
                let (set, rest) = rest.split_first_chunk::<16>()?;
                let (len, rest) = rest.split_first_chunk::<2>()?;
                let (name, rest) = rest.split_at_checked(usize::from(u16::from_be_bytes(*len)))?;
                Some((
                    PropKeyRef::Name {
                        set: Guid(*set),
                        name: std::str::from_utf8(name).ok()?,
                    },
                    rest,
                ))
            }
            _ => None,
        }
    }
}

impl PropKey {
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        self.as_ref().write_canonical(out);
    }

    pub fn read_canonical(b: &[u8]) -> Option<(Self, &[u8])> {
        PropKeyRef::read_canonical(b).map(|(key, rest)| (key.to_key(), rest))
    }
}

fn write_framed(out: &mut Vec<u8>, ptype: PropType, f: impl FnOnce(&mut Vec<u8>)) {
    out.extend_from_slice(&ptype.code().to_le_bytes());
    let len_at = out.len();
    out.extend_from_slice(&[0; 4]);
    let start = out.len();
    f(out);
    let len = u32::try_from(out.len().saturating_sub(start)).unwrap_or(u32::MAX);
    if let Some(slot) = out.get_mut(len_at..start) {
        slot.copy_from_slice(&len.to_le_bytes());
    }
}

impl PropValue<'_> {
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        write_framed(out, self.ptype(), |out| {
            encode_value(out, self, CountWidth::Wide)
        });
    }
}

impl OwnedPropValue {
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        write_framed(out, self.ptype(), |out| {
            encode_owned(out, self, CountWidth::Wide)
        });
    }

    pub fn read_canonical(b: &[u8]) -> Option<(Self, &[u8])> {
        read_canonical_borrowed(b).map(|(value, rest)| (value.to_owned_value(), rest))
    }
}

pub fn read_canonical_borrowed(b: &[u8]) -> Option<(PropValue<'_>, &[u8])> {
    let (ptype, rest) = b.split_first_chunk::<2>()?;
    let (len, rest) = rest.split_first_chunk::<4>()?;
    let (body, rest) = rest.split_at_checked(usize::try_from(u32::from_le_bytes(*len)).ok()?)?;
    let mut r = LeReader::new(body);
    let value = decode_value(
        &mut r,
        PropType::from_code(u16::from_le_bytes(*ptype)),
        CountWidth::Wide,
        &STORED,
    )
    .ok()?;
    r.is_empty().then_some((value, rest))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/prop/canonical/tests.rs"]
mod tests;
