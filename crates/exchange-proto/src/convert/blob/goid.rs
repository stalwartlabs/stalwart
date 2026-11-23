/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::{common::time::FileTime, convert::hex_value};

pub const BYTE_ARRAY_ID: [u8; 16] = [
    0x04, 0x00, 0x00, 0x00, 0x82, 0x00, 0xE0, 0x00, 0x74, 0xC5, 0xB7, 0x10, 0x1A, 0x82, 0xE0, 0x08,
];
pub const VCAL_UID_MARKER: [u8; 12] = *b"vCal-Uid\x01\x00\x00\x00";
const VCAL_UID_TERMINATOR: u8 = 0;

const HEADER_LEN: usize = 40;
const MIN_ENCODED_UID_LEN: usize = 82;
const MIN_INSTANCE_YEAR: u16 = 1601;
const MAX_INSTANCE_YEAR: u16 = 4500;
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalObjectId {
    pub instance_date: Option<(u16, u8, u8)>,
    pub creation_time: FileTime,
    pub padding: u64,
    pub data: Box<[u8]>,
}

impl GlobalObjectId {
    pub fn decode(b: &[u8]) -> Option<Self> {
        let header: &[u8; HEADER_LEN] = b.first_chunk()?;
        let goid = Self::from_header(header, b.get(HEADER_LEN..)?.into())?;
        Some(goid)
    }

    fn from_header(header: &[u8; HEADER_LEN], data: Box<[u8]>) -> Option<Self> {
        let (id, rest) = header.split_first_chunk::<16>()?;
        let (&[yh, yl, month, day], rest) = rest.split_first_chunk::<4>()?;
        let (creation, rest) = rest.split_first_chunk::<8>()?;
        let (padding, size) = rest.split_first_chunk::<8>()?;
        let size = u32::from_le_bytes(*size.first_chunk()?);
        if *id != BYTE_ARRAY_ID || usize::try_from(size).ok()? != data.len() {
            return None;
        }
        let year = u16::from_be_bytes([yh, yl]);
        Some(GlobalObjectId {
            instance_date: (year != 0 || month != 0 || day != 0).then_some((year, month, day)),
            creation_time: FileTime(u64::from_le_bytes(*creation)),
            padding: u64::from_le_bytes(*padding),
            data,
        })
    }

    pub fn encoded_len(&self) -> usize {
        HEADER_LEN.saturating_add(self.data.len())
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(self.encoded_len());
        self.write_header(self.instance_date, out);
        out.extend_from_slice(&self.data);
    }

    fn write_header(&self, instance_date: Option<(u16, u8, u8)>, out: &mut Vec<u8>) {
        let (year, month, day) = instance_date.unwrap_or_default();
        out.extend_from_slice(&BYTE_ARRAY_ID);
        out.extend_from_slice(&year.to_be_bytes());
        out.extend_from_slice(&[month, day]);
        out.extend_from_slice(&self.creation_time.0.to_le_bytes());
        out.extend_from_slice(&self.padding.to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(self.data.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
    }

    pub fn from_uid(uid: &str) -> Self {
        Self::from_encoded_uid(uid.as_bytes()).unwrap_or_else(|| {
            let mut data = Vec::with_capacity(
                VCAL_UID_MARKER
                    .len()
                    .saturating_add(uid.len())
                    .saturating_add(1),
            );
            data.extend_from_slice(&VCAL_UID_MARKER);
            data.extend_from_slice(uid.as_bytes());
            data.push(VCAL_UID_TERMINATOR);
            GlobalObjectId {
                instance_date: None,
                creation_time: FileTime(0),
                padding: 0,
                data: data.into_boxed_slice(),
            }
        })
    }

    fn from_encoded_uid(uid: &[u8]) -> Option<Self> {
        if uid.len() < MIN_ENCODED_UID_LEN || !uid.len().is_multiple_of(2) {
            return None;
        }
        let (header_hex, data_hex) = uid.split_at_checked(HEADER_LEN.saturating_mul(2))?;
        let mut header = [0u8; HEADER_LEN];
        decode_hex_into(header_hex, header.iter_mut())?;
        let mut data = vec![0u8; data_hex.len() / 2].into_boxed_slice();
        decode_hex_into(data_hex, data.iter_mut())?;
        let mut goid = Self::from_header(&header, data)?;
        goid.instance_date = goid
            .instance_date
            .filter(|&date| is_valid_instance_date(date));
        Some(goid)
    }

    pub fn to_uid(&self) -> Cow<'_, str> {
        if let Some(uid) = third_party_uid(&self.data) {
            return String::from_utf8_lossy(uid);
        }
        let mut header = Vec::with_capacity(HEADER_LEN);
        self.write_header(None, &mut header);
        let mut uid = String::with_capacity(self.encoded_len().saturating_mul(2));
        push_hex(&mut uid, header.iter().chain(self.data.iter()));
        Cow::Owned(uid)
    }

    pub fn uid_of(b: &[u8]) -> Option<Cow<'_, str>> {
        let (header, data) = b.split_first_chunk::<HEADER_LEN>()?;
        let (id, rest) = header.split_first_chunk::<16>()?;
        let (_, after_date) = rest.split_first_chunk::<4>()?;
        let (_, size) = after_date.split_last_chunk::<4>()?;
        if *id != BYTE_ARRAY_ID || usize::try_from(u32::from_le_bytes(*size)).ok()? != data.len() {
            return None;
        }
        if let Some(uid) = third_party_uid(data) {
            return Some(String::from_utf8_lossy(uid));
        }
        let mut uid = String::with_capacity(b.len().saturating_mul(2));
        push_hex(
            &mut uid,
            id.iter().chain(&[0u8; 4]).chain(after_date).chain(data),
        );
        Some(Cow::Owned(uid))
    }

    pub fn clean(&self) -> Self {
        GlobalObjectId {
            instance_date: None,
            creation_time: self.creation_time,
            padding: self.padding,
            data: self.data.clone(),
        }
    }
}

fn third_party_uid(data: &[u8]) -> Option<&[u8]> {
    let uid = data.strip_prefix(&VCAL_UID_MARKER)?;
    Some(uid.strip_suffix(&[VCAL_UID_TERMINATOR]).unwrap_or(uid))
}

fn decode_hex_into<'a>(hex: &[u8], out: impl Iterator<Item = &'a mut u8>) -> Option<()> {
    let (pairs, _) = hex.as_chunks::<2>();
    for (slot, [high, low]) in out.zip(pairs) {
        *slot = (hex_value(*high)? << 4) | hex_value(*low)?;
    }
    Some(())
}

fn is_valid_instance_date((year, month, day): (u16, u8, u8)) -> bool {
    (MIN_INSTANCE_YEAR..=MAX_INSTANCE_YEAR).contains(&year)
        && day >= 1
        && day <= days_in_month(year, month)
}

pub(crate) fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn push_hex<'a>(out: &mut String, bytes: impl Iterator<Item = &'a u8>) {
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0F] {
            if let Some(&digit) = HEX_UPPER.get(usize::from(nibble)) {
                out.push(char::from(digit));
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/blob/goid/tests.rs"]
mod tests;
