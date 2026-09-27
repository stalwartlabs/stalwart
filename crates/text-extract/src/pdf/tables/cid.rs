/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::OnceLock;

use flate2::{Decompress, FlushDecompress, Status};

use super::cid_data::{
    CNS1, CNS1_RAW_LEN, EXTRA_SENTINEL, GB1, GB1_RAW_LEN, JAPAN1, JAPAN1_RAW_LEN, KOREA1,
    KOREA1_RAW_LEN,
};

const REGISTRY: &[u8] = b"Adobe";
const COLLECTION_COUNT: usize = 4;

static TABLES: [OnceLock<Option<CidTable>>; COLLECTION_COUNT] =
    [const { OnceLock::new() }; COLLECTION_COUNT];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CidCollection {
    Japan1,
    Gb1,
    Cns1,
    Korea1,
}

impl CidCollection {
    pub(crate) fn from_ordering(registry: &[u8], ordering: &[u8]) -> Option<Self> {
        if registry.trim_ascii() != REGISTRY {
            return None;
        }
        hashify::map!(ordering.trim_ascii(), CidCollection,
            b"Japan1" => CidCollection::Japan1,
            b"GB1" => CidCollection::Gb1,
            b"CNS1" => CidCollection::Cns1,
            b"Korea1" => CidCollection::Korea1,
        )
        .copied()
    }

    pub(crate) fn unicode(self, cid: u32, out: &mut String) -> bool {
        self.table().is_some_and(|table| table.append(cid, out))
    }

    fn table(self) -> Option<&'static CidTable> {
        let (packed, raw_len) = self.source();
        TABLES
            .get(self as usize)?
            .get_or_init(|| CidTable::inflate(packed, raw_len))
            .as_ref()
    }

    fn source(self) -> (&'static [u8], usize) {
        match self {
            Self::Japan1 => (JAPAN1, JAPAN1_RAW_LEN),
            Self::Gb1 => (GB1, GB1_RAW_LEN),
            Self::Cns1 => (CNS1, CNS1_RAW_LEN),
            Self::Korea1 => (KOREA1, KOREA1_RAW_LEN),
        }
    }
}

struct CidTable {
    values: Box<[u16]>,
    extra_cids: Box<[u16]>,
    extra_offsets: Box<[u16]>,
    extra_text: Box<str>,
}

impl CidTable {
    fn inflate(packed: &[u8], raw_len: usize) -> Option<Self> {
        let mut raw = Vec::with_capacity(raw_len);
        let status = Decompress::new(false)
            .decompress_vec(packed, &mut raw, FlushDecompress::Finish)
            .ok()?;
        if status != Status::StreamEnd || raw.len() != raw_len {
            return None;
        }
        Self::parse(&raw)
    }

    fn parse(raw: &[u8]) -> Option<Self> {
        let mut reader = Reader { rest: raw };
        let count = usize::from(reader.u16()?);
        let extra_count = usize::from(reader.u16()?);
        let unit_count = usize::from(reader.u16()?);
        let low = reader.take(count)?;
        let high = reader.take(count)?;
        let cid_deltas = reader.take(extra_count * 2)?;
        let lengths = reader.take(extra_count)?;
        let units = reader.take(unit_count * 2)?;
        if !reader.rest.is_empty() {
            return None;
        }

        let mut previous = 0u16;
        let values = low
            .iter()
            .zip(high)
            .map(|(&low, &high)| {
                previous = previous.wrapping_add(u16::from_le_bytes([low, high]));
                previous
            })
            .collect();
        let mut previous = 0u16;
        let extra_cids = cid_deltas
            .as_chunks::<2>()
            .0
            .iter()
            .map(|delta| {
                previous = previous.wrapping_add(u16::from_le_bytes(*delta));
                previous
            })
            .collect();

        let mut units = units
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit));
        let mut extra_text = String::with_capacity(unit_count * 3);
        let mut extra_offsets = Vec::with_capacity(extra_count + 1);
        extra_offsets.push(0);
        for &length in lengths {
            for ch in char::decode_utf16(units.by_ref().take(usize::from(length))) {
                extra_text.push(ch.ok()?);
            }
            extra_offsets.push(u16::try_from(extra_text.len()).ok()?);
        }

        Some(Self {
            values,
            extra_cids,
            extra_offsets: extra_offsets.into_boxed_slice(),
            extra_text: extra_text.into_boxed_str(),
        })
    }

    fn append(&self, cid: u32, out: &mut String) -> bool {
        let Some(&value) = usize::try_from(cid)
            .ok()
            .and_then(|cid| self.values.get(cid))
        else {
            return false;
        };
        match value {
            0 => false,
            EXTRA_SENTINEL => self.append_extra(cid, out).is_some(),
            value => char::from_u32(u32::from(value))
                .map(|ch| out.push(ch))
                .is_some(),
        }
    }

    fn append_extra(&self, cid: u32, out: &mut String) -> Option<()> {
        let index = self
            .extra_cids
            .binary_search(&u16::try_from(cid).ok()?)
            .ok()?;
        let &[start, end] = self.extra_offsets.get(index..index + 2)? else {
            return None;
        };
        out.push_str(self.extra_text.get(usize::from(start)..usize::from(end))?);
        Some(())
    }
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.rest.split_at_checked(len)?;
        self.rest = rest;
        Some(head)
    }

    fn u16(&mut self) -> Option<u16> {
        let (head, rest) = self.rest.split_first_chunk::<2>()?;
        self.rest = rest;
        Some(u16::from_le_bytes(*head))
    }
}

#[cfg(test)]
pub(super) fn table_stats(collection: CidCollection) -> Option<(usize, usize, usize)> {
    collection.table().map(|table| {
        (
            table.values.len(),
            table.extra_cids.len(),
            table.extra_text.len(),
        )
    })
}
