/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::memmem;
use std::cmp::Ordering;

const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const EOCD_LEN: usize = 22;
const MAX_EOCD_COMMENT: usize = 0xFFFF;
const ZIP64_LOCATOR_SIGNATURE: &[u8; 4] = b"PK\x06\x07";
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_EOCD_SIGNATURE: &[u8; 4] = b"PK\x06\x06";
const ZIP64_EOCD_LEN: usize = 56;
const CENTRAL_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
const CENTRAL_LEN: usize = 46;
const LOCAL_SIGNATURE: &[u8; 4] = b"PK\x03\x04";
const LOCAL_LEN: usize = 30;
const ZIP64_EXTRA_ID: u16 = 0x0001;
const FLAG_ENCRYPTED: u16 = 0x0001;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATED: u16 = 8;
const U16_MAX: u64 = 0xFFFF;
const U32_MAX: u64 = 0xFFFF_FFFF;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry {
    record: usize,
    name_len: u16,
}

pub(crate) struct Archive<'a> {
    data: &'a [u8],
    entries: &'a [Entry],
    central_start: usize,
    shift: usize,
    pub(crate) entries_truncated: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Member<'a> {
    pub(crate) name: &'a [u8],
    flags: u16,
    method: u16,
    compressed_size: u64,
    local_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum MemberData<'a> {
    Stored(&'a [u8]),
    Deflated(&'a [u8]),
}

#[derive(Default)]
pub(crate) struct ReadRanges {
    ranges: Vec<(usize, usize)>,
}

impl ReadRanges {
    pub(crate) fn clear(&mut self) {
        self.ranges.clear();
    }

    fn claim(&mut self, start: usize, end: usize) -> bool {
        let index = self
            .ranges
            .partition_point(|&(range_start, _)| range_start < start);
        let overlaps_previous = index
            .checked_sub(1)
            .and_then(|previous| self.ranges.get(previous))
            .is_some_and(|&(_, previous_end)| previous_end > start);
        let overlaps_next = self
            .ranges
            .get(index)
            .is_some_and(|&(next_start, _)| next_start < end);
        if overlaps_previous || overlaps_next {
            return false;
        }
        self.ranges.insert(index, (start, end));
        true
    }
}

impl Member<'_> {
    #[inline]
    pub(crate) fn is_readable(&self) -> bool {
        self.flags & FLAG_ENCRYPTED == 0 && matches!(self.method, METHOD_STORED | METHOD_DEFLATED)
    }
}

impl<'a> Archive<'a> {
    pub(crate) fn open(
        data: &'a [u8],
        entries: &'a mut Vec<Entry>,
        max_entries: usize,
    ) -> Option<Archive<'a>> {
        let (central_start, central_end, shift) = locate_central_directory(data)?;
        entries.clear();
        let mut entries_truncated = false;
        let mut cursor = central_start;
        while cursor < central_end {
            if entries.len() >= max_entries {
                entries_truncated = true;
                break;
            }
            let Some(record) = data.get(cursor..central_end) else {
                break;
            };
            if record.get(..4) != Some(CENTRAL_SIGNATURE.as_slice()) {
                break;
            }
            let (Some(name_len), Some(extra_len), Some(comment_len)) =
                (le_u16(record, 28), le_u16(record, 30), le_u16(record, 32))
            else {
                break;
            };
            let Some(record_len) = CENTRAL_LEN
                .checked_add(usize::from(name_len))
                .and_then(|len| len.checked_add(usize::from(extra_len)))
                .and_then(|len| len.checked_add(usize::from(comment_len)))
                .filter(|&len| len <= record.len())
            else {
                break;
            };
            entries.push(Entry {
                record: cursor,
                name_len,
            });
            cursor += record_len;
        }
        if entries.is_empty() {
            return None;
        }
        entries
            .sort_by(|left, right| compare_names(entry_name(data, left), entry_name(data, right)));
        Some(Archive {
            data,
            entries,
            central_start,
            shift,
            entries_truncated,
        })
    }

    pub(crate) fn find(&self, name: &[u8]) -> Option<Member<'a>> {
        let index = self
            .entries
            .partition_point(|entry| compare_names(entry_name(self.data, entry), name).is_lt());
        let entry = self.entries.get(index)?;
        if compare_names(entry_name(self.data, entry), name).is_eq() {
            self.member(entry)
        } else {
            None
        }
    }

    pub(crate) fn contains(&self, name: &[u8]) -> bool {
        self.find(name).is_some()
    }

    pub(crate) fn members(&self) -> impl Iterator<Item = Member<'a>> + '_ {
        self.entries.iter().filter_map(|entry| self.member(entry))
    }

    fn member(&self, entry: &Entry) -> Option<Member<'a>> {
        let record = self.data.get(entry.record..)?;
        let flags = le_u16(record, 8)?;
        let method = le_u16(record, 10)?;
        let mut compressed_size = u64::from(le_u32(record, 20)?);
        let mut uncompressed_size = u64::from(le_u32(record, 24)?);
        let extra_len = usize::from(le_u16(record, 30)?);
        let mut local_offset = u64::from(le_u32(record, 42)?);
        let name_end = CENTRAL_LEN.checked_add(usize::from(entry.name_len))?;
        let name = record.get(CENTRAL_LEN..name_end)?;
        let extra = record.get(name_end..name_end.checked_add(extra_len)?)?;
        if compressed_size == U32_MAX || uncompressed_size == U32_MAX || local_offset == U32_MAX {
            let mut fields = zip64_extra(extra)?;
            for value in [
                &mut uncompressed_size,
                &mut compressed_size,
                &mut local_offset,
            ] {
                if *value == U32_MAX {
                    *value = fields.next()?;
                }
            }
        }
        Some(Member {
            name,
            flags,
            method,
            compressed_size,
            local_offset,
        })
    }

    pub(crate) fn read(
        &self,
        member: &Member<'a>,
        claimed: &mut ReadRanges,
    ) -> Option<MemberData<'a>> {
        if !member.is_readable() {
            return None;
        }
        let header_start = usize::try_from(member.local_offset)
            .ok()?
            .checked_add(self.shift)?;
        let header = self.data.get(header_start..self.central_start)?;
        if header.get(..4) != Some(LOCAL_SIGNATURE.as_slice()) {
            return None;
        }
        let data_start = LOCAL_LEN
            .checked_add(usize::from(le_u16(header, 26)?))?
            .checked_add(usize::from(le_u16(header, 28)?))?;
        let data_end = data_start.checked_add(usize::try_from(member.compressed_size).ok()?)?;
        let body = header.get(data_start..data_end)?;
        if !claimed.claim(header_start, header_start.checked_add(data_end)?) {
            return None;
        }
        Some(if member.method == METHOD_STORED {
            MemberData::Stored(body)
        } else {
            MemberData::Deflated(body)
        })
    }
}

fn locate_central_directory(data: &[u8]) -> Option<(usize, usize, usize)> {
    let tail_start = data
        .len()
        .saturating_sub(EOCD_LEN.saturating_add(MAX_EOCD_COMMENT));
    let tail = data.get(tail_start..)?;
    memmem::rfind_iter(tail, EOCD_SIGNATURE)
        .find_map(|offset| central_directory_from_eocd(data, tail_start.checked_add(offset)?))
}

fn central_directory_from_eocd(data: &[u8], eocd: usize) -> Option<(usize, usize, usize)> {
    let record = data.get(eocd..eocd.checked_add(EOCD_LEN)?)?;
    let comment_len = usize::from(le_u16(record, 20)?);
    if eocd.checked_add(EOCD_LEN)?.checked_add(comment_len)? > data.len() {
        return None;
    }
    let entries = u64::from(le_u16(record, 10)?);
    let mut central_size = u64::from(le_u32(record, 12)?);
    let mut central_offset = u64::from(le_u32(record, 16)?);
    let mut central_end = eocd;
    if (entries == U16_MAX || central_size == U32_MAX || central_offset == U32_MAX)
        && let Some((zip64_eocd, size, offset)) = zip64_directory(data, eocd)
    {
        central_end = zip64_eocd;
        central_size = size;
        central_offset = offset;
    }
    let central_size = usize::try_from(central_size).ok()?;
    let central_start = central_end.checked_sub(central_size)?;
    let central_offset = usize::try_from(central_offset).ok()?;
    let shift = central_start.checked_sub(central_offset)?;
    if data.get(central_start..central_start.checked_add(4)?)? != CENTRAL_SIGNATURE {
        return None;
    }
    Some((central_start, central_end, shift))
}

fn zip64_directory(data: &[u8], eocd: usize) -> Option<(usize, u64, u64)> {
    let locator_start = eocd.checked_sub(ZIP64_LOCATOR_LEN)?;
    let locator = data.get(locator_start..eocd)?;
    if locator.get(..4)? != ZIP64_LOCATOR_SIGNATURE {
        return None;
    }
    let record_start = locator_start.checked_sub(ZIP64_EOCD_LEN)?;
    let record = data.get(record_start..locator_start)?;
    if record.get(..4)? != ZIP64_EOCD_SIGNATURE {
        return None;
    }
    Some((record_start, le_u64(record, 40)?, le_u64(record, 48)?))
}

fn zip64_extra(mut extra: &[u8]) -> Option<impl Iterator<Item = u64>> {
    while let [id_low, id_high, len_low, len_high, rest @ ..] = extra {
        let len = usize::from(u16::from_le_bytes([*len_low, *len_high]));
        let body = rest.get(..len)?;
        if u16::from_le_bytes([*id_low, *id_high]) == ZIP64_EXTRA_ID {
            return Some(
                body.as_chunks::<8>()
                    .0
                    .iter()
                    .map(|chunk| u64::from_le_bytes(*chunk)),
            );
        }
        extra = rest.get(len..)?;
    }
    None
}

fn entry_name<'a>(data: &'a [u8], entry: &Entry) -> &'a [u8] {
    entry
        .record
        .checked_add(CENTRAL_LEN)
        .and_then(|start| data.get(start..start.checked_add(usize::from(entry.name_len))?))
        .unwrap_or_default()
}

#[inline]
fn normalize(byte: u8) -> u8 {
    if byte == b'\\' {
        b'/'
    } else {
        byte.to_ascii_lowercase()
    }
}

fn trim_root(name: &[u8]) -> &[u8] {
    match name {
        [b'/' | b'\\', rest @ ..] => rest,
        _ => name,
    }
}

pub(crate) fn compare_names(left: &[u8], right: &[u8]) -> Ordering {
    trim_root(left)
        .iter()
        .map(|&byte| normalize(byte))
        .cmp(trim_root(right).iter().map(|&byte| normalize(byte)))
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}
