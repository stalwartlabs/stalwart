/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::read::ReadBytes;

const RECORDS_OFFSET: usize = 4;
const RECORD_LEN: usize = 8;
const RECORD_SUBTABLE_FIELD: usize = 4;
const FORMAT0_GLYPHS: usize = 6;
const FORMAT0_LEN: usize = 256;
const FORMAT2_KEYS: usize = 6;
const FORMAT2_KEY_COUNT: usize = 256;
const FORMAT2_SUBHEADERS: usize = FORMAT2_KEYS + 2 * FORMAT2_KEY_COUNT;
const FORMAT2_SUBHEADER_LEN: usize = 8;
const FORMAT2_RANGE_FIELD: usize = 6;
const FORMAT4_SEG_COUNT_X2: usize = 6;
const FORMAT4_END_CODES: usize = 14;
const FORMAT4_RESERVED_PAD: usize = 2;
const FORMAT6_FIRST_CODE: usize = 6;
const FORMAT6_GLYPHS: usize = 10;
const FORMAT12_LENGTH: usize = 4;
const FORMAT12_GROUP_COUNT: usize = 12;
const FORMAT12_GROUPS: usize = 16;
const FORMAT12_GROUP_LEN: usize = 12;
const SHORT_LENGTH_FIELD: usize = 2;
const MAX_CODE_POINT: u32 = 0x10_FFFF;
const BYTE_CODES: u32 = 256;
const BYTE_BITS: u32 = 8;
const BYTE_MASK: u32 = 0xFF;
const FORMAT2_KEY_SCALE: u16 = 8;

pub(crate) const PLATFORM_UNICODE: u16 = 0;
pub(crate) const PLATFORM_MAC: u16 = 1;
pub(crate) const PLATFORM_WINDOWS: u16 = 3;
pub(crate) const WINDOWS_SYMBOL: u16 = 0;
pub(crate) const WINDOWS_UNICODE_BMP: u16 = 1;
pub(crate) const WINDOWS_UNICODE_FULL: u16 = 10;
pub(crate) const MAC_ROMAN: u16 = 0;

const UNICODE_PREFERENCE: [(u16, u16); 7] = [
    (PLATFORM_WINDOWS, WINDOWS_UNICODE_FULL),
    (PLATFORM_UNICODE, 4),
    (PLATFORM_WINDOWS, WINDOWS_UNICODE_BMP),
    (PLATFORM_UNICODE, 3),
    (PLATFORM_UNICODE, 2),
    (PLATFORM_UNICODE, 1),
    (PLATFORM_UNICODE, 0),
];

type U16Be = [u8; 2];
type Group = [u8; FORMAT12_GROUP_LEN];

#[derive(Debug, Clone, Copy)]
pub(crate) struct Cmap<'x> {
    data: &'x [u8],
    records: &'x [[u8; RECORD_LEN]],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CmapSubtable<'x> {
    format: Format<'x>,
}

#[derive(Debug, Clone, Copy)]
enum Format<'x> {
    ByteEncoding(&'x [u8]),
    HighByte(&'x [u8]),
    SegmentDelta(SegmentDelta<'x>),
    Trimmed { first: u32, glyphs: &'x [U16Be] },
    SegmentedCoverage(&'x [Group]),
}

struct Segment {
    start: u16,
    delta: u16,
    range_at: usize,
    range: usize,
}

struct SubHeader<'x> {
    data: &'x [u8],
    first: u32,
    count: u32,
    delta: u16,
    range: usize,
}

#[derive(Debug, Clone, Copy)]
struct SegmentDelta<'x> {
    ends: &'x [U16Be],
    starts: &'x [U16Be],
    deltas: &'x [U16Be],
    ranges: &'x [u8],
}

impl<'x> Cmap<'x> {
    pub(crate) fn parse(data: &'x [u8]) -> Option<Self> {
        let count = usize::from(data.be_u16(2)?);
        let (records, _) = data.get(RECORDS_OFFSET..)?.as_chunks::<RECORD_LEN>();
        let records = records.get(..count).unwrap_or(records);
        Some(Self { data, records })
    }

    pub(crate) fn subtables(&self) -> impl Iterator<Item = (u16, u16, CmapSubtable<'x>)> + '_ {
        self.records.iter().filter_map(|record| {
            let platform = record.be_u16(0)?;
            let encoding = record.be_u16(2)?;
            let offset = usize::try_from(record.be_u32(RECORD_SUBTABLE_FIELD)?).ok()?;
            let subtable = CmapSubtable::parse(self.data.get(offset..)?)?;
            Some((platform, encoding, subtable))
        })
    }

    #[cfg(test)]
    pub(crate) fn subtable(&self, platform: u16, encoding: u16) -> Option<CmapSubtable<'x>> {
        self.subtables()
            .find(|&(p, e, _)| p == platform && e == encoding)
            .map(|(_, _, subtable)| subtable)
    }

    pub(crate) fn unicode(&self) -> Option<CmapSubtable<'x>> {
        let mut best: Option<(usize, CmapSubtable<'x>)> = None;
        for (platform, encoding, subtable) in self.subtables() {
            let Some(rank) = UNICODE_PREFERENCE
                .iter()
                .position(|&key| key == (platform, encoding))
            else {
                continue;
            };
            if best.is_none_or(|(best_rank, _)| rank < best_rank) {
                best = Some((rank, subtable));
                if rank == 0 {
                    break;
                }
            }
        }
        best.map(|(_, subtable)| subtable)
    }
}

impl<'x> CmapSubtable<'x> {
    fn parse(data: &'x [u8]) -> Option<Self> {
        let format = match data.be_u16(0)? {
            0 => {
                let glyphs = bounded(data, SHORT_LENGTH_FIELD).get(FORMAT0_GLYPHS..)?;
                Format::ByteEncoding(glyphs.get(..FORMAT0_LEN).unwrap_or(glyphs))
            }
            2 => Format::HighByte(bounded(data, SHORT_LENGTH_FIELD)),
            4 => Format::SegmentDelta(SegmentDelta::parse(bounded(data, SHORT_LENGTH_FIELD))?),
            6 => {
                let data = bounded(data, SHORT_LENGTH_FIELD);
                let first = u32::from(data.be_u16(FORMAT6_FIRST_CODE)?);
                let count = usize::from(data.be_u16(FORMAT6_FIRST_CODE + 2)?);
                let glyphs = chunks::<2>(data, FORMAT6_GLYPHS, count)?;
                Format::Trimmed { first, glyphs }
            }
            12 => {
                let len = usize::try_from(data.be_u32(FORMAT12_LENGTH)?).ok()?;
                let data = data.get(..len).unwrap_or(data);
                let count = usize::try_from(data.be_u32(FORMAT12_GROUP_COUNT)?).ok()?;
                Format::SegmentedCoverage(chunks::<FORMAT12_GROUP_LEN>(
                    data,
                    FORMAT12_GROUPS,
                    count,
                )?)
            }
            _ => return None,
        };
        Some(Self { format })
    }

    pub(crate) fn glyph(&self, code: u32) -> Option<u16> {
        let glyph = match self.format {
            Format::ByteEncoding(glyphs) => u16::from(*glyphs.get(usize::try_from(code).ok()?)?),
            Format::HighByte(data) => high_byte_glyph(data, code)?,
            Format::SegmentDelta(table) => {
                let code = u16::try_from(code).ok()?;
                let index = table
                    .ends
                    .partition_point(|&end| u16::from_be_bytes(end) < code);
                table.segment(index)?.glyph(table.ranges, code)?
            }
            Format::Trimmed { first, glyphs } => {
                let index = usize::try_from(code.checked_sub(first)?).ok()?;
                u16::from_be_bytes(*glyphs.get(index)?)
            }
            Format::SegmentedCoverage(groups) => {
                let index = groups.partition_point(|group| group_end(group) < code);
                let group = groups.get(index)?;
                let start = group.be_u32(0)?;
                let offset = code.checked_sub(start)?;
                u16::try_from(group.be_u32(8)?.checked_add(offset)?).ok()?
            }
        };
        (glyph != 0).then_some(glyph)
    }

    pub(crate) fn for_each_mapping(&self, glyph_limit: u32, mut f: impl FnMut(u32, u16)) {
        let mut emit = |code: u32, glyph: u16| {
            if glyph != 0 && u32::from(glyph) < glyph_limit {
                f(code, glyph);
            }
        };
        match self.format {
            Format::ByteEncoding(glyphs) => {
                for (code, &glyph) in (0u32..).zip(glyphs) {
                    emit(code, u16::from(glyph));
                }
            }
            Format::HighByte(data) => {
                for (high, key) in (0u32..).zip(high_byte_keys(data)) {
                    let key = u16::from_be_bytes(*key);
                    let Some(subheader) = SubHeader::parse(data, key) else {
                        continue;
                    };
                    if key == 0 {
                        if let Some(glyph) = subheader.glyph(high) {
                            emit(high, glyph);
                        }
                        continue;
                    }
                    let end = subheader
                        .first
                        .saturating_add(subheader.count)
                        .min(BYTE_CODES);
                    for low in subheader.first..end {
                        if let Some(glyph) = subheader.glyph(low) {
                            emit(high << BYTE_BITS | low, glyph);
                        }
                    }
                }
            }
            Format::SegmentDelta(table) => {
                let mut next_code = 0u32;
                for (index, &end) in table.ends.iter().enumerate() {
                    let Some(segment) = table.segment(index) else {
                        break;
                    };
                    let start = u32::from(segment.start).max(next_code);
                    let end = u32::from(u16::from_be_bytes(end));
                    if start > end {
                        continue;
                    }
                    next_code = end + 1;
                    for code in (start..=end).filter_map(|code| u16::try_from(code).ok()) {
                        if let Some(glyph) = segment.glyph(table.ranges, code) {
                            emit(u32::from(code), glyph);
                        }
                    }
                }
            }
            Format::Trimmed { first, glyphs } => {
                for (code, glyph) in (first..).zip(glyphs) {
                    emit(code, u16::from_be_bytes(*glyph));
                }
            }
            Format::SegmentedCoverage(groups) => {
                let mut next_code = 0u32;
                for group in groups {
                    let (Some(group_start), Some(end), Some(first_glyph)) =
                        (group.be_u32(0), group.be_u32(4), group.be_u32(8))
                    else {
                        continue;
                    };
                    let start = group_start.max(next_code);
                    let end = end.min(MAX_CODE_POINT);
                    if start > end {
                        continue;
                    }
                    next_code = end + 1;
                    let Some(first_glyph) = first_glyph.checked_add(start - group_start) else {
                        continue;
                    };
                    let Some(room) = glyph_limit.checked_sub(first_glyph) else {
                        continue;
                    };
                    let last = end.min(start.saturating_add(room.saturating_sub(1)));
                    for (code, glyph) in (start..=last).zip(first_glyph..) {
                        if let Ok(glyph) = u16::try_from(glyph) {
                            emit(code, glyph);
                        }
                    }
                }
            }
        }
    }
}

impl<'x> SegmentDelta<'x> {
    fn parse(data: &'x [u8]) -> Option<Self> {
        let seg_count_x2 = usize::from(data.be_u16(FORMAT4_SEG_COUNT_X2)?);
        let seg_count = seg_count_x2 / 2;
        let starts_at = FORMAT4_END_CODES + seg_count_x2 + FORMAT4_RESERVED_PAD;
        let deltas_at = starts_at + seg_count_x2;
        let ranges_at = deltas_at + seg_count_x2;
        Some(Self {
            ends: chunks::<2>(data, FORMAT4_END_CODES, seg_count)?,
            starts: chunks::<2>(data, starts_at, seg_count).unwrap_or_default(),
            deltas: chunks::<2>(data, deltas_at, seg_count).unwrap_or_default(),
            ranges: data.get(ranges_at..).unwrap_or_default(),
        })
    }

    fn segment(&self, index: usize) -> Option<Segment> {
        let range_at = index.checked_mul(2)?;
        Some(Segment {
            start: u16::from_be_bytes(*self.starts.get(index)?),
            delta: u16::from_be_bytes(*self.deltas.get(index)?),
            range_at,
            range: usize::from(self.ranges.be_u16(range_at)?),
        })
    }
}

impl Segment {
    fn glyph(&self, ranges: &[u8], code: u16) -> Option<u16> {
        let offset = code.checked_sub(self.start)?;
        if self.range == 0 {
            return Some(code.wrapping_add(self.delta));
        }
        let at = self
            .range_at
            .checked_add(self.range)?
            .checked_add(usize::from(offset) * 2)?;
        Some(apply_delta(ranges.be_u16(at)?, self.delta))
    }
}

fn bounded(data: &[u8], length_field: usize) -> &[u8] {
    data.be_u16(length_field)
        .and_then(|len| data.get(..usize::from(len)))
        .unwrap_or(data)
}

fn chunks<const N: usize>(data: &[u8], at: usize, count: usize) -> Option<&[[u8; N]]> {
    let (chunks, _) = data.get(at..)?.as_chunks::<N>();
    Some(chunks.get(..count).unwrap_or(chunks))
}

fn group_end(group: &Group) -> u32 {
    group.be_u32(4).unwrap_or(0)
}

fn high_byte_keys(data: &[u8]) -> &[U16Be] {
    chunks::<2>(data, FORMAT2_KEYS, FORMAT2_KEY_COUNT).unwrap_or_default()
}

impl<'x> SubHeader<'x> {
    fn parse(data: &'x [u8], key: u16) -> Option<Self> {
        let at = FORMAT2_SUBHEADERS + usize::from(key / FORMAT2_KEY_SCALE) * FORMAT2_SUBHEADER_LEN;
        let data = data.get(at..)?;
        Some(Self {
            data,
            first: u32::from(data.be_u16(0)?),
            count: u32::from(data.be_u16(2)?),
            delta: data.be_u16(4)?,
            range: usize::from(data.be_u16(FORMAT2_RANGE_FIELD)?),
        })
    }

    fn glyph(&self, low: u32) -> Option<u16> {
        let index = low
            .checked_sub(self.first)
            .filter(|&index| index < self.count)?;
        let at = FORMAT2_RANGE_FIELD
            .checked_add(self.range)?
            .checked_add(usize::try_from(index).ok()? * 2)?;
        Some(apply_delta(self.data.be_u16(at)?, self.delta))
    }
}

fn apply_delta(glyph: u16, delta: u16) -> u16 {
    if glyph == 0 {
        0
    } else {
        glyph.wrapping_add(delta)
    }
}

fn high_byte_glyph(data: &[u8], code: u32) -> Option<u16> {
    let keys = high_byte_keys(data);
    let (high, low) = if code < BYTE_CODES {
        (code, code)
    } else {
        (code >> BYTE_BITS, code & BYTE_MASK)
    };
    let key = u16::from_be_bytes(*keys.get(usize::try_from(high).ok()?)?);
    if (key == 0) != (code < BYTE_CODES) {
        return None;
    }
    SubHeader::parse(data, key)?.glyph(low)
}
