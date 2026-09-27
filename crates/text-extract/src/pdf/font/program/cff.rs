/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::cff_data::{
    EXPERT_CHARSET, EXPERT_SUBSET_CHARSET, STANDARD_STRING_NAMES, STANDARD_STRING_OFFSETS,
};
use super::read::{NameTable, ReadBytes, Reader};
use super::{BuiltinEncoding, CodeNames, Sfnt};

const STANDARD_STRINGS: NameTable = NameTable {
    names: STANDARD_STRING_NAMES,
    offsets: &STANDARD_STRING_OFFSETS,
};
const STANDARD_STRING_COUNT: usize = 391;
const ISO_ADOBE_LAST_SID: u16 = 228;
const CFF_MAJOR_VERSION: u8 = 1;
const HEADER_SIZE_FIELD: usize = 2;
const MAX_OFFSET_SIZE: usize = 4;
const MAX_OPERANDS: usize = 48;
const PREDEFINED_ISO_ADOBE: usize = 0;
const PREDEFINED_EXPERT: usize = 1;
const PREDEFINED_EXPERT_SUBSET: usize = 2;
const PREDEFINED_STANDARD_ENCODING: usize = 0;
const PREDEFINED_EXPERT_ENCODING: usize = 1;
const ENCODING_FORMAT_MASK: u8 = 0x7F;
const ENCODING_SUPPLEMENT_FLAG: u8 = 0x80;

const OP_ESCAPE: u8 = 12;
const OP_CHARSET: u16 = 15;
const OP_ENCODING: u16 = 16;
const OP_CHAR_STRINGS: u16 = 17;
const OP_ROS: u16 = 0x0C00 | 30;
const OPERAND_SHORT: u8 = 28;
const OPERAND_LONG: u8 = 29;
const OPERAND_REAL: u8 = 30;
const REAL_END_NIBBLE: u8 = 0x0F;

#[derive(Debug, Clone)]
pub(crate) struct Cff<'x> {
    data: &'x [u8],
    strings: Index<'x>,
    num_glyphs: u16,
    charset: Charset,
    encoding_offset: usize,
    ros: Option<[i64; 3]>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ros<'x> {
    pub(crate) registry: &'x [u8],
    pub(crate) ordering: &'x [u8],
    pub(crate) supplement: i64,
}

#[derive(Debug, Clone)]
enum Charset {
    IsoAdobe,
    Expert,
    ExpertSubset,
    Identity,
    Custom(Box<[u16]>),
}

#[derive(Debug, Clone, Copy, Default)]
struct Index<'x> {
    count: usize,
    off_size: usize,
    offsets: &'x [u8],
    data: &'x [u8],
}

#[derive(Debug, Default)]
struct TopDict {
    charset: i64,
    encoding: i64,
    char_strings: Option<i64>,
    ros: Option<[i64; 3]>,
}

impl<'x> Cff<'x> {
    pub(crate) fn parse(data: &'x [u8]) -> Option<Self> {
        match Sfnt::parse(data) {
            Some(sfnt) => Self::parse_bare(sfnt.table(b"CFF ")?),
            None => Self::parse_bare(data),
        }
    }

    fn parse_bare(data: &'x [u8]) -> Option<Self> {
        if data.first() != Some(&CFF_MAJOR_VERSION) {
            return None;
        }
        let header_size = usize::from(data.be_u8(HEADER_SIZE_FIELD)?);
        let (_, top_dicts_at) = Index::parse(data, header_size)?;
        let (top_dicts, strings_at) = Index::parse(data, top_dicts_at)?;
        let (strings, _) = Index::parse(data, strings_at).unwrap_or_default();
        let top = TopDict::parse(top_dicts.get(0)?);
        let char_strings = usize::try_from(top.char_strings?).ok()?;
        let num_glyphs = Index::count(data, char_strings)?;
        let charset = Charset::parse(
            data,
            usize::try_from(top.charset).ok()?,
            num_glyphs,
            top.ros.is_some(),
        )?;
        Some(Self {
            data,
            strings,
            num_glyphs,
            charset,
            encoding_offset: usize::try_from(top.encoding).unwrap_or(usize::MAX),
            ros: top.ros,
        })
    }

    pub(crate) fn num_glyphs(&self) -> u16 {
        self.num_glyphs
    }

    pub(crate) fn is_cid(&self) -> bool {
        self.ros.is_some()
    }

    #[cfg(test)]
    pub(crate) fn ros(&self) -> Option<Ros<'x>> {
        let [registry, ordering, supplement] = self.ros?;
        Some(Ros {
            registry: self.string(u16::try_from(registry).ok()?)?,
            ordering: self.string(u16::try_from(ordering).ok()?)?,
            supplement,
        })
    }

    fn string(&self, sid: u16) -> Option<&'x [u8]> {
        let sid = usize::from(sid);
        match sid.checked_sub(STANDARD_STRING_COUNT) {
            None => STANDARD_STRINGS.get(sid),
            Some(index) => self.strings.get(index),
        }
    }

    pub(crate) fn glyph_name(&self, glyph: u16) -> Option<&'x [u8]> {
        if self.is_cid() {
            return None;
        }
        self.string(self.glyph_sid(glyph)?)
    }

    pub(crate) fn glyph_cid(&self, glyph: u16) -> Option<u16> {
        if !self.is_cid() {
            return None;
        }
        self.glyph_sid(glyph)
    }

    pub(crate) fn builtin_encoding(&self) -> Option<BuiltinEncoding<'x>> {
        if self.is_cid() {
            return None;
        }
        match self.encoding_offset {
            PREDEFINED_STANDARD_ENCODING => Some(BuiltinEncoding::Standard),
            PREDEFINED_EXPERT_ENCODING => Some(BuiltinEncoding::Expert),
            offset => {
                let mut reader = Reader::at(self.data, offset)?;
                let format = reader.u8()?;
                let mut names = CodeNames::new();
                self.read_encoding(&mut reader, format, &mut names);
                Some(BuiltinEncoding::Custom(names))
            }
        }
    }

    fn read_encoding(&self, reader: &mut Reader<'x>, format: u8, names: &mut CodeNames<'x>) {
        let mut glyph = 1u16;
        let mut assign = |code: u8| {
            if let Some(name) = self.glyph_name(glyph) {
                names.set(code, name);
            }
            glyph = glyph.saturating_add(1);
        };
        let complete = match format & ENCODING_FORMAT_MASK {
            0 => read_codes(reader, &mut assign),
            1 => read_code_ranges(reader, &mut assign),
            _ => None,
        };
        if complete.is_some() && format & ENCODING_SUPPLEMENT_FLAG != 0 {
            self.read_supplements(reader, names);
        }
    }

    fn read_supplements(&self, reader: &mut Reader<'x>, names: &mut CodeNames<'x>) -> Option<()> {
        for _ in 0..reader.u8()? {
            let code = reader.u8()?;
            let sid = reader.u16()?;
            if let Some(name) = self.string(sid) {
                names.set(code, name);
            }
        }
        Some(())
    }

    fn glyph_sid(&self, glyph: u16) -> Option<u16> {
        if glyph >= self.num_glyphs {
            return None;
        }
        let Some(index) = usize::from(glyph).checked_sub(1) else {
            return Some(0);
        };
        match &self.charset {
            Charset::IsoAdobe => (glyph <= ISO_ADOBE_LAST_SID).then_some(glyph),
            Charset::Expert => EXPERT_CHARSET.get(index).copied(),
            Charset::ExpertSubset => EXPERT_SUBSET_CHARSET.get(index).copied(),
            Charset::Identity => Some(glyph),
            Charset::Custom(sids) => sids.get(index).copied(),
        }
    }
}

fn read_codes(reader: &mut Reader<'_>, assign: &mut impl FnMut(u8)) -> Option<()> {
    for _ in 0..reader.u8()? {
        assign(reader.u8()?);
    }
    Some(())
}

fn read_code_ranges(reader: &mut Reader<'_>, assign: &mut impl FnMut(u8)) -> Option<()> {
    for _ in 0..reader.u8()? {
        let first = reader.u8()?;
        let left = reader.u8()?;
        for code in first..=first.saturating_add(left) {
            assign(code);
        }
    }
    Some(())
}

impl Charset {
    fn parse(data: &[u8], offset: usize, num_glyphs: u16, cid: bool) -> Option<Self> {
        match offset {
            PREDEFINED_ISO_ADOBE | PREDEFINED_EXPERT | PREDEFINED_EXPERT_SUBSET if cid => {
                Some(Charset::Identity)
            }
            PREDEFINED_ISO_ADOBE => Some(Charset::IsoAdobe),
            PREDEFINED_EXPERT => Some(Charset::Expert),
            PREDEFINED_EXPERT_SUBSET => Some(Charset::ExpertSubset),
            offset => {
                let mut reader = Reader::at(data, offset)?;
                let format = reader.u8()?;
                let wanted = usize::from(num_glyphs.saturating_sub(1));
                let mut sids = Vec::with_capacity(wanted.min(reader.remaining().len()));
                match format {
                    0 => {
                        while sids.len() < wanted {
                            let Some(sid) = reader.u16() else { break };
                            sids.push(sid);
                        }
                    }
                    1 | 2 => {
                        while sids.len() < wanted {
                            let Some(first) = reader.u16() else { break };
                            let left = if format == 1 {
                                reader.u8().map(u16::from)
                            } else {
                                reader.u16()
                            };
                            let Some(left) = left else { break };
                            let room = wanted - sids.len();
                            let run = usize::from(left).saturating_add(1).min(room);
                            sids.extend((first..=u16::MAX).take(run));
                        }
                    }
                    _ => return None,
                }
                Some(Charset::Custom(sids.into_boxed_slice()))
            }
        }
    }
}

impl<'x> Index<'x> {
    fn parse(data: &'x [u8], at: usize) -> Option<(Self, usize)> {
        let count = usize::from(data.be_u16(at)?);
        if count == 0 {
            return Some((Self::default(), at.checked_add(2)?));
        }
        let off_size = usize::from(data.be_u8(at.checked_add(2)?)?);
        if !(1..=MAX_OFFSET_SIZE).contains(&off_size) {
            return None;
        }
        let offsets_at = at.checked_add(3)?;
        let offsets = data.range(offsets_at, (count + 1) * off_size)?;
        let data_at = offsets_at + offsets.len();
        let mut index = Self {
            count,
            off_size,
            offsets,
            data: &[],
        };
        let data_len = index.offset(count)?.checked_sub(1)?;
        let payload = data.get(data_at..)?;
        index.data = payload.get(..data_len).unwrap_or(payload);
        Some((index, data_at.checked_add(data_len)?))
    }

    fn count(data: &'x [u8], at: usize) -> Option<u16> {
        let (index, _) = Self::parse(data, at)?;
        u16::try_from(index.count).ok()
    }

    fn offset(&self, index: usize) -> Option<usize> {
        let bytes = self
            .offsets
            .range(index.checked_mul(self.off_size)?, self.off_size)?;
        Some(
            bytes
                .iter()
                .fold(0usize, |value, &byte| value << 8 | usize::from(byte)),
        )
    }

    fn get(&self, index: usize) -> Option<&'x [u8]> {
        let start = self.offset(index)?.checked_sub(1)?;
        let end = self.offset(index.checked_add(1)?)?.checked_sub(1)?;
        self.data.get(start..end)
    }
}

impl TopDict {
    fn parse(dict: &[u8]) -> Self {
        let mut top = TopDict::default();
        let mut operands = [0i64; MAX_OPERANDS];
        let mut len = 0usize;
        let mut reader = Reader::new(dict);
        while let Some(byte) = reader.u8() {
            let operand = match byte {
                OPERAND_SHORT => reader.u16().map(|value| i64::from(value.cast_signed())),
                OPERAND_LONG => reader.u32().map(|value| i64::from(value.cast_signed())),
                OPERAND_REAL => skip_real(&mut reader).map(|()| 0),
                32..=246 => Some(i64::from(byte) - 139),
                247..=250 => reader
                    .u8()
                    .map(|next| (i64::from(byte) - 247) * 256 + i64::from(next) + 108),
                251..=254 => reader
                    .u8()
                    .map(|next| -(i64::from(byte) - 251) * 256 - i64::from(next) - 108),
                _ => {
                    let operator = if byte == OP_ESCAPE {
                        let Some(next) = reader.u8() else { break };
                        u16::from(OP_ESCAPE) << 8 | u16::from(next)
                    } else {
                        u16::from(byte)
                    };
                    top.apply(operator, operands.get(..len).unwrap_or_default());
                    len = 0;
                    continue;
                }
            };
            let Some(operand) = operand else { break };
            if let Some(slot) = operands.get_mut(len) {
                *slot = operand;
                len += 1;
            }
        }
        top
    }

    fn apply(&mut self, operator: u16, operands: &[i64]) {
        match (operator, operands) {
            (OP_CHARSET, [.., value]) => self.charset = *value,
            (OP_ENCODING, [.., value]) => self.encoding = *value,
            (OP_CHAR_STRINGS, [.., value]) => self.char_strings = Some(*value),
            (OP_ROS, [.., registry, ordering, supplement]) => {
                self.ros = Some([*registry, *ordering, *supplement])
            }
            _ => {}
        }
    }
}

fn skip_real(reader: &mut Reader<'_>) -> Option<()> {
    loop {
        let byte = reader.u8()?;
        if byte >> 4 == REAL_END_NIBBLE || byte & 0x0F == REAL_END_NIBBLE {
            return Some(());
        }
    }
}
