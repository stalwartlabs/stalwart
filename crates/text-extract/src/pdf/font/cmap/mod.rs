/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{code::code_value, ranges::RangeMap};
use crate::pdf::{
    lexer::{Lexer, Token},
    object::{Array, Object},
    tables::{CodeRange, PredefinedCmap, glyph_unicode},
};

pub(crate) const MAX_CMAP_ENTRIES: usize = 1 << 17;
pub(crate) const MAX_CODESPACE_RANGES: usize = 40;
const MAX_CODE_BYTES: usize = 4;
const MAX_TARGET_UNITS: usize = 256;
const LENGTH_SHIFT: u32 = 32;
const MAX_UNIT: u32 = 0xFFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CmapKind {
    ToUnicode,
    Encoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Units { offset: u32, len: u32 },
    Cid(u32),
}

#[derive(Debug)]
pub(crate) struct Cmap {
    kind: CmapKind,
    entries: RangeMap<Target>,
    units: Vec<u16>,
    codespace: Vec<CodeRange>,
    source_lengths: u8,
    vertical: bool,
    base: Option<PredefinedCmap>,
}

#[derive(Clone, Copy)]
enum Block {
    Codespace,
    BfChar,
    BfRange,
    CidChar,
    CidRange,
}

impl Block {
    fn from_keyword(keyword: &[u8]) -> Option<(Block, &'static [u8])> {
        hashify::map!(keyword, (Block, &'static [u8]),
            b"begincodespacerange" => (Block::Codespace, b"endcodespacerange"),
            b"beginbfchar" => (Block::BfChar, b"endbfchar"),
            b"beginbfrange" => (Block::BfRange, b"endbfrange"),
            b"begincidchar" => (Block::CidChar, b"endcidchar"),
            b"begincidrange" => (Block::CidRange, b"endcidrange"),
        )
        .copied()
    }

    fn arity(self) -> usize {
        match self {
            Block::Codespace | Block::BfChar | Block::CidChar => 2,
            Block::BfRange | Block::CidRange => 3,
        }
    }
}

impl Cmap {
    pub(crate) fn new(kind: CmapKind) -> Self {
        Cmap {
            kind,
            entries: RangeMap::default(),
            units: Vec::new(),
            codespace: Vec::new(),
            source_lengths: 0,
            vertical: false,
            base: None,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn is_vertical(&self) -> bool {
        self.vertical
    }

    pub(crate) fn set_base(&mut self, base: Option<PredefinedCmap>) {
        self.base = base.or(self.base);
    }

    pub(crate) fn set_vertical(&mut self) {
        self.vertical = true;
    }

    pub(crate) fn base(&self) -> Option<PredefinedCmap> {
        self.base
    }

    pub(crate) fn codespace(&self) -> &[CodeRange] {
        &self.codespace
    }

    pub(crate) fn heap_size(&self) -> usize {
        self.entries.heap_size()
            + self.units.capacity() * 2
            + self.codespace.capacity() * std::mem::size_of::<CodeRange>()
    }

    pub(crate) fn uniform_source_length(&self) -> Option<usize> {
        match self.source_lengths.count_ones() {
            1 => Some(self.source_lengths.trailing_zeros() as usize),
            _ => None,
        }
    }

    pub(crate) fn parse(&mut self, data: &[u8]) {
        let mut lexer = Lexer::new(data);
        let mut previous: [Option<Object<'_>>; 2] = [None, None];
        while self.entries.len() < MAX_CMAP_ENTRIES {
            if let Some(object) = Object::read(&mut lexer, None) {
                let [_, last] = previous;
                previous = [last, Some(object)];
                continue;
            }
            match lexer.next() {
                Some(Token::Keyword(keyword)) => {
                    self.keyword(keyword, &previous, &mut lexer);
                    previous = [None, None];
                }
                Some(_) => previous = [None, None],
                None => break,
            }
        }
    }

    fn keyword(
        &mut self,
        keyword: &[u8],
        previous: &[Option<Object<'_>>; 2],
        lexer: &mut Lexer<'_>,
    ) {
        if let Some((block, end)) = Block::from_keyword(keyword) {
            self.block(block, end, lexer);
            return;
        }
        hashify::fnc_map!(keyword,
            b"usecmap" => {
                if let [_, Some(Object::Name(name))] = previous {
                    self.base = self
                        .base
                        .or_else(|| PredefinedCmap::from_name(&name.decoded()));
                }
            },
            b"def" => {
                if let [Some(Object::Name(key)), Some(value)] = previous
                    && key.is(b"WMode")
                {
                    self.vertical = value.as_int() == Some(1);
                }
            },
            b"endcmap" => lexer.set_pos(lexer.data().len()),
            _ => {}
        );
    }

    fn block(&mut self, block: Block, end: &[u8], lexer: &mut Lexer<'_>) {
        let mut operands: [Object<'_>; 3] = [Object::Null; 3];
        let mut count = 0usize;
        loop {
            if self.entries.len() >= MAX_CMAP_ENTRIES {
                return;
            }
            match Object::read(lexer, None) {
                Some(object) => {
                    if let Some(slot) = operands.get_mut(count) {
                        *slot = object;
                    }
                    count += 1;
                    if count == block.arity() {
                        self.entry(block, &operands);
                        count = 0;
                    }
                }
                None => {
                    let before = lexer.pos();
                    match lexer.next() {
                        Some(Token::Keyword(keyword)) if keyword == end => return,
                        Some(Token::Keyword(_)) => {
                            lexer.set_pos(before);
                            return;
                        }
                        Some(_) => count = 0,
                        None => return,
                    }
                }
            }
        }
    }

    fn entry(&mut self, block: Block, operands: &[Object<'_>; 3]) {
        let [first, second, third] = operands;
        match block {
            Block::Codespace => {
                if let (Some(low), Some(high)) = (source(first), source(second)) {
                    self.add_codespace(&low, &high);
                }
            }
            Block::BfChar => {
                if let Some(code) = source(first) {
                    self.add_bf(&code, &code, second);
                }
            }
            Block::CidChar => {
                if let (Some(code), Some(cid)) = (source(first), second.as_int()) {
                    self.add_cid(&code, &code, cid);
                }
            }
            Block::BfRange => {
                if let (Some(low), Some(high)) = (source(first), source(second)) {
                    match third {
                        Object::Array(array) => self.add_bf_array(&low, &high, *array),
                        target => self.add_bf(&low, &high, target),
                    }
                }
            }
            Block::CidRange => {
                if let (Some(low), Some(high), Some(cid)) =
                    (source(first), source(second), third.as_int())
                {
                    self.add_cid(&low, &high, cid);
                }
            }
        }
    }

    fn add_codespace(&mut self, low: &[u8], high: &[u8]) {
        if low.len() != high.len() || self.codespace.len() >= MAX_CODESPACE_RANGES {
            return;
        }
        let (mut lows, mut highs) = ([0u8; MAX_CODE_BYTES], [0u8; MAX_CODE_BYTES]);
        for ((slot_low, slot_high), (&byte_low, &byte_high)) in lows
            .iter_mut()
            .zip(highs.iter_mut())
            .zip(low.iter().zip(high.iter()))
        {
            *slot_low = byte_low.min(byte_high);
            *slot_high = byte_low.max(byte_high);
        }
        if let Ok(len) = u8::try_from(low.len()) {
            self.codespace.push(CodeRange::new(len, lows, highs));
        }
    }

    fn key(&self, code: &[u8]) -> Option<u64> {
        let value = u64::from(code_value(code)?);
        Some(match self.kind {
            CmapKind::ToUnicode => value,
            CmapKind::Encoding => (code.len() as u64) << LENGTH_SHIFT | value,
        })
    }

    fn range(&mut self, low: &[u8], high: &[u8]) -> Option<(u64, u64)> {
        if low.len() != high.len() && self.kind == CmapKind::Encoding {
            return None;
        }
        let (lo, hi) = (self.key(low)?, self.key(high)?);
        if hi < lo {
            return None;
        }
        if let Some(bit) = u32::try_from(low.len())
            .ok()
            .and_then(|len| 1u8.checked_shl(len))
        {
            self.source_lengths |= bit;
        }
        Some((lo, hi))
    }

    fn push(&mut self, lo: u64, hi: u64, target: Target) {
        self.entries.push(lo, hi, target);
    }

    fn add_cid(&mut self, low: &[u8], high: &[u8], cid: i64) {
        let (Some((lo, hi)), Ok(cid)) = (self.range(low, high), u32::try_from(cid)) else {
            return;
        };
        let target = match self.kind {
            CmapKind::Encoding => Target::Cid(cid),
            CmapKind::ToUnicode => match self.units_for_char(cid) {
                Some(target) => target,
                None => return,
            },
        };
        self.push(lo, hi, target);
    }

    fn add_bf(&mut self, low: &[u8], high: &[u8], target: &Object<'_>) {
        let Some((lo, hi)) = self.range(low, high) else {
            return;
        };
        let target = match self.kind {
            CmapKind::Encoding => match target {
                Object::Str(value) => code_value(&value.decoded()).map(Target::Cid),
                other => other
                    .as_int()
                    .and_then(|cid| u32::try_from(cid).ok())
                    .map(Target::Cid),
            },
            CmapKind::ToUnicode => self.text_target(target),
        };
        if let Some(target) = target {
            self.push(lo, hi, target);
        }
    }

    fn add_bf_array(&mut self, low: &[u8], high: &[u8], array: Array<'_>) {
        let Some((lo, hi)) = self.range(low, high) else {
            return;
        };
        let span = hi - lo;
        for (offset, item) in (0..=span).zip(array.iter()) {
            if self.entries.len() >= MAX_CMAP_ENTRIES {
                return;
            }
            let target = match self.kind {
                CmapKind::Encoding => item
                    .as_str()
                    .and_then(|value| code_value(&value.decoded()))
                    .map(Target::Cid),
                CmapKind::ToUnicode => self.text_target(&item),
            };
            if let Some(target) = target {
                self.push(lo + offset, lo + offset, target);
            }
        }
    }

    fn text_target(&mut self, target: &Object<'_>) -> Option<Target> {
        match target {
            Object::Str(value) => self.units_for_bytes(&value.decoded()),
            Object::Name(name) => {
                let mut text = String::new();
                glyph_unicode(&name.decoded(), &mut text).then_some(())?;
                self.units_for_str(&text)
            }
            other => u32::try_from(other.as_int()?)
                .ok()
                .and_then(|value| self.units_for_char(value)),
        }
    }

    fn units_for_bytes(&mut self, bytes: &[u8]) -> Option<Target> {
        if bytes.is_empty() {
            return None;
        }
        let offset = u32::try_from(self.units.len()).ok()?;
        let padded = bytes.len() % 2 == 1;
        let mut units = 0u32;
        let mut pairs = bytes.as_chunks::<2>();
        if padded {
            let (&first, rest) = bytes.split_first()?;
            self.units.push(u16::from(first));
            units += 1;
            pairs = rest.as_chunks::<2>();
        }
        for pair in pairs.0.iter().take(MAX_TARGET_UNITS) {
            self.units.push(u16::from_be_bytes(*pair));
            units += 1;
        }
        Some(Target::Units { offset, len: units })
    }

    fn units_for_str(&mut self, text: &str) -> Option<Target> {
        let offset = u32::try_from(self.units.len()).ok()?;
        let before = self.units.len();
        self.units
            .extend(text.encode_utf16().take(MAX_TARGET_UNITS));
        let len = u32::try_from(self.units.len() - before).ok()?;
        (len > 0).then_some(Target::Units { offset, len })
    }

    fn units_for_char(&mut self, value: u32) -> Option<Target> {
        let ch = char::from_u32(value)?;
        let mut buf = [0u16; 2];
        let offset = u32::try_from(self.units.len()).ok()?;
        let encoded = ch.encode_utf16(&mut buf);
        self.units.extend_from_slice(encoded);
        Some(Target::Units {
            offset,
            len: encoded.len() as u32,
        })
    }

    pub(crate) fn finish(&mut self) {
        self.entries.finish();
        self.units.shrink_to_fit();
    }

    pub(crate) fn unicode(&self, code: u32, out: &mut String) -> bool {
        let Some((target, delta)) = self.entries.find(u64::from(code)) else {
            return false;
        };
        let Target::Units { offset, len } = target else {
            return false;
        };
        let Some(units) = usize::try_from(offset)
            .ok()
            .zip(usize::try_from(len).ok())
            .and_then(|(offset, len)| self.units.get(offset..offset.checked_add(len)?))
        else {
            return false;
        };
        let Some((&last, head)) = units.split_last() else {
            return false;
        };
        let Some(last) = u64::from(last)
            .checked_add(delta)
            .filter(|&value| value <= u64::from(MAX_UNIT))
            .and_then(|value| u16::try_from(value).ok())
        else {
            return false;
        };
        let mark = out.len();
        for ch in char::decode_utf16(head.iter().copied().chain(std::iter::once(last))) {
            match ch {
                Ok(ch) => out.push(ch),
                Err(_) => {
                    out.truncate(mark);
                    return false;
                }
            }
        }
        out.len() > mark
    }

    pub(crate) fn cid(&self, code: u32, len: usize) -> Option<u32> {
        let key = (len as u64) << LENGTH_SHIFT | u64::from(code);
        match self.entries.find(key)? {
            (Target::Cid(start), delta) => u32::try_from(u64::from(start).checked_add(delta)?).ok(),
            (Target::Units { .. }, _) => None,
        }
    }
}

fn source(object: &Object<'_>) -> Option<Vec<u8>> {
    let bytes = object.as_str()?.decoded();
    (!bytes.is_empty() && bytes.len() <= MAX_CODE_BYTES).then(|| bytes.into_owned())
}

#[cfg(test)]
mod tests;
