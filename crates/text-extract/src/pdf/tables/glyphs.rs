/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::cmp::Ordering;
use std::ops::RangeInclusive;

use super::encoding::std_glyph_char;
use super::glyph_data::{
    BLOCK_OFFSETS, BLOCK_SIZE, GLYPH_VALUES, MAX_NAME, MULTI_BASE, MULTI_OFFSETS, MULTI_TEXT,
    NAME_BLOCKS, PREFIX_LIMIT, TOKEN_BASE, TOKEN_OFFSETS, TOKEN_TEXT, ZAPF_VALUES,
};
use super::names::NameTable;

static TOKENS: NameTable = NameTable::new(TOKEN_TEXT, &TOKEN_OFFSETS);
static MULTI: NameTable = NameTable::new(MULTI_TEXT, &MULTI_OFFSETS);

const MAX_SCALAR: u32 = 0x10FFFF;
const MIN_NAMED_CODE: u32 = 0x20;
const C1_CONTROLS: RangeInclusive<u32> = 0x7F..=0x9F;
const MAX_ZAPF_DIGITS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodeRadix {
    Decimal,
    Hex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GlyphCode {
    Code(u32),
    NeedsHex,
}

#[derive(Clone, Copy)]
enum HexCase {
    Upper,
    Any,
}

pub(crate) fn glyph_unicode(name: &[u8], out: &mut String) -> bool {
    let base = strip_suffix(name);
    if base.is_empty() {
        return false;
    }
    let mark = out.len();
    for component in base.split(|byte| *byte == b'_') {
        if !append_component(component, out) {
            out.truncate(mark);
            return false;
        }
    }
    true
}

pub(crate) fn zapf_dingbats_unicode(name: &[u8], out: &mut String) -> bool {
    match zapf_char(strip_suffix(name)) {
        Some(ch) => {
            out.push(ch);
            true
        }
        None => glyph_unicode(name, out),
    }
}

fn strip_suffix(name: &[u8]) -> &[u8] {
    name.split(|byte| *byte == b'.').next().unwrap_or_default()
}

fn zapf_digits(name: &[u8]) -> Option<&[u8]> {
    name.strip_prefix(b"a")
        .filter(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
}

fn zapf_char(name: &[u8]) -> Option<char> {
    let digits = zapf_digits(name)
        .filter(|digits| digits.len() <= MAX_ZAPF_DIGITS && digits.first() != Some(&b'0'))?;
    let index = usize::try_from(parse_decimal(digits)?)
        .ok()?
        .checked_sub(1)?;
    let value = *ZAPF_VALUES.get(index)?;
    (value != 0)
        .then(|| char::from_u32(u32::from(value)))
        .flatten()
}

pub(crate) fn glyph_name_code(name: &[u8], c_radix: CodeRadix) -> Option<GlyphCode> {
    let (&first, digits) = name.split_first()?;
    let code = match (first, digits.len()) {
        (b'G', 2) | (b'g', 4) => parse_hex(digits, HexCase::Any)?,
        (b'C' | b'c', 2..=3) => match c_radix {
            CodeRadix::Hex => parse_hex(digits, HexCase::Any)?,
            CodeRadix::Decimal => match parse_decimal(digits) {
                Some(code) => code,
                None => {
                    return parse_hex(digits, HexCase::Any).map(|_| GlyphCode::NeedsHex);
                }
            },
        },
        _ => return None,
    };
    ((MIN_NAMED_CODE..=MAX_SCALAR).contains(&code) && !C1_CONTROLS.contains(&code))
        .then_some(GlyphCode::Code(code))
}

fn append_component(component: &[u8], out: &mut String) -> bool {
    if zapf_digits(component).is_some() {
        return false;
    }
    if let Some(ch) = std_glyph_char(component) {
        out.push(ch);
        return true;
    }
    if let Some(index) = glyph_index(component) {
        return append_value(index, out).is_some();
    }
    if let Some(hex) = component.strip_prefix(b"uni")
        && append_uni(hex, out)
    {
        return true;
    }
    component
        .strip_prefix(b"u")
        .is_some_and(|hex| append_u(hex, out))
}

fn append_uni(hex: &[u8], out: &mut String) -> bool {
    if hex.is_empty() || !hex.len().is_multiple_of(4) {
        return false;
    }
    let mark = out.len();
    for group in hex.chunks(4) {
        match parse_hex(group, HexCase::Any).and_then(char::from_u32) {
            Some(ch) => out.push(ch),
            None => {
                out.truncate(mark);
                return false;
            }
        }
    }
    true
}

fn append_u(hex: &[u8], out: &mut String) -> bool {
    if !(4..=6).contains(&hex.len()) {
        return false;
    }
    match parse_hex(hex, HexCase::Upper).and_then(char::from_u32) {
        Some(ch) => {
            out.push(ch);
            true
        }
        None => false,
    }
}

fn parse_hex(digits: &[u8], case: HexCase) -> Option<u32> {
    digits.iter().try_fold(0u32, |acc, &byte| {
        let digit = match (byte, case) {
            (b'0'..=b'9', _) => byte - b'0',
            (b'A'..=b'F', _) => byte - b'A' + 10,
            (b'a'..=b'f', HexCase::Any) => byte - b'a' + 10,
            _ => return None,
        };
        Some((acc << 4) | u32::from(digit))
    })
}

fn parse_decimal(digits: &[u8]) -> Option<u32> {
    digits.iter().try_fold(0u32, |acc, &byte| {
        if byte.is_ascii_digit() {
            acc.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
        } else {
            None
        }
    })
}

fn append_value(index: usize, out: &mut String) -> Option<()> {
    let value = *GLYPH_VALUES.get(index)?;
    match char::from_u32(u32::from(value)) {
        Some(ch) => out.push(ch),
        None => out.push_str(MULTI.get(usize::from(value.checked_sub(MULTI_BASE)?))?),
    }
    Some(())
}

pub(super) fn glyph_index(name: &[u8]) -> Option<usize> {
    if name.is_empty() || name.len() > MAX_NAME {
        return None;
    }
    let mut buf = NameBuf::new();
    let (mut low, mut high) = (0, block_count());
    while low < high {
        let mid = low + (high - low) / 2;
        let (_, body) = Entries::new(block(mid)?).next()?;
        buf.load(0, body)?;
        if buf.as_slice() <= name {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    let block_index = low.checked_sub(1)?;
    for (position, (prefix, body)) in Entries::new(block(block_index)?).enumerate() {
        buf.load(prefix, body)?;
        match buf.as_slice().cmp(name) {
            Ordering::Less => {}
            Ordering::Equal => return Some(block_index * BLOCK_SIZE + position),
            Ordering::Greater => return None,
        }
    }
    None
}

fn block_count() -> usize {
    BLOCK_OFFSETS.len().saturating_sub(1)
}

fn block(index: usize) -> Option<&'static [u8]> {
    let &[start, end] = BLOCK_OFFSETS.get(index..index + 2)? else {
        return None;
    };
    NAME_BLOCKS.get(usize::from(start)..usize::from(end))
}

struct Entries {
    rest: &'static [u8],
}

impl Entries {
    fn new(block: &'static [u8]) -> Self {
        Self { rest: block }
    }
}

impl Iterator for Entries {
    type Item = (usize, &'static [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let (&prefix, tail) = self.rest.split_first()?;
        let body = tail
            .split(|byte| *byte < PREFIX_LIMIT)
            .next()
            .unwrap_or_default();
        self.rest = tail.get(body.len()..).unwrap_or_default();
        Some((usize::from(prefix), body))
    }
}

struct NameBuf {
    bytes: [u8; MAX_NAME],
    len: usize,
}

impl NameBuf {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_NAME],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    fn load(&mut self, prefix: usize, body: &[u8]) -> Option<()> {
        self.len = prefix.min(self.len);
        for &byte in body {
            match byte.checked_sub(TOKEN_BASE) {
                Some(token) => self.extend(TOKENS.get(usize::from(token))?.as_bytes())?,
                None => self.extend(&[byte])?,
            }
        }
        Some(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.len + bytes.len();
        self.bytes.get_mut(self.len..end)?.copy_from_slice(bytes);
        self.len = end;
        Some(())
    }
}

#[cfg(test)]
pub(super) fn all_names() -> Vec<String> {
    let mut names = Vec::with_capacity(GLYPH_VALUES.len());
    let mut buf = NameBuf::new();
    for index in 0..block_count() {
        for (prefix, body) in Entries::new(block(index).unwrap_or_default()) {
            if buf.load(prefix, body).is_some() {
                names.push(String::from_utf8_lossy(buf.as_slice()).into_owned());
            }
        }
    }
    names
}
