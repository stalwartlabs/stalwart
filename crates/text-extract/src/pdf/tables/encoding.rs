/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::encoding_data::{ENCODINGS, FIRST_CODE, NO_GLYPH, STD_NAMES, STD_OFFSETS, STD_UNICODE};
use super::names::NameTable;

pub(super) static STD_GLYPHS: NameTable = NameTable::new(STD_NAMES, &STD_OFFSETS);

const PDFDOC_SPACING_FIRST: u8 = 0x18;
const PDFDOC_SPACING: [u16; 8] = [
    0x02D8, 0x02C7, 0x02C6, 0x02D9, 0x02DD, 0x02DB, 0x02DA, 0x02DC,
];
const PDFDOC_HIGH_FIRST: u8 = 0x80;
const PDFDOC_HIGH: [u16; 33] = [
    0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x0192, 0x2044, 0x2039, 0x203A, 0x2212, 0x2030,
    0x201E, 0x201C, 0x201D, 0x2018, 0x2019, 0x201A, 0x2122, 0xFB01, 0xFB02, 0x0141, 0x0152, 0x0160,
    0x0178, 0x017D, 0x0131, 0x0142, 0x0153, 0x0161, 0x017E, 0x0000, 0x20AC,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BaseEncoding {
    Standard,
    WinAnsi,
    MacRoman,
    MacExpert,
    Symbol,
    ZapfDingbats,
    Expert,
}

impl BaseEncoding {
    pub(crate) fn from_name(name: &[u8]) -> Option<Self> {
        hashify::map!(name, BaseEncoding,
            b"StandardEncoding" => BaseEncoding::Standard,
            b"WinAnsiEncoding" => BaseEncoding::WinAnsi,
            b"MacRomanEncoding" => BaseEncoding::MacRoman,
            b"MacExpertEncoding" => BaseEncoding::MacExpert,
            b"SymbolSetEncoding" => BaseEncoding::Symbol,
            b"ZapfDingbatsEncoding" => BaseEncoding::ZapfDingbats,
            b"ExpertEncoding" => BaseEncoding::Expert,
        )
        .copied()
    }

    pub(crate) fn glyph_name(self, code: u8) -> Option<&'static str> {
        STD_GLYPHS.get(self.glyph_index(code)?)
    }

    pub(crate) fn unicode(self, code: u8) -> Option<char> {
        std_char(self.glyph_index(code)?)
    }

    fn glyph_index(self, code: u8) -> Option<usize> {
        let index = *ENCODINGS
            .get(self as usize)?
            .get(usize::from(code.checked_sub(FIRST_CODE)?))?;
        (index != NO_GLYPH).then_some(usize::from(index))
    }
}

pub(super) fn std_glyph_char(name: &[u8]) -> Option<char> {
    std_char(STD_GLYPHS.find(name)?)
}

fn std_char(index: usize) -> Option<char> {
    char::from_u32(u32::from(*STD_UNICODE.get(index)?))
}

pub(crate) fn pdfdoc_char(byte: u8) -> Option<char> {
    let mapped = match byte {
        b'\t' | b'\n' | b'\r' | 0x20..=0x7E | 0xA1..=0xFF => return Some(char::from(byte)),
        0x18..=0x1F => PDFDOC_SPACING.get(usize::from(byte - PDFDOC_SPACING_FIRST)),
        0x80..=0xA0 => PDFDOC_HIGH.get(usize::from(byte - PDFDOC_HIGH_FIRST)),
        _ => None,
    };
    mapped
        .filter(|value| **value != 0)
        .and_then(|value| char::from_u32(u32::from(*value)))
}
