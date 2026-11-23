/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::char::REPLACEMENT_CHARACTER;

use crate::common::LeWriter;

const CP_UTF8: u16 = 65001;
const CP_LATIN1: u16 = 28591;
const CP_WINDOWS_1252: u16 = 1252;
const CP_LOGON: u16 = 0x0FFF;
const UNMAPPABLE: u8 = b'?';
const ASCII_END: u8 = 0x80;
const C1_END: u8 = 0xA0;
const C1_MASK: u8 = 0x7F;

macro_rules! windows_1252_c1 {
    ($($byte:literal => $unit:literal,)*) => {
        const WINDOWS_1252_C1: [u16; 32] = [$($unit),*];

        fn windows_1252_high(ch: char) -> Option<u8> {
            match u32::from(ch) {
                $($unit => Some($byte),)*
                _ => None,
            }
        }
    };
}

windows_1252_c1! {
    0x80 => 0x20AC,
    0x81 => 0x0081,
    0x82 => 0x201A,
    0x83 => 0x0192,
    0x84 => 0x201E,
    0x85 => 0x2026,
    0x86 => 0x2020,
    0x87 => 0x2021,
    0x88 => 0x02C6,
    0x89 => 0x2030,
    0x8A => 0x0160,
    0x8B => 0x2039,
    0x8C => 0x0152,
    0x8D => 0x008D,
    0x8E => 0x017D,
    0x8F => 0x008F,
    0x90 => 0x0090,
    0x91 => 0x2018,
    0x92 => 0x2019,
    0x93 => 0x201C,
    0x94 => 0x201D,
    0x95 => 0x2022,
    0x96 => 0x2013,
    0x97 => 0x2014,
    0x98 => 0x02DC,
    0x99 => 0x2122,
    0x9A => 0x0161,
    0x9B => 0x203A,
    0x9C => 0x0153,
    0x9D => 0x009D,
    0x9E => 0x017E,
    0x9F => 0x0178,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodePage(pub u16);

impl CodePage {
    pub const UTF8: CodePage = CodePage(CP_UTF8);
    pub const LATIN1: CodePage = CodePage(CP_LATIN1);
    pub const WINDOWS_1252: CodePage = CodePage(CP_WINDOWS_1252);

    pub fn from_identifier(id: u32) -> Option<Self> {
        let id = u16::try_from(id).ok()?;
        matches!(
            id,
            37 | 437
                | 500
                | 708..=710
                | 720
                | 737
                | 775
                | 850
                | 852
                | 855
                | 857
                | 858
                | 860..=866
                | 869
                | 870
                | 874
                | 875
                | 932
                | 936
                | 949
                | 950
                | 1026
                | 1047
                | 1140..=1149
                | 1200
                | 1201
                | 1250..=1258
                | 1361
                | 10000..=10008
                | 10010
                | 10017
                | 10021
                | 10029
                | 10079
                | 10081
                | 10082
                | 12000
                | 12001
                | 20000..=20005
                | 20105..=20108
                | 20127
                | 20261
                | 20269
                | 20273
                | 20277
                | 20278
                | 20280
                | 20284
                | 20285
                | 20290
                | 20297
                | 20420
                | 20423
                | 20424
                | 20833
                | 20838
                | 20866
                | 20871
                | 20880
                | 20905
                | 20924
                | 20932
                | 20936
                | 20949
                | 21025
                | 21027
                | 21866
                | 28591..=28599
                | 28603
                | 28605
                | 29001
                | 38598
                | 50220..=50222
                | 50225
                | 50227
                | 50229
                | 50930
                | 50931
                | 50933
                | 50935..=50937
                | 50939
                | 51932
                | 51936
                | 51949
                | 51950
                | 52936
                | 54936
                | 57002..=57011
                | 65000
                | 65001
        )
        .then_some(CodePage(id))
    }

    pub fn is_known_rop_id(id: u16) -> bool {
        id == CP_LOGON || Self::from_identifier(u32::from(id)).is_some()
    }

    pub fn narrow_utf16(self, units: &[u8], max: usize, out: &mut Vec<u8>) {
        let units = units
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .take_while(|unit| *unit != 0);
        self.narrow_chars(
            char::decode_utf16(units).map(|ch| ch.unwrap_or(REPLACEMENT_CHARACTER)),
            max,
            out,
        );
    }

    pub fn narrow_str(self, text: &str, max: usize, out: &mut Vec<u8>) {
        let text = text.split_once('\0').map_or(text, |(head, _)| head);
        if text.is_ascii() {
            let bytes = text.as_bytes();
            out.extend_from_slice(bytes.get(..max).unwrap_or(bytes));
        } else {
            self.narrow_chars(text.chars(), max, out);
        }
    }

    pub fn widen(self, bytes: &[u8], max_units: usize, out: &mut Vec<u8>) {
        let bytes = bytes
            .get(..memchr::memchr(0, bytes).unwrap_or(bytes.len()))
            .unwrap_or(bytes);
        if self.0 == CP_UTF8 {
            let mut left = max_units;
            let mut buf = [0u16; 2];
            for ch in String::from_utf8_lossy(bytes).chars() {
                let Some(rest) = left.checked_sub(ch.len_utf16()) else {
                    break;
                };
                left = rest;
                for unit in ch.encode_utf16(&mut buf) {
                    out.put_u16(*unit);
                }
            }
            return;
        }
        out.reserve(bytes.len().min(max_units).saturating_mul(2));
        for byte in bytes.iter().take(max_units) {
            out.put_u16(self.widen_byte(*byte));
        }
    }

    fn narrow_chars(self, chars: impl Iterator<Item = char>, max: usize, out: &mut Vec<u8>) {
        if self.0 == CP_UTF8 {
            let mut left = max;
            let mut buf = [0u8; 4];
            for ch in chars {
                let encoded = ch.encode_utf8(&mut buf).as_bytes();
                let Some(rest) = left.checked_sub(encoded.len()) else {
                    break;
                };
                left = rest;
                out.extend_from_slice(encoded);
            }
        } else {
            out.extend(chars.take(max).map(|ch| self.narrow_char(ch)));
        }
    }

    fn narrow_char(self, ch: char) -> u8 {
        let Ok(byte) = u8::try_from(ch) else {
            return match self.0 {
                CP_WINDOWS_1252 => windows_1252_high(ch).unwrap_or(UNMAPPABLE),
                _ => UNMAPPABLE,
            };
        };
        match self.0 {
            _ if byte < ASCII_END => byte,
            CP_LATIN1 => byte,
            CP_WINDOWS_1252 if byte >= C1_END => byte,
            CP_WINDOWS_1252 => windows_1252_high(ch).unwrap_or(UNMAPPABLE),
            _ => UNMAPPABLE,
        }
    }

    fn widen_byte(self, byte: u8) -> u16 {
        match self.0 {
            _ if byte < ASCII_END => u16::from(byte),
            CP_LATIN1 => u16::from(byte),
            CP_WINDOWS_1252 if byte >= C1_END => u16::from(byte),
            CP_WINDOWS_1252 => WINDOWS_1252_C1
                .get(usize::from(byte & C1_MASK))
                .copied()
                .unwrap_or(0xFFFD),
            _ => 0xFFFD,
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/prop/code_page/tests.rs"]
mod tests;
