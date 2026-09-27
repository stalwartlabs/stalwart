/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod markers;

pub(crate) use markers::Markers;

use crate::pdf::{
    lexer::{Lexer, Token, is_whitespace},
    object::Object,
};
use markers::{ASCII85_END, DATA_MARKER, END_MARKER, delimited_after};

const MAX_DICT_ENTRIES: usize = 64;
const MAX_END_GAP: usize = 256;
const BITS_PER_BYTE: u64 = 8;

#[derive(Debug, Default)]
struct ImageInfo {
    length: Option<u64>,
    filtered: bool,
    hex: bool,
    ascii85: bool,
    width: Option<u64>,
    height: Option<u64>,
    bits: Option<u64>,
    components: Option<u64>,
    mask: bool,
}

pub(crate) fn skip(lexer: &mut Lexer<'_>, markers: &mut Markers) {
    let Some(info) = read_dict(lexer, markers) else {
        return;
    };
    let data = lexer.data();
    let start = data_start(data, lexer.pos());
    let end = info
        .length
        .and_then(|length| accept_at(data, start, length))
        .or_else(|| info.filter_end(data, start, markers))
        .or_else(|| {
            info.unfiltered_size()
                .and_then(|size| accept_at(data, start, size))
        })
        .or_else(|| markers.scan(data, start))
        .unwrap_or(data.len());
    lexer.set_pos(end);
}

fn read_dict(lexer: &mut Lexer<'_>, markers: &mut Markers) -> Option<ImageInfo> {
    let mut info = ImageInfo::default();
    for _ in 0..MAX_DICT_ENTRIES * 2 {
        let before = lexer.pos();
        match lexer.next()? {
            Token::Keyword(b"ID") => return Some(info),
            Token::Keyword(b"EI") => return None,
            Token::Keyword(_) => {
                lexer.set_pos(before);
                return None;
            }
            Token::Name(key) => {
                let value = Object::read(lexer, None).unwrap_or_default();
                info.set(key, value);
            }
            _ => {}
        }
    }
    let found = markers.data(lexer.data(), lexer.pos())?;
    lexer.set_pos(found + DATA_MARKER.len());
    Some(info)
}

impl ImageInfo {
    fn set(&mut self, key: &[u8], value: Object<'_>) {
        let count = || value.as_int().and_then(|value| u64::try_from(value).ok());
        hashify::fnc_map!(key,
            b"L" => { self.length = count(); },
            b"Length" => { self.length = count(); },
            b"W" => { self.width = count(); },
            b"Width" => { self.width = count(); },
            b"H" => { self.height = count(); },
            b"Height" => { self.height = count(); },
            b"BPC" => { self.bits = count(); },
            b"BitsPerComponent" => { self.bits = count(); },
            b"IM" => { self.mask = value.as_bool().unwrap_or(false); },
            b"ImageMask" => { self.mask = value.as_bool().unwrap_or(false); },
            b"CS" => self.set_color_space(value),
            b"ColorSpace" => self.set_color_space(value),
            b"F" => self.set_filter(value),
            b"Filter" => self.set_filter(value),
            _ => {}
        );
    }

    fn set_color_space(&mut self, value: Object<'_>) {
        self.components = match value {
            Object::Name(name) => hashify::map!(name.raw(), u64,
                b"G" => 1,
                b"DeviceGray" => 1,
                b"I" => 1,
                b"Indexed" => 1,
                b"RGB" => 3,
                b"DeviceRGB" => 3,
                b"CMYK" => 4,
                b"DeviceCMYK" => 4,
            )
            .copied(),
            Object::Array(array) => match array.get(0).and_then(|first| first.as_name()) {
                Some(name) if name.is(b"I") || name.is(b"Indexed") => Some(1),
                _ => None,
            },
            _ => None,
        }
    }

    fn set_filter(&mut self, value: Object<'_>) {
        let first = match value {
            Object::Array(array) => array.get(0).and_then(|first| first.as_name()),
            other => other.as_name(),
        };
        if let Some(name) = first {
            self.filtered = true;
            self.hex = name.is(b"AHx") || name.is(b"ASCIIHexDecode");
            self.ascii85 = name.is(b"A85") || name.is(b"ASCII85Decode");
        }
    }

    fn filter_end(&self, data: &[u8], start: usize, markers: &mut Markers) -> Option<usize> {
        let after = if self.hex {
            markers.hex_end(data, start)? + 1
        } else if self.ascii85 {
            markers.ascii85_end(data, start)? + ASCII85_END.len()
        } else {
            return None;
        };
        let marker = markers.end(data, after)?;
        delimited_after(data, marker).then_some(marker + END_MARKER.len())
    }

    fn unfiltered_size(&self) -> Option<u64> {
        if self.filtered {
            return None;
        }
        let (components, bits) = if self.mask {
            (1, 1)
        } else {
            (self.components?, self.bits?)
        };
        let row_bits = self.width?.checked_mul(components)?.checked_mul(bits)?;
        row_bits.div_ceil(BITS_PER_BYTE).checked_mul(self.height?)
    }
}

fn data_start(data: &[u8], pos: usize) -> usize {
    match (data.get(pos), data.get(pos + 1)) {
        (Some(b'\r'), Some(b'\n')) => pos + 2,
        (Some(&byte), _) if is_whitespace(byte) => pos + 1,
        _ => pos,
    }
    .min(data.len())
}

fn accept_at(data: &[u8], start: usize, length: u64) -> Option<usize> {
    let end = start.checked_add(usize::try_from(length).ok()?)?;
    let rest = data.get(end..)?;
    let skip = rest
        .iter()
        .take(MAX_END_GAP + 1)
        .take_while(|&&byte| is_whitespace(byte))
        .count();
    if skip > MAX_END_GAP {
        return None;
    }
    let marker = end + skip;
    (data.get(marker..)?.starts_with(END_MARKER) && delimited_after(data, marker))
        .then_some(marker + END_MARKER.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn after(content: &[u8]) -> Vec<u8> {
        let mut lexer = Lexer::new(content);
        assert_eq!(lexer.next(), Some(Token::Keyword(b"BI")));
        skip(&mut lexer, &mut Markers::default());
        lexer.rest().to_vec()
    }

    #[test]
    fn length_and_exact_size_are_used() {
        assert_eq!(
            after(b"BI /W 2 /H 2 /BPC 8 /CS /G /L 4 ID \x00EI\x01 EI Q"),
            b" Q"
        );
        assert_eq!(
            after(b"BI /W 4 /H 1 /BPC 8 /CS /RGB ID EI EI EI EI EI\nBT"),
            b"\nBT"
        );
        assert_eq!(
            after(b"BI /IM true /W 9 /H 2 ID \xff\xffEI\x01 EI Q"),
            b" Q"
        );
    }

    #[test]
    fn filters_and_heuristics_find_the_end() {
        assert_eq!(
            after(b"BI /F /AHx /W 1 /H 1 ID 41 EI 42> EI (x) Tj"),
            b" (x) Tj"
        );
        assert_eq!(after(b"BI /F [/A85] ID abc~> EI BT"), b" BT");
        assert_eq!(
            after(b"BI /F /Fl ID x\x9c EI \x01\x02\x03\xff binary EI Q"),
            b" Q"
        );
        assert_eq!(after(b"BI /F /Fl ID no end marker"), b"");
    }

    #[test]
    fn many_candidates_stay_linear() {
        let mut content = b"BI /F /Fl ID ".to_vec();
        for _ in 0..200_000 {
            content.extend_from_slice(b" EI \x01");
        }
        content.extend_from_slice(b" EI Q");
        let started = std::time::Instant::now();
        let rest = after(&content);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(rest.len() < content.len());
    }
}
