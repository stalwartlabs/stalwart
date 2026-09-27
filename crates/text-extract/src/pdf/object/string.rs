/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ObjRef;
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Name<'a> {
    raw: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Literal,
    Hex,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Str<'a> {
    raw: &'a [u8],
    encoding: Encoding,
    owner: Option<ObjRef>,
}

pub(crate) struct NameBytes<'a> {
    rest: &'a [u8],
}

impl<'a> Name<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Name { raw }
    }

    pub(crate) fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub(crate) fn bytes(&self) -> NameBytes<'a> {
        NameBytes { rest: self.raw }
    }

    pub(crate) fn is(&self, other: &[u8]) -> bool {
        if !self.raw.contains(&b'#') {
            return self.raw == other;
        }
        self.bytes().eq(other.iter().copied())
    }

    pub(crate) fn decoded(&self) -> Cow<'a, [u8]> {
        if self.raw.contains(&b'#') {
            Cow::Owned(self.bytes().collect())
        } else {
            Cow::Borrowed(self.raw)
        }
    }
}

impl Iterator for NameBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let (&first, rest) = self.rest.split_first()?;
        if first == b'#'
            && let [high, low, tail @ ..] = rest
            && let (Some(high), Some(low)) = (hex_value(*high), hex_value(*low))
        {
            self.rest = tail;
            return Some(high << 4 | low);
        }
        self.rest = rest;
        Some(first)
    }
}

impl<'a> Str<'a> {
    pub(crate) fn literal(raw: &'a [u8], owner: Option<ObjRef>) -> Self {
        Str {
            raw,
            encoding: Encoding::Literal,
            owner,
        }
    }

    pub(crate) fn hex(raw: &'a [u8], owner: Option<ObjRef>) -> Self {
        Str {
            raw,
            encoding: Encoding::Hex,
            owner,
        }
    }

    pub(crate) fn owner(&self) -> Option<ObjRef> {
        self.owner
    }

    pub(crate) fn plain(&self) -> Option<&'a [u8]> {
        (self.encoding == Encoding::Literal && !self.raw.iter().any(|&b| b == b'\\' || b == b'\r'))
            .then_some(self.raw)
    }

    pub(crate) fn decoded(&self) -> Cow<'a, [u8]> {
        if let Some(raw) = self.plain() {
            return Cow::Borrowed(raw);
        }
        let mut out = Vec::with_capacity(self.raw.len());
        self.decode_into(&mut out);
        Cow::Owned(out)
    }

    pub(crate) fn decode_into(&self, out: &mut Vec<u8>) {
        match self.encoding {
            Encoding::Literal => decode_literal(self.raw, out),
            Encoding::Hex => decode_hex(self.raw, out),
        }
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(raw: &[u8], out: &mut Vec<u8>) {
    out.reserve(raw.len() / 2 + 1);
    let mut high = None;
    for digit in raw.iter().filter_map(|&byte| hex_value(byte)) {
        match high.take() {
            None => high = Some(digit),
            Some(value) => out.push(value << 4 | digit),
        }
    }
    if let Some(value) = high {
        out.push(value << 4);
    }
}

fn decode_literal(raw: &[u8], out: &mut Vec<u8>) {
    out.reserve(raw.len());
    let mut bytes = raw.iter().copied().peekable();
    while let Some(byte) = bytes.next() {
        match byte {
            b'\\' => {
                let Some(escaped) = bytes.next() else {
                    break;
                };
                match escaped {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'0'..=b'7' => {
                        let mut value = u32::from(escaped - b'0');
                        for _ in 0..2 {
                            match bytes.peek() {
                                Some(&digit @ b'0'..=b'7') => {
                                    value = value * 8 + u32::from(digit - b'0');
                                    bytes.next();
                                }
                                _ => break,
                            }
                        }
                        out.push((value & 0xFF) as u8);
                    }
                    b'\r' => {
                        bytes.next_if_eq(&b'\n');
                    }
                    b'\n' => {}
                    other => out.push(other),
                }
            }
            b'\r' => {
                bytes.next_if_eq(&b'\n');
                out.push(b'\n');
            }
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_decode_escapes() {
        assert!(Name::new(b"Type").is(b"Type"));
        assert!(Name::new(b"Ty#70e").is(b"Type"));
        assert!(!Name::new(b"Ty#70e").is(b"Typ"));
        assert_eq!(&*Name::new(b"A#2").decoded(), b"A#2");
        assert_eq!(&*Name::new(b"#G1#4G#00").decoded(), b"#G1#4G\0");
    }

    #[test]
    fn literal_strings_follow_the_spec() {
        let decode = |raw: &[u8]| Str::literal(raw, None).decoded().into_owned();
        assert!(matches!(
            Str::literal(b"plain", None).decoded(),
            Cow::Borrowed(_)
        ));
        assert_eq!(decode(b"a\\nb\\(c\\)\\\\"), b"a\nb(c)\\");
        assert_eq!(decode(b"\\101\\7\\0012\\777"), b"A\x07\x012\xFF");
        assert_eq!(decode(b"line\\\r\nnext\\\nx"), b"linenextx");
        assert_eq!(decode(b"a\r\nb\rc\nd"), b"a\nb\nc\nd");
        assert_eq!(decode(b"\\q\\"), b"q");
    }

    #[test]
    fn hex_strings_ignore_garbage_and_pad() {
        let decode = |raw: &[u8]| Str::hex(raw, None).decoded().into_owned();
        assert_eq!(decode(b"48 65 6c6C6f"), b"Hello");
        assert_eq!(decode(b"4G1 2"), b"\x41\x20");
        assert_eq!(decode(b""), b"");
    }
}
