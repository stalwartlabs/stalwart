/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{BuiltinEncoding, CodeNames};

const PFB_MARKER: u8 = 0x80;
const PFB_ASCII: u8 = 1;
const PFB_BINARY: u8 = 2;
const PFB_HEADER_LEN: usize = 6;
const MAX_RADIX: u32 = 36;

impl<'x> BuiltinEncoding<'x> {
    pub(crate) fn from_type1(program: &'x [u8]) -> Option<Self> {
        if program.first() == Some(&PFB_MARKER) {
            PfbSegments { data: program }.find_map(parse_cleartext)
        } else {
            parse_cleartext(program)
        }
    }
}

struct PfbSegments<'x> {
    data: &'x [u8],
}

impl<'x> Iterator for PfbSegments<'x> {
    type Item = &'x [u8];

    fn next(&mut self) -> Option<&'x [u8]> {
        loop {
            let (header, rest) = self.data.split_first_chunk::<PFB_HEADER_LEN>()?;
            let [PFB_MARKER, kind, len @ ..] = *header else {
                return None;
            };
            if kind != PFB_ASCII && kind != PFB_BINARY {
                return None;
            }
            let len = usize::try_from(u32::from_le_bytes(len)).ok()?;
            let (segment, rest) = rest.split_at_checked(len).unwrap_or((rest, &[]));
            self.data = rest;
            if kind == PFB_ASCII {
                return Some(segment);
            }
        }
    }
}

fn parse_cleartext(data: &[u8]) -> Option<BuiltinEncoding<'_>> {
    let mut tokens = Tokens { data };
    let mut encoding = None;
    while let Some(token) = tokens.next() {
        if token == b"/Encoding"
            && let Some(parsed) = parse_encoding(&mut tokens)
        {
            encoding = Some(parsed);
        }
    }
    encoding
}

fn parse_encoding<'x>(tokens: &mut Tokens<'x>) -> Option<BuiltinEncoding<'x>> {
    let first = tokens.next()?;
    if first == b"StandardEncoding" {
        return Some(BuiltinEncoding::Standard);
    }
    parse_int(first)?;
    let mut names = CodeNames::new();
    while let Some(token) = tokens.next() {
        match token {
            b"dup" => {
                let Some(code) = tokens.next().and_then(parse_int) else {
                    continue;
                };
                let Some(name) = tokens.next().and_then(|token| token.strip_prefix(b"/")) else {
                    continue;
                };
                if let Ok(code) = u8::try_from(code) {
                    names.set(code, name);
                }
            }
            b"def" => break,
            _ => {}
        }
    }
    Some(BuiltinEncoding::Custom(names))
}

fn parse_int(token: &[u8]) -> Option<i64> {
    let (negative, unsigned) = match token {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, token),
    };
    let mut parts = unsigned.splitn(2, |&byte| byte == b'#');
    let head = parts.next()?;
    let value = match parts.next() {
        Some(digits) => {
            let radix = u32::try_from(parse_digits(head, 10)?)
                .ok()
                .filter(|radix| (2..=MAX_RADIX).contains(radix))?;
            parse_digits(digits, radix)?
        }
        None => parse_digits(head, 10)?,
    };
    Some(if negative { -value } else { value })
}

fn parse_digits(digits: &[u8], radix: u32) -> Option<i64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0i64, |value, &byte| {
        let digit = char::from(byte).to_digit(radix)?;
        value
            .checked_mul(i64::from(radix))?
            .checked_add(i64::from(digit))
    })
}

struct Tokens<'x> {
    data: &'x [u8],
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

fn is_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn is_regular(byte: u8) -> bool {
    !is_whitespace(byte) && !is_delimiter(byte)
}

impl<'x> Tokens<'x> {
    fn skip_space_and_comments(&mut self) {
        loop {
            let start = self.data.iter().position(|&byte| !is_whitespace(byte));
            self.data = self
                .data
                .get(start.unwrap_or(self.data.len())..)
                .unwrap_or_default();
            if self.data.first() != Some(&b'%') {
                return;
            }
            let end = self
                .data
                .iter()
                .position(|&byte| byte == b'\n' || byte == b'\r');
            self.data = self
                .data
                .get(end.unwrap_or(self.data.len())..)
                .unwrap_or_default();
        }
    }

    fn split(&mut self, len: usize) -> &'x [u8] {
        let (token, rest) = self.data.split_at_checked(len).unwrap_or((self.data, &[]));
        self.data = rest;
        token
    }

    fn string_len(&self) -> usize {
        let mut depth = 0usize;
        let mut escaped = false;
        for (index, &byte) in self.data.iter().enumerate() {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return index + 1;
                    }
                }
                _ => {}
            }
        }
        self.data.len()
    }

    fn run_len(&self, skip: usize) -> usize {
        let run = self.data.get(skip..).unwrap_or_default();
        skip + run
            .iter()
            .position(|&byte| !is_regular(byte))
            .unwrap_or(run.len())
    }
}

impl<'x> Iterator for Tokens<'x> {
    type Item = &'x [u8];

    fn next(&mut self) -> Option<&'x [u8]> {
        self.skip_space_and_comments();
        let len = match *self.data.first()? {
            b'(' => self.string_len(),
            b'<' => self
                .data
                .iter()
                .position(|&byte| byte == b'>')
                .map_or(self.data.len(), |end| end + 1),
            b'/' => self.run_len(1),
            byte if is_delimiter(byte) => 1,
            _ => self.run_len(0),
        };
        let token = self.split(len);
        if token == b"eexec" {
            self.data = &[];
            return None;
        }
        Some(token)
    }
}
