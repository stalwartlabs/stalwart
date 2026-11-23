/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::char::REPLACEMENT_CHARACTER;

const NARROW_CHUNK: usize = 64;
const WIDE_RUN_MAX: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Utf16Le<'a>(&'a [u8]);

impl<'a> Utf16Le<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        bytes.len().is_multiple_of(2).then_some(Utf16Le(bytes))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    pub fn len_units(&self) -> usize {
        self.0.len() / 2
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn units(&self) -> impl Iterator<Item = u16> + 'a {
        self.0
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
    }

    pub fn chars_lossy(&self) -> impl Iterator<Item = char> + 'a {
        char::decode_utf16(self.units()).map(|c| c.unwrap_or(REPLACEMENT_CHARACTER))
    }

    pub fn to_string_lossy(&self, out: &mut String) {
        let (mut pairs, _) = self.0.as_chunks::<2>();
        out.reserve(pairs.len());
        if pairs.len() < WIDE_RUN_MAX {
            push_wide(out, pairs);
            return;
        }
        while !pairs.is_empty() {
            let ascii = pairs
                .iter()
                .position(|unit| !is_ascii_unit(unit))
                .unwrap_or(pairs.len());
            let (head, tail) = pairs.split_at_checked(ascii).unwrap_or((&[], pairs));
            push_ascii(out, head);
            let Some((wide, next)) = tail
                .iter()
                .take(WIDE_RUN_MAX)
                .position(is_ascii_unit)
                .and_then(|at| tail.split_at_checked(at))
            else {
                push_wide(out, tail);
                return;
            };
            push_wide(out, wide);
            pairs = next;
        }
    }

    pub fn eq_ignore_ascii_case(&self, s: &str) -> bool {
        self.units()
            .map(ascii_lower)
            .eq(s.encode_utf16().map(ascii_lower))
    }
}

fn is_ascii_unit([lo, hi]: &[u8; 2]) -> bool {
    *hi == 0 && lo.is_ascii()
}

fn push_ascii(out: &mut String, pairs: &[[u8; 2]]) {
    let mut buf = [0u8; NARROW_CHUNK];
    for chunk in pairs.chunks(NARROW_CHUNK) {
        for (dst, [lo, _]) in buf.iter_mut().zip(chunk) {
            *dst = *lo;
        }
        if let Some(Ok(ascii)) = buf.get(..chunk.len()).map(str::from_utf8) {
            out.push_str(ascii);
        }
    }
}

fn push_wide(out: &mut String, pairs: &[[u8; 2]]) {
    out.extend(
        char::decode_utf16(pairs.iter().map(|unit| u16::from_le_bytes(*unit)))
            .map(|c| c.unwrap_or(REPLACEMENT_CHARACTER)),
    );
}

fn ascii_lower(unit: u16) -> u16 {
    match u8::try_from(unit) {
        Ok(byte) => u16::from(byte.to_ascii_lowercase()),
        Err(_) => unit,
    }
}

pub fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}
