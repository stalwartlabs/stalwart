/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::CompactString;
use std::borrow::Cow;

pub const MAX_KEYWORD_LEN: usize = 255;

const ESCAPE: u8 = b'&';
const SYSTEM_PREFIX: u8 = b'$';
const FLAG_PREFIX: u8 = b'\\';
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

const PLAIN: [bool; 256] = {
    let mut table = [false; 256];
    let mut ch = 0x21;
    while ch < 0x7f {
        table[ch] = !matches!(
            ch as u8,
            b'(' | b')' | b'{' | b']' | b'%' | b'*' | b'"' | b'\\' | ESCAPE
        );
        ch += 1;
    }
    table
};

pub fn to_keyword(name: &str) -> Option<CompactString> {
    let (&first, rest) = name.as_bytes().split_first()?;
    if name.len() > MAX_KEYWORD_LEN {
        return None;
    }
    let mut keyword = CompactString::with_capacity(name.len());
    push_byte(&mut keyword, first, first != SYSTEM_PREFIX);
    for &byte in rest {
        push_byte(&mut keyword, byte, true);
    }
    (keyword.len() <= MAX_KEYWORD_LEN).then_some(keyword)
}

pub fn is_category_keyword(keyword: &str) -> bool {
    !matches!(
        keyword.as_bytes().first(),
        Some(&(SYSTEM_PREFIX | FLAG_PREFIX))
    )
}

pub fn from_keyword(keyword: &str) -> Cow<'_, str> {
    if memchr::memchr(ESCAPE, keyword.as_bytes()).is_none() {
        return Cow::Borrowed(keyword);
    }
    decode(keyword.as_bytes()).map_or(Cow::Borrowed(keyword), Cow::Owned)
}

fn push_byte(keyword: &mut CompactString, byte: u8, plain_allowed: bool) {
    if plain_allowed && PLAIN[usize::from(byte)] {
        keyword.push(char::from(byte.to_ascii_lowercase()));
    } else {
        keyword.push(char::from(ESCAPE));
        keyword.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        keyword.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
}

fn decode(keyword: &[u8]) -> Option<String> {
    let mut parts = keyword.split(|&byte| byte == ESCAPE);
    let mut out = Vec::with_capacity(keyword.len());
    out.extend_from_slice(parts.next()?);
    for part in parts {
        let (&[high, low], tail) = part.split_first_chunk::<2>()?;
        out.push((hex_value(high)? << 4) | hex_value(low)?);
        out.extend_from_slice(tail);
    }
    String::from_utf8(out).ok()
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/convert/category/tests.rs"]
mod tests;
