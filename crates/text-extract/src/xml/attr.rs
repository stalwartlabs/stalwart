/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MAX_ENTITY, Tag, local_name};
use crate::output::Output;
use memchr::memchr;

impl<'a> Tag<'a> {
    pub(crate) fn attributes(&self) -> Attributes<'a> {
        Attributes {
            rest: self.attrs.unwrap_or_default(),
        }
    }
}

#[inline]
pub(crate) fn split_prefix(name: &[u8]) -> (bool, &[u8]) {
    let local = local_name(name);
    (local.len() < name.len(), local)
}

pub(crate) struct Attributes<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Attributes<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.rest.trim_ascii_start();
        let name_len = rest
            .iter()
            .position(|&byte| byte == b'=' || byte.is_ascii_whitespace())?;
        let (name, rest) = rest.split_at(name_len);
        let rest = rest
            .trim_ascii_start()
            .strip_prefix(b"=")?
            .trim_ascii_start();
        let (&quote, rest) = rest.split_first()?;
        if quote != b'"' && quote != b'\'' {
            self.rest = b"";
            return None;
        }
        let value_len = rest.iter().position(|&byte| byte == quote)?;
        let (value, rest) = rest.split_at(value_len);
        self.rest = rest.get(1..).unwrap_or_default();
        Some((name, value))
    }
}

pub(crate) fn resolve_entity(body: &[u8]) -> Option<char> {
    match body {
        [b'#', b'x' | b'X', hex @ ..] => parse_code_point(hex, 16),
        [b'#', decimal @ ..] => parse_code_point(decimal, 10),
        _ => hashify::tiny_map!(body,
            b"amp" => '&',
            b"lt" => '<',
            b"gt" => '>',
            b"quot" => '"',
            b"apos" => '\'',
        ),
    }
}

fn parse_code_point(digits: &[u8], radix: u32) -> Option<char> {
    if digits.is_empty() {
        return None;
    }
    digits
        .iter()
        .try_fold(0u32, |value, &digit| {
            value
                .checked_mul(radix)?
                .checked_add(char::from(digit).to_digit(radix)?)
        })
        .and_then(char::from_u32)
}

pub(crate) fn split_entity(text: &[u8]) -> Option<(&[u8], &[u8])> {
    let window = text.get(1..text.len().min(MAX_ENTITY))?;
    let semicolon = memchr(b';', window)?;
    Some((window.get(..semicolon)?, text.get(semicolon + 2..)?))
}

pub(crate) fn decode_into(value: &[u8], dst: &mut Vec<u8>) {
    let mut rest = value;
    while let Some(amp) = memchr(b'&', rest) {
        let (plain, tail) = rest.split_at(amp);
        dst.extend_from_slice(plain);
        match split_entity(tail).and_then(|(body, after)| Some((resolve_entity(body)?, after))) {
            Some((ch, after)) => {
                let mut encoded = [0u8; 4];
                dst.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
                rest = after;
            }
            None => {
                dst.push(b'&');
                rest = tail.get(1..).unwrap_or_default();
            }
        }
    }
    dst.extend_from_slice(rest);
}

pub(crate) fn push_decoded(value: &[u8], out: &mut Output<'_>) {
    let mut rest = value;
    while let Some(amp) = memchr(b'&', rest) {
        let (plain, tail) = rest.split_at(amp);
        out.push_utf8(plain);
        match split_entity(tail).and_then(|(body, after)| Some((resolve_entity(body)?, after))) {
            Some((ch, after)) => {
                out.push_char(ch);
                rest = after;
            }
            None => {
                out.push_str("&");
                rest = tail.get(1..).unwrap_or_default();
            }
        }
    }
    out.push_utf8(rest);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_parse_quotes_and_prefixes() {
        let tag = Tag {
            name: b"p:sldId",
            attrs: Some(b" id=\"256\" r:id='rId2' broken"),
        };
        let attrs: Vec<_> = tag
            .attributes()
            .map(|(name, value)| (split_prefix(name), value))
            .collect();
        assert_eq!(
            attrs,
            vec![
                ((false, b"id".as_slice()), b"256".as_slice()),
                ((true, b"id".as_slice()), b"rId2".as_slice())
            ]
        );
    }

    #[test]
    fn entities_decode() {
        let mut dst = Vec::new();
        decode_into(b"a&amp;b&#x41;&#66;&bogus;&", &mut dst);
        assert_eq!(dst, b"a&bAB&bogus;&");
        assert_eq!(resolve_entity(b"#x110000"), None);
        assert_eq!(resolve_entity(b"#99999999999999999999"), None);
    }
}
