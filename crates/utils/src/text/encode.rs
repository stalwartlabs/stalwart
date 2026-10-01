/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const SIMD_UTF8_MIN_LEN: usize = 64;

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = vec![b'0'; bytes.len() * 2];
    hex_encode_into(bytes, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

pub fn hex_encode_into<'a>(bytes: &[u8], out: &'a mut [u8]) -> &'a str {
    let (pairs, _) = out.as_chunks_mut::<2>();
    let len = pairs.len().min(bytes.len()) * 2;
    for (pair, &byte) in pairs.iter_mut().zip(bytes) {
        *pair = [
            HEX_DIGITS[usize::from(byte >> 4)],
            HEX_DIGITS[usize::from(byte & 0x0F)],
        ];
    }
    let out: &'a [u8] = out;
    out.get(..len)
        .and_then(|encoded| std::str::from_utf8(encoded).ok())
        .unwrap_or_default()
}

pub fn validate_utf8(bytes: &[u8]) -> Option<&str> {
    if bytes.len() >= SIMD_UTF8_MIN_LEN {
        simdutf8::basic::from_utf8(bytes).ok()
    } else if bytes.is_ascii() {
        std::str::from_utf8(bytes).ok()
    } else {
        single_valid_chunk(bytes)
    }
}

pub fn utf8_lossy(bytes: &[u8]) -> Cow<'_, str> {
    match validate_utf8(bytes) {
        Some(text) => Cow::Borrowed(text),
        None => Cow::Owned(replace_invalid(bytes)),
    }
}

fn single_valid_chunk(bytes: &[u8]) -> Option<&str> {
    bytes
        .utf8_chunks()
        .next()
        .filter(|chunk| chunk.invalid().is_empty())
        .map(|chunk| chunk.valid())
}

fn replace_invalid(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
    out
}
