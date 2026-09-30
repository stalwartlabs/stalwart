/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bumpalo::{Bump, collections::String as BumpString};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const SIMD_UTF8_MIN_LEN: usize = 64;

pub fn hex_encode<'a>(bytes: &[u8], arena: &'a Bump) -> &'a str {
    let out = arena.alloc_slice_fill_copy(bytes.len() * 2, b'0');
    let (pairs, _) = out.as_chunks_mut::<2>();
    for (pair, &byte) in pairs.iter_mut().zip(bytes) {
        *pair = [
            HEX_DIGITS[usize::from(byte >> 4)],
            HEX_DIGITS[usize::from(byte & 0x0F)],
        ];
    }
    std::str::from_utf8(out).unwrap_or_default()
}

pub fn utf8_lossy<'a>(bytes: &'a [u8], arena: &'a Bump) -> &'a str {
    let valid = if bytes.len() >= SIMD_UTF8_MIN_LEN {
        simdutf8::basic::from_utf8(bytes).ok()
    } else if bytes.is_ascii() {
        std::str::from_utf8(bytes).ok()
    } else {
        single_valid_chunk(bytes)
    };
    valid.unwrap_or_else(|| replace_invalid(bytes, arena))
}

fn single_valid_chunk(bytes: &[u8]) -> Option<&str> {
    bytes
        .utf8_chunks()
        .next()
        .filter(|chunk| chunk.invalid().is_empty())
        .map(|chunk| chunk.valid())
}

fn replace_invalid<'a>(bytes: &[u8], arena: &'a Bump) -> &'a str {
    let mut out = BumpString::with_capacity_in(bytes.len(), arena);
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
    out.into_bump_str()
}
