/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bumpalo::{Bump, collections::String as BumpString};
use utils::text::{hex_encode_into, validate_utf8};

pub fn hex_encode<'a>(bytes: &[u8], arena: &'a Bump) -> &'a str {
    hex_encode_into(bytes, arena.alloc_slice_fill_copy(bytes.len() * 2, b'0'))
}

pub fn utf8_lossy<'a>(bytes: &'a [u8], arena: &'a Bump) -> &'a str {
    validate_utf8(bytes).unwrap_or_else(|| replace_invalid(bytes, arena))
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
