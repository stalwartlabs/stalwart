/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::segments::{Change, find_change, is_ascii};
use bumpalo::Bump;
use std::borrow::Cow;

pub fn to_lowercase<'a>(text: &'a str, arena: &'a Bump) -> &'a str {
    match find_change(text, |byte| byte.is_ascii_uppercase(), lower_fixed) {
        None => text,
        Some(change) => convert_ascii(text, change, arena, str::make_ascii_lowercase)
            .unwrap_or_else(|| arena.alloc_str(&text.to_lowercase())),
    }
}

pub fn to_uppercase<'a>(text: &'a str, arena: &'a Bump) -> &'a str {
    match find_change(text, |byte| byte.is_ascii_lowercase(), upper_fixed) {
        None => text,
        Some(change) => convert_ascii(text, change, arena, str::make_ascii_uppercase)
            .unwrap_or_else(|| arena.alloc_str(&text.to_uppercase())),
    }
}

pub(crate) fn lowercase(text: &str) -> Cow<'_, str> {
    if find_change(text, |byte| byte.is_ascii_uppercase(), lower_fixed).is_some() {
        Cow::Owned(text.to_lowercase())
    } else {
        Cow::Borrowed(text)
    }
}

fn convert_ascii<'a>(
    text: &str,
    change: Change,
    arena: &'a Bump,
    convert: fn(&mut str),
) -> Option<&'a str> {
    let Change::Ascii { position, checked } = change else {
        return None;
    };
    if !text.as_bytes().get(checked..).is_none_or(is_ascii) {
        return None;
    }
    let out = arena.alloc_str(text);
    if let Some(changed) = out.get_mut(position..) {
        convert(changed);
    }
    Some(out)
}

fn lower_fixed(c: char) -> bool {
    let mut lower = c.to_lowercase();
    lower.next() == Some(c) && lower.next().is_none()
}

fn upper_fixed(c: char) -> bool {
    let mut upper = c.to_uppercase();
    upper.next() == Some(c) && upper.next().is_none()
}
