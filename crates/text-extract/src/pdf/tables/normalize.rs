/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::names::NameTable;
use super::presentation_data::{FORM_KEYS, FORM_OFFSETS, FORM_TEXT, FORM_VALUES};

static FORMS: NameTable = NameTable::new(FORM_TEXT, &FORM_OFFSETS);

pub(crate) fn presentation_form(c: char) -> Option<&'static str> {
    let key = u16::try_from(u32::from(c)).ok()?;
    let position = FORM_KEYS.binary_search(&key).ok()?;
    FORMS.get(usize::from(*FORM_VALUES.get(position)?))
}

pub(crate) fn combining_accent(c: char) -> Option<char> {
    match c {
        '\u{60}' => Some('\u{300}'),
        '\u{A8}' => Some('\u{308}'),
        '\u{AF}' => Some('\u{304}'),
        '\u{B4}' => Some('\u{301}'),
        '\u{B8}' => Some('\u{327}'),
        '\u{2C6}' => Some('\u{302}'),
        '\u{2C7}' => Some('\u{30C}'),
        '\u{2D8}' => Some('\u{306}'),
        '\u{2D9}' => Some('\u{307}'),
        '\u{2DA}' => Some('\u{30A}'),
        '\u{2DB}' => Some('\u{328}'),
        '\u{2DC}' => Some('\u{303}'),
        '\u{2DD}' => Some('\u{30B}'),
        _ => None,
    }
}
