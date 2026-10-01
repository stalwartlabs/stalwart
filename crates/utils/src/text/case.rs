/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::segments::{Change, find_change, is_ascii};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseChange {
    Unchanged,
    AsciiFrom(usize),
    Unicode,
}

impl CaseChange {
    pub fn lowercase(text: &str) -> Self {
        Self::classify(
            text,
            find_change(text, |byte| byte.is_ascii_uppercase(), lower_fixed),
        )
    }

    pub fn uppercase(text: &str) -> Self {
        Self::classify(
            text,
            find_change(text, |byte| byte.is_ascii_lowercase(), upper_fixed),
        )
    }

    fn classify(text: &str, change: Option<Change>) -> Self {
        match change {
            None => Self::Unchanged,
            Some(Change::Ascii { position, checked })
                if text.as_bytes().get(checked..).is_none_or(is_ascii) =>
            {
                Self::AsciiFrom(position)
            }
            Some(_) => Self::Unicode,
        }
    }
}

pub fn lowercase(text: &str) -> Cow<'_, str> {
    match CaseChange::lowercase(text) {
        CaseChange::Unchanged => Cow::Borrowed(text),
        CaseChange::AsciiFrom(position) => {
            Cow::Owned(convert_ascii(text, position, str::make_ascii_lowercase))
        }
        CaseChange::Unicode => Cow::Owned(text.to_lowercase()),
    }
}

pub fn uppercase(text: &str) -> Cow<'_, str> {
    match CaseChange::uppercase(text) {
        CaseChange::Unchanged => Cow::Borrowed(text),
        CaseChange::AsciiFrom(position) => {
            Cow::Owned(convert_ascii(text, position, str::make_ascii_uppercase))
        }
        CaseChange::Unicode => Cow::Owned(text.to_uppercase()),
    }
}

fn convert_ascii(text: &str, position: usize, convert: fn(&mut str)) -> String {
    let mut out = text.to_owned();
    if let Some(changed) = out.get_mut(position..) {
        convert(changed);
    }
    out
}

fn lower_fixed(c: char) -> bool {
    let mut lower = c.to_lowercase();
    lower.next() == Some(c) && lower.next().is_none()
}

fn upper_fixed(c: char) -> bool {
    let mut upper = c.to_uppercase();
    upper.next() == Some(c) && upper.next().is_none()
}
