/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bumpalo::Bump;
use utils::text::CaseChange;

pub fn to_lowercase<'a>(text: &'a str, arena: &'a Bump) -> &'a str {
    convert(
        text,
        CaseChange::lowercase(text),
        arena,
        str::make_ascii_lowercase,
        str::to_lowercase,
    )
}

pub fn to_uppercase<'a>(text: &'a str, arena: &'a Bump) -> &'a str {
    convert(
        text,
        CaseChange::uppercase(text),
        arena,
        str::make_ascii_uppercase,
        str::to_uppercase,
    )
}

fn convert<'a>(
    text: &'a str,
    change: CaseChange,
    arena: &'a Bump,
    ascii: fn(&mut str),
    unicode: fn(&str) -> String,
) -> &'a str {
    match change {
        CaseChange::Unchanged => text,
        CaseChange::AsciiFrom(position) => {
            let out = arena.alloc_str(text);
            if let Some(changed) = out.get_mut(position..) {
                ascii(changed);
            }
            out
        }
        CaseChange::Unicode => arena.alloc_str(&unicode(text)),
    }
}
