/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use exchange_proto::mapi::prop::{CodePage, PropValue};

const MAX_TEXT: usize = 4096;

pub fn decode_text(value: &PropValue<'_>, code_page: CodePage, out: &mut String) -> bool {
    decode_text_within(value, code_page, MAX_TEXT, out)
}

pub fn decode_text_within(
    value: &PropValue<'_>,
    code_page: CodePage,
    max_chars: usize,
    out: &mut String,
) -> bool {
    out.clear();
    match value {
        PropValue::Unicode(text) => {
            out.extend(
                text.chars_lossy()
                    .take_while(|ch| *ch != '\0')
                    .take(max_chars),
            );
            true
        }
        PropValue::String8(bytes) => {
            let bytes = bytes.get(..max_chars).unwrap_or(bytes);
            if let Ok(text) = std::str::from_utf8(bytes)
                && text.is_ascii()
            {
                out.push_str(text);
            } else {
                let mut units = Vec::with_capacity(bytes.len().saturating_mul(2));
                code_page.widen(bytes, max_chars, &mut units);
                out.extend(
                    char::decode_utf16(
                        units
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|unit| u16::from_le_bytes(*unit)),
                    )
                    .map(|ch| ch.unwrap_or(char::REPLACEMENT_CHARACTER)),
                );
            }
            true
        }
        _ => false,
    }
}
