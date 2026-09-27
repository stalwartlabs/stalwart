/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::memchr;

use super::output::Output;

const FIRST_DIGIT: u8 = b'!';
const LAST_DIGIT: u8 = b'u';
const ZERO_GROUP: u8 = b'z';
const END: u8 = b'~';
const GROUP: usize = 5;
const BASE: u32 = 85;

pub(super) fn decode(input: &[u8], output: &mut Output<'_>) -> bool {
    let input = input.trim_ascii_start();
    let input = input.strip_prefix(b"<~").unwrap_or(input);
    let body = memchr(END, input)
        .and_then(|end| input.get(..end))
        .unwrap_or(input);
    output.reserve(body.len() / GROUP * 4 + 4);
    let mut corrupt = false;
    let mut value = 0u32;
    let mut count = 0usize;
    for &byte in body {
        match byte {
            FIRST_DIGIT..=LAST_DIGIT => {
                value = value
                    .wrapping_mul(BASE)
                    .wrapping_add(u32::from(byte - FIRST_DIGIT));
                count += 1;
                if count == GROUP {
                    if !output.push(&value.to_be_bytes()) {
                        return corrupt;
                    }
                    value = 0;
                    count = 0;
                }
            }
            ZERO_GROUP if count == 0 => {
                if !output.push(&[0; 4]) {
                    return corrupt;
                }
            }
            b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ' | b'\x08' | b'\x7f' => {}
            _ => corrupt = true,
        }
    }
    match count {
        0 => {}
        1 => corrupt = true,
        _ => {
            let padded = (count..GROUP).fold(value, |value, _| {
                value
                    .wrapping_mul(BASE)
                    .wrapping_add(u32::from(LAST_DIGIT - FIRST_DIGIT))
            });
            if let Some(bytes) = padded.to_be_bytes().get(..count - 1) {
                output.push(bytes);
            }
        }
    }
    corrupt
}
