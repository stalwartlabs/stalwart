/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::memchr;

use super::output::Output;

const END: u8 = b'>';

pub(super) fn decode(input: &[u8], output: &mut Output<'_>) -> bool {
    let body = memchr(END, input)
        .and_then(|end| input.get(..end))
        .unwrap_or(input);
    output.reserve(body.len() / 2 + 1);
    let mut corrupt = false;
    let mut high: Option<u8> = None;
    for &byte in body {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ' => continue,
            _ => {
                corrupt = true;
                continue;
            }
        };
        match high.take() {
            Some(high) => {
                if !output.push_byte(high << 4 | nibble) {
                    return corrupt;
                }
            }
            None => high = Some(nibble),
        }
    }
    if let Some(high) = high {
        output.push_byte(high << 4);
    }
    corrupt
}
