/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::base64::{Base64, LineEnding, STANDARD};

use crate::mime::Sink;

pub(crate) const MIME_LINE_BYTES: usize = 57;
pub(crate) const ARMOR: Base64 = STANDARD.wrapped(64, LineEnding::CrLf);
pub(crate) const MIME: Base64 = STANDARD.wrapped(76, LineEnding::CrLf);
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_INVALID: u8 = 0xFF;
const DECODE_GROUPS: usize = 512;

static B64_DECODE: [u8; 256] = {
    let mut table = [B64_INVALID; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

pub(crate) fn decoded_base64_len(input: &[u8]) -> usize {
    let data = memchr::memchr(b'=', input).map_or(input, |end| input.split_at(end).0);
    let sextets = data
        .iter()
        .filter(|b| B64_DECODE[usize::from(**b)] != B64_INVALID)
        .count();
    sextets / 4 * 3 + [0, 0, 1, 2][sextets % 4]
}

pub(crate) fn decode_base64<S: Sink>(input: &[u8], out: &mut S) {
    let mut groups = [[0u8; 3]; DECODE_GROUPS];
    let mut filled = 0;
    let mut acc = 0u32;
    let mut count = 0;
    for byte in input {
        if *byte == b'=' {
            break;
        }
        let value = B64_DECODE[usize::from(*byte)];
        if value == B64_INVALID {
            continue;
        }
        acc = (acc << 6) | u32::from(value);
        count += 1;
        if count == 4 {
            let [_, a, b, c] = acc.to_be_bytes();
            if let Some(slot) = groups.get_mut(filled) {
                *slot = [a, b, c];
                filled += 1;
            }
            if filled == DECODE_GROUPS {
                out.put(groups.as_flattened());
                filled = 0;
            }
            acc = 0;
            count = 0;
        }
    }
    out.put(groups.get(..filled).unwrap_or_default().as_flattened());
    match count {
        2 => out.put(&[(acc >> 4) as u8]),
        3 => out.put(&[(acc >> 10) as u8, (acc >> 2) as u8]),
        _ => {}
    }
}
