/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const WORD: usize = 8;
const LSB: u64 = 0x0101_0101_0101_0101;
const MSB: u64 = 0x8080_8080_8080_8080;
const HEX: &[u8; 16] = b"0123456789abcdef";
const HEX_ESCAPE: u8 = b'x';

static ESCAPES: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut byte = 0;
    while byte < 0x20 {
        table[byte] = HEX_ESCAPE;
        byte += 1;
    }
    table[0x7f] = HEX_ESCAPE;
    table[b'\r' as usize] = b'r';
    table[b'\n' as usize] = b'n';
    table[b'\t' as usize] = b't';
    table[b'\\' as usize] = b'\\';
    table[b'"' as usize] = b'"';
    table
};

#[inline(always)]
const fn has_zero_byte(word: u64) -> u64 {
    word.wrapping_sub(LSB) & !word & MSB
}

#[inline(always)]
const fn may_need_escape(word: u64) -> bool {
    let below_space = word.wrapping_sub(LSB * 0x20) & !word & MSB;
    (below_space
        | has_zero_byte(word ^ (LSB * b'"' as u64))
        | has_zero_byte(word ^ (LSB * b'\\' as u64))
        | has_zero_byte(word ^ (LSB * 0x7f)))
        != 0
}

pub fn escape_into(out: &mut Vec<u8>, input: &[u8]) {
    let mut clean_start = 0;
    let mut offset = 0;
    let (chunks, remainder) = input.as_chunks::<WORD>();

    for chunk in chunks {
        if may_need_escape(u64::from_le_bytes(*chunk)) {
            clean_start = escape_bytes(out, input, chunk, offset, clean_start);
        }
        offset += WORD;
    }

    clean_start = escape_bytes(out, input, remainder, offset, clean_start);
    out.extend_from_slice(&input[clean_start..]);
}

#[inline(always)]
fn escape_bytes(
    out: &mut Vec<u8>,
    input: &[u8],
    bytes: &[u8],
    offset: usize,
    mut clean_start: usize,
) -> usize {
    for (pos, &byte) in bytes.iter().enumerate() {
        let escape = ESCAPES[byte as usize];
        if escape != 0 {
            let pos = offset + pos;
            out.extend_from_slice(&input[clean_start..pos]);
            if escape == HEX_ESCAPE {
                out.extend_from_slice(&[
                    b'\\',
                    b'x',
                    HEX[(byte >> 4) as usize],
                    HEX[(byte & 0x0f) as usize],
                ]);
            } else {
                out.extend_from_slice(&[b'\\', escape]);
            }
            clean_start = pos + 1;
        }
    }
    clean_start
}

#[cfg(test)]
mod tests {
    use super::escape_into;

    fn reference(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for &byte in input {
            match byte {
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'"' => out.extend_from_slice(b"\\\""),
                0..0x20 | 0x7f => out.extend_from_slice(format!("\\x{byte:02x}").as_bytes()),
                _ => out.push(byte),
            }
        }
        out
    }

    fn check(input: &[u8]) {
        let mut out = Vec::new();
        escape_into(&mut out, input);
        assert_eq!(out, reference(input), "input: {input:?}");
    }

    #[test]
    fn escape_matches_reference() {
        let all_bytes = (0..=255u8).collect::<Vec<_>>();
        check(&all_bytes);
        for len in 0..all_bytes.len() {
            check(&all_bytes[..len]);
            check(&all_bytes[len..]);
        }

        for input in [
            &b""[..],
            b"plain ascii text that needs no escaping at all",
            b"a\", spanId = 999, accountId = 1, x = \"b",
            b"line one\r\nline two\r\n",
            b"\x1b[31mred\x1b[0m",
            b"tab\there\\and\x7fdel\x00nul",
            "grüße, jürgen ❤ \"quoted\"".as_bytes(),
            b"\x21\x21\x21\x21\x21\x21\x21\x1f\x20\x20\x20\x20\x20\x20\x20\x20",
            b"\x80\x81\xa0\xff\x22\x5c\x7e\x7f\x5b\x5d\x23\x21\x1f\x20\x60\x61",
        ] {
            check(input);
            for split in 0..input.len() {
                check(&input[split..]);
            }
        }

        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for len in [7usize, 8, 9, 63, 64, 65, 511, 4096] {
            for _ in 0..64 {
                let input = (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state as u8
                    })
                    .collect::<Vec<_>>();
                check(&input);
            }
        }
    }
}
