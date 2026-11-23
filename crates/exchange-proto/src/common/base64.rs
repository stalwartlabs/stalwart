/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base64Error {
    pub offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Mode {
    Lenient,
    Canonical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base64Text<'a>(pub Cow<'a, [u8]>);

impl Base64Text<'_> {
    pub fn decoded_len_max(&self) -> usize {
        (self.0.len() / 4).saturating_add(1).saturating_mul(3)
    }

    pub fn decode_into(&self, out: &mut Vec<u8>, max: usize) -> Result<(), Base64Error> {
        base64_decode_into(&self.0, out, max, Base64Mode::Lenient)
    }
}

pub fn base64_encoded_len(n: usize) -> usize {
    n.div_ceil(3).saturating_mul(4)
}

fn symbol(index: u32) -> u8 {
    ALPHABET
        .get(usize::try_from(index & 0x3f).unwrap_or(0))
        .copied()
        .unwrap_or(PAD)
}

fn encode_block([a, b, c]: [u8; 3], out: &mut Vec<u8>) {
    let n = u32::from_be_bytes([0, a, b, c]);
    out.extend_from_slice(&[symbol(n >> 18), symbol(n >> 12), symbol(n >> 6), symbol(n)]);
}

fn encode_tail(tail: &[u8], out: &mut Vec<u8>) {
    match *tail {
        [a] => {
            let n = u32::from(a) << 16;
            out.extend_from_slice(&[symbol(n >> 18), symbol(n >> 12), PAD, PAD]);
        }
        [a, b] => {
            let n = (u32::from(a) << 16) | (u32::from(b) << 8);
            out.extend_from_slice(&[symbol(n >> 18), symbol(n >> 12), symbol(n >> 6), PAD]);
        }
        _ => {}
    }
}

pub fn base64_encode_into(src: &[u8], out: &mut Vec<u8>) {
    out.reserve(base64_encoded_len(src.len()));
    let (blocks, tail) = src.as_chunks::<3>();
    for block in blocks {
        encode_block(*block, out);
    }
    encode_tail(tail, out);
}

#[derive(Debug, Clone, Default)]
pub struct Base64Encoder {
    carry: [u8; 2],
    carry_len: u8,
}

impl Base64Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, mut src: &[u8], out: &mut Vec<u8>) {
        out.reserve(base64_encoded_len(src.len().saturating_add(2)));
        while self.carry_len > 0 {
            let Some((byte, rest)) = src.split_first() else {
                return;
            };
            src = rest;
            match (self.carry_len, self.carry) {
                (1, [a, _]) => {
                    self.carry = [a, *byte];
                    self.carry_len = 2;
                }
                (_, [a, b]) => {
                    encode_block([a, b, *byte], out);
                    self.carry_len = 0;
                }
            }
        }
        let (blocks, tail) = src.as_chunks::<3>();
        for block in blocks {
            encode_block(*block, out);
        }
        match *tail {
            [a] => {
                self.carry = [a, 0];
                self.carry_len = 1;
            }
            [a, b] => {
                self.carry = [a, b];
                self.carry_len = 2;
            }
            _ => {}
        }
    }

    pub fn finish(self, out: &mut Vec<u8>) {
        let [a, b] = self.carry;
        match self.carry_len {
            1 => encode_tail(&[a], out),
            2 => encode_tail(&[a, b], out),
            _ => {}
        }
    }
}

fn sextet(b: u8) -> Option<u32> {
    let value = match b {
        b'A'..=b'Z' => b.wrapping_sub(b'A'),
        b'a'..=b'z' => b.wrapping_sub(b'a').wrapping_add(26),
        b'0'..=b'9' => b.wrapping_sub(b'0').wrapping_add(52),
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

pub fn base64_decode_into(
    src: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
    mode: Base64Mode,
) -> Result<(), Base64Error> {
    let start = out.len();
    let limit = start.saturating_add(max_out);
    out.reserve((src.len() / 4).saturating_mul(3).min(max_out));
    let mut acc: u32 = 0;
    let mut sextets: u8 = 0;
    let mut padding: usize = 0;
    for (offset, &b) in src.iter().enumerate() {
        if b == PAD {
            padding = padding.saturating_add(1);
            continue;
        }
        if mode == Base64Mode::Lenient && b.is_ascii_whitespace() {
            continue;
        }
        let Some(value) = sextet(b) else {
            return Err(Base64Error { offset });
        };
        if padding > 0 {
            return Err(Base64Error { offset });
        }
        acc = (acc << 6) | value;
        sextets = sextets.saturating_add(1);
        if sextets == 4 {
            if out.len().saturating_add(3) > limit {
                return Err(Base64Error { offset });
            }
            let [_, a, b, c] = acc.to_be_bytes();
            out.extend_from_slice(&[a, b, c]);
            acc = 0;
            sextets = 0;
        }
    }
    let end = src.len();
    let (bytes, spare_mask, shift, expected_padding) = match sextets {
        0 => (0, 0, 0, 0),
        2 => (1, 0x0f, 12, 2),
        3 => (2, 0x03, 6, 1),
        _ => return Err(Base64Error { offset: end }),
    };
    if mode == Base64Mode::Canonical {
        if padding != expected_padding || acc & spare_mask != 0 {
            return Err(Base64Error { offset: end });
        }
    } else if padding > 2 {
        return Err(Base64Error { offset: end });
    }
    if bytes > 0 {
        if out.len().saturating_add(bytes) > limit {
            return Err(Base64Error { offset: end });
        }
        let value = acc << shift;
        let [_, a, b, _] = value.to_be_bytes();
        out.push(a);
        if bytes == 2 {
            out.push(b);
        }
    }
    Ok(())
}
