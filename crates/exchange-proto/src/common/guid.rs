/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Guid(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexCase {
    Lower,
    Upper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Braces {
    None,
    Curly,
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

impl Guid {
    pub const NIL: Guid = Guid([0; 16]);

    pub const fn from_wire(bytes: [u8; 16]) -> Self {
        Guid(bytes)
    }

    pub const fn from_fields(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        let [a0, a1, a2, a3] = data1.to_le_bytes();
        let [b0, b1] = data2.to_le_bytes();
        let [c0, c1] = data3.to_le_bytes();
        let [d0, d1, d2, d3, d4, d5, d6, d7] = data4;
        Guid([
            a0, a1, a2, a3, b0, b1, c0, c1, d0, d1, d2, d3, d4, d5, d6, d7,
        ])
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn parse_text(s: &[u8]) -> Option<Self> {
        let s = match s.strip_prefix(b"{") {
            Some(inner) => inner.strip_suffix(b"}")?,
            None => s,
        };
        let (data1, rest) = s.split_first_chunk::<8>()?;
        let rest = rest.strip_prefix(b"-")?;
        let (data2, rest) = rest.split_first_chunk::<4>()?;
        let rest = rest.strip_prefix(b"-")?;
        let (data3, rest) = rest.split_first_chunk::<4>()?;
        let rest = rest.strip_prefix(b"-")?;
        let (data4_hi, rest) = rest.split_first_chunk::<4>()?;
        let rest = rest.strip_prefix(b"-")?;
        let data4_lo: &[u8; 12] = rest.try_into().ok()?;

        let mut d1 = [0u8; 4];
        let mut d2 = [0u8; 2];
        let mut d3 = [0u8; 2];
        let mut d4 = [0u8; 8];
        let (d4_hi, d4_lo) = d4.split_at_mut(2);
        decode_hex(data1, &mut d1)?;
        decode_hex(data2, &mut d2)?;
        decode_hex(data3, &mut d3)?;
        decode_hex(data4_hi, d4_hi)?;
        decode_hex(data4_lo, d4_lo)?;
        Some(Self::from_fields(
            u32::from_be_bytes(d1),
            u16::from_be_bytes(d2),
            u16::from_be_bytes(d3),
            d4,
        ))
    }

    pub fn write_text(&self, out: &mut Vec<u8>, case: HexCase, braces: Braces) {
        let digits = match case {
            HexCase::Lower => HEX_LOWER,
            HexCase::Upper => HEX_UPPER,
        };
        let [
            a0,
            a1,
            a2,
            a3,
            b0,
            b1,
            c0,
            c1,
            d0,
            d1,
            d2,
            d3,
            d4,
            d5,
            d6,
            d7,
        ] = self.0;
        out.reserve(38);
        if braces == Braces::Curly {
            out.push(b'{');
        }
        encode_hex(&[a3, a2, a1, a0], digits, out);
        out.push(b'-');
        encode_hex(&[b1, b0], digits, out);
        out.push(b'-');
        encode_hex(&[c1, c0], digits, out);
        out.push(b'-');
        encode_hex(&[d0, d1], digits, out);
        out.push(b'-');
        encode_hex(&[d2, d3, d4, d5, d6, d7], digits, out);
        if braces == Braces::Curly {
            out.push(b'}');
        }
    }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

pub fn decode_hex_into<'b>(src: &[u8], buf: &'b mut [u8]) -> Option<&'b [u8]> {
    let dest = buf.get_mut(..src.len() / 2)?;
    decode_hex(src, dest)?;
    Some(dest)
}

fn decode_hex(src: &[u8], dest: &mut [u8]) -> Option<()> {
    let (pairs, rest) = src.as_chunks::<2>();
    if !rest.is_empty() || pairs.len() != dest.len() {
        return None;
    }
    for ([hi, lo], byte) in pairs.iter().zip(dest.iter_mut()) {
        *byte = (hex_value(*hi)? << 4) | hex_value(*lo)?;
    }
    Some(())
}

pub fn push_hex_lower(src: &[u8], out: &mut Vec<u8>) {
    encode_hex(src, HEX_LOWER, out);
}

pub fn push_hex_upper(src: &[u8], out: &mut Vec<u8>) {
    encode_hex(src, HEX_UPPER, out);
}

fn encode_hex(src: &[u8], digits: &[u8; 16], out: &mut Vec<u8>) {
    for byte in src {
        let hi = digits.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let lo = digits
            .get(usize::from(byte & 0x0f))
            .copied()
            .unwrap_or(b'0');
        out.extend_from_slice(&[hi, lo]);
    }
}
