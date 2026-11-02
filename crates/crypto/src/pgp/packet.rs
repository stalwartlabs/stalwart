/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::error::KeyError;

pub(crate) const TAG_PKESK: u8 = 1;
pub(crate) const TAG_SIGNATURE: u8 = 2;
pub(crate) const TAG_SECRET_KEY: u8 = 5;
pub(crate) const TAG_PUBLIC_KEY: u8 = 6;
pub(crate) const TAG_SECRET_SUBKEY: u8 = 7;
pub(crate) const TAG_MARKER: u8 = 10;
pub(crate) const TAG_LITERAL: u8 = 11;
pub(crate) const TAG_TRUST: u8 = 12;
pub(crate) const TAG_USER_ID: u8 = 13;
pub(crate) const TAG_PUBLIC_SUBKEY: u8 = 14;
pub(crate) const TAG_USER_ATTRIBUTE: u8 = 17;
pub(crate) const TAG_SEIPD: u8 = 18;
pub(crate) const TAG_PADDING: u8 = 21;

const NEW_FORMAT: u8 = 0x40;
const PACKET_BIT: u8 = 0x80;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Packet<'x> {
    pub tag: u8,
    pub body: &'x [u8],
}

pub(crate) struct PacketReader<'x> {
    data: &'x [u8],
}

impl<'x> PacketReader<'x> {
    pub(crate) fn new(data: &'x [u8]) -> Self {
        PacketReader { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn read_raw(&mut self) -> Result<(Packet<'x>, &'x [u8]), KeyError> {
        let start = self.data;
        let packet = self.read()?;
        let (raw, _) = start
            .split_at_checked(start.len() - self.data.len())
            .ok_or(KeyError::MalformedPacket)?;
        Ok((packet, raw))
    }

    fn read(&mut self) -> Result<Packet<'x>, KeyError> {
        let [header, rest @ ..] = self.data else {
            return Err(KeyError::MalformedPacket);
        };
        if header & PACKET_BIT == 0 {
            return Err(KeyError::MalformedPacket);
        }
        let (tag, len, rest) = if header & NEW_FORMAT != 0 {
            let tag = header & 0x3F;
            match rest {
                [a, rest @ ..] if *a < 192 => (tag, usize::from(*a), rest),
                [a, b, rest @ ..] if *a < 224 => (
                    tag,
                    ((usize::from(*a) - 192) << 8) + usize::from(*b) + 192,
                    rest,
                ),
                [255, a, b, c, d, rest @ ..] => {
                    (tag, u32::from_be_bytes([*a, *b, *c, *d]) as usize, rest)
                }
                _ => return Err(KeyError::MalformedPacket),
            }
        } else {
            let tag = (header >> 2) & 0x0F;
            match (header & 0x03, rest) {
                (0, [a, rest @ ..]) => (tag, usize::from(*a), rest),
                (1, [a, b, rest @ ..]) => (tag, usize::from(u16::from_be_bytes([*a, *b])), rest),
                (2, [a, b, c, d, rest @ ..]) => {
                    (tag, u32::from_be_bytes([*a, *b, *c, *d]) as usize, rest)
                }
                _ => return Err(KeyError::MalformedPacket),
            }
        };
        let (body, rest) = rest
            .split_at_checked(len)
            .ok_or(KeyError::MalformedPacket)?;
        self.data = rest;
        Ok(Packet { tag, body })
    }
}

impl<'x> Iterator for PacketReader<'x> {
    type Item = Result<Packet<'x>, KeyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            None
        } else {
            let result = self.read();
            if result.is_err() {
                self.data = &[];
            }
            Some(result)
        }
    }
}

pub(crate) const fn header_len(body_len: usize) -> usize {
    if body_len < 192 {
        2
    } else if body_len < 8384 {
        3
    } else {
        6
    }
}

pub(crate) fn header_bytes(tag: u8, body_len: usize) -> ([u8; 6], usize) {
    let mut out = [0u8; 6];
    out[0] = PACKET_BIT | NEW_FORMAT | tag;
    if body_len < 192 {
        out[1] = body_len as u8;
    } else if body_len < 8384 {
        let v = body_len - 192;
        out[1] = ((v >> 8) + 192) as u8;
        out[2] = v as u8;
    } else {
        out[1] = 255;
        out[2..6].copy_from_slice(&(body_len as u32).to_be_bytes());
    }
    (out, header_len(body_len))
}

pub(crate) fn write_header(out: &mut Vec<u8>, tag: u8, body_len: usize) {
    let (bytes, len) = header_bytes(tag, body_len);
    out.extend_from_slice(&bytes[..len]);
}

pub(crate) struct Fields<'x> {
    data: &'x [u8],
}

impl<'x> Fields<'x> {
    pub(crate) fn new(data: &'x [u8]) -> Self {
        Fields { data }
    }

    pub(crate) fn remaining(&self) -> &'x [u8] {
        self.data
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn u8(&mut self) -> Result<u8, KeyError> {
        let (first, rest) = self.data.split_first().ok_or(KeyError::MalformedPacket)?;
        self.data = rest;
        Ok(*first)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, KeyError> {
        self.array::<2>().map(u16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, KeyError> {
        self.array::<4>().map(u32::from_be_bytes)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], KeyError> {
        let (head, rest) = self
            .data
            .split_first_chunk::<N>()
            .ok_or(KeyError::MalformedPacket)?;
        self.data = rest;
        Ok(*head)
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'x [u8], KeyError> {
        let (head, rest) = self
            .data
            .split_at_checked(len)
            .ok_or(KeyError::MalformedPacket)?;
        self.data = rest;
        Ok(head)
    }

    pub(crate) fn mpi(&mut self) -> Result<&'x [u8], KeyError> {
        let bits = usize::from(self.u16()?);
        let bytes = self.bytes(bits.div_ceil(8))?;
        Ok(bytes)
    }

    pub(crate) fn short_bytes(&mut self) -> Result<&'x [u8], KeyError> {
        let len = usize::from(self.u8()?);
        self.bytes(len)
    }
}

pub(crate) fn strip_leading_zeros(value: &[u8]) -> &[u8] {
    let first = value.iter().position(|b| *b != 0).unwrap_or(value.len());
    &value[first..]
}

pub(crate) fn mpi_header(value: &[u8]) -> ([u8; 2], &[u8]) {
    let value = strip_leading_zeros(value);
    let bits = match value.first() {
        Some(first) => value.len() * 8 - first.leading_zeros() as usize,
        None => 0,
    };
    ((bits as u16).to_be_bytes(), value)
}
