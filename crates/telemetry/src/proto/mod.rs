/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod reader;
pub mod writer;

pub const WIRE_VARINT: u8 = 0;
pub const WIRE_I64: u8 = 1;
pub const WIRE_LEN: u8 = 2;
pub const WIRE_I32: u8 = 5;

#[inline(always)]
pub const fn varint_len(value: u64) -> usize {
    (((64 - (value | 1).leading_zeros()) * 9 + 64) / 64) as usize
}

#[inline(always)]
pub const fn tag_len(field: u32) -> usize {
    varint_len((field as u64) << 3)
}

#[inline(always)]
pub const fn len_field_len(field: u32, len: usize) -> usize {
    tag_len(field) + varint_len(len as u64) + len
}

pub const MAX_VARINT_LEN: usize = 10;

#[inline(always)]
pub fn encode_varint(mut value: u64, out: &mut [u8; MAX_VARINT_LEN]) -> usize {
    let mut len = 0;
    for byte in out.iter_mut() {
        len += 1;
        if value < 0x80 {
            *byte = value as u8;
            break;
        }
        *byte = (value as u8) | 0x80;
        value >>= 7;
    }
    len
}

pub struct SliceCursor<'x> {
    out: &'x mut [u8],
    pos: usize,
}

impl<'x> SliceCursor<'x> {
    pub fn new(out: &'x mut [u8]) -> Self {
        Self { out, pos: 0 }
    }

    #[inline(always)]
    pub fn put(&mut self, bytes: &[u8]) {
        if let Some(dst) = self.out.get_mut(self.pos..self.pos + bytes.len()) {
            dst.copy_from_slice(bytes);
        }
        self.pos += bytes.len();
    }

    #[inline(always)]
    pub fn put_varint(&mut self, value: u64) {
        let mut tmp = [0u8; MAX_VARINT_LEN];
        let len = encode_varint(value, &mut tmp);
        self.put(&tmp[..len]);
    }
}
