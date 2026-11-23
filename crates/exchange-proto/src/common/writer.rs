/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::guid::Guid;

const WIDE_RUN_MAX: usize = 32;

fn put_ascii(out: &mut Vec<u8>, ascii: &[u8]) {
    let start = out.len();
    out.resize(start.saturating_add(ascii.len().saturating_mul(2)), 0);
    if let Some(tail) = out.get_mut(start..) {
        for (dst, src) in tail.as_chunks_mut::<2>().0.iter_mut().zip(ascii) {
            *dst = [*src, 0];
        }
    }
}

fn put_units(out: &mut Vec<u8>, s: &str) {
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

pub trait LeWriter {
    fn put_u8(&mut self, v: u8);
    fn put_u16(&mut self, v: u16);
    fn put_u32(&mut self, v: u32);
    fn put_u64(&mut self, v: u64);
    fn put_i32(&mut self, v: i32);
    fn put_f64(&mut self, v: f64);
    fn put_guid(&mut self, g: &Guid);
    fn put_ascii_z(&mut self, s: &[u8]);
    fn put_utf16_z(&mut self, s: &str);
    fn put_utf16(&mut self, s: &str);
    fn patch_u16(&mut self, at: usize, v: u16) -> bool;
    fn patch_u32(&mut self, at: usize, v: u32) -> bool;
}

impl LeWriter for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v);
    }

    fn put_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_le_bytes());
    }

    fn put_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_le_bytes());
    }

    fn put_u64(&mut self, v: u64) {
        self.extend_from_slice(&v.to_le_bytes());
    }

    fn put_i32(&mut self, v: i32) {
        self.extend_from_slice(&v.to_le_bytes());
    }

    fn put_f64(&mut self, v: f64) {
        self.extend_from_slice(&v.to_le_bytes());
    }

    fn put_guid(&mut self, g: &Guid) {
        self.extend_from_slice(g.as_bytes());
    }

    fn put_ascii_z(&mut self, s: &[u8]) {
        self.reserve(s.len().saturating_add(1));
        self.extend_from_slice(s);
        self.push(0);
    }

    fn put_utf16_z(&mut self, s: &str) {
        self.put_utf16(s);
        self.extend_from_slice(&[0, 0]);
    }

    fn put_utf16(&mut self, s: &str) {
        self.reserve(s.len().saturating_mul(2));
        let mut rest = s;
        while !rest.is_empty() {
            let ascii = rest
                .bytes()
                .position(|b| !b.is_ascii())
                .unwrap_or(rest.len());
            let Some((head, tail)) = rest.split_at_checked(ascii) else {
                put_units(self, rest);
                return;
            };
            put_ascii(self, head.as_bytes());
            let Some((wide, next)) = tail
                .bytes()
                .take(WIDE_RUN_MAX)
                .position(|b| b.is_ascii())
                .and_then(|at| tail.split_at_checked(at))
            else {
                put_units(self, tail);
                return;
            };
            put_units(self, wide);
            rest = next;
        }
    }

    fn patch_u16(&mut self, at: usize, v: u16) -> bool {
        match self
            .get_mut(at..)
            .and_then(|tail| tail.first_chunk_mut::<2>())
        {
            Some(dest) => {
                *dest = v.to_le_bytes();
                true
            }
            None => false,
        }
    }

    fn patch_u32(&mut self, at: usize, v: u32) -> bool {
        match self
            .get_mut(at..)
            .and_then(|tail| tail.first_chunk_mut::<4>())
        {
            Some(dest) => {
                *dest = v.to_le_bytes();
                true
            }
            None => false,
        }
    }
}
