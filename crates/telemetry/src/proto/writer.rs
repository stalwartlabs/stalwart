/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MAX_VARINT_LEN, WIRE_I32, WIRE_I64, WIRE_LEN, WIRE_VARINT, encode_varint, varint_len};
use bytes::{BufMut, BytesMut};

pub struct ProtoWriter {
    buf: BytesMut,
}

#[must_use]
pub struct Nested {
    len_pos: usize,
    reserved: usize,
}

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum LenHint {
    Small = 1,
    Medium = 2,
    Large = 3,
}

impl ProtoWriter {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_inner(self) -> BytesMut {
        self.buf
    }

    pub fn inner_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    #[inline(always)]
    pub fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    #[inline(always)]
    pub fn varint(&mut self, value: u64) {
        if value < 0x80 {
            self.buf.put_u8(value as u8);
        } else {
            let mut out = [0u8; MAX_VARINT_LEN];
            let len = encode_varint(value, &mut out);
            self.buf.extend_from_slice(&out[..len]);
        }
    }

    #[inline(always)]
    pub fn tag(&mut self, field: u32, wire: u8) {
        self.varint(((field as u64) << 3) | wire as u64);
    }

    #[inline(always)]
    pub fn uint64(&mut self, field: u32, value: u64) {
        if value != 0 {
            self.tag(field, WIRE_VARINT);
            self.varint(value);
        }
    }

    #[inline(always)]
    pub fn int64_always(&mut self, field: u32, value: i64) {
        self.tag(field, WIRE_VARINT);
        self.varint(value as u64);
    }

    #[inline(always)]
    pub fn bool_always(&mut self, field: u32, value: bool) {
        self.tag(field, WIRE_VARINT);
        self.buf.put_u8(value as u8);
    }

    #[inline(always)]
    pub fn fixed32(&mut self, field: u32, value: u32) {
        if value != 0 {
            self.tag(field, WIRE_I32);
            self.buf.put_u32_le(value);
        }
    }

    #[inline(always)]
    pub fn fixed64(&mut self, field: u32, value: u64) {
        if value != 0 {
            self.fixed64_always(field, value);
        }
    }

    #[inline(always)]
    pub fn fixed64_always(&mut self, field: u32, value: u64) {
        self.tag(field, WIRE_I64);
        self.buf.put_u64_le(value);
    }

    #[inline(always)]
    pub fn sfixed64_always(&mut self, field: u32, value: i64) {
        self.tag(field, WIRE_I64);
        self.buf.put_i64_le(value);
    }

    #[inline(always)]
    pub fn double_always(&mut self, field: u32, value: f64) {
        self.tag(field, WIRE_I64);
        self.buf.put_f64_le(value);
    }

    #[inline(always)]
    pub fn bytes(&mut self, field: u32, value: &[u8]) {
        if !value.is_empty() {
            self.bytes_always(field, value);
        }
    }

    #[inline(always)]
    pub fn bytes_always(&mut self, field: u32, value: &[u8]) {
        self.tag(field, WIRE_LEN);
        self.varint(value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    #[inline(always)]
    pub fn len_prefix(&mut self, field: u32, len: usize) {
        self.tag(field, WIRE_LEN);
        self.varint(len as u64);
    }

    pub fn packed_fixed64(&mut self, field: u32, values: impl ExactSizeIterator<Item = u64>) {
        if values.len() != 0 {
            self.len_prefix(field, values.len() * 8);
            for value in values {
                self.buf.put_u64_le(value);
            }
        }
    }

    pub fn packed_double(&mut self, field: u32, values: impl ExactSizeIterator<Item = f64>) {
        if values.len() != 0 {
            self.len_prefix(field, values.len() * 8);
            for value in values {
                self.buf.put_f64_le(value);
            }
        }
    }

    #[inline(always)]
    pub fn begin(&mut self, field: u32, hint: LenHint) -> Nested {
        self.tag(field, WIRE_LEN);
        let len_pos = self.buf.len();
        let reserved = hint as usize;
        self.buf.put_bytes(0, reserved);
        Nested { len_pos, reserved }
    }

    #[inline(always)]
    pub fn end(&mut self, nested: Nested) {
        let Nested { len_pos, reserved } = nested;
        let body_start = len_pos + reserved;
        let body_len = self.buf.len() - body_start;
        let needed = varint_len(body_len as u64);
        if needed != reserved {
            self.shift_body(body_start, needed, reserved);
        }
        let mut value = body_len as u64;
        if let Some((last, head)) = self
            .buf
            .get_mut(len_pos..len_pos + needed)
            .and_then(|out| out.split_last_mut())
        {
            for byte in head {
                *byte = (value as u8) | 0x80;
                value >>= 7;
            }
            *last = value as u8;
        }
    }

    #[cold]
    #[inline(never)]
    fn shift_body(&mut self, body_start: usize, needed: usize, reserved: usize) {
        #[cfg(stalwart_tests)]
        BODY_SHIFTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let old_len = self.buf.len();
        if needed > reserved {
            self.buf.put_bytes(0, needed - reserved);
            self.buf
                .copy_within(body_start..old_len, body_start + needed - reserved);
        } else {
            let diff = reserved - needed;
            self.buf.copy_within(body_start..old_len, body_start - diff);
            self.buf.truncate(old_len - diff);
        }
    }
}

#[cfg(stalwart_tests)]
pub static BODY_SHIFTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
