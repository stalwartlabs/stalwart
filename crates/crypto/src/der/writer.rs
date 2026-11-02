/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::tag;
use crate::mime::Sink;

pub(crate) const fn length_len(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len < 0x100 {
        2
    } else if len < 0x1_0000 {
        3
    } else if len < 0x100_0000 {
        4
    } else {
        5
    }
}

pub(crate) const fn tlv_len(content_len: usize) -> usize {
    1 + length_len(content_len) + content_len
}

pub(crate) fn write_header<S: Sink + ?Sized>(out: &mut S, tag: u8, len: usize) {
    match length_len(len) {
        1 => out.put(&[tag, len as u8]),
        n => {
            let bytes = (len as u64).to_be_bytes();
            out.put(&[tag, 0x80 | (n - 1) as u8]);
            out.put(&bytes[bytes.len() - (n - 1)..]);
        }
    }
}

pub(crate) fn write_tlv<S: Sink + ?Sized>(out: &mut S, tag: u8, content: &[u8]) {
    write_header(out, tag, content.len());
    out.put(content);
}

fn strip_unsigned(bytes: &[u8]) -> (&[u8], bool) {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let stripped = &bytes[first..];
    match stripped.first() {
        Some(b) => (stripped, *b & 0x80 != 0),
        None => (&[], true),
    }
}

pub(crate) fn unsigned_integer_content_len(bytes: &[u8]) -> usize {
    let (stripped, pad) = strip_unsigned(bytes);
    stripped.len() + usize::from(pad)
}

pub(crate) fn unsigned_integer_len(bytes: &[u8]) -> usize {
    tlv_len(unsigned_integer_content_len(bytes))
}

pub(crate) fn write_unsigned_integer<S: Sink + ?Sized>(out: &mut S, bytes: &[u8]) {
    let (stripped, pad) = strip_unsigned(bytes);
    write_header(out, tag::INTEGER, stripped.len() + usize::from(pad));
    if pad {
        out.put(&[0]);
    }
    out.put(stripped);
}

pub(crate) const fn small_integer_len(value: u32) -> usize {
    tlv_len(small_integer_content_len(value))
}

const fn small_integer_content_len(value: u32) -> usize {
    let bits = 32 - value.leading_zeros() as usize;
    bits / 8 + 1
}

pub(crate) fn write_small_integer<S: Sink + ?Sized>(out: &mut S, value: u32) {
    let len = small_integer_content_len(value);
    let bytes = value.to_be_bytes();
    out.put(&[tag::INTEGER, len as u8]);
    if len > bytes.len() {
        out.put(&[0]);
        out.put(&bytes);
    } else {
        out.put(&bytes[bytes.len() - len..]);
    }
}

pub(crate) const fn bit_string_len(content_len: usize) -> usize {
    tlv_len(content_len + 1)
}

pub(crate) fn write_bit_string_header<S: Sink + ?Sized>(out: &mut S, content_len: usize) {
    write_header(out, tag::BIT_STRING, content_len + 1);
    out.put(&[0]);
}

pub(crate) fn rsa_public_key_len(n: &[u8], e: &[u8]) -> usize {
    tlv_len(unsigned_integer_len(n) + unsigned_integer_len(e))
}

pub(crate) fn write_rsa_public_key<S: Sink + ?Sized>(out: &mut S, n: &[u8], e: &[u8]) {
    write_header(
        out,
        tag::SEQUENCE,
        unsigned_integer_len(n) + unsigned_integer_len(e),
    );
    write_unsigned_integer(out, n);
    write_unsigned_integer(out, e);
}

pub(crate) struct StackBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
    overflow: bool,
}

impl<const N: usize> StackBuf<N> {
    pub(crate) const fn new() -> Self {
        StackBuf {
            buf: [0u8; N],
            len: 0,
            overflow: false,
        }
    }

    pub(crate) fn as_slice(&self) -> Option<&[u8]> {
        (!self.overflow).then(|| &self.buf[..self.len])
    }
}

impl<const N: usize> Sink for StackBuf<N> {
    fn put(&mut self, data: &[u8]) {
        let end = self.len + data.len();
        match self.buf.get_mut(self.len..end) {
            Some(slot) => {
                slot.copy_from_slice(data);
                self.len = end;
            }
            None => self.overflow = true,
        }
    }
}
