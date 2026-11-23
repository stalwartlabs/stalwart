/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    END, HEADER, OPAQUE, STR_I, SWITCH_PAGE, TAG_CONTENT,
    segments::{Part, Segments},
};
use crate::{
    common::base64::base64_encode_into,
    eas::tokens::{ProtocolVersion, Tag},
};
use bytes::Bytes;
use smallvec::SmallVec;

pub const SHARED_MIN_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NulPolicy {
    Strip,
    Reject,
}

#[derive(Debug)]
pub struct Encoder {
    buf: Vec<u8>,
    page: u8,
    pending: Option<usize>,
    inline_start: usize,
    parts: SmallVec<[Part; 4]>,
    version: ProtocolVersion,
    rejected: bool,
}

impl Encoder {
    pub fn new(version: ProtocolVersion) -> Self {
        Self::with_buffer(Vec::new(), version)
    }

    pub fn with_buffer(mut buf: Vec<u8>, version: ProtocolVersion) -> Self {
        buf.clear();
        buf.extend_from_slice(&HEADER);
        Encoder {
            buf,
            page: 0,
            pending: None,
            inline_start: 0,
            parts: SmallVec::new(),
            version,
            rejected: false,
        }
    }

    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    pub fn allows(&self, tag: Tag) -> bool {
        tag.info().versions.contains(self.version)
    }

    pub fn rejected(&self) -> bool {
        self.rejected
    }

    fn mark_content(&mut self) {
        if let Some(byte) = self.pending.take().and_then(|pos| self.buf.get_mut(pos)) {
            *byte |= TAG_CONTENT;
        }
    }

    pub fn start(&mut self, tag: Tag) -> &mut Self {
        debug_assert!(
            tag.info().versions.contains(self.version),
            "{tag} is not valid in {}",
            self.version
        );
        self.mark_content();
        if tag.page() != self.page {
            self.page = tag.page();
            self.buf.extend_from_slice(&[SWITCH_PAGE, self.page]);
        }
        self.pending = Some(self.buf.len());
        self.buf.push(tag.token());
        self
    }

    pub fn end(&mut self) -> &mut Self {
        if self.pending.take().is_none() {
            self.buf.push(END);
        }
        self
    }

    pub fn empty(&mut self, tag: Tag) -> &mut Self {
        self.start(tag).end()
    }

    pub fn text(&mut self, tag: Tag, value: &[u8]) -> &mut Self {
        self.start(tag);
        if !value.is_empty() {
            self.mark_content();
            self.buf.push(STR_I);
            push_without_nul(&mut self.buf, value);
            self.buf.push(0);
        }
        self.end()
    }

    fn text_without_nul(&mut self, tag: Tag, value: &[u8]) -> &mut Self {
        self.start(tag);
        if !value.is_empty() {
            self.mark_content();
            self.buf.push(STR_I);
            self.buf.extend_from_slice(value);
            self.buf.push(0);
        }
        self.end()
    }

    pub fn text_str(&mut self, tag: Tag, value: &str) -> &mut Self {
        self.text(tag, value.as_bytes())
    }

    pub fn text_u64(&mut self, tag: Tag, value: u64) -> &mut Self {
        let mut digits = [0u8; 20];
        let len = format_u64(value, &mut digits);
        self.text(tag, digits.get(..len).unwrap_or_default())
    }

    pub fn text_i64(&mut self, tag: Tag, value: i64) -> &mut Self {
        if value < 0 {
            let mut digits = [0u8; 21];
            let (sign, rest) = digits.split_at_mut(1);
            sign.fill(b'-');
            let len = format_u64(value.unsigned_abs(), rest).saturating_add(1);
            self.text(tag, digits.get(..len).unwrap_or_default())
        } else {
            self.text_u64(tag, value.unsigned_abs())
        }
    }

    pub fn text_bool(&mut self, tag: Tag, value: bool) -> &mut Self {
        self.text(tag, if value { b"1" } else { b"0" })
    }

    pub fn text_with(&mut self, tag: Tag, write: impl FnOnce(&mut Vec<u8>)) -> &mut Self {
        self.start(tag);
        self.mark_content();
        self.buf.push(STR_I);
        let start = self.buf.len();
        write(&mut self.buf);
        if self.buf.len() == start {
            self.buf.pop();
            self.pending = self.buf.len().checked_sub(1);
            if let Some(byte) = self.pending.and_then(|pos| self.buf.get_mut(pos)) {
                *byte &= !TAG_CONTENT;
            }
        } else {
            self.buf.push(0);
        }
        self.end()
    }

    pub fn opaque(&mut self, tag: Tag, value: &[u8]) -> &mut Self {
        self.start(tag);
        if !value.is_empty() && self.opaque_header(value.len()) {
            self.buf.extend_from_slice(value);
        }
        self.end()
    }

    pub fn opaque_shared(&mut self, tag: Tag, value: Bytes) -> &mut Self {
        if value.len() < SHARED_MIN_LEN {
            return self.opaque(tag, &value);
        }
        self.start(tag);
        if self.opaque_header(value.len()) {
            self.push_shared(value);
        }
        self.end()
    }

    pub fn text_shared(&mut self, tag: Tag, value: Bytes, nul: NulPolicy) -> &mut Self {
        let has_nul = memchr::memchr(0, &value).is_some();
        if has_nul && nul == NulPolicy::Reject {
            self.rejected = true;
            return self.empty(tag);
        }
        if value.len() < SHARED_MIN_LEN {
            return if has_nul {
                self.text(tag, &value)
            } else {
                self.text_without_nul(tag, &value)
            };
        }
        self.start(tag);
        self.mark_content();
        self.buf.push(STR_I);
        if has_nul {
            let mut from = 0;
            for at in memchr::memchr_iter(0, &value) {
                if at > from {
                    self.push_shared(value.slice(from..at));
                }
                from = at.saturating_add(1);
            }
            if from < value.len() {
                self.push_shared(value.slice(from..));
            }
        } else {
            self.push_shared(value);
        }
        self.buf.push(0);
        self.end()
    }

    pub fn text_base64(&mut self, tag: Tag, value: &[u8]) -> &mut Self {
        self.start(tag);
        if !value.is_empty() {
            self.mark_content();
            self.buf.push(STR_I);
            base64_encode_into(value, &mut self.buf);
            self.buf.push(0);
        }
        self.end()
    }

    fn opaque_header(&mut self, len: usize) -> bool {
        let Ok(len) = u32::try_from(len) else {
            self.rejected = true;
            return false;
        };
        self.mark_content();
        self.buf.push(OPAQUE);
        write_mb_u_int32(&mut self.buf, len);
        true
    }

    fn push_shared(&mut self, value: Bytes) {
        if self.buf.len() > self.inline_start {
            self.parts
                .push(Part::Inline(self.inline_start..self.buf.len()));
        }
        self.inline_start = self.buf.len();
        self.parts.push(Part::Shared(value));
    }

    pub fn finish(mut self) -> Segments {
        if self.buf.len() > self.inline_start || self.parts.is_empty() {
            self.parts
                .push(Part::Inline(self.inline_start..self.buf.len()));
        }
        Segments::new(self.buf, self.parts)
    }
}

pub(crate) fn write_mb_u_int32(out: &mut Vec<u8>, value: u32) {
    let mut bytes = [0u8; 5];
    let mut start = 4;
    let mut rest = value;
    let mut continuation = 0;
    for (index, slot) in bytes.iter_mut().enumerate().rev() {
        *slot = u8::try_from(rest & 0x7F).unwrap_or(0) | continuation;
        continuation = 0x80;
        start = index;
        rest >>= 7;
        if rest == 0 {
            break;
        }
    }
    out.extend_from_slice(bytes.get(start..).unwrap_or_default());
}

fn push_without_nul(out: &mut Vec<u8>, value: &[u8]) {
    let mut from = 0;
    for at in memchr::memchr_iter(0, value) {
        out.extend_from_slice(value.get(from..at).unwrap_or_default());
        from = at.saturating_add(1);
    }
    out.extend_from_slice(value.get(from..).unwrap_or_default());
}

pub(crate) fn format_u64(mut value: u64, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    for slot in tmp.iter_mut() {
        *slot = b'0'.wrapping_add(u8::try_from(value % 10).unwrap_or(0));
        len = len.saturating_add(1);
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for (dst, src) in out
        .iter_mut()
        .zip(tmp.get(..len).unwrap_or_default().iter().rev())
    {
        *dst = *src;
    }
    len.min(out.len())
}
