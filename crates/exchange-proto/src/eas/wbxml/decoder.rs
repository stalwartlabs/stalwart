/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CHARSET_UTF8, END, LITERAL, OPAQUE, STR_I, SWITCH_PAGE, TAG_ATTRIBUTES, TAG_CONTENT, TAG_ID,
    WBXML_VERSION,
};
use crate::eas::tokens::Tag;
use smallvec::SmallVec;
use std::borrow::Cow;

const MB_UINT32_MAX_BYTES: usize = 5;
const SHORT_UTF8: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WbxmlLimits {
    pub max_depth: u8,
}

impl WbxmlLimits {
    pub const DEFAULT: Self = WbxmlLimits { max_depth: 64 };
}

impl Default for WbxmlLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    Start { tag: Tag, has_content: bool },
    Text(&'a [u8]),
    Opaque(&'a [u8]),
    End,
    Eof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Header,
    Truncated { offset: usize },
    BadGlobal { offset: usize, byte: u8 },
    MbUint { offset: usize },
    DepthExceeded,
    UnbalancedEnd { offset: usize },
    Nul { offset: usize },
    Utf8 { offset: usize },
    UnexpectedEvent { offset: usize },
    InvalidValue { offset: usize },
}

const _: () = assert!(size_of::<DecodeError>() <= 24);

impl DecodeError {
    pub fn offset(&self) -> Option<usize> {
        match self {
            DecodeError::Header | DecodeError::DepthExceeded => None,
            DecodeError::Truncated { offset }
            | DecodeError::BadGlobal { offset, .. }
            | DecodeError::MbUint { offset }
            | DecodeError::UnbalancedEnd { offset }
            | DecodeError::Nul { offset }
            | DecodeError::Utf8 { offset }
            | DecodeError::UnexpectedEvent { offset }
            | DecodeError::InvalidValue { offset } => Some(*offset),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    page: u8,
    stack: SmallVec<[Tag; 16]>,
    pending_end: bool,
    root_seen: bool,
    fragment: bool,
    max_depth: u8,
}

impl<'a> Decoder<'a> {
    pub fn new(body: &'a [u8], limits: &WbxmlLimits) -> Result<Self, DecodeError> {
        let mut decoder = Decoder {
            input: body,
            pos: 0,
            page: 0,
            stack: SmallVec::new(),
            pending_end: false,
            root_seen: false,
            fragment: false,
            max_depth: limits.max_depth,
        };
        decoder.header()?;
        Ok(decoder)
    }

    pub(crate) fn fragment(body: &'a [u8], page: u8, limits: &WbxmlLimits) -> Self {
        Decoder {
            input: body,
            pos: 0,
            page,
            stack: SmallVec::new(),
            pending_end: false,
            root_seen: false,
            fragment: true,
            max_depth: limits.max_depth,
        }
    }

    fn header(&mut self) -> Result<(), DecodeError> {
        if self.byte().map_err(|_| DecodeError::Header)? != WBXML_VERSION {
            return Err(DecodeError::Header);
        }
        if self.mb_u_int32().map_err(|_| DecodeError::Header)? == 0 {
            self.mb_u_int32().map_err(|_| DecodeError::Header)?;
        }
        if self.mb_u_int32().map_err(|_| DecodeError::Header)? != CHARSET_UTF8
            || self.mb_u_int32().map_err(|_| DecodeError::Header)? != 0
        {
            return Err(DecodeError::Header);
        }
        Ok(())
    }

    pub fn depth(&self) -> u8 {
        let depth = self
            .stack
            .len()
            .saturating_add(usize::from(self.pending_end));
        u8::try_from(depth).unwrap_or(u8::MAX)
    }

    pub fn offset(&self) -> usize {
        self.pos
    }

    pub fn page(&self) -> u8 {
        self.page
    }

    pub fn input(&self) -> &'a [u8] {
        self.input
    }

    pub fn current(&self) -> Option<Tag> {
        self.stack.last().copied()
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let byte = *self
            .input
            .get(self.pos)
            .ok_or(DecodeError::Truncated { offset: self.pos })?;
        self.pos = self.pos.saturating_add(1);
        Ok(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn mb_u_int32(&mut self) -> Result<u32, DecodeError> {
        let start = self.pos;
        let mut value: u32 = 0;
        for _ in 0..MB_UINT32_MAX_BYTES {
            let byte = self.byte()?;
            if value > u32::MAX >> 7 {
                return Err(DecodeError::MbUint { offset: start });
            }
            value = (value << 7) | u32::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(DecodeError::MbUint { offset: start })
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(DecodeError::Truncated { offset: self.pos })?;
        let slice = self
            .input
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated { offset: self.pos })?;
        self.pos = end;
        Ok(slice)
    }

    fn inline_string(&mut self) -> Result<&'a [u8], DecodeError> {
        let rest = self
            .input
            .get(self.pos..)
            .ok_or(DecodeError::Truncated { offset: self.pos })?;
        let len = memchr::memchr(0, rest).ok_or(DecodeError::Truncated {
            offset: self.input.len(),
        })?;
        let text = self.take(len)?;
        self.pos = self.pos.saturating_add(1);
        Ok(text)
    }

    #[allow(clippy::should_implement_trait)]
    #[inline(always)]
    pub fn next(&mut self) -> Result<Event<'a>, DecodeError> {
        if self.pending_end {
            self.pending_end = false;
            return Ok(Event::End);
        }
        loop {
            let offset = self.pos;
            let Some(byte) = self.peek() else {
                return if self.stack.is_empty() && (self.root_seen || self.fragment) {
                    Ok(Event::Eof)
                } else {
                    Err(DecodeError::Truncated { offset })
                };
            };
            self.pos = self.pos.saturating_add(1);
            match byte {
                SWITCH_PAGE => {
                    self.page = self.byte()?;
                }
                END => {
                    return if self.stack.pop().is_some() {
                        Ok(Event::End)
                    } else {
                        Err(DecodeError::UnbalancedEnd { offset })
                    };
                }
                STR_I => {
                    self.expect_open(offset)?;
                    return self.inline_string().map(Event::Text);
                }
                OPAQUE => {
                    self.expect_open(offset)?;
                    let len = usize::try_from(self.mb_u_int32()?)
                        .map_err(|_| DecodeError::Truncated { offset })?;
                    return self.take(len).map(Event::Opaque);
                }
                _ if byte & TAG_ID <= LITERAL || byte & TAG_ATTRIBUTES != 0 => {
                    return Err(DecodeError::BadGlobal { offset, byte });
                }
                _ => {
                    if self.stack.is_empty() && self.root_seen && !self.fragment {
                        return Err(DecodeError::UnexpectedEvent { offset });
                    }
                    self.root_seen = true;
                    if self.stack.len() >= usize::from(self.max_depth) {
                        return Err(DecodeError::DepthExceeded);
                    }
                    let tag = Tag::new(self.page, byte & TAG_ID);
                    let has_content = byte & TAG_CONTENT != 0 && self.peek() != Some(END);
                    if has_content {
                        self.stack.push(tag);
                    } else {
                        if byte & TAG_CONTENT != 0 {
                            self.pos = self.pos.saturating_add(1);
                        }
                        self.pending_end = true;
                    }
                    return Ok(Event::Start { tag, has_content });
                }
            }
        }
    }

    fn expect_open(&self, offset: usize) -> Result<(), DecodeError> {
        if self.stack.is_empty() {
            Err(DecodeError::UnexpectedEvent { offset })
        } else {
            Ok(())
        }
    }

    fn target_depth(&self) -> Result<u8, DecodeError> {
        self.depth()
            .checked_sub(1)
            .ok_or(DecodeError::UnexpectedEvent { offset: self.pos })
    }

    pub fn skip_element(&mut self) -> Result<(), DecodeError> {
        let target = self.target_depth()?;
        loop {
            match self.next()? {
                Event::End if self.depth() == target => return Ok(()),
                Event::Eof => return Err(DecodeError::Truncated { offset: self.pos }),
                _ => {}
            }
        }
    }

    pub(crate) fn element_bytes(&mut self) -> Result<(u8, &'a [u8]), DecodeError> {
        let page = self.page;
        if self.pending_end {
            self.pending_end = false;
            return Ok((page, &[]));
        }
        let start = self.pos;
        let target = self.target_depth()?;
        let end = loop {
            let before = self.pos;
            match self.next()? {
                Event::End if self.depth() == target => break before,
                Event::Eof => return Err(DecodeError::Truncated { offset: self.pos }),
                _ => {}
            }
        };
        let content = self
            .input
            .get(start..end)
            .ok_or(DecodeError::Truncated { offset: start })?;
        Ok((page, content))
    }

    fn value(&mut self, allow_opaque: bool) -> Result<Cow<'a, [u8]>, DecodeError> {
        let target = self.target_depth()?;
        let mut value: Option<Cow<'a, [u8]>> = None;
        loop {
            let offset = self.pos;
            match self.next()? {
                Event::End if self.depth() == target => {
                    return Ok(value.unwrap_or(Cow::Borrowed(&[])));
                }
                Event::Text(run) => append_run(&mut value, run),
                Event::Opaque(run) if allow_opaque => append_run(&mut value, run),
                _ => return Err(DecodeError::UnexpectedEvent { offset }),
            }
        }
    }

    pub fn text(&mut self) -> Result<Cow<'a, [u8]>, DecodeError> {
        self.value(false)
    }

    pub fn bytes(&mut self) -> Result<Cow<'a, [u8]>, DecodeError> {
        self.value(true)
    }

    pub fn str(&mut self) -> Result<Cow<'a, str>, DecodeError> {
        let offset = self.pos;
        match self.bytes()? {
            Cow::Borrowed(bytes) => validate_utf8(bytes, offset).map(Cow::Borrowed),
            Cow::Owned(bytes) => {
                if memchr::memchr(0, &bytes).is_some() {
                    return Err(DecodeError::Nul { offset });
                }
                String::from_utf8(bytes)
                    .map(Cow::Owned)
                    .map_err(|_| DecodeError::Utf8 { offset })
            }
        }
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let offset = self.pos;
        parse_u32(&self.text()?).ok_or(DecodeError::InvalidValue { offset })
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let offset = self.pos;
        parse_u64(&self.text()?).ok_or(DecodeError::InvalidValue { offset })
    }

    pub fn i32(&mut self) -> Result<i32, DecodeError> {
        let offset = self.pos;
        let text = self.text()?;
        let (negative, digits) = match text.split_first() {
            Some((b'-', rest)) => (true, rest),
            _ => (false, text.as_ref()),
        };
        let value = i64::try_from(parse_u64(digits).ok_or(DecodeError::InvalidValue { offset })?)
            .map_err(|_| DecodeError::InvalidValue { offset })?;
        i32::try_from(if negative {
            value.wrapping_neg()
        } else {
            value
        })
        .map_err(|_| DecodeError::InvalidValue { offset })
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        let offset = self.pos;
        u8::try_from(self.u32()?).map_err(|_| DecodeError::InvalidValue { offset })
    }

    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        let offset = self.pos;
        match self.text()?.as_ref() {
            b"1" => Ok(true),
            b"0" => Ok(false),
            _ => Err(DecodeError::InvalidValue { offset }),
        }
    }
}

fn append_run<'a>(value: &mut Option<Cow<'a, [u8]>>, run: &'a [u8]) {
    match value {
        None => *value = Some(Cow::Borrowed(run)),
        Some(existing) => existing.to_mut().extend_from_slice(run),
    }
}

fn validate_utf8(bytes: &[u8], offset: usize) -> Result<&str, DecodeError> {
    if memchr::memchr(0, bytes).is_some() {
        return Err(DecodeError::Nul { offset });
    }
    if bytes.len() <= SHORT_UTF8 {
        std::str::from_utf8(bytes).map_err(|_| DecodeError::Utf8 { offset })
    } else {
        simdutf8::basic::from_utf8(bytes).map_err(|_| DecodeError::Utf8 { offset })
    }
}

pub fn parse_u64(text: &[u8]) -> Option<u64> {
    if text.is_empty() || text.len() > 20 {
        return None;
    }
    text.iter().try_fold(0u64, |acc, &b| {
        if b.is_ascii_digit() {
            acc.checked_mul(10)?
                .checked_add(u64::from(b.wrapping_sub(b'0')))
        } else {
            None
        }
    })
}

pub fn parse_u32(text: &[u8]) -> Option<u32> {
    parse_u64(text).and_then(|v| u32::try_from(v).ok())
}
