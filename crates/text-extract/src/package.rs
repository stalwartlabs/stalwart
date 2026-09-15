/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    output::Output,
    xml::{
        Handler,
        attr::decode_into,
        stream::{Budget, Buffers},
    },
    zip::{Archive, Member, ReadRanges},
};
use memchr::{memmem, memrchr};
use std::ops::Range;

const MAX_ARENA: usize = 1 << 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Span {
    start: u32,
    end: u32,
}

impl Span {
    fn range(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}

#[derive(Default)]
pub(crate) struct Arena {
    bytes: Vec<u8>,
    scratch: Vec<u8>,
    decoded: Vec<u8>,
}

impl Arena {
    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
    }

    pub(crate) fn mark(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn rewind(&mut self, mark: usize) {
        self.bytes.truncate(mark);
    }

    pub(crate) fn get(&self, span: Span) -> &[u8] {
        self.bytes.get(span.range()).unwrap_or_default()
    }

    fn span_from(&mut self, start: usize) -> Option<Span> {
        if self.bytes.len() > MAX_ARENA {
            self.bytes.truncate(start);
            return None;
        }
        Some(Span {
            start: u32::try_from(start).ok()?,
            end: u32::try_from(self.bytes.len()).ok()?,
        })
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Option<Span> {
        let start = self.bytes.len();
        self.bytes
            .extend_from_slice(bytes.get(..MAX_ARENA.min(bytes.len()))?);
        self.span_from(start)
    }

    pub(crate) fn push_decoded(&mut self, raw: &[u8]) -> Option<Span> {
        let start = self.bytes.len();
        decode_into(raw.get(..MAX_ARENA.min(raw.len()))?, &mut self.bytes);
        self.span_from(start)
    }

    pub(crate) fn push_rels_path(&mut self, part: Span) -> Option<Span> {
        let start = self.bytes.len();
        let part = part.range();
        let file_len = self
            .bytes
            .get(part.clone())?
            .rsplit(|&byte| byte == b'/')
            .next()
            .map_or(0, <[u8]>::len);
        let dir_end = part.end - file_len;
        self.bytes.extend_from_within(part.start..dir_end);
        self.bytes.extend_from_slice(b"_rels/");
        self.bytes.extend_from_within(dir_end..part.end);
        self.bytes.extend_from_slice(b".rels");
        self.span_from(start)
    }

    pub(crate) fn push_resolved(&mut self, source: Span, target: &[u8]) -> Option<Span> {
        self.scratch.clear();
        decode_into(
            target.get(..MAX_ARENA.min(target.len()))?,
            &mut self.scratch,
        );
        self.decoded.clear();
        percent_decode_into(
            self.scratch
                .split(|&byte| byte == b'#')
                .next()
                .unwrap_or_default(),
            &mut self.decoded,
        );
        if self.decoded.is_empty() || memmem::find(&self.decoded, b"://").is_some() {
            return None;
        }
        let start = self.bytes.len();
        if self.decoded.first() != Some(&b'/') {
            let source = source.range();
            if let Some(mut pieces) = self
                .bytes
                .get(source.clone())
                .map(|path| path.rsplitn(2, |&byte| byte == b'/'))
                && let (Some(_), Some(dir)) = (pieces.next(), pieces.next())
            {
                let dir_end = source.start + dir.len();
                self.bytes.extend_from_within(source.start..dir_end);
            }
        }
        for segment in self.decoded.split(|&byte| byte == b'/' || byte == b'\\') {
            match segment {
                b"" | b"." => {}
                b".." => {
                    let current = self.bytes.get(start..).unwrap_or_default();
                    let keep = memrchr(b'/', current).unwrap_or(0);
                    self.bytes.truncate(start + keep);
                }
                _ => {
                    if self.bytes.len() > start {
                        self.bytes.push(b'/');
                    }
                    self.bytes.extend_from_slice(segment);
                }
            }
            if self.bytes.len() > MAX_ARENA {
                self.bytes.truncate(start);
                return None;
            }
        }
        self.span_from(start)
    }
}

fn percent_decode_into(source: &[u8], target: &mut Vec<u8>) {
    let mut pieces = source.split(|&byte| byte == b'%');
    if let Some(head) = pieces.next() {
        target.extend_from_slice(head);
    }
    for piece in pieces {
        match split_escape(piece) {
            Some((value, rest)) => {
                target.push(value);
                target.extend_from_slice(rest);
            }
            None => {
                target.push(b'%');
                target.extend_from_slice(piece);
            }
        }
    }
}

fn split_escape(piece: &[u8]) -> Option<(u8, &[u8])> {
    let [high, low, rest @ ..] = piece else {
        return None;
    };
    Some(((hex_digit(*high)? << 4) | hex_digit(*low)?, rest))
}

#[inline]
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) struct Package<'a, 's> {
    pub(crate) archive: &'s Archive<'a>,
    pub(crate) buffers: &'s mut Buffers,
    pub(crate) claimed: &'s mut ReadRanges,
    pub(crate) budget: Budget,
}

impl<'a> Package<'a, '_> {
    pub(crate) fn scan<H: Handler>(
        &mut self,
        name: &[u8],
        handler: &mut H,
        out: &mut Output<'_>,
    ) -> bool {
        if out.is_full() {
            return false;
        }
        match self.archive.find(name) {
            Some(member) => self.scan_member(&member, handler, out),
            None => false,
        }
    }

    pub(crate) fn scan_member<H: Handler>(
        &mut self,
        member: &Member<'a>,
        handler: &mut H,
        out: &mut Output<'_>,
    ) -> bool {
        if out.is_full() {
            return false;
        }
        match self.archive.read(member, self.claimed) {
            Some(data) => {
                self.buffers.scan(data, &mut self.budget, handler, out);
                true
            }
            None => false,
        }
    }

    pub(crate) fn stopped(&mut self, out: &Output<'_>) -> bool {
        if out.is_full() {
            return true;
        }
        let exhausted = self.budget.exhausted();
        self.budget.truncated |= exhausted;
        exhausted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_targets() {
        let mut arena = Arena::default();
        let source = arena.push(b"ppt/slides/slide1.xml").unwrap_or_default();
        let resolved = arena
            .push_resolved(source, b"../notesSlides/notes%20Slide1.xml#frag")
            .unwrap_or_default();
        assert_eq!(arena.get(resolved), b"ppt/notesSlides/notes Slide1.xml");
        let absolute = arena
            .push_resolved(source, b"/xl/../word/a&amp;b.xml")
            .unwrap_or_default();
        assert_eq!(arena.get(absolute), b"word/a&b.xml");
        let escape = arena
            .push_resolved(source, b"../../../../x.xml")
            .unwrap_or_default();
        assert_eq!(arena.get(escape), b"x.xml");
        assert!(
            arena
                .push_resolved(source, b"http://example.com/x")
                .is_none()
        );
        let rels = arena.push_rels_path(source).unwrap_or_default();
        assert_eq!(arena.get(rels), b"ppt/slides/_rels/slide1.xml.rels");
    }

    fn percent_decoded(input: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::new();
        percent_decode_into(input, &mut decoded);
        decoded
    }

    #[test]
    fn percent_decode_accepts_only_hex_digits() {
        assert_eq!(percent_decoded(b"%+a%-1%+0"), b"%+a%-1%+0");
        assert_eq!(percent_decoded(b"a%20b%2Fc%2f"), b"a b/c/");
        assert_eq!(percent_decoded(b"%%41%4"), b"%A%4");
        assert_eq!(percent_decoded(b"%zz%"), b"%zz%");
        assert_eq!(percent_decoded(b"plain"), b"plain");
        assert_eq!(percent_decoded(b""), b"");
    }

    #[test]
    fn stale_spans_do_not_panic() {
        let mut arena = Arena::default();
        let source = arena.push(b"word/document.xml").unwrap_or_default();
        let stale = Span { start: 8, end: 64 };
        assert!(arena.push_rels_path(stale).is_none());
        arena.rewind(0);
        assert!(arena.push_rels_path(source).is_none());
        let resolved = arena
            .push_resolved(source, b"media/image.xml")
            .unwrap_or_default();
        assert_eq!(arena.get(resolved), b"media/image.xml");
        let root = arena.push(b"document.xml").unwrap_or_default();
        let rels = arena.push_rels_path(root).unwrap_or_default();
        assert_eq!(arena.get(rels), b"_rels/document.xml.rels");
    }
}
