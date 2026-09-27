/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const MIN_AMORTIZED_CAPACITY: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Separator {
    None,
    Space,
    Newline,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Mark {
    len: usize,
    pending: Separator,
}

pub(crate) struct Output<'a> {
    buf: &'a mut String,
    start: usize,
    limit: usize,
    pending: Separator,
    full: bool,
}

impl<'a> Output<'a> {
    pub(crate) fn new(buf: &'a mut String, max_bytes: usize) -> Self {
        let start = buf.len();
        Output {
            limit: start.saturating_add(max_bytes),
            buf,
            start,
            pending: Separator::None,
            full: false,
        }
    }

    #[inline]
    pub(crate) fn is_full(&self) -> bool {
        self.full
    }

    #[inline]
    pub(crate) fn separator(&mut self, separator: Separator) {
        self.pending = self.pending.max(separator);
    }

    pub(crate) fn push_str(&mut self, text: &str) {
        if self.full || text.is_empty() {
            return;
        }
        if text.bytes().all(|byte| byte.is_ascii_whitespace()) {
            self.separator(Separator::Space);
            return;
        }
        if self.pending != Separator::None {
            let separator = std::mem::replace(&mut self.pending, Separator::None);
            if self.buf.len() > self.start {
                if self.buf.len() >= self.limit {
                    self.full = true;
                    return;
                }
                self.reserve(text.len() + 1);
                self.buf.push(if separator == Separator::Newline {
                    '\n'
                } else {
                    ' '
                });
            }
        }
        let room = self.limit.saturating_sub(self.buf.len());
        if text.len() <= room {
            self.reserve(text.len());
            self.buf.push_str(text);
        } else {
            let text = text
                .get(..text.floor_char_boundary(room))
                .unwrap_or_default();
            self.reserve(text.len());
            self.buf.push_str(text);
            self.full = true;
        }
    }

    #[inline]
    fn reserve(&mut self, additional: usize) {
        if self.buf.capacity() - self.buf.len() < additional {
            self.grow(additional);
        }
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, additional: usize) {
        let capacity = self.buf.capacity();
        let room = self.limit.saturating_sub(self.buf.len());
        let additional = additional.min(room);
        if capacity.saturating_mul(2).max(MIN_AMORTIZED_CAPACITY) <= self.limit {
            self.buf.reserve(additional);
        } else {
            self.buf.reserve_exact(additional.max(capacity).min(room));
        }
    }

    pub(crate) fn push_utf8(&mut self, bytes: &[u8]) {
        if let Ok(text) = std::str::from_utf8(bytes) {
            self.push_str(text);
            return;
        }
        for chunk in bytes.utf8_chunks() {
            self.push_str(chunk.valid());
            if !chunk.invalid().is_empty() {
                self.push_char(char::REPLACEMENT_CHARACTER);
            }
        }
    }

    pub(crate) fn push_char(&mut self, ch: char) {
        let mut encoded = [0u8; 4];
        self.push_str(ch.encode_utf8(&mut encoded));
    }

    pub(crate) fn mark(&self) -> Mark {
        Mark {
            len: self.buf.len(),
            pending: self.pending,
        }
    }

    pub(crate) fn cut(&mut self, mark: Mark, into: &mut String, max_bytes: usize) {
        let start = mark.len.max(self.start);
        if let Some(tail) = self.buf.get(start..).map(str::trim)
            && !tail.is_empty()
        {
            let room = max_bytes.saturating_sub(into.len() + 1);
            if !into.is_empty() && room > 0 {
                into.push(' ');
            }
            into.push_str(
                tail.get(..tail.floor_char_boundary(room))
                    .unwrap_or_default(),
            );
        }
        self.buf.truncate(start);
        self.pending = mark.pending;
        self.full = self.full && self.buf.len() >= self.limit;
    }

    pub(crate) fn since(&self, mark: Mark) -> &str {
        self.buf.get(mark.len.max(self.start)..).unwrap_or_default()
    }

    pub(crate) fn written(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_collapse_and_never_lead() {
        let mut buf = String::new();
        let mut out = Output::new(&mut buf, 64);
        out.separator(Separator::Newline);
        out.push_str("a");
        out.separator(Separator::Space);
        out.separator(Separator::Newline);
        out.push_str("   ");
        out.push_str("b");
        out.separator(Separator::Space);
        assert_eq!(buf, "a\nb");
    }

    #[test]
    fn limit_respects_char_boundaries() {
        let mut buf = String::from("x");
        let mut out = Output::new(&mut buf, 4);
        out.push_str("ab\u{e9}\u{e9}");
        assert!(out.is_full());
        assert_eq!(out.written(), 4);
        assert_eq!(buf, "xab\u{e9}");
    }

    #[test]
    fn capacity_never_exceeds_limit() {
        let mut buf = String::from("prefix");
        let mut out = Output::new(&mut buf, 1000);
        for _ in 0..500 {
            out.push_str("abc");
            out.separator(Separator::Space);
        }
        assert!(out.is_full());
        assert_eq!(buf.len(), 1006);
        assert!(buf.capacity() <= 1006, "{}", buf.capacity());

        let mut buf = String::with_capacity(500);
        buf.push_str(&"x".repeat(500));
        let mut out = Output::new(&mut buf, 500);
        out.push_str(&"y".repeat(600));
        assert!(out.is_full());
        assert_eq!(buf.len(), 1000);
        assert!(buf.capacity() <= 1000, "{}", buf.capacity());

        let mut buf = String::new();
        let mut out = Output::new(&mut buf, 3);
        out.push_str("ab");
        out.push_str("cd");
        assert_eq!(buf, "abc");
        assert!(buf.capacity() <= 3, "{}", buf.capacity());

        let mut buf = String::new();
        let mut out = Output::new(&mut buf, usize::MAX);
        for _ in 0..1000 {
            out.push_str("abcdefgh");
        }
        assert_eq!(buf.len(), 8000);
        assert!(buf.capacity() < 16_000);
    }

    #[test]
    fn cut_moves_text_since_mark() {
        let mut buf = String::from("keep ");
        let mut note = String::new();
        let mut out = Output::new(&mut buf, 8);
        out.push_str("host");
        let mark = out.mark();
        out.separator(Separator::Space);
        out.push_str("note text");
        assert!(out.is_full());
        out.cut(mark, &mut note, 64);
        assert!(!out.is_full());
        out.push_str("word");
        assert_eq!(note, "not");
        assert_eq!(buf, "keep hostword");
    }

    #[test]
    fn invalid_utf8_is_replaced() {
        let mut buf = String::new();
        let mut out = Output::new(&mut buf, 64);
        out.push_utf8(b"a\xffb\xc3");
        assert_eq!(buf, "a\u{fffd}b\u{fffd}");
    }
}
