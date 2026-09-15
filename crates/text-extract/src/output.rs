/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Separator {
    None,
    Space,
    Newline,
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
                self.buf.push(if separator == Separator::Newline {
                    '\n'
                } else {
                    ' '
                });
            }
        }
        let room = self.limit.saturating_sub(self.buf.len());
        if text.len() <= room {
            self.buf.push_str(text);
        } else {
            self.buf.push_str(
                text.get(..text.floor_char_boundary(room))
                    .unwrap_or_default(),
            );
            self.full = true;
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
    fn invalid_utf8_is_replaced() {
        let mut buf = String::new();
        let mut out = Output::new(&mut buf, 64);
        out.push_utf8(b"a\xffb\xc3");
        assert_eq!(buf, "a\u{fffd}b\u{fffd}");
    }
}
