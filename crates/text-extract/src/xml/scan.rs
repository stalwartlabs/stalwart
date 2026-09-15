/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Handler, MAX_ENTITY, MAX_NAME, MAX_TAG_CARRY, Tag,
    attr::{resolve_entity, split_entity},
};
use crate::output::Output;
use memchr::{memchr2, memmem};

const CDATA_OPEN: &[u8] = b"<![CDATA[";
const COMMENT_OPEN: &[u8] = b"<!--";

#[derive(Clone, Copy)]
enum State {
    Text,
    Comment,
    CData,
    Instruction,
    Declaration { depth: u32, quote: u8 },
    LongTag(LongTag),
}

#[derive(Clone, Copy)]
struct LongTag {
    closing: bool,
    quote: u8,
    previous: u8,
    name: [u8; MAX_NAME],
    name_len: usize,
}

impl LongTag {
    fn new(closing: bool, name: &[u8]) -> Self {
        let mut stored = [0u8; MAX_NAME];
        let name_len = match stored.get_mut(..name.len()) {
            Some(slot) => {
                slot.copy_from_slice(name);
                name.len()
            }
            None => 0,
        };
        LongTag {
            closing,
            quote: 0,
            previous: 0,
            name: stored,
            name_len,
        }
    }

    fn name(&self) -> &[u8] {
        self.name.get(..self.name_len).unwrap_or_default()
    }
}

pub(crate) struct Scanner {
    state: State,
}

impl Default for Scanner {
    fn default() -> Self {
        Scanner { state: State::Text }
    }
}

impl Scanner {
    pub(crate) fn feed<H: Handler>(
        &mut self,
        input: &[u8],
        last: bool,
        handler: &mut H,
        out: &mut Output<'_>,
    ) -> usize {
        let mut rest = input;
        while !out.is_full() && !handler.aborted() {
            match self.state {
                State::Text => match if rest.first() == Some(&b'<') {
                    Some(0)
                } else {
                    memchr2(b'<', b'&', rest)
                } {
                    None => {
                        let keep = if last { 0 } else { incomplete_utf8_tail(rest) };
                        let (text, tail) = rest.split_at(rest.len() - keep);
                        if !text.is_empty() {
                            handler.text(text, out);
                        }
                        return input.len() - tail.len();
                    }
                    Some(at) => {
                        let (text, markup) = rest.split_at(at);
                        if !text.is_empty() {
                            handler.text(text, out);
                        }
                        let step = if markup.first() == Some(&b'&') {
                            entity(markup, last, handler, out)
                        } else {
                            self.markup(markup, last, handler, out)
                        };
                        match step {
                            Some(consumed) => rest = markup.get(consumed..).unwrap_or_default(),
                            None => return input.len() - markup.len(),
                        }
                    }
                },
                State::Comment => match memmem::find(rest, b"-->") {
                    Some(at) => {
                        self.state = State::Text;
                        rest = rest.get(at + 3..).unwrap_or_default();
                    }
                    None => return input.len() - if last { 0 } else { rest.len().min(2) },
                },
                State::Instruction => match memmem::find(rest, b"?>") {
                    Some(at) => {
                        self.state = State::Text;
                        rest = rest.get(at + 2..).unwrap_or_default();
                    }
                    None => return input.len() - if last { 0 } else { rest.len().min(1) },
                },
                State::CData => match memmem::find(rest, b"]]>") {
                    Some(at) => {
                        let (text, tail) = rest.split_at(at);
                        if !text.is_empty() {
                            handler.text(text, out);
                        }
                        self.state = State::Text;
                        rest = tail.get(3..).unwrap_or_default();
                    }
                    None => {
                        let mut end = if last {
                            rest.len()
                        } else {
                            rest.len().saturating_sub(2)
                        };
                        if !last {
                            end -= incomplete_utf8_tail(rest.get(..end).unwrap_or_default());
                        }
                        let (text, tail) = rest.split_at(end);
                        if !text.is_empty() {
                            handler.text(text, out);
                        }
                        return input.len() - tail.len();
                    }
                },
                State::Declaration { depth, quote } => match skip_declaration(rest, depth, quote) {
                    Ok(consumed) => {
                        self.state = State::Text;
                        rest = rest.get(consumed..).unwrap_or_default();
                    }
                    Err((depth, quote)) => {
                        self.state = State::Declaration { depth, quote };
                        return input.len();
                    }
                },
                State::LongTag(mut long) => match find_tag_end(rest, &mut long.quote) {
                    Some(at) => {
                        let self_closing = match at.checked_sub(1) {
                            Some(before) => rest.get(before) == Some(&b'/'),
                            None => long.previous == b'/',
                        };
                        let name = long.name();
                        if long.closing {
                            handler.end(name, out);
                        } else {
                            handler.start(&Tag { name, attrs: None }, out);
                            if self_closing {
                                handler.end(name, out);
                            }
                        }
                        self.state = State::Text;
                        rest = rest.get(at + 1..).unwrap_or_default();
                    }
                    None => {
                        if let Some(&previous) = rest.last() {
                            long.previous = previous;
                        }
                        self.state = State::LongTag(long);
                        return input.len();
                    }
                },
            }
        }
        input.len()
    }

    fn markup<H: Handler>(
        &mut self,
        rest: &[u8],
        last: bool,
        handler: &mut H,
        out: &mut Output<'_>,
    ) -> Option<usize> {
        match rest {
            [b'<', b'/', tail @ ..] => match tail.iter().position(|&byte| byte == b'>') {
                Some(gt) => {
                    handler.end(tail.get(..gt).unwrap_or_default().trim_ascii_end(), out);
                    Some(gt + 3)
                }
                None if !last && rest.len() < MAX_TAG_CARRY => None,
                None => {
                    let name_len = tail
                        .iter()
                        .position(|byte| byte.is_ascii_whitespace())
                        .unwrap_or(tail.len());
                    self.state = State::LongTag(LongTag::new(
                        true,
                        tail.get(..name_len).unwrap_or_default(),
                    ));
                    Some(rest.len())
                }
            },
            [b'<', b'!', b'-', b'-', ..] => {
                self.state = State::Comment;
                Some(COMMENT_OPEN.len())
            }
            [b'<', b'!', ..] if rest.starts_with(CDATA_OPEN) => {
                self.state = State::CData;
                Some(CDATA_OPEN.len())
            }
            [b'<', b'!', ..]
                if !last && (CDATA_OPEN.starts_with(rest) || COMMENT_OPEN.starts_with(rest)) =>
            {
                None
            }
            [b'<', b'!', ..] => {
                self.state = State::Declaration { depth: 0, quote: 0 };
                Some(2)
            }
            [b'<', b'?', ..] => {
                self.state = State::Instruction;
                Some(2)
            }
            [b'<', first, ..] if is_name_start(*first) => self.start_tag(rest, last, handler, out),
            [b'<'] if !last => None,
            _ => {
                handler.text(b"<", out);
                Some(1)
            }
        }
    }

    fn start_tag<H: Handler>(
        &mut self,
        rest: &[u8],
        last: bool,
        handler: &mut H,
        out: &mut Output<'_>,
    ) -> Option<usize> {
        let body = rest.get(1..).unwrap_or_default();
        let name_len = body
            .iter()
            .position(|&byte| byte.is_ascii_whitespace() || byte == b'/' || byte == b'>');
        let mut quote = 0;
        let end = name_len.and_then(|name_len| {
            find_tag_end(body.get(name_len..)?, &mut quote).map(|at| name_len + at)
        });
        match (name_len, end) {
            (Some(name_len), Some(at)) => {
                let (name, _) = body.split_at(name_len);
                let self_closing = at > name_len && body.get(at - 1) == Some(&b'/');
                let attrs_end = if self_closing { at - 1 } else { at };
                handler.start(
                    &Tag {
                        name,
                        attrs: body.get(name_len..attrs_end.max(name_len)),
                    },
                    out,
                );
                if self_closing {
                    handler.end(name, out);
                }
                Some(at + 2)
            }
            _ if !last && rest.len() < MAX_TAG_CARRY => None,
            (name_len, _) => {
                let name_len = name_len.unwrap_or(body.len());
                let mut long = LongTag::new(false, body.get(..name_len).unwrap_or_default());
                long.quote = quote;
                long.previous = rest.last().copied().unwrap_or(0);
                self.state = State::LongTag(long);
                Some(rest.len())
            }
        }
    }
}

fn entity<H: Handler>(
    rest: &[u8],
    last: bool,
    handler: &mut H,
    out: &mut Output<'_>,
) -> Option<usize> {
    match split_entity(rest) {
        Some((body, after)) => {
            match resolve_entity(body) {
                Some(ch) => {
                    let mut encoded = [0u8; 4];
                    handler.text(ch.encode_utf8(&mut encoded).as_bytes(), out);
                }
                None if body.first() == Some(&b'#') => (),
                None if !body.is_empty() && body.iter().all(u8::is_ascii_alphanumeric) => {
                    handler.entity(body, out);
                }
                None => {
                    handler.text(b"&", out);
                    return Some(1);
                }
            }
            Some(rest.len() - after.len())
        }
        None if !last && rest.len() < MAX_ENTITY => None,
        None => {
            handler.text(b"&", out);
            Some(1)
        }
    }
}

fn find_tag_end(bytes: &[u8], quote: &mut u8) -> Option<usize> {
    let mut cursor = 0;
    loop {
        let tail = bytes.get(cursor..)?;
        if *quote != 0 {
            cursor += tail.iter().position(|&byte| byte == *quote)? + 1;
            *quote = 0;
            continue;
        }
        let at = tail
            .iter()
            .position(|&byte| byte == b'>' || byte == b'"' || byte == b'\'')?;
        match tail.get(at) {
            Some(b'>') => return Some(cursor + at),
            Some(&found) => {
                *quote = found;
                cursor += at + 1;
            }
            None => return None,
        }
    }
}

fn skip_declaration(bytes: &[u8], mut depth: u32, mut quote: u8) -> Result<usize, (u32, u8)> {
    for (at, &byte) in bytes.iter().enumerate() {
        if quote != 0 {
            if byte == quote {
                quote = 0;
            }
            continue;
        }
        match byte {
            b'"' | b'\'' => quote = byte,
            b'[' => depth = depth.saturating_add(1),
            b']' => depth = depth.saturating_sub(1),
            b'>' if depth == 0 => return Ok(at + 1),
            _ => {}
        }
    }
    Err((depth, quote))
}

#[inline]
fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b':' || byte >= 0x80
}

pub(crate) fn incomplete_utf8_tail(bytes: &[u8]) -> usize {
    for (back, &byte) in bytes.iter().rev().take(3).enumerate() {
        if byte & 0xC0 != 0x80 {
            let needed = match byte {
                0xF0.. => 4,
                0xE0.. => 3,
                0xC0.. => 2,
                _ => 1,
            };
            return if needed > back + 1 { back + 1 } else { 0 };
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::local_name;

    #[derive(Default)]
    struct Recorder {
        events: String,
    }

    impl Handler for Recorder {
        fn start(&mut self, tag: &Tag<'_>, _out: &mut Output<'_>) {
            self.events.push('<');
            self.events
                .push_str(&String::from_utf8_lossy(local_name(tag.name)));
            if let Some(attrs) = tag.attrs.map(<[u8]>::trim_ascii)
                && !attrs.is_empty()
            {
                self.events.push('[');
                self.events.push_str(&String::from_utf8_lossy(attrs));
                self.events.push(']');
            }
            self.events.push('>');
        }

        fn end(&mut self, name: &[u8], _out: &mut Output<'_>) {
            self.events.push_str("</");
            self.events
                .push_str(&String::from_utf8_lossy(local_name(name)));
            self.events.push('>');
        }

        fn text(&mut self, text: &[u8], _out: &mut Output<'_>) {
            self.events.push_str(&String::from_utf8_lossy(text));
        }

        fn entity(&mut self, name: &[u8], _out: &mut Output<'_>) {
            self.events.push('{');
            self.events.push_str(&String::from_utf8_lossy(name));
            self.events.push('}');
        }
    }

    fn scan_chunked(input: &[u8], chunk: usize) -> String {
        let mut recorder = Recorder::default();
        let mut sink = String::new();
        let mut out = Output::new(&mut sink, usize::MAX);
        let mut scanner = Scanner::default();
        let mut window: Vec<u8> = Vec::new();
        let mut chunks = input.chunks(chunk).peekable();
        while let Some(piece) = chunks.next() {
            window.extend_from_slice(piece);
            let last = chunks.peek().is_none();
            let consumed = scanner.feed(&window, last, &mut recorder, &mut out);
            window.drain(..consumed);
        }
        recorder.events
    }

    #[test]
    fn events_are_identical_for_any_chunking() {
        let input = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"]>\">]><w:p a=\"x>y\" b='1/'><w:t>caf\u{e9} &amp; &#x4E2D;&nbsp;&bad</w:t><!-- c > d --><br/><![CDATA[<raw>\u{e9}]]></w:p>< x";
        let expected =
            "<p[a=\"x>y\" b='1/']><t>caf\u{e9} & \u{4e2d}{nbsp}&bad</t><br></br><raw>\u{e9}</p>< x";
        for chunk in [1, 2, 3, 5, 7, 64, 4096] {
            assert_eq!(
                scan_chunked(input.as_bytes(), chunk),
                expected,
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn long_tags_are_reported_without_attributes() {
        let mut input = b"<a:t ".to_vec();
        input.extend(std::iter::repeat_n(b'x', MAX_TAG_CARRY * 2));
        input.extend_from_slice(b" q=\"/>\"/>tail</a:t>");
        assert_eq!(scan_chunked(&input, 4096), "<t></t>tail</t>");
    }

    #[test]
    fn utf8_tail_detection() {
        assert_eq!(incomplete_utf8_tail(b"abc"), 0);
        assert_eq!(incomplete_utf8_tail(b"ab\xc3"), 1);
        assert_eq!(incomplete_utf8_tail(b"a\xe4\xb8"), 2);
        assert_eq!(incomplete_utf8_tail(b"a\xe4\xb8\xad"), 0);
        assert_eq!(incomplete_utf8_tail(b"\xf0\x9f\x98"), 3);
    }
}
