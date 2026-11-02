/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::base64::STANDARD;
use mail_parser::{Encoding, HeaderName, Message, MessagePart, PartKind};

use super::{CRLF, Counter, Sink};
use crate::backend::base64::{MIME, MIME_LINE_BYTES, decode_base64, decoded_base64_len};

pub(crate) const MAX_LEGACY_PARTS: usize = 4;
pub(crate) const LEGACY_PARAM: &[u8] = b"; hp-legacy-display=1";
const MAX_DEPTH: usize = 8;
const SUBJECT_PREFIX: &[u8] = b"Subject: ";
const HTML_DIV: &[u8] = b"<div class=\"header-protection-legacy-display\">";
const HTML_PRE: &[u8] = b"<pre>Subject: ";
const HTML_CLOSE: &[u8] = b"</pre></div>";
const QP_SOFT_BREAK: &[u8] = b"=\r\n";
const QP_MAX_COLUMN: usize = 75;
const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
const BODY_TAG: &[u8; 4] = b"body";
const B64_ENCODED_LINE: usize = MIME_LINE_BYTES / 3 * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Markup {
    Plain,
    Html,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transfer {
    SevenBit,
    EightBit,
    QuotedPrintable,
    Base64,
}

#[derive(Debug, Clone, Copy)]
enum Subject<'x> {
    Decoded(&'x [u8]),
    Raw(&'x [u8]),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LegacyPart<'x> {
    pub content_type: Option<(usize, usize)>,
    pub body: (usize, usize),
    pub insert_at: usize,
    markup: Markup,
    transfer: Transfer,
    subject: Subject<'x>,
    element_len: usize,
    decoded_len: usize,
    encoded_body: &'x [u8],
}

pub(crate) struct LegacyParts<'x> {
    pub root: bool,
    pub parts: [Option<LegacyPart<'x>>; MAX_LEGACY_PARTS],
}

impl<'x> LegacyParts<'x> {
    pub(crate) const fn none() -> Self {
        LegacyParts {
            root: false,
            parts: [None; MAX_LEGACY_PARTS],
        }
    }

    pub(crate) fn collect(message: &'x Message<'x>) -> Self {
        let mut legacy = LegacyParts::none();
        let Some(subject) = message
            .root_part()
            .headers()
            .iter()
            .find(|h| h.name() == HeaderName::Subject)
        else {
            return legacy;
        };
        let decoded = message.subject().unwrap_or_default().as_bytes();
        let raw = subject.raw_value().trim_ascii();
        let mut found = Found {
            legacy: &mut legacy,
            count: 0,
            min_offset: message.root_part().offset_body() as usize,
            root: message.root_part().id(),
            decoded,
            raw,
        };
        found.visit(message.root_part(), 0);
        legacy
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &LegacyPart<'x>> {
        self.parts.iter().flatten()
    }
}

struct Found<'a, 'x> {
    legacy: &'a mut LegacyParts<'x>,
    count: usize,
    min_offset: usize,
    root: mail_parser::PartId,
    decoded: &'x [u8],
    raw: &'x [u8],
}

impl<'x> Found<'_, 'x> {
    fn visit(&mut self, part: MessagePart<'x>, depth: usize) {
        if depth > MAX_DEPTH || self.count >= MAX_LEGACY_PARTS {
            return;
        }
        match part.kind() {
            PartKind::Multipart => {
                let alternative = part
                    .content_type()
                    .and_then(|ct| ct.subtype())
                    .is_some_and(|sub| sub.eq_ignore_ascii_case("alternative"));
                if alternative {
                    for child in part.children() {
                        self.visit(child, depth + 1);
                    }
                } else if let Some(first) = part.children().next() {
                    self.visit(first, depth + 1);
                }
            }
            PartKind::Text | PartKind::Html => {
                if let Some(legacy) = self.leaf(&part) {
                    self.min_offset = legacy.body.1;
                    if let Some(slot) = self.legacy.parts.get_mut(self.count) {
                        *slot = Some(legacy);
                        self.count += 1;
                    }
                }
            }
            _ => {}
        }
    }

    fn leaf(&mut self, part: &MessagePart<'x>) -> Option<LegacyPart<'x>> {
        let ct = part.content_type();
        let markup = match part.kind() {
            PartKind::Html => Markup::Html,
            _ if ct.as_ref().is_none_or(|ct| {
                ct.subtype()
                    .is_some_and(|s| s.eq_ignore_ascii_case("plain"))
            }) =>
            {
                Markup::Plain
            }
            _ => return None,
        };
        if part
            .content_disposition()
            .is_some_and(|cd| cd.ctype().eq_ignore_ascii_case("attachment"))
        {
            return None;
        }
        let transfer = match part.encoding() {
            Encoding::QuotedPrintable => Transfer::QuotedPrintable,
            Encoding::Base64 => Transfer::Base64,
            Encoding::None => match part.content_transfer_encoding() {
                None => Transfer::SevenBit,
                Some(cte) => *hashify::map_ignore_case!(
                    cte.trim().as_bytes(),
                    Transfer,
                    "7bit" => Transfer::SevenBit,
                    "8bit" => Transfer::EightBit,
                    "binary" => Transfer::EightBit,
                )?,
            },
        };
        let utf8 = ct
            .as_ref()
            .and_then(|ct| ct.attribute("charset"))
            .is_some_and(|cs| hashify::set_ignore_case!(cs.trim().as_bytes(), "utf-8", "utf8"));
        let subject = if self.decoded.is_ascii() || (utf8 && transfer != Transfer::SevenBit) {
            Subject::Decoded(self.decoded)
        } else if self.raw.is_ascii() {
            Subject::Raw(self.raw)
        } else {
            return None;
        };
        let is_root = part.id() == self.root;
        let content_type = if is_root {
            None
        } else {
            let field = part
                .headers()
                .iter()
                .find(|h| h.name() == HeaderName::ContentType)?;
            Some((field.offset_field() as usize, field.offset_end() as usize))
        };
        let body = (part.offset_body() as usize, part.offset_end() as usize);
        let encoded_body = part.raw_body();
        let header_start = content_type.map_or(body.0, |(start, _)| start);
        if header_start < self.min_offset
            || content_type.is_some_and(|(_, end)| end > body.0)
            || body.1 < body.0
            || encoded_body.len() != body.1 - body.0
        {
            return None;
        }
        let (decoded_len, insert_at) = match (transfer, markup) {
            (Transfer::Base64, Markup::Plain) => (decoded_base64_len(encoded_body), 0),
            (Transfer::Base64, Markup::Html) => {
                let mut finder = BodyTagFinder::default();
                decode_base64(encoded_body, &mut finder);
                (decoded_base64_len(encoded_body), finder.found.unwrap_or(0))
            }
            (_, Markup::Plain) => (0, 0),
            (_, Markup::Html) => {
                let mut finder = BodyTagFinder::default();
                finder.put(encoded_body);
                (0, finder.found.unwrap_or(0))
            }
        };
        let mut legacy = LegacyPart {
            content_type,
            body,
            insert_at,
            markup,
            transfer,
            subject,
            element_len: 0,
            decoded_len,
            encoded_body,
        };
        let mut counter = Counter::default();
        legacy.write_element(&mut counter, ElementEncoding::Raw);
        legacy.element_len = counter.0;
        if is_root {
            self.legacy.root = true;
        }
        Some(legacy)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ElementEncoding {
    Raw,
    QuotedPrintable,
}

struct ElementWriter<'s, S: Sink> {
    sink: &'s mut S,
    encoding: ElementEncoding,
    column: usize,
    last_ws: bool,
}

impl<S: Sink> ElementWriter<'_, S> {
    fn text(&mut self, data: &[u8]) {
        match self.encoding {
            ElementEncoding::Raw => self.sink.put(data),
            ElementEncoding::QuotedPrintable => {
                for byte in data {
                    self.qp_byte(*byte);
                }
            }
        }
    }

    fn qp_byte(&mut self, byte: u8) {
        let literal = matches!(byte, b' ' | b'\t' | b'!'..=b'<' | b'>'..=b'~');
        let width = if literal { 1 } else { 3 };
        if self.column + width > QP_MAX_COLUMN {
            self.sink.put(QP_SOFT_BREAK);
            self.column = 0;
        }
        if literal {
            self.sink.put(&[byte]);
        } else {
            self.sink.put(&[
                b'=',
                UPPER_HEX[usize::from(byte >> 4)],
                UPPER_HEX[usize::from(byte & 0x0F)],
            ]);
        }
        self.column += width;
        self.last_ws = matches!(byte, b' ' | b'\t');
    }

    fn newline(&mut self) {
        if self.encoding == ElementEncoding::QuotedPrintable && self.last_ws {
            self.sink.put(QP_SOFT_BREAK);
        }
        self.sink.put(CRLF);
        self.column = 0;
        self.last_ws = false;
    }

    fn subject(&mut self, subject: Subject<'_>, markup: Markup) {
        let (bytes, unfold) = match subject {
            Subject::Decoded(bytes) => (bytes, false),
            Subject::Raw(bytes) => (bytes, true),
        };
        for byte in bytes {
            match (byte, markup) {
                (b'\r' | b'\n', _) if unfold => {}
                (b'&', Markup::Html) => self.text(b"&amp;"),
                (b'<', Markup::Html) => self.text(b"&lt;"),
                (b'>', Markup::Html) => self.text(b"&gt;"),
                _ => self.text(std::slice::from_ref(byte)),
            }
        }
    }
}

impl LegacyPart<'_> {
    fn write_element<S: Sink>(&self, sink: &mut S, encoding: ElementEncoding) {
        let mut writer = ElementWriter {
            sink,
            encoding,
            column: 0,
            last_ws: false,
        };
        match self.markup {
            Markup::Plain => {
                writer.text(SUBJECT_PREFIX);
                writer.subject(self.subject, self.markup);
                writer.newline();
                writer.newline();
            }
            Markup::Html => {
                writer.newline();
                writer.text(HTML_DIV);
                writer.newline();
                writer.text(HTML_PRE);
                writer.subject(self.subject, self.markup);
                writer.text(HTML_CLOSE);
                writer.newline();
            }
        }
    }

    pub(crate) fn is_base64(&self) -> bool {
        self.transfer == Transfer::Base64
    }

    pub(crate) fn write_inline<S: Sink>(&self, sink: &mut S) {
        let encoding = if self.transfer == Transfer::QuotedPrintable {
            ElementEncoding::QuotedPrintable
        } else {
            ElementEncoding::Raw
        };
        self.write_element(sink, encoding);
    }

    pub(crate) fn base64_len(&self) -> usize {
        match self.element_len + self.decoded_len {
            0 => 0,
            len => MIME.encoded_len(len) - CRLF.len(),
        }
    }

    pub(crate) fn write_base64<S: Sink>(&self, sink: &mut S) {
        let mut lines = Base64Lines {
            sink,
            line: [0u8; MIME_LINE_BYTES],
            filled: 0,
            started: false,
        };
        let mut splice = Splice {
            lines: &mut lines,
            remaining: Some(self.insert_at),
            part: self,
        };
        splice.insert_if_due();
        decode_base64(self.encoded_body, &mut splice);
        if splice.remaining.is_some() {
            self.write_element(splice.lines, ElementEncoding::Raw);
        }
        lines.finish();
    }
}

struct Splice<'a, 'p, 's, S: Sink> {
    lines: &'a mut Base64Lines<'s, S>,
    remaining: Option<usize>,
    part: &'a LegacyPart<'p>,
}

impl<S: Sink> Splice<'_, '_, '_, S> {
    fn insert_if_due(&mut self) {
        if self.remaining == Some(0) {
            self.part.write_element(self.lines, ElementEncoding::Raw);
            self.remaining = None;
        }
    }
}

impl<S: Sink> Sink for Splice<'_, '_, '_, S> {
    fn put(&mut self, data: &[u8]) {
        match self.remaining {
            Some(remaining) if remaining <= data.len() => {
                let (head, tail) = data.split_at(remaining);
                self.lines.put(head);
                self.remaining = Some(0);
                self.insert_if_due();
                self.lines.put(tail);
            }
            Some(remaining) => {
                self.lines.put(data);
                self.remaining = Some(remaining - data.len());
            }
            None => self.lines.put(data),
        }
    }
}

struct Base64Lines<'s, S: Sink> {
    sink: &'s mut S,
    line: [u8; MIME_LINE_BYTES],
    filled: usize,
    started: bool,
}

impl<S: Sink> Base64Lines<'_, S> {
    fn emit(&mut self) {
        if self.filled == 0 {
            return;
        }
        if self.started {
            self.sink.put(CRLF);
        }
        let mut encoded = [0u8; B64_ENCODED_LINE];
        let len = STANDARD
            .encode_slice(
                self.line.get(..self.filled).unwrap_or_default(),
                &mut encoded,
            )
            .unwrap_or_default();
        self.sink.put(encoded.get(..len).unwrap_or_default());
        self.started = true;
        self.filled = 0;
    }

    fn finish(&mut self) {
        self.emit();
    }
}

impl<S: Sink> Sink for Base64Lines<'_, S> {
    fn put(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let free = self.line.get_mut(self.filled..).unwrap_or_default();
            let take = free.len().min(data.len());
            let (head, tail) = data.split_at(take);
            free.get_mut(..take)
                .unwrap_or_default()
                .copy_from_slice(head);
            self.filled += take;
            data = tail;
            if self.filled == MIME_LINE_BYTES {
                self.emit();
            }
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum TagState {
    #[default]
    Scan,
    Name(usize),
    Attributes,
}

#[derive(Default)]
struct BodyTagFinder {
    offset: usize,
    state: TagState,
    found: Option<usize>,
}

impl Sink for BodyTagFinder {
    fn put(&mut self, data: &[u8]) {
        let mut rest = data;
        while self.found.is_none() {
            if self.state == TagState::Scan {
                let Some(pos) = memchr::memchr(b'<', rest) else {
                    self.offset += rest.len();
                    return;
                };
                self.offset += pos + 1;
                rest = rest.get(pos + 1..).unwrap_or_default();
                self.state = TagState::Name(0);
                continue;
            }
            let Some((byte, tail)) = rest.split_first() else {
                return;
            };
            rest = tail;
            self.offset += 1;
            self.state = match self.state {
                TagState::Name(matched) => match BODY_TAG.get(matched) {
                    Some(expected) if byte.to_ascii_lowercase() == *expected => {
                        TagState::Name(matched + 1)
                    }
                    Some(_) if *byte == b'<' => TagState::Name(0),
                    Some(_) => TagState::Scan,
                    None if *byte == b'>' => {
                        self.found = Some(self.offset);
                        TagState::Scan
                    }
                    None if byte.is_ascii_whitespace() || *byte == b'/' => TagState::Attributes,
                    None if *byte == b'<' => TagState::Name(0),
                    None => TagState::Scan,
                },
                TagState::Attributes if *byte == b'>' => {
                    self.found = Some(self.offset);
                    TagState::Scan
                }
                state => state,
            };
        }
    }
}
