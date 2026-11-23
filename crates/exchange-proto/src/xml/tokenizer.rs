/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Ns, XmlError, XmlErrorKind, XmlLimits, XmlName};
use quick_xml::{
    Reader, XmlVersion,
    errors::{Error as QxError, IllFormedError, SyntaxError},
    escape::{EscapeError, ParseCharRefError},
    events::{BytesRef, BytesStart, Event, attributes::Attributes},
};
use std::borrow::Cow;

const BOM: &[u8] = b"\xEF\xBB\xBF";
const SCAN_CHUNK: usize = 64;
const CONTROL_LIMIT: u8 = 0x20;
const NONCHARACTER_LEAD: u8 = 0xEF;
const NONCHARACTER_SECOND: u8 = 0xBF;

#[derive(Debug)]
pub enum Token<'a, N: XmlName> {
    Start {
        name: N,
        attrs: Attrs<'a>,
    },
    Unknown {
        ns: Ns,
        local: &'a str,
        attrs: Attrs<'a>,
    },
    End,
    Text,
    Eof,
}

enum EntityText {
    Predefined(&'static str),
    Char(char),
}

#[derive(Debug, Clone, Copy)]
struct Binding<'a> {
    prefix: &'a str,
    ns: Ns,
    depth: u8,
}

pub struct Tokenizer<'a> {
    body: &'a str,
    reader: Reader<&'a [u8]>,
    base: u32,
    depth: u8,
    pending_end: bool,
    failed: Option<XmlError>,
    bindings: Vec<Binding<'a>>,
    limits: XmlLimits,
}

impl<'a> Tokenizer<'a> {
    pub fn new(body: &'a [u8], limits: &XmlLimits) -> Self {
        let (body, base) = match body.strip_prefix(BOM) {
            Some(rest) => (rest, BOM.len() as u32),
            None => (body, 0),
        };
        let (body, failed) = match simdutf8::basic::from_utf8(body) {
            Ok(text) => match first_illegal_char(text.as_bytes()) {
                None => (text, None),
                Some(pos) => (
                    "",
                    Some(XmlError::new(
                        XmlErrorKind::InvalidChar,
                        base.saturating_add(u32::try_from(pos).unwrap_or(u32::MAX)),
                    )),
                ),
            },
            Err(_) => {
                let valid = std::str::from_utf8(body)
                    .err()
                    .map_or(0, |err| err.valid_up_to());
                (
                    "",
                    Some(XmlError::new(
                        XmlErrorKind::Utf8,
                        base.saturating_add(u32::try_from(valid).unwrap_or(u32::MAX)),
                    )),
                )
            }
        };
        let mut reader = Reader::from_str(body);
        let config = reader.config_mut();
        config.check_end_names = true;
        config.expand_empty_elements = false;
        config.trim_text(false);
        Tokenizer {
            body,
            reader,
            base,
            depth: 0,
            pending_end: false,
            failed,
            bindings: Vec::new(),
            limits: *limits,
        }
    }

    pub fn offset(&self) -> u32 {
        self.base
            .saturating_add(u32::try_from(self.reader.buffer_position()).unwrap_or(u32::MAX))
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn error(&self, kind: XmlErrorKind) -> XmlError {
        XmlError::new(kind, self.offset())
    }

    pub fn next_token<N: XmlName>(&mut self) -> Result<Token<'a, N>, XmlError> {
        if let Some(err) = self.failed {
            return Err(err);
        }
        loop {
            if self.pending_end {
                self.pending_end = false;
                self.close();
                return Ok(Token::End);
            }
            let start = self.reader.buffer_position();
            match self.read()? {
                Event::Start(tag) => return self.open(tag, false),
                Event::Empty(tag) => return self.open(tag, true),
                Event::End(_) => {
                    self.close();
                    return Ok(Token::End);
                }
                Event::Text(text) => {
                    if text.bytes().any(|ch| !ch.is_ascii_whitespace()) {
                        return Ok(Token::Text);
                    }
                }
                Event::CData(_) => return Ok(Token::Text),
                Event::GeneralRef(entity) => {
                    self.entity(&entity)?;
                    return Ok(Token::Text);
                }
                Event::Decl(_) if start != 0 => return Err(self.fail(XmlErrorKind::Syntax)),
                Event::Decl(decl) => {
                    if let Some(encoding) = decl.encoding() {
                        let encoding = encoding.map_err(|_| self.error(XmlErrorKind::Syntax))?;
                        if !encoding.eq_ignore_ascii_case("utf-8")
                            && !encoding.eq_ignore_ascii_case("utf8")
                        {
                            return Err(self.fail(XmlErrorKind::UnsupportedEncoding));
                        }
                    }
                }
                Event::DocType(_) => return Err(self.fail(XmlErrorKind::DocType)),
                Event::Comment(_) | Event::PI(_) => {}
                Event::Eof => {
                    return if self.depth == 0 {
                        Ok(Token::Eof)
                    } else {
                        Err(self.fail(XmlErrorKind::UnexpectedEof))
                    };
                }
            }
        }
    }

    pub fn text(&mut self) -> Result<Cow<'a, str>, XmlError> {
        self.content(true)
    }

    pub fn raw_text(&mut self) -> Result<Cow<'a, str>, XmlError> {
        self.content(false)
    }

    pub fn skip_element(&mut self) -> Result<(), XmlError> {
        if let Some(err) = self.failed {
            return Err(err);
        }
        if self.pending_end {
            self.pending_end = false;
            self.close();
            return Ok(());
        }
        let target = self.depth.saturating_sub(1);
        loop {
            match self.read()? {
                Event::Start(_) => {
                    if self.depth >= self.limits.max_depth {
                        return Err(self.fail(XmlErrorKind::TooDeep));
                    }
                    self.depth = self.depth.saturating_add(1);
                }
                Event::End(_) => {
                    self.close();
                    if self.depth == target {
                        return Ok(());
                    }
                }
                Event::DocType(_) => return Err(self.fail(XmlErrorKind::DocType)),
                Event::Decl(_) => return Err(self.fail(XmlErrorKind::Syntax)),
                Event::Eof => return Err(self.fail(XmlErrorKind::UnexpectedEof)),
                Event::GeneralRef(entity) => {
                    self.entity(&entity)?;
                }
                Event::Empty(_)
                | Event::Text(_)
                | Event::CData(_)
                | Event::Comment(_)
                | Event::PI(_) => {}
            }
        }
    }

    pub fn skip_to_end(&mut self) -> Result<(), XmlError> {
        loop {
            match self.next_token::<NoName>()? {
                Token::End => return Ok(()),
                Token::Start { .. } | Token::Unknown { .. } => self.skip_element()?,
                Token::Text => {}
                Token::Eof => return Err(self.fail(XmlErrorKind::UnexpectedEof)),
            }
        }
    }

    pub fn finish(&mut self) -> Result<(), XmlError> {
        match self.next_token::<NoName>()? {
            Token::Eof => Ok(()),
            _ => Err(self.fail(XmlErrorKind::Syntax)),
        }
    }

    fn content(&mut self, normalize: bool) -> Result<Cow<'a, str>, XmlError> {
        if let Some(err) = self.failed {
            return Err(err);
        }
        if self.pending_end {
            self.pending_end = false;
            self.close();
            return Ok(Cow::Borrowed(""));
        }
        let mut acc: Option<Cow<'a, str>> = None;
        loop {
            let piece = match self.read()? {
                Event::Text(text) => {
                    if normalize {
                        text.xml10_content()
                    } else {
                        text.into_inner()
                    }
                }
                Event::CData(data) => {
                    if normalize {
                        data.xml10_content()
                    } else {
                        data.into_inner()
                    }
                }
                Event::GeneralRef(entity) => match self.entity(&entity)? {
                    EntityText::Predefined(text) => Cow::Borrowed(text),
                    EntityText::Char(ch) => {
                        let mut owned = acc.map(Cow::into_owned).unwrap_or_default();
                        owned.push(ch);
                        acc = Some(Cow::Owned(owned));
                        continue;
                    }
                },
                Event::Comment(_) | Event::PI(_) => continue,
                Event::End(_) => {
                    self.close();
                    return Ok(acc.unwrap_or(Cow::Borrowed("")));
                }
                Event::Start(_) | Event::Empty(_) => {
                    return Err(self.fail(XmlErrorKind::UnexpectedElement));
                }
                Event::Eof => return Err(self.fail(XmlErrorKind::UnexpectedEof)),
                Event::DocType(_) => return Err(self.fail(XmlErrorKind::DocType)),
                Event::Decl(_) => return Err(self.fail(XmlErrorKind::Syntax)),
            };
            acc = Some(match acc {
                None => piece,
                Some(prev) => {
                    let mut owned = prev.into_owned();
                    owned.push_str(&piece);
                    Cow::Owned(owned)
                }
            });
        }
    }

    fn read(&mut self) -> Result<Event<'a>, XmlError> {
        match self.reader.read_event() {
            Ok(event) => Ok(event),
            Err(err) => {
                let kind = match err {
                    QxError::Syntax(
                        SyntaxError::UnclosedTag
                        | SyntaxError::UnclosedCData
                        | SyntaxError::UnclosedComment
                        | SyntaxError::UnclosedPI
                        | SyntaxError::UnclosedDoctype
                        | SyntaxError::UnclosedXmlDecl
                        | SyntaxError::UnclosedDoubleQuotedAttributeValue
                        | SyntaxError::UnclosedSingleQuotedAttributeValue,
                    )
                    | QxError::IllFormed(IllFormedError::MissingEndTag(_)) => {
                        XmlErrorKind::UnexpectedEof
                    }
                    QxError::Encoding(_) => XmlErrorKind::Utf8,
                    QxError::Escape(_) => XmlErrorKind::UnknownEntity,
                    QxError::InvalidAttr(_) => XmlErrorKind::InvalidAttribute,
                    _ => XmlErrorKind::Syntax,
                };
                let offset = self.base.saturating_add(
                    u32::try_from(self.reader.error_position()).unwrap_or(u32::MAX),
                );
                let err = XmlError::new(kind, offset);
                self.failed = Some(err);
                Err(err)
            }
        }
    }

    fn fail(&mut self, kind: XmlErrorKind) -> XmlError {
        let err = self.error(kind);
        self.failed = Some(err);
        err
    }

    fn entity(&mut self, entity: &BytesRef<'_>) -> Result<EntityText, XmlError> {
        if entity.is_char_ref() {
            match entity.resolve_char_ref() {
                Ok(Some(ch)) if is_xml_char(ch) => Ok(EntityText::Char(ch)),
                Ok(Some(_))
                | Err(QxError::Escape(EscapeError::InvalidCharRef(
                    ParseCharRefError::IllegalCharacter(_) | ParseCharRefError::InvalidCodepoint(_),
                ))) => Err(self.fail(XmlErrorKind::InvalidChar)),
                _ => Err(self.fail(XmlErrorKind::UnknownEntity)),
            }
        } else {
            match predefined_entity(entity) {
                Some(text) => Ok(EntityText::Predefined(text)),
                None => Err(self.fail(XmlErrorKind::UnknownEntity)),
            }
        }
    }

    fn open<N: XmlName>(
        &mut self,
        tag: BytesStart<'a>,
        empty: bool,
    ) -> Result<Token<'a, N>, XmlError> {
        if self.depth >= self.limits.max_depth {
            return Err(self.fail(XmlErrorKind::TooDeep));
        }
        let offset = self.offset();
        let Some(raw) = self.rebase(&tag) else {
            return Err(self.fail(XmlErrorKind::Syntax));
        };
        let name_len = tag.name().as_ref().len();
        let Some(name) = raw.get(..name_len) else {
            return Err(self.fail(XmlErrorKind::Syntax));
        };
        self.depth = self.depth.saturating_add(1);
        if empty {
            self.pending_end = true;
        }
        let attrs = Attrs {
            raw,
            start: name_len,
            offset,
        };
        if memchr::memmem::find(raw.as_bytes(), b"xmlns").is_some() {
            self.bind(&attrs)?;
        }
        let (prefix, local) = name.split_once(':').unwrap_or(("", name));
        let ns = match self.resolve(prefix) {
            Some(ns) => ns,
            None if prefix.is_empty() => Ns::None,
            None => return Err(self.fail(XmlErrorKind::UnboundPrefix)),
        };
        Ok(match N::parse(ns, local.as_bytes()) {
            Some(name) => Token::Start { name, attrs },
            None => Token::Unknown { ns, local, attrs },
        })
    }

    fn rebase(&self, tag: &BytesStart<'_>) -> Option<&'a str> {
        let content: &str = tag;
        let start = (content.as_ptr() as usize).checked_sub(self.body.as_ptr() as usize)?;
        self.body.get(start..start.checked_add(content.len())?)
    }

    fn bind(&mut self, attrs: &Attrs<'a>) -> Result<(), XmlError> {
        for attr in attrs.iter() {
            let attr = attr.inspect_err(|err| self.failed = Some(*err))?;
            let prefix = match (attr.prefix, attr.local) {
                (None, "xmlns") => "",
                (Some("xmlns"), prefix) => prefix,
                _ => continue,
            };
            if !prefix.is_empty() && attr.value.is_empty() {
                return Err(self.fail(XmlErrorKind::UnboundPrefix));
            }
            if self
                .bindings
                .iter()
                .rev()
                .take_while(|binding| binding.depth == self.depth)
                .any(|binding| binding.prefix == prefix)
            {
                return Err(self.fail(XmlErrorKind::InvalidAttribute));
            }
            if self.bindings.len() >= usize::from(self.limits.max_ns_bindings) {
                return Err(self.fail(XmlErrorKind::TooManyNamespaces));
            }
            self.bindings.push(Binding {
                prefix,
                ns: Ns::from_uri(attr.value.as_bytes()),
                depth: self.depth,
            });
        }
        Ok(())
    }

    fn resolve(&self, prefix: &str) -> Option<Ns> {
        self.bindings
            .iter()
            .rev()
            .find(|binding| binding.prefix == prefix)
            .map(|binding| binding.ns)
    }

    fn close(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        while self
            .bindings
            .last()
            .is_some_and(|binding| binding.depth > self.depth)
        {
            self.bindings.pop();
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NoName;

impl XmlName for NoName {
    fn parse(_: Ns, _: &[u8]) -> Option<Self> {
        None
    }
}

fn predefined_entity(entity: &BytesRef<'_>) -> Option<&'static str> {
    resolve_predefined(entity)
}

fn resolve_predefined(name: &str) -> Option<&'static str> {
    hashify::map!(
        name.as_bytes(),
        &'static str,
        "lt" => "<",
        "gt" => ">",
        "amp" => "&",
        "apos" => "'",
        "quot" => "\"",
    )
    .copied()
}

#[derive(Debug, Clone, Copy)]
pub struct Attrs<'a> {
    raw: &'a str,
    start: usize,
    offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr<'a> {
    pub prefix: Option<&'a str>,
    pub local: &'a str,
    pub value: Cow<'a, str>,
}

impl<'a> Attrs<'a> {
    pub const EMPTY: Attrs<'static> = Attrs {
        raw: "",
        start: 0,
        offset: 0,
    };

    pub fn get(&self, local: &str) -> Result<Option<Cow<'a, str>>, XmlError> {
        let mut found = None;
        for attr in self.iter() {
            let attr = attr?;
            if attr.prefix.is_none() && attr.local == local {
                if found.is_some() {
                    return Err(XmlError::new(XmlErrorKind::InvalidAttribute, self.offset));
                }
                found = Some(attr.value);
            }
        }
        Ok(found)
    }

    pub fn is_empty(&self) -> bool {
        self.raw
            .get(self.start..)
            .is_none_or(|rest| rest.trim_ascii().is_empty())
    }

    pub fn offset(&self) -> u32 {
        self.offset
    }

    pub fn iter(&self) -> impl Iterator<Item = Result<Attr<'a>, XmlError>> + 'a {
        let offset = self.offset;
        let mut inner = Attributes::new(self.raw, self.start);
        inner.with_checks(false);
        inner.map(move |attr| {
            let attr = attr.map_err(|_| XmlError::new(XmlErrorKind::InvalidAttribute, offset))?;
            let value = attr
                .normalized_value_with(XmlVersion::Implicit1_0, 1, resolve_predefined)
                .map_err(|err| {
                    XmlError::new(
                        match err {
                            QxError::Escape(EscapeError::InvalidCharRef(
                                ParseCharRefError::IllegalCharacter(_)
                                | ParseCharRefError::InvalidCodepoint(_),
                            )) => XmlErrorKind::InvalidChar,
                            QxError::Escape(
                                EscapeError::UnrecognizedEntity(..)
                                | EscapeError::InvalidCharRef(_),
                            ) => XmlErrorKind::UnknownEntity,
                            _ => XmlErrorKind::InvalidAttribute,
                        },
                        offset,
                    )
                })?;
            if let Cow::Owned(text) = &value
                && !text.chars().all(is_xml_char)
            {
                return Err(XmlError::new(XmlErrorKind::InvalidChar, offset));
            }
            let key = attr.key.into_inner();
            let (prefix, local) = match key.split_once(':') {
                Some((prefix, local)) => (Some(prefix), local),
                None => (None, key),
            };
            Ok(Attr {
                prefix,
                local,
                value,
            })
        })
    }
}

fn is_xml_char(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\r' | ' '..='\u{FFFD}' | '\u{10000}'..)
}

fn is_illegal_control(b: u8) -> bool {
    (b < CONTROL_LIMIT) & (b != b'\t') & (b != b'\n') & (b != b'\r')
}

fn has_suspect(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| {
        acc | u8::from(is_illegal_control(b) | (b == NONCHARACTER_LEAD))
    }) != 0
}

fn first_illegal_char(bytes: &[u8]) -> Option<usize> {
    let (chunks, tail) = bytes.as_chunks::<SCAN_CHUNK>();
    let mut start = 0;
    for chunk in chunks {
        if has_suspect(chunk)
            && let Some(pos) = locate_illegal_char(bytes, start, SCAN_CHUNK)
        {
            return Some(pos);
        }
        start += SCAN_CHUNK;
    }
    if has_suspect(tail) {
        locate_illegal_char(bytes, start, tail.len())
    } else {
        None
    }
}

#[cold]
#[inline(never)]
fn locate_illegal_char(bytes: &[u8], start: usize, len: usize) -> Option<usize> {
    let rest = bytes.get(start..)?;
    rest.iter().take(len).enumerate().find_map(|(pos, &b)| {
        let noncharacter = b == NONCHARACTER_LEAD
            && matches!(
                rest.get(pos + 1..pos + 3),
                Some([NONCHARACTER_SECOND, 0xBE | 0xBF])
            );
        (is_illegal_control(b) || noncharacter).then_some(start + pos)
    })
}

pub fn line_column(body: &[u8], offset: u32) -> (u32, u32) {
    let end = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(body.len());
    let prefix = body.get(..end).unwrap_or_default();
    let line = memchr::memchr_iter(b'\n', prefix).count();
    let line_start = memchr::memrchr(b'\n', prefix).map_or(0, |pos| pos.saturating_add(1));
    (
        u32::try_from(line.saturating_add(1)).unwrap_or(u32::MAX),
        u32::try_from(end.saturating_sub(line_start).saturating_add(1)).unwrap_or(u32::MAX),
    )
}
