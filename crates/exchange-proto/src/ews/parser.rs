/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Fault, Operation, schema::ResponseCode};
use crate::xml::{
    Attrs, Ns, Token, Tokenizer, XmlError, XmlErrorKind, XmlLimits, XmlValue, line_column,
    tokenizer::NoName,
};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EwsLimits {
    pub xml: XmlLimits,
    pub max_restriction_nodes: u16,
    pub max_restriction_depth: u8,
    pub max_ids: u32,
    pub max_paths: u32,
    pub max_id_len: u16,
}

impl EwsLimits {
    pub const DEFAULT: Self = EwsLimits {
        xml: XmlLimits::DEFAULT,
        max_restriction_nodes: 256,
        max_restriction_depth: 16,
        max_ids: 1000,
        max_paths: 2048,
        max_id_len: 512,
    };
}

impl Default for EwsLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    Xml(XmlErrorKind),
    NotSoapEnvelope,
    MissingBody,
    UnknownOperation,
    WrongNamespace,
    MissingElement(&'static str),
    MissingAttribute(&'static str),
    InvalidValue(&'static str),
    IdTooLong,
    TooManyIds,
    TooManyPaths,
    RestrictionTooLong,
    RestrictionTooComplex,
    InvalidSubscription,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub offset: u32,
    pub op: Option<Operation>,
}

const _: () = assert!(std::mem::size_of::<ParseError>() <= 32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome<'x> {
    Fault(Fault<'x>),
    MessageError { op: Operation, code: ResponseCode },
}

impl ParseError {
    pub fn outcome(&self, body: &[u8]) -> ParseOutcome<'static> {
        let message_code = match self.kind {
            ParseErrorKind::RestrictionTooLong => Some(ResponseCode::ErrorRestrictionTooLong),
            ParseErrorKind::RestrictionTooComplex => Some(ResponseCode::ErrorRestrictionTooComplex),
            ParseErrorKind::TooManyIds | ParseErrorKind::TooManyPaths => {
                Some(ResponseCode::ErrorInvalidRequest)
            }
            ParseErrorKind::InvalidSubscription => {
                Some(ResponseCode::ErrorInvalidSubscriptionRequest)
            }
            ParseErrorKind::IdTooLong => Some(ResponseCode::ErrorInvalidIdMalformed),
            _ => None,
        };
        if let (Some(code), Some(op)) = (message_code, self.op) {
            return ParseOutcome::MessageError { op, code };
        }
        let code = match self.kind {
            ParseErrorKind::MissingBody
            | ParseErrorKind::UnknownOperation
            | ParseErrorKind::TooManyIds
            | ParseErrorKind::TooManyPaths => ResponseCode::ErrorInvalidRequest,
            ParseErrorKind::WrongNamespace if self.op.is_none() => {
                ResponseCode::ErrorInvalidRequest
            }
            ParseErrorKind::IdTooLong => ResponseCode::ErrorInvalidIdMalformed,
            _ => ResponseCode::ErrorSchemaValidation,
        };
        ParseOutcome::Fault(Fault {
            code,
            text: Cow::Borrowed(self.description()),
            line: (code == ResponseCode::ErrorSchemaValidation)
                .then(|| line_column(body, self.offset)),
            message_xml: None,
        })
    }

    pub fn description(&self) -> &'static str {
        match self.kind {
            ParseErrorKind::Xml(XmlErrorKind::DocType) => "DTDs are not allowed.",
            ParseErrorKind::Xml(XmlErrorKind::UnsupportedEncoding) => {
                "Only UTF-8 encoded requests are supported."
            }
            ParseErrorKind::Xml(XmlErrorKind::TooDeep) => "The request is nested too deeply.",
            ParseErrorKind::Xml(_) => "The request failed schema validation: malformed XML.",
            ParseErrorKind::NotSoapEnvelope => "The request is not a SOAP envelope.",
            ParseErrorKind::MissingBody => "The SOAP body is missing or empty.",
            ParseErrorKind::UnknownOperation => "The request element is not a known operation.",
            ParseErrorKind::WrongNamespace => "The request element is in the wrong namespace.",
            ParseErrorKind::MissingElement(_) => "A required element is missing.",
            ParseErrorKind::MissingAttribute(_) => "A required attribute is missing.",
            ParseErrorKind::InvalidValue(_) => "An element or attribute has an invalid value.",
            ParseErrorKind::IdTooLong => "An id or change key exceeds the maximum length.",
            ParseErrorKind::TooManyIds => "The request contains too many ids.",
            ParseErrorKind::TooManyPaths => "The request contains too many property paths.",
            ParseErrorKind::RestrictionTooLong => "The restriction contains too many filters.",
            ParseErrorKind::RestrictionTooComplex => "The restriction is too complex.",
            ParseErrorKind::InvalidSubscription => {
                "FolderIds and SubscribeToAllFolders must not be combined, and one is required."
            }
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} at byte {}", self.kind, self.offset)
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Copy)]
pub struct Child<'a> {
    pub ns: Ns,
    pub local: &'a str,
    pub attrs: Attrs<'a>,
}

impl Child<'_> {
    pub fn is_types(&self) -> bool {
        self.ns == Ns::Types
    }

    pub fn is_messages(&self) -> bool {
        self.ns == Ns::Messages
    }
}

pub struct Parser<'a> {
    tok: Tokenizer<'a>,
    pub limits: EwsLimits,
    pub op: Option<Operation>,
    ids: u32,
    paths: u32,
    attached_items: u8,
}

const MAX_ATTACHED_ITEM_NESTING: u8 = 8;

pub type Result<T> = std::result::Result<T, ParseError>;

impl<'a> Parser<'a> {
    pub fn new(body: &'a [u8], limits: &EwsLimits) -> Self {
        Parser {
            tok: Tokenizer::new(body, &limits.xml),
            limits: *limits,
            op: None,
            ids: 0,
            paths: 0,
            attached_items: 0,
        }
    }

    pub fn enter_attached_item(&mut self) -> Result<()> {
        if self.attached_items >= MAX_ATTACHED_ITEM_NESTING {
            return Err(self.error(ParseErrorKind::Xml(XmlErrorKind::TooDeep)));
        }
        self.attached_items = self.attached_items.saturating_add(1);
        Ok(())
    }

    pub fn leave_attached_item(&mut self) {
        self.attached_items = self.attached_items.saturating_sub(1);
    }

    pub fn offset(&self) -> u32 {
        self.tok.offset()
    }

    pub fn depth(&self) -> u8 {
        self.tok.depth()
    }

    pub fn error(&self, kind: ParseErrorKind) -> ParseError {
        ParseError {
            kind,
            offset: self.tok.offset(),
            op: self.op,
        }
    }

    fn xml(&self, err: XmlError) -> ParseError {
        ParseError {
            kind: ParseErrorKind::Xml(err.kind),
            offset: err.offset,
            op: self.op,
        }
    }

    pub fn token(&mut self) -> Result<Token<'a, NoName>> {
        self.tok.next_token().map_err(|err| self.xml(err))
    }

    pub fn finish(&mut self) -> Result<()> {
        self.tok.finish().map_err(|err| self.xml(err))
    }

    pub fn child(&mut self) -> Result<Option<Child<'a>>> {
        loop {
            match self.token()? {
                Token::Unknown { ns, local, attrs } => {
                    if matches!(ns, Ns::Messages | Ns::Types) {
                        return Ok(Some(Child { ns, local, attrs }));
                    }
                    self.skip()?;
                }
                Token::Start { .. } => self.skip()?,
                Token::Text => {}
                Token::End => return Ok(None),
                Token::Eof => {
                    return Err(self.error(ParseErrorKind::Xml(XmlErrorKind::UnexpectedEof)));
                }
            }
        }
    }

    pub fn any_child(&mut self) -> Result<Option<Child<'a>>> {
        loop {
            match self.token()? {
                Token::Unknown { ns, local, attrs } => return Ok(Some(Child { ns, local, attrs })),
                Token::Start { .. } => self.skip()?,
                Token::Text => {}
                Token::End => return Ok(None),
                Token::Eof => {
                    return Err(self.error(ParseErrorKind::Xml(XmlErrorKind::UnexpectedEof)));
                }
            }
        }
    }

    pub fn skip(&mut self) -> Result<()> {
        self.tok.skip_element().map_err(|err| self.xml(err))
    }

    pub fn skip_rest(&mut self) -> Result<()> {
        self.tok.skip_to_end().map_err(|err| self.xml(err))
    }

    pub fn text(&mut self) -> Result<Cow<'a, str>> {
        self.tok.text().map_err(|err| self.xml(err))
    }

    pub fn raw_text(&mut self) -> Result<Cow<'a, str>> {
        self.tok.raw_text().map_err(|err| self.xml(err))
    }

    pub fn value<T: XmlValue<'a>>(&mut self, name: &'static str) -> Result<T> {
        let text = self.text()?;
        T::parse_value(text).ok_or_else(|| self.error(ParseErrorKind::InvalidValue(name)))
    }

    pub fn attr(&self, attrs: &Attrs<'a>, name: &'static str) -> Result<Option<Cow<'a, str>>> {
        attrs.get(name).map_err(|err| self.xml(err))
    }

    pub fn attr_required(&self, attrs: &Attrs<'a>, name: &'static str) -> Result<Cow<'a, str>> {
        self.attr(attrs, name)?
            .ok_or_else(|| self.error(ParseErrorKind::MissingAttribute(name)))
    }

    pub fn xml_lang(&self, attrs: &Attrs<'a>) -> Result<Option<Cow<'a, str>>> {
        for attr in attrs.iter() {
            let attr = attr.map_err(|err| self.xml(err))?;
            if attr.prefix == Some("xml") && attr.local == "lang" {
                return Ok(Some(attr.value));
            }
        }
        Ok(None)
    }

    pub fn attr_value<T: XmlValue<'a>>(
        &self,
        attrs: &Attrs<'a>,
        name: &'static str,
    ) -> Result<Option<T>> {
        match self.attr(attrs, name)? {
            Some(text) => T::parse_value(text)
                .map(Some)
                .ok_or_else(|| self.error(ParseErrorKind::InvalidValue(name))),
            None => Ok(None),
        }
    }

    pub fn attr_enum<T>(
        &self,
        attrs: &Attrs<'a>,
        name: &'static str,
        parse: fn(&[u8]) -> Option<T>,
    ) -> Result<Option<T>> {
        match self.attr(attrs, name)? {
            Some(text) => parse(text.trim_ascii().as_bytes())
                .map(Some)
                .ok_or_else(|| self.error(ParseErrorKind::InvalidValue(name))),
            None => Ok(None),
        }
    }

    pub fn text_enum<T>(&mut self, name: &'static str, parse: fn(&[u8]) -> Option<T>) -> Result<T> {
        let text = self.text()?;
        parse(text.trim_ascii().as_bytes())
            .ok_or_else(|| self.error(ParseErrorKind::InvalidValue(name)))
    }

    pub fn count_id(&mut self) -> Result<()> {
        self.ids = self.ids.saturating_add(1);
        if self.ids > self.limits.max_ids {
            Err(self.error(ParseErrorKind::TooManyIds))
        } else {
            Ok(())
        }
    }

    pub fn count_path(&mut self) -> Result<()> {
        self.paths = self.paths.saturating_add(1);
        if self.paths > self.limits.max_paths {
            Err(self.error(ParseErrorKind::TooManyPaths))
        } else {
            Ok(())
        }
    }

    pub fn expect_ns(&self, child: &Child<'a>, ns: Ns) -> Result<()> {
        if child.ns == ns {
            Ok(())
        } else {
            Err(self.error(ParseErrorKind::WrongNamespace))
        }
    }

    pub fn expect_types(&self, child: &Child<'a>) -> Result<()> {
        self.expect_ns(child, Ns::Types)
    }

    pub fn expect_messages(&self, child: &Child<'a>) -> Result<()> {
        self.expect_ns(child, Ns::Messages)
    }

    pub fn check_id_len(&self, id: &str) -> Result<()> {
        if id.len() > usize::from(self.limits.max_id_len) {
            Err(self.error(ParseErrorKind::IdTooLong))
        } else {
            Ok(())
        }
    }
}
