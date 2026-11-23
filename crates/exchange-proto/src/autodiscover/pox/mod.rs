/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod model;
pub mod write;

use super::AdLimits;
use crate::xml::{Token, Tokenizer, XmlError, XmlErrorKind, tokenizer::NoName};
use std::borrow::Cow;

pub use model::{
    AdAccount, AdUser, AltMailboxKind, AltMailboxTarget, AlternativeMailbox, AuthPackage,
    Encryption, ExchangeProtocol, MailProtocol, MailboxAccess, OWA_AUTH_TEXT_MAX, OutlookRedirect,
    OutlookResponse, OwaAuthMethods, OwaUrl, RpcBlocks, UrlPair, WebBlock, WebBlocks,
};
pub use write::{write_outlook_redirect, write_outlook_response, write_pox_error};

pub(crate) const OUTLOOK_RESPONSE_SCHEMA: &str =
    "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a";
pub(crate) const MOBILESYNC_RESPONSE_SCHEMA: &str =
    "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006";
const BOM: &[u8] = b"\xEF\xBB\xBF";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoxRequest<'a> {
    Outlook {
        email: Option<Cow<'a, str>>,
        legacy_dn: Option<Cow<'a, str>>,
    },
    MobileSync {
        email: Cow<'a, str>,
    },
    UnknownSchema,
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoxErrorCode {
    NotFound500,
    BadAddress501,
    InvalidRequest600,
    ProviderUnavailable601,
    InternalError603,
}

impl PoxErrorCode {
    pub const fn code(self) -> u16 {
        match self {
            PoxErrorCode::NotFound500 => 500,
            PoxErrorCode::BadAddress501 => 501,
            PoxErrorCode::InvalidRequest600 => 600,
            PoxErrorCode::ProviderUnavailable601 => 601,
            PoxErrorCode::InternalError603 => 603,
        }
    }

    pub const fn default_message(self) -> &'static str {
        match self {
            PoxErrorCode::NotFound500 => "The email address can't be found.",
            PoxErrorCode::BadAddress501 => "Bad Address",
            PoxErrorCode::InvalidRequest600 => "Invalid Request",
            PoxErrorCode::ProviderUnavailable601 => {
                "A provider for the requested schema could not be found."
            }
            PoxErrorCode::InternalError603 => "Internal Error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoxParseErrorKind {
    Xml(XmlErrorKind),
    TooLarge,
    MultipleRequests,
    MissingAddress,
    MissingRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoxParseError {
    pub kind: PoxParseErrorKind,
    pub offset: u32,
}

const _: () = assert!(std::mem::size_of::<PoxParseError>() <= 8);

impl PoxParseError {
    pub const fn code(&self) -> PoxErrorCode {
        PoxErrorCode::InvalidRequest600
    }

    const fn new(kind: PoxParseErrorKind, offset: u32) -> Self {
        PoxParseError { kind, offset }
    }
}

impl From<XmlError> for PoxParseError {
    fn from(err: XmlError) -> Self {
        PoxParseError::new(PoxParseErrorKind::Xml(err.kind), err.offset)
    }
}

impl std::fmt::Display for PoxParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} at byte {}", self.kind, self.offset)
    }
}

impl std::error::Error for PoxParseError {}

#[derive(Clone, Copy)]
enum RequestChild {
    Email,
    LegacyDn,
    Schema,
}

#[derive(Default)]
struct RequestFields<'a> {
    email: Option<Cow<'a, str>>,
    legacy_dn: Option<Cow<'a, str>>,
    schema: Option<Cow<'a, str>>,
}

pub fn parse_pox_request<'a>(
    body: &'a [u8],
    limits: &AdLimits,
) -> Result<PoxRequest<'a>, PoxParseError> {
    if u32::try_from(body.len()).map_or(true, |len| len > limits.max_pox_body) {
        return Err(PoxParseError::new(PoxParseErrorKind::TooLarge, 0));
    }
    if body
        .strip_prefix(BOM)
        .unwrap_or(body)
        .trim_ascii()
        .is_empty()
    {
        return Ok(PoxRequest::Empty);
    }

    parse_document(body, limits)
}

fn parse_document<'a>(body: &'a [u8], limits: &AdLimits) -> Result<PoxRequest<'a>, PoxParseError> {
    let mut tok = Tokenizer::new(body, &limits.xml);
    let mut fields: Option<RequestFields<'a>> = None;
    let mut seen_root = false;
    loop {
        match tok.next_token::<NoName>()? {
            Token::Unknown { local, .. } if !seen_root && local == "Autodiscover" => {
                seen_root = true;
                parse_root(&mut tok, &mut fields)?;
            }
            Token::Unknown { .. } | Token::Start { .. } => {
                return Err(tok.error(XmlErrorKind::UnexpectedElement).into());
            }
            Token::Text => return Err(tok.error(XmlErrorKind::Syntax).into()),
            Token::End => return Err(tok.error(XmlErrorKind::Syntax).into()),
            Token::Eof => break,
        }
    }

    let fields = fields
        .ok_or_else(|| PoxParseError::new(PoxParseErrorKind::MissingRequest, tok.offset()))?;
    let schema = fields.schema.as_deref().unwrap_or_default();
    let missing_address = || PoxParseError::new(PoxParseErrorKind::MissingAddress, tok.offset());
    if schema == OUTLOOK_RESPONSE_SCHEMA {
        if fields.email.is_none() && fields.legacy_dn.is_none() {
            return Err(missing_address());
        }
        Ok(PoxRequest::Outlook {
            email: fields.email,
            legacy_dn: fields.legacy_dn,
        })
    } else if schema == MOBILESYNC_RESPONSE_SCHEMA {
        fields
            .email
            .map(|email| PoxRequest::MobileSync { email })
            .ok_or_else(missing_address)
    } else {
        Ok(PoxRequest::UnknownSchema)
    }
}

fn parse_root<'a>(
    tok: &mut Tokenizer<'a>,
    fields: &mut Option<RequestFields<'a>>,
) -> Result<(), PoxParseError> {
    loop {
        match tok.next_token::<NoName>()? {
            Token::Unknown {
                local: "Request", ..
            } => {
                if fields.is_some() {
                    return Err(PoxParseError::new(
                        PoxParseErrorKind::MultipleRequests,
                        tok.offset(),
                    ));
                }
                *fields = Some(parse_request(tok)?);
            }
            Token::Unknown { .. } | Token::Start { .. } => tok.skip_element()?,
            Token::Text => {}
            Token::End => return Ok(()),
            Token::Eof => return Err(tok.error(XmlErrorKind::UnexpectedEof).into()),
        }
    }
}

fn parse_request<'a>(tok: &mut Tokenizer<'a>) -> Result<RequestFields<'a>, PoxParseError> {
    let mut fields = RequestFields::default();
    loop {
        match tok.next_token::<NoName>()? {
            Token::Unknown { local, .. } => {
                let Some(child) = hashify::map!(
                    local.as_bytes(),
                    RequestChild,
                    "EMailAddress" => RequestChild::Email,
                    "LegacyDN" => RequestChild::LegacyDn,
                    "AcceptableResponseSchema" => RequestChild::Schema,
                ) else {
                    tok.skip_element()?;
                    continue;
                };
                let value = trim_cow(tok.text()?);
                let slot = match child {
                    RequestChild::Email => &mut fields.email,
                    RequestChild::LegacyDn => &mut fields.legacy_dn,
                    RequestChild::Schema => &mut fields.schema,
                };
                if slot.is_none() && !value.is_empty() {
                    *slot = Some(value);
                }
            }
            Token::Start { .. } => tok.skip_element()?,
            Token::Text => {}
            Token::End => return Ok(fields),
            Token::Eof => return Err(tok.error(XmlErrorKind::UnexpectedEof).into()),
        }
    }
}

pub(crate) fn trim_cow(value: Cow<'_, str>) -> Cow<'_, str> {
    match value {
        Cow::Borrowed(text) => Cow::Borrowed(text.trim()),
        Cow::Owned(text) if text.trim().len() == text.len() => Cow::Owned(text),
        Cow::Owned(text) => Cow::Owned(text.trim().to_owned()),
    }
}
