/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Write;

use super::error::{HeaderError, HeaderKind};
use crate::common::{Guid, xml::escape_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Emsmdb,
    Nspi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestType {
    Connect,
    Execute,
    Disconnect,
    NotificationWait,
    Ping,
    Bind,
    Unbind,
    CompareMinIds,
    DnToMinId,
    GetMatches,
    GetPropList,
    GetProps,
    GetSpecialTable,
    GetTemplateInfo,
    ModLinkAtt,
    ModProps,
    QueryRows,
    QueryColumns,
    ResolveNames,
    ResortRestriction,
    SeekEntries,
    UpdateStat,
    GetMailboxUrl,
    GetAddressBookUrl,
}

impl RequestType {
    pub fn parse(endpoint: Endpoint, value: &[u8]) -> Option<Self> {
        let request_type = *hashify::map_ignore_case!(value, RequestType,
            "Connect" => RequestType::Connect,
            "Execute" => RequestType::Execute,
            "Disconnect" => RequestType::Disconnect,
            "NotificationWait" => RequestType::NotificationWait,
            "PING" => RequestType::Ping,
            "Bind" => RequestType::Bind,
            "Unbind" => RequestType::Unbind,
            "CompareMIds" => RequestType::CompareMinIds,
            "CompareMinIds" => RequestType::CompareMinIds,
            "DNToMId" => RequestType::DnToMinId,
            "DnToMinId" => RequestType::DnToMinId,
            "GetMatches" => RequestType::GetMatches,
            "GetPropList" => RequestType::GetPropList,
            "GetProps" => RequestType::GetProps,
            "GetSpecialTable" => RequestType::GetSpecialTable,
            "GetTemplateInfo" => RequestType::GetTemplateInfo,
            "ModLinkAtt" => RequestType::ModLinkAtt,
            "ModProps" => RequestType::ModProps,
            "QueryRows" => RequestType::QueryRows,
            "QueryColumns" => RequestType::QueryColumns,
            "ResolveNames" => RequestType::ResolveNames,
            "ResortRestriction" => RequestType::ResortRestriction,
            "SeekEntries" => RequestType::SeekEntries,
            "UpdateStat" => RequestType::UpdateStat,
            "GetMailboxUrl" => RequestType::GetMailboxUrl,
            "GetAddressBookUrl" => RequestType::GetAddressBookUrl,
        )?;
        (request_type == RequestType::Ping || request_type.endpoint() == endpoint)
            .then_some(request_type)
    }

    pub fn endpoint(self) -> Endpoint {
        match self {
            RequestType::Connect
            | RequestType::Execute
            | RequestType::Disconnect
            | RequestType::NotificationWait
            | RequestType::Ping => Endpoint::Emsmdb,
            _ => Endpoint::Nspi,
        }
    }

    pub fn header_value(self) -> &'static str {
        match self {
            RequestType::Connect => "Connect",
            RequestType::Execute => "Execute",
            RequestType::Disconnect => "Disconnect",
            RequestType::NotificationWait => "NotificationWait",
            RequestType::Ping => "PING",
            RequestType::Bind => "Bind",
            RequestType::Unbind => "Unbind",
            RequestType::CompareMinIds => "CompareMIds",
            RequestType::DnToMinId => "DNToMId",
            RequestType::GetMatches => "GetMatches",
            RequestType::GetPropList => "GetPropList",
            RequestType::GetProps => "GetProps",
            RequestType::GetSpecialTable => "GetSpecialTable",
            RequestType::GetTemplateInfo => "GetTemplateInfo",
            RequestType::ModLinkAtt => "ModLinkAtt",
            RequestType::ModProps => "ModProps",
            RequestType::QueryRows => "QueryRows",
            RequestType::QueryColumns => "QueryColumns",
            RequestType::ResolveNames => "ResolveNames",
            RequestType::ResortRestriction => "ResortRestriction",
            RequestType::SeekEntries => "SeekEntries",
            RequestType::UpdateStat => "UpdateStat",
            RequestType::GetMailboxUrl => "GetMailboxUrl",
            RequestType::GetAddressBookUrl => "GetAddressBookUrl",
        }
    }

    pub fn may_overlap(self) -> bool {
        matches!(self, RequestType::NotificationWait | RequestType::Ping)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RawMapiHeaders<'a> {
    pub request_type: Option<&'a [u8]>,
    pub request_id: Option<&'a [u8]>,
    pub client_info: Option<&'a [u8]>,
    pub client_application: Option<&'a [u8]>,
    pub content_type: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapiHeaders<'a> {
    pub request_type: RequestType,
    pub request_id: RequestId<'a>,
    pub client_info: Option<&'a str>,
    pub client_application: Option<ClientVersion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId<'a>(&'a str);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientVersion(pub [u16; 4]);

pub const MAX_HEADER_LEN: usize = 256;

impl<'a> RequestId<'a> {
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    pub fn parts(&self) -> Option<(Guid, u32)> {
        parse_guid_counter(self.0)
    }
}

fn parse_guid_counter(value: &str) -> Option<(Guid, u32)> {
    let (guid, counter) = value.rsplit_once(':')?;
    Some((Guid::parse_text(guid.as_bytes())?, counter.parse().ok()?))
}

impl ClientVersion {
    pub fn parse(value: &[u8]) -> Option<Self> {
        let value = std::str::from_utf8(value).ok()?;
        let (_, version) = value.split_once('/')?;
        let version = version.split_ascii_whitespace().next()?;
        let mut parts = version.split('.');
        let mut out = [0u16; 4];
        for slot in &mut out {
            *slot = parts.next()?.parse().ok()?;
        }
        parts.next().is_none().then_some(ClientVersion(out))
    }
}

fn header_token(value: &[u8]) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= MAX_HEADER_LEN
        && value.iter().all(|b| b.is_ascii_graphic()))
    .then(|| std::str::from_utf8(value).ok())
    .flatten()
}

pub fn validate_headers<'a>(
    endpoint: Endpoint,
    raw: &RawMapiHeaders<'a>,
) -> Result<MapiHeaders<'a>, HeaderError> {
    let request_type = raw
        .request_type
        .ok_or(HeaderError::Missing(HeaderKind::RequestType))?;
    let request_type = RequestType::parse(endpoint, request_type.trim_ascii())
        .ok_or(HeaderError::UnknownRequestType)?;
    let request_id = raw
        .request_id
        .ok_or(HeaderError::Missing(HeaderKind::RequestId))?;
    let request_id = header_token(request_id.trim_ascii())
        .map(RequestId)
        .ok_or(HeaderError::Invalid(HeaderKind::RequestId))?;
    let client_info = match raw.client_info {
        Some(value) => Some(
            header_token(value.trim_ascii()).ok_or(HeaderError::Invalid(HeaderKind::ClientInfo))?,
        ),
        None => None,
    };
    let client_application = raw.client_application.and_then(ClientVersion::parse);
    if let Some(content_type) = raw.content_type {
        let media = content_type
            .split(|b| *b == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii();
        if request_type != RequestType::Ping && !media.eq_ignore_ascii_case(CONTENT_TYPE.as_bytes())
        {
            return Err(HeaderError::Invalid(HeaderKind::ContentType));
        }
    }
    Ok(MapiHeaders {
        request_type,
        request_id,
        client_info,
        client_application,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResponseCode {
    Success = 0,
    UnknownFailure = 1,
    InvalidVerb = 2,
    InvalidPath = 3,
    InvalidHeader = 4,
    InvalidRequestType = 5,
    InvalidContextCookie = 6,
    MissingHeader = 7,
    AnonymousNotAllowed = 8,
    TooLarge = 9,
    ContextNotFound = 10,
    NoPrivilege = 11,
    InvalidRequestBody = 12,
    MissingCookie = 13,
    InvalidSequence = 15,
    EndpointDisabled = 16,
    InvalidResponse = 17,
    EndpointShuttingDown = 18,
}

impl ResponseCode {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            0 => ResponseCode::Success,
            1 => ResponseCode::UnknownFailure,
            2 => ResponseCode::InvalidVerb,
            3 => ResponseCode::InvalidPath,
            4 => ResponseCode::InvalidHeader,
            5 => ResponseCode::InvalidRequestType,
            6 => ResponseCode::InvalidContextCookie,
            7 => ResponseCode::MissingHeader,
            8 => ResponseCode::AnonymousNotAllowed,
            9 => ResponseCode::TooLarge,
            10 => ResponseCode::ContextNotFound,
            11 => ResponseCode::NoPrivilege,
            12 => ResponseCode::InvalidRequestBody,
            13 => ResponseCode::MissingCookie,
            15 => ResponseCode::InvalidSequence,
            16 => ResponseCode::EndpointDisabled,
            17 => ResponseCode::InvalidResponse,
            18 => ResponseCode::EndpointShuttingDown,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ResponseCode::Success => "Success",
            ResponseCode::UnknownFailure => "Unknown Failure",
            ResponseCode::InvalidVerb => "Invalid Verb",
            ResponseCode::InvalidPath => "Invalid Path",
            ResponseCode::InvalidHeader => "Invalid Header",
            ResponseCode::InvalidRequestType => "Invalid Request Type",
            ResponseCode::InvalidContextCookie => "Invalid Context Cookie",
            ResponseCode::MissingHeader => "Missing Header",
            ResponseCode::AnonymousNotAllowed => "Anonymous Not Allowed",
            ResponseCode::TooLarge => "Too Large",
            ResponseCode::ContextNotFound => "Context Not Found",
            ResponseCode::NoPrivilege => "No Privilege",
            ResponseCode::InvalidRequestBody => "Invalid Request Body",
            ResponseCode::MissingCookie => "Missing Cookie",
            ResponseCode::InvalidSequence => "Invalid Sequence",
            ResponseCode::EndpointDisabled => "Endpoint Disabled",
            ResponseCode::InvalidResponse => "Invalid Response",
            ResponseCode::EndpointShuttingDown => "Endpoint Shutting Down",
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            ResponseCode::Success => CONTENT_TYPE,
            _ => ERROR_CONTENT_TYPE,
        }
    }
}

pub const CONTENT_TYPE: &str = "application/mapi-http";
pub const ERROR_CONTENT_TYPE: &str = "text/html";
pub const PENDING_PERIOD_MS: u32 = 30000;
pub const EXPIRATION_CONNECT_MS: u32 = 300000;
pub const EXPIRATION_MS: u32 = 900000;
pub const NOTIFICATION_WAIT_MS: u32 = 300000;
pub const COOKIE_CONTEXT: &str = "MapiContext";
pub const COOKIE_SEQUENCE: &str = "MapiSequence";

pub mod header {
    pub const REQUEST_TYPE: &str = "X-RequestType";
    pub const REQUEST_ID: &str = "X-RequestId";
    pub const CLIENT_INFO: &str = "X-ClientInfo";
    pub const CLIENT_APPLICATION: &str = "X-ClientApplication";
    pub const RESPONSE_CODE: &str = "X-ResponseCode";
    pub const SERVER_APPLICATION: &str = "X-ServerApplication";
    pub const EXPIRATION_INFO: &str = "X-ExpirationInfo";
    pub const PENDING_PERIOD: &str = "X-PendingPeriod";
    pub const START_TIME: &str = "X-StartTime";
    pub const ELAPSED_TIME: &str = "X-ElapsedTime";
}

pub fn write_error_page(out: &mut Vec<u8>, code: ResponseCode) {
    let name = code.name();
    out.extend_from_slice(b"<html><head><title>");
    escape_text(name, out);
    let _ = write!(
        out,
        "</title></head><body><p>X-ResponseCode: {} (",
        code.code()
    );
    escape_text(name, out);
    out.extend_from_slice(b")</p></body></html>");
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/http/tests.rs"]
mod tests;
