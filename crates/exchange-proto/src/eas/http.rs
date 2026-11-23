/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::common::base64::{Base64Mode, base64_decode_into};
use crate::common::reader::{LeReader, Truncated};
use crate::eas::status::CommonStatus;
use crate::eas::tokens::ProtocolVersion;

pub const OPTIONS_VERSIONS: &str = "14.1,16.1";
pub const OPTIONS_COMMANDS: &str = "Sync,SendMail,SmartForward,SmartReply,GetAttachment,FolderSync,FolderCreate,FolderDelete,FolderUpdate,MoveItems,GetItemEstimate,MeetingResponse,Search,Settings,Ping,ItemOperations,Provision,ResolveRecipients,ValidateCert,Find";
pub const WBXML_CONTENT_TYPE: &str = "application/vnd.ms-sync.wbxml";
pub const WBXML_SHORT_CONTENT_TYPE: &str = "application/vnd.ms-sync";
pub const MULTIPART_CONTENT_TYPE: &str = "application/vnd.ms-sync.multipart";

pub const MAX_QUERY_LEN: usize = 4096;
pub const MAX_DEVICE_ID_LEN: usize = 32;
pub const MAX_DEVICE_TYPE_LEN: usize = 32;

const OPTION_SAVE_IN_SENT: u8 = 0x01;
const OPTION_ACCEPT_MULTIPART: u8 = 0x02;
const POLICY_KEY_LEN: u8 = 4;

macro_rules! commands {
    ($( $variant:ident $name:literal = $code:literal ),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Command {
            $( $variant, )*
        }

        impl Command {
            pub const ALL: &'static [Command] = &[$( Command::$variant, )*];

            pub fn code(self) -> u8 {
                match self {
                    $( Command::$variant => $code, )*
                }
            }

            pub fn from_code(code: u8) -> Option<Self> {
                match code {
                    $( $code => Some(Command::$variant), )*
                    _ => None,
                }
            }

            pub fn from_name(name: &[u8]) -> Option<Self> {
                hashify::map!(name, Command, $( $name => Command::$variant, )*).copied()
            }

            pub fn name(self) -> &'static str {
                match self {
                    $( Command::$variant => $name, )*
                }
            }
        }
    };
}

commands!(
    Sync "Sync" = 0,
    SendMail "SendMail" = 1,
    SmartForward "SmartForward" = 2,
    SmartReply "SmartReply" = 3,
    GetAttachment "GetAttachment" = 4,
    FolderSync "FolderSync" = 9,
    FolderCreate "FolderCreate" = 10,
    FolderDelete "FolderDelete" = 11,
    FolderUpdate "FolderUpdate" = 12,
    MoveItems "MoveItems" = 13,
    GetItemEstimate "GetItemEstimate" = 14,
    MeetingResponse "MeetingResponse" = 15,
    Search "Search" = 16,
    Settings "Settings" = 17,
    Ping "Ping" = 18,
    ItemOperations "ItemOperations" = 19,
    Provision "Provision" = 20,
    ResolveRecipients "ResolveRecipients" = 21,
    ValidateCert "ValidateCert" = 22,
    Find "Find" = 23,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryForm {
    Plain,
    Base64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceId<'a>(Cow<'a, [u8]>);

impl DeviceId<'_> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    pub fn into_owned(self) -> DeviceId<'static> {
        DeviceId(Cow::Owned(self.0.into_owned()))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestParams<'a> {
    pub attachment_name: Option<Cow<'a, str>>,
    pub collection_id: Option<Cow<'a, str>>,
    pub item_id: Option<Cow<'a, str>>,
    pub long_id: Option<Cow<'a, str>>,
    pub occurrence: Option<Cow<'a, str>>,
    pub save_in_sent: bool,
    pub accept_multipart: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine<'a> {
    pub command: Command,
    pub user: Option<Cow<'a, str>>,
    pub device_id: DeviceId<'a>,
    pub device_type: Cow<'a, str>,
    pub version: Option<ProtocolVersion>,
    pub raw_version: Option<&'a str>,
    pub policy_key: Option<u32>,
    pub locale: Option<u16>,
    pub params: RequestParams<'a>,
    pub form: QueryForm,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EasHeaders<'a> {
    pub protocol_version: Option<&'a str>,
    pub policy_key: Option<&'a str>,
    pub accept_multipart: Option<&'a str>,
    pub content_type: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    TooLong,
    PercentEncoding { offset: usize },
    Base64 { offset: usize },
    Truncated { offset: usize },
    Utf8,
    MissingCommand,
    UnknownCommand,
    MissingUser,
    MissingDeviceId,
    InvalidDeviceId { command: Command },
    MissingDeviceType,
    InvalidDeviceType { command: Command },
    InvalidPolicyKey,
    InvalidParameter { tag: u8 },
}

impl HttpError {
    pub fn common_status(self) -> Option<CommonStatus> {
        match self {
            HttpError::MissingDeviceId | HttpError::InvalidDeviceId { .. } => {
                Some(CommonStatus::DEVICE_ID_MISSING_OR_INVALID)
            }
            HttpError::MissingDeviceType | HttpError::InvalidDeviceType { .. } => {
                Some(CommonStatus::DEVICE_TYPE_MISSING_OR_INVALID)
            }
            _ => None,
        }
    }
}

impl From<Truncated> for HttpError {
    fn from(err: Truncated) -> Self {
        HttpError::Truncated { offset: err.offset }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    Wbxml,
    Empty,
    Other,
}

pub fn classify_body(content_type: Option<&[u8]>, len: usize) -> BodyKind {
    if len == 0 {
        return BodyKind::Empty;
    }
    let Some(content_type) = content_type else {
        return BodyKind::Wbxml;
    };
    let media = content_type
        .split(|&b| b == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    if hashify::set_ignore_case!(
        media,
        "application/vnd.ms-sync.wbxml",
        "application/vnd.ms-sync"
    ) {
        BodyKind::Wbxml
    } else {
        BodyKind::Other
    }
}

pub fn parse_request_line<'a>(
    query: &'a str,
    headers: &EasHeaders<'a>,
) -> Result<RequestLine<'a>, HttpError> {
    if query.len() > MAX_QUERY_LEN {
        return Err(HttpError::TooLong);
    }
    if query.contains('&') {
        parse_plain(query, headers)
    } else {
        parse_base64(query)
    }
}

enum PlainParam {
    Cmd,
    User,
    DeviceId,
    DeviceType,
    AttachmentName,
    CollectionId,
    ItemId,
    LongId,
    Occurrence,
    SaveInSent,
}

fn parse_plain<'a>(query: &'a str, headers: &EasHeaders<'a>) -> Result<RequestLine<'a>, HttpError> {
    let mut command = None;
    let mut user = None;
    let mut device_id = None;
    let mut device_type = None;
    let mut params = RequestParams::default();
    let mut offset = 0usize;
    for pair in query.split('&') {
        let pair_offset = offset;
        offset = offset.saturating_add(pair.len()).saturating_add(1);
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        let Some(param) = hashify::map_ignore_case!(
            name.as_bytes(),
            PlainParam,
            "Cmd" => PlainParam::Cmd,
            "User" => PlainParam::User,
            "DeviceId" => PlainParam::DeviceId,
            "DeviceType" => PlainParam::DeviceType,
            "AttachmentName" => PlainParam::AttachmentName,
            "CollectionId" => PlainParam::CollectionId,
            "ItemId" => PlainParam::ItemId,
            "LongId" => PlainParam::LongId,
            "Occurrence" => PlainParam::Occurrence,
            "SaveInSent" => PlainParam::SaveInSent,
        ) else {
            continue;
        };
        let value = percent_decode(value, pair_offset)?;
        match param {
            PlainParam::Cmd => command = Some(value),
            PlainParam::User => user = Some(value),
            PlainParam::DeviceId => device_id = Some(value),
            PlainParam::DeviceType => device_type = Some(value),
            PlainParam::AttachmentName => params.attachment_name = Some(value),
            PlainParam::CollectionId => params.collection_id = Some(value),
            PlainParam::ItemId => params.item_id = Some(value),
            PlainParam::LongId => params.long_id = Some(value),
            PlainParam::Occurrence => params.occurrence = Some(value),
            PlainParam::SaveInSent => params.save_in_sent = value.eq_ignore_ascii_case("T"),
        }
    }
    let command = command.ok_or(HttpError::MissingCommand)?;
    let command = Command::from_name(command.as_bytes()).ok_or(HttpError::UnknownCommand)?;
    let user = user
        .filter(|u| !u.is_empty())
        .ok_or(HttpError::MissingUser)?;
    let device_id = device_id
        .filter(|d| !d.is_empty())
        .ok_or(HttpError::MissingDeviceId)?;
    if device_id.len() > MAX_DEVICE_ID_LEN {
        return Err(HttpError::InvalidDeviceId { command });
    }
    let device_type = device_type
        .filter(|d| !d.is_empty())
        .ok_or(HttpError::MissingDeviceType)?;
    if device_type.len() > MAX_DEVICE_TYPE_LEN {
        return Err(HttpError::InvalidDeviceType { command });
    }
    let policy_key = headers
        .policy_key
        .map(|key| {
            key.trim()
                .parse::<u32>()
                .map_err(|_| HttpError::InvalidPolicyKey)
        })
        .transpose()?;
    params.accept_multipart = headers
        .accept_multipart
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("T"));
    let raw_version = headers.protocol_version.map(str::trim);
    Ok(RequestLine {
        command,
        user: Some(user),
        device_id: DeviceId(match device_id {
            Cow::Borrowed(id) => Cow::Borrowed(id.as_bytes()),
            Cow::Owned(id) => Cow::Owned(id.into_bytes()),
        }),
        device_type,
        version: raw_version.and_then(|v| ProtocolVersion::parse(v.as_bytes())),
        raw_version,
        policy_key,
        locale: None,
        params,
        form: QueryForm::Plain,
    })
}

const PARAM_ATTACHMENT_NAME: u8 = 0;
const PARAM_COLLECTION_ID: u8 = 1;
const PARAM_ITEM_ID: u8 = 3;
const PARAM_LONG_ID: u8 = 4;
const PARAM_OCCURRENCE: u8 = 6;
const PARAM_OPTIONS: u8 = 7;
const PARAM_USER: u8 = 8;

fn parse_base64<'a>(query: &'a str) -> Result<RequestLine<'a>, HttpError> {
    let encoded = percent_decode(query, 0)?;
    let mut raw = Vec::with_capacity(encoded.len());
    base64_decode_into(
        encoded.as_bytes(),
        &mut raw,
        MAX_QUERY_LEN,
        Base64Mode::Lenient,
    )
    .map_err(|err| HttpError::Base64 { offset: err.offset })?;
    let mut reader = LeReader::new(&raw);
    let version_code = reader.u8()?;
    let command = Command::from_code(reader.u8()?).ok_or(HttpError::UnknownCommand)?;
    let locale = reader.u16()?;
    let device_id_len = reader.u8()?;
    if device_id_len == 0 {
        return Err(HttpError::MissingDeviceId);
    }
    if usize::from(device_id_len) > MAX_DEVICE_ID_LEN {
        return Err(HttpError::InvalidDeviceId { command });
    }
    let device_id = reader.bytes(usize::from(device_id_len))?.to_vec();
    let policy_key = match reader.u8()? {
        0 => None,
        POLICY_KEY_LEN => Some(reader.u32()?),
        _ => return Err(HttpError::InvalidPolicyKey),
    };
    let device_type_len = reader.u8()?;
    if device_type_len == 0 {
        return Err(HttpError::MissingDeviceType);
    }
    if usize::from(device_type_len) > MAX_DEVICE_TYPE_LEN {
        return Err(HttpError::InvalidDeviceType { command });
    }
    let device_type = owned_str(reader.bytes(usize::from(device_type_len))?)?;
    let mut user = None;
    let mut params = RequestParams::default();
    while !reader.is_empty() {
        let tag = reader.u8()?;
        let len = reader.u8()?;
        let value = reader.bytes(usize::from(len))?;
        match tag {
            PARAM_ATTACHMENT_NAME => params.attachment_name = Some(owned_str(value)?),
            PARAM_COLLECTION_ID => params.collection_id = Some(owned_str(value)?),
            PARAM_ITEM_ID => params.item_id = Some(owned_str(value)?),
            PARAM_LONG_ID => params.long_id = Some(owned_str(value)?),
            PARAM_OCCURRENCE => params.occurrence = Some(owned_str(value)?),
            PARAM_OPTIONS => {
                let [options] = value else {
                    return Err(HttpError::InvalidParameter { tag });
                };
                params.save_in_sent = options & OPTION_SAVE_IN_SENT != 0;
                params.accept_multipart = options & OPTION_ACCEPT_MULTIPART != 0;
            }
            PARAM_USER => user = Some(owned_str(value)?),
            _ => {}
        }
    }
    Ok(RequestLine {
        command,
        user,
        device_id: DeviceId(Cow::Owned(device_id)),
        device_type,
        version: ProtocolVersion::from_code(version_code),
        raw_version: legacy_version_name(version_code),
        policy_key,
        locale: Some(locale),
        params,
        form: QueryForm::Base64,
    })
}

fn legacy_version_name(code: u8) -> Option<&'static str> {
    match code {
        25 => Some("2.5"),
        120 => Some("12.0"),
        121 => Some("12.1"),
        _ => ProtocolVersion::from_code(code).map(ProtocolVersion::as_str),
    }
}

fn owned_str<'a>(value: &[u8]) -> Result<Cow<'a, str>, HttpError> {
    std::str::from_utf8(value)
        .map(|value| Cow::Owned(value.to_owned()))
        .map_err(|_| HttpError::Utf8)
}

fn percent_decode(value: &str, offset: usize) -> Result<Cow<'_, str>, HttpError> {
    let Some(first) = memchr::memchr(b'%', value.as_bytes()) else {
        return Ok(Cow::Borrowed(value));
    };
    let (plain, mut rest) = value.as_bytes().split_at(first);
    let mut out = Vec::with_capacity(value.len());
    out.extend_from_slice(plain);
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let position = offset.saturating_add(value.len() - rest.len());
            let Some(([hi, lo], tail)) = tail.split_first_chunk::<2>() else {
                return Err(HttpError::PercentEncoding { offset: position });
            };
            let (Some(hi), Some(lo)) = (hex_value(*hi), hex_value(*lo)) else {
                return Err(HttpError::PercentEncoding { offset: position });
            };
            out.push((hi << 4) | lo);
            rest = tail;
        } else {
            out.push(byte);
            rest = tail;
        }
    }
    String::from_utf8(out)
        .map(Cow::Owned)
        .map_err(|_| HttpError::Utf8)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
