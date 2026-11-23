/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{IMPLEMENTED_COMMANDS, SUPPORTED_VERSIONS};
use bytes::Bytes;
use exchange_proto::eas::{
    http::Command,
    status::{HeaderValue, HttpOutcome, Status},
    tokens::{
        ProtocolVersion, Tag,
        tag::{
            airsync, compose_mail, find, folder_hierarchy, get_item_estimate, item_operations,
            meeting_response, move_items, ping, provision, resolve_recipients, search, settings,
            validate_cert,
        },
    },
    wbxml::{Encoder, Segments},
};
use flate2::{Compression, write::GzEncoder};
use http_body_util::BodyExt;
use http_proto::HttpResponse;
use hyper::{
    StatusCode,
    body::{Body, Frame, SizeHint},
    header::{CONTENT_ENCODING, HeaderValue as HttpHeaderValue, VARY},
};
use std::{
    io::Write,
    pin::Pin,
    task::{Context, Poll},
    vec,
};
use tokio::task::spawn_blocking;

pub const WBXML_CONTENT_TYPE: &str = "application/vnd.ms-sync.wbxml";
pub const MULTIPART_CONTENT_TYPE: &str = "application/vnd.ms-sync.multipart";
pub const SERVER_VERSION: &str = "16.1";
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const GZIP_MIN_BYTES: usize = 128;
const GZIP_INLINE_MAX_BYTES: usize = 32 * 1024;
const QVALUE_MAX: u16 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCoding {
    Identity,
    Gzip,
}

pub enum EasResponse {
    Empty,
    Wbxml(Segments),
    Resync(Segments),
    Multipart(Vec<Bytes>),
    Raw {
        content_type: HttpHeaderValue,
        data: Bytes,
    },
    Status {
        command: Command,
        status: Status,
    },
    Http(HttpOutcome),
}

impl EasResponse {
    pub fn status(command: Command, status: Status) -> Self {
        EasResponse::Status { command, status }
    }

    pub fn encode(version: ProtocolVersion, write: impl FnOnce(&mut Encoder)) -> Self {
        let mut encoder = Encoder::new(version);
        write(&mut encoder);
        EasResponse::Wbxml(encoder.finish())
    }

    pub async fn into_http_coded(
        self,
        version: Option<ProtocolVersion>,
        coding: ContentCoding,
    ) -> trc::Result<HttpResponse> {
        match (coding, self) {
            (ContentCoding::Gzip, EasResponse::Wbxml(segments)) => {
                gzip_response(wbxml_headers(HttpResponse::new(StatusCode::OK)), segments).await
            }
            (ContentCoding::Gzip, EasResponse::Resync(segments)) => {
                gzip_response(resync_headers(HttpResponse::new(StatusCode::OK)), segments).await
            }
            (_, response) => Ok(response.into_http(version)),
        }
    }

    pub fn into_http(self, version: Option<ProtocolVersion>) -> HttpResponse {
        let response = match self {
            EasResponse::Empty => HttpResponse::new(StatusCode::OK).with_content_length(0),
            EasResponse::Wbxml(segments) => parts_body(
                wbxml_headers(HttpResponse::new(StatusCode::OK)),
                segments.into_parts().collect(),
            ),
            EasResponse::Resync(segments) => parts_body(
                resync_headers(HttpResponse::new(StatusCode::OK)),
                segments.into_parts().collect(),
            ),
            EasResponse::Multipart(parts) => parts_body(
                HttpResponse::new(StatusCode::OK).with_content_type(MULTIPART_CONTENT_TYPE),
                parts,
            ),
            EasResponse::Raw { content_type, data } => HttpResponse::new(StatusCode::OK)
                .with_content_type(content_type)
                .with_binary_body(data),
            EasResponse::Status { command, status } => {
                let Some((root, status_tag)) = status_root(command) else {
                    return HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                        .with_header("MS-Server-ActiveSync", SERVER_VERSION);
                };
                let mut encoder = Encoder::new(version.unwrap_or(ProtocolVersion::V141));
                let code = u64::from(status.0);
                encoder.start(root);
                match command {
                    Command::MeetingResponse => encoder
                        .start(meeting_response::RESULT)
                        .text_u64(status_tag, code)
                        .end(),
                    _ => encoder.text_u64(status_tag, code),
                };
                encoder.end();
                HttpResponse::new(StatusCode::OK)
                    .with_content_type(WBXML_CONTENT_TYPE)
                    .with_binary_body(encoder.finish().into_vec())
            }
            EasResponse::Http(outcome) => {
                let response = HttpResponse::new(
                    StatusCode::from_u16(outcome.status_code())
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                );
                let response = match outcome.header() {
                    Some((name, HeaderValue::Text(value))) => {
                        response.with_header(name, value.to_string())
                    }
                    Some((name, HeaderValue::Seconds(value))) => {
                        response.with_header(name, value.to_string())
                    }
                    None => response,
                };
                if matches!(outcome, HttpOutcome::BadRequest) {
                    response
                        .with_header("MS-ASProtocolVersions", SUPPORTED_VERSIONS)
                        .with_content_length(0)
                } else {
                    response.with_content_length(0)
                }
            }
        };
        response.with_header("MS-Server-ActiveSync", SERVER_VERSION)
    }
}

impl ContentCoding {
    pub fn negotiate<'x>(values: impl IntoIterator<Item = &'x [u8]>) -> Self {
        let mut preferences = CodingPreferences::default();
        for item in values
            .into_iter()
            .flat_map(|value| value.split(|byte| *byte == b','))
        {
            preferences.add(item);
        }
        preferences.coding()
    }
}

#[derive(Clone, Copy)]
enum ListedCoding {
    Gzip,
    Identity,
    Any,
}

#[derive(Default)]
struct CodingPreferences {
    gzip: Option<u16>,
    identity: Option<u16>,
    any: Option<u16>,
}

impl CodingPreferences {
    fn add(&mut self, item: &[u8]) {
        let mut params = item.split(|byte| *byte == b';');
        let Some(listed) = params.next().and_then(|coding| {
            hashify::map_ignore_case!(coding.trim_ascii(), ListedCoding,
                "gzip" => ListedCoding::Gzip,
                "x-gzip" => ListedCoding::Gzip,
                "identity" => ListedCoding::Identity,
                "*" => ListedCoding::Any,
            )
            .copied()
        }) else {
            return;
        };
        let mut quality = Some(QVALUE_MAX);
        for param in params {
            let mut pair = param.splitn(2, |byte| *byte == b'=');
            if pair
                .next()
                .is_some_and(|name| name.trim_ascii().eq_ignore_ascii_case(b"q"))
            {
                quality = pair.next().and_then(|value| qvalue(value.trim_ascii()));
            }
        }
        let Some(quality) = quality else {
            return;
        };
        let slot = match listed {
            ListedCoding::Gzip => &mut self.gzip,
            ListedCoding::Identity => &mut self.identity,
            ListedCoding::Any => &mut self.any,
        };
        *slot = Some(slot.map_or(quality, |current| current.max(quality)));
    }

    fn coding(&self) -> ContentCoding {
        let gzip = self.gzip.or(self.any).unwrap_or(0);
        let identity = self.identity.or(self.any).unwrap_or(0);
        if gzip > 0 && gzip >= identity {
            ContentCoding::Gzip
        } else {
            ContentCoding::Identity
        }
    }
}

fn qvalue(value: &[u8]) -> Option<u16> {
    let (whole, fraction) = value.split_first()?;
    let digits = match fraction {
        [] => &[][..],
        [b'.', digits @ ..] if digits.len() <= 3 => digits,
        _ => return None,
    };
    match whole {
        b'1' => digits
            .iter()
            .all(|digit| *digit == b'0')
            .then_some(QVALUE_MAX),
        b'0' => digits
            .iter()
            .zip([100u16, 10, 1])
            .try_fold(0u16, |total, (digit, scale)| {
                digit
                    .is_ascii_digit()
                    .then(|| total + u16::from(digit - b'0') * scale)
            }),
        _ => None,
    }
}

fn wbxml_headers(response: HttpResponse) -> HttpResponse {
    response
        .with_content_type(WBXML_CONTENT_TYPE)
        .with_header(VARY, "Accept-Encoding")
}

fn resync_headers(response: HttpResponse) -> HttpResponse {
    wbxml_headers(response)
        .with_header("X-MS-RP", SUPPORTED_VERSIONS)
        .with_header("MS-ASProtocolVersions", SUPPORTED_VERSIONS)
        .with_header("MS-ASProtocolCommands", protocol_commands())
}

async fn gzip_response(response: HttpResponse, segments: Segments) -> trc::Result<HttpResponse> {
    let len = segments.len();
    let (segments, body) = if len < GZIP_MIN_BYTES {
        (segments, None)
    } else if len <= GZIP_INLINE_MAX_BYTES {
        let body = gzip(&segments, len);
        (segments, body)
    } else {
        spawn_blocking(move || {
            let body = gzip(&segments, len);
            (segments, body)
        })
        .await
        .map_err(|err| {
            trc::EventType::Server(trc::ServerEvent::ThreadError)
                .reason(err)
                .details("EAS response compression task failed")
                .caused_by(trc::location!())
        })?
    };
    let response = match body {
        Some(body) => response
            .with_header(CONTENT_ENCODING, "gzip")
            .with_binary_body(body),
        None => parts_body(response, segments.into_parts().collect()),
    };
    Ok(response.with_header("MS-Server-ActiveSync", SERVER_VERSION))
}

fn gzip(segments: &Segments, len: usize) -> Option<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::with_capacity(len / 4), Compression::fast());
    let written = segments.iter().try_for_each(|part| encoder.write_all(part));
    written.and_then(|()| encoder.finish()).ok()
}

fn protocol_commands() -> String {
    let mut commands = String::with_capacity(256);
    for command in IMPLEMENTED_COMMANDS {
        if !commands.is_empty() {
            commands.push(',');
        }
        commands.push_str(command.name());
    }
    commands
}

pub fn options_response() -> HttpResponse {
    HttpResponse::new(StatusCode::OK)
        .with_header("Allow", "OPTIONS,POST")
        .with_header("Public", "OPTIONS,POST")
        .with_header("MS-Server-ActiveSync", SERVER_VERSION)
        .with_header("MS-ASProtocolVersions", SUPPORTED_VERSIONS)
        .with_header("MS-ASProtocolCommands", protocol_commands())
        .with_content_length(0)
}

fn status_root(command: Command) -> Option<(Tag, Tag)> {
    Some(match command {
        Command::Sync => (airsync::SYNC, airsync::STATUS),
        Command::SendMail => (compose_mail::SEND_MAIL, compose_mail::STATUS),
        Command::SmartForward => (compose_mail::SMART_FORWARD, compose_mail::STATUS),
        Command::SmartReply => (compose_mail::SMART_REPLY, compose_mail::STATUS),
        Command::FolderSync => (folder_hierarchy::FOLDER_SYNC, folder_hierarchy::STATUS),
        Command::FolderCreate => (folder_hierarchy::FOLDER_CREATE, folder_hierarchy::STATUS),
        Command::FolderDelete => (folder_hierarchy::FOLDER_DELETE, folder_hierarchy::STATUS),
        Command::FolderUpdate => (folder_hierarchy::FOLDER_UPDATE, folder_hierarchy::STATUS),
        Command::MoveItems => (move_items::MOVE_ITEMS, move_items::STATUS),
        Command::GetItemEstimate => (
            get_item_estimate::GET_ITEM_ESTIMATE,
            get_item_estimate::STATUS,
        ),
        Command::MeetingResponse => (meeting_response::MEETING_RESPONSE, meeting_response::STATUS),
        Command::Search => (search::SEARCH, search::STATUS),
        Command::Settings => (settings::SETTINGS, settings::STATUS),
        Command::Ping => (ping::PING, ping::STATUS),
        Command::ItemOperations => (item_operations::ITEM_OPERATIONS, item_operations::STATUS),
        Command::Provision => (provision::PROVISION, provision::STATUS),
        Command::ResolveRecipients => (
            resolve_recipients::RESOLVE_RECIPIENTS,
            resolve_recipients::STATUS,
        ),
        Command::ValidateCert => (validate_cert::VALIDATE_CERT, validate_cert::STATUS),
        Command::Find => (find::FIND, find::STATUS),
        Command::GetAttachment => return None,
    })
}

fn parts_body(response: HttpResponse, mut parts: Vec<Bytes>) -> HttpResponse {
    if parts.len() == 1
        && let Some(part) = parts.pop()
    {
        response.with_binary_body(part)
    } else {
        let len = parts.iter().map(Bytes::len).sum();
        response
            .with_content_length(len)
            .with_stream_body(PartsBody(parts.into_iter()).boxed())
    }
}

struct PartsBody(vec::IntoIter<Bytes>);

impl Body for PartsBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        Poll::Ready(self.0.next().map(|part| Ok(Frame::data(part))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.len() == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_slice().iter().map(|part| part.len() as u64).sum())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/eas/response/tests.rs"]
mod tests;
