/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::session::{SessionKey, SessionKind};
use exchange_proto::{
    common::UtcSeconds,
    mapi::{
        Endpoint, RequestType, ResponseCode,
        http::{
            CONTENT_TYPE, COOKIE_CONTEXT, COOKIE_SEQUENCE, MapiHeaders, PENDING_PERIOD_MS,
            RawMapiHeaders, header, validate_headers, write_error_page,
        },
        stream::{DoneTrailer, MetaTag, write_done, write_meta},
    },
};
use futures::stream;
use http_body_util::{StreamBody, combinators::BoxBody};
use http_proto::{HttpRequest, HttpResponse};
use hyper::{
    StatusCode,
    body::{Bytes, Frame},
    header::COOKIE,
};
use std::{
    pin::pin,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DONE_TRAILER_HINT: usize = 96;

pub const SERVER_APPLICATION: &str = "Exchange/15.02.1544.004";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiration {
    Connect,
    Session,
}

impl Expiration {
    fn millis(self) -> u32 {
        match self {
            Expiration::Connect => exchange_proto::mapi::http::EXPIRATION_CONNECT_MS,
            Expiration::Session => exchange_proto::mapi::http::EXPIRATION_MS,
        }
    }
}

pub struct Envelope {
    pub endpoint: Endpoint,
    pub request_type: RequestType,
    pub request_id: Box<str>,
    pub client_info: Option<Box<str>>,
    pub context: Option<Box<str>>,
    pub sequence: Option<Box<str>>,
    pub started: Instant,
    pub start_time: UtcSeconds,
}

pub struct Reply {
    pub body: Vec<u8>,
    pub response_code: Option<ResponseCode>,
    pub cookies: Option<CookieSet>,
    pub expiration: Option<Expiration>,
}

impl Reply {
    pub fn response_code(code: ResponseCode) -> Self {
        Reply {
            body: Vec::new(),
            response_code: Some(code),
            cookies: None,
            expiration: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CookieSet {
    pub context: SessionKey,
    pub sequence: Option<u64>,
    pub expired: bool,
}

pub fn endpoint_from_path(path: &str) -> Option<Endpoint> {
    let rest = path.trim_start_matches('/');
    let (_, rest) = rest.split_once('/')?;
    let segment = rest.split('/').next().unwrap_or_default();
    hashify::map_ignore_case!(segment.as_bytes(), Endpoint,
        "emsmdb" => Endpoint::Emsmdb,
        "nspi" => Endpoint::Nspi,
    )
    .copied()
}

fn header_bytes<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a [u8]> {
    req.headers().get(name).map(|value| value.as_bytes())
}

pub fn parse_envelope(req: &HttpRequest, endpoint: Endpoint) -> Result<Envelope, EnvelopeError> {
    let raw = RawMapiHeaders {
        request_type: header_bytes(req, header::REQUEST_TYPE),
        request_id: header_bytes(req, header::REQUEST_ID),
        client_info: header_bytes(req, header::CLIENT_INFO),
        client_application: header_bytes(req, header::CLIENT_APPLICATION),
        content_type: header_bytes(req, hyper::header::CONTENT_TYPE.as_str()),
    };
    let MapiHeaders {
        request_type,
        request_id,
        client_info,
        ..
    } = validate_headers(endpoint, &raw).map_err(|err| EnvelopeError {
        code: err.response_code(),
        request_type: raw
            .request_type
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(Box::from),
        request_id: raw
            .request_id
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(Box::from),
    })?;
    let (context, sequence) = cookies(req);
    Ok(Envelope {
        endpoint,
        request_type,
        request_id: request_id.as_str().into(),
        client_info: client_info.map(Box::from),
        context,
        sequence,
        started: Instant::now(),
        start_time: UtcSeconds(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
        ),
    })
}

fn cookies(req: &HttpRequest) -> (Option<Box<str>>, Option<Box<str>>) {
    let mut context = None;
    let mut sequence = None;
    for value in req.headers().get_all(COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.eq_ignore_ascii_case(COOKIE_CONTEXT) {
                context = Some(value.trim().into());
            } else if name.eq_ignore_ascii_case(COOKIE_SEQUENCE) {
                sequence = Some(value.trim().into());
            }
        }
    }
    (context, sequence)
}

pub struct EnvelopeError {
    pub code: ResponseCode,
    pub request_type: Option<Box<str>>,
    pub request_id: Option<Box<str>>,
}

impl EnvelopeError {
    pub fn new(code: ResponseCode) -> Self {
        EnvelopeError {
            code,
            request_type: None,
            request_id: None,
        }
    }

    pub fn into_response(self) -> HttpResponse {
        let mut body = Vec::new();
        write_error_page(&mut body, self.code);
        let mut response = HttpResponse::new(StatusCode::OK)
            .with_content_type(self.code.content_type())
            .with_header(header::RESPONSE_CODE, self.code.code().to_string())
            .with_header(header::SERVER_APPLICATION, SERVER_APPLICATION)
            .with_cache_control("private")
            .with_binary_body(body);
        if let Some(request_type) = self.request_type {
            response = response.with_header(header::REQUEST_TYPE, request_type.as_ref());
        }
        if let Some(request_id) = self.request_id {
            response = response.with_header(header::REQUEST_ID, request_id.as_ref());
        }
        response
    }
}

pub(crate) fn endpoint_path(endpoint: Endpoint) -> &'static str {
    match endpoint {
        Endpoint::Emsmdb => "/mapi/emsmdb",
        Endpoint::Nspi => "/mapi/nspi",
    }
}

impl Envelope {
    pub fn error(&self, code: ResponseCode) -> HttpResponse {
        EnvelopeError {
            code,
            request_type: Some(self.request_type.header_value().into()),
            request_id: Some(self.request_id.clone()),
        }
        .into_response()
    }

    pub fn context_key(
        &self,
        kind: SessionKind,
        account_id: u32,
    ) -> Result<SessionKey, ResponseCode> {
        let value = self.context.as_deref().ok_or(ResponseCode::MissingCookie)?;
        let key = SessionKey::parse(kind, value).ok_or(ResponseCode::InvalidContextCookie)?;
        if key.account_id == account_id {
            Ok(key)
        } else {
            Err(ResponseCode::ContextNotFound)
        }
    }

    pub fn sequence_value(&self) -> Option<u64> {
        self.sequence
            .as_deref()
            .and_then(|value| u64::from_str_radix(value, 16).ok())
    }

    pub fn reply(&self, reply: Reply) -> HttpResponse {
        if let Some(code) = reply
            .response_code
            .filter(|code| *code != ResponseCode::Success)
        {
            let response = self.error(code);
            return match &reply.cookies {
                Some(cookies) => self.with_cookies(response, cookies),
                None => response,
            };
        }
        let mut prefix = Vec::with_capacity(128);
        write_meta(&mut prefix, MetaTag::Processing);
        write_done(
            &mut prefix,
            &DoneTrailer {
                start: self.start_time,
                elapsed_ms: u32::try_from(self.started.elapsed().as_millis()).unwrap_or(u32::MAX),
                response_code: None,
            },
        );
        let frames = [prefix, reply.body]
            .into_iter()
            .filter(|data| !data.is_empty())
            .map(|data| Ok::<_, hyper::Error>(Frame::data(Bytes::from(data))));
        self.response(reply.expiration, reply.cookies.as_ref())
            .with_stream_body(BoxBody::new(StreamBody::new(stream::iter(frames))))
    }

    pub fn streamed_reply(
        &self,
        expiration: Expiration,
        cookies: CookieSet,
        work: impl Future<Output = Vec<u8>> + Send + Sync + 'static,
    ) -> HttpResponse {
        let start = self.start_time;
        let started = self.started;
        let period = Duration::from_millis(u64::from(PENDING_PERIOD_MS));
        let stream = async_stream::stream! {
            yield Ok::<_, hyper::Error>(Frame::data(Bytes::from_static(
                MetaTag::Processing.as_bytes(),
            )));
            let mut work = pin!(work);
            let body = loop {
                match tokio::time::timeout(period, &mut work).await {
                    Ok(body) => break body,
                    Err(_) => {
                        yield Ok(Frame::data(Bytes::from_static(MetaTag::Pending.as_bytes())));
                    }
                }
            };
            let mut tail = Vec::with_capacity(DONE_TRAILER_HINT.saturating_add(body.len()));
            write_done(
                &mut tail,
                &DoneTrailer {
                    start,
                    elapsed_ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
                    response_code: None,
                },
            );
            tail.extend_from_slice(&body);
            yield Ok(Frame::data(Bytes::from(tail)));
        };
        self.response(Some(expiration), Some(&cookies))
            .with_stream_body(BoxBody::new(StreamBody::new(stream)))
    }

    fn response(
        &self,
        expiration: Option<Expiration>,
        cookies: Option<&CookieSet>,
    ) -> HttpResponse {
        let mut response = HttpResponse::new(StatusCode::OK)
            .with_content_type(CONTENT_TYPE)
            .with_header(header::REQUEST_TYPE, self.request_type.header_value())
            .with_header(header::REQUEST_ID, self.request_id.as_ref())
            .with_header(header::RESPONSE_CODE, "0")
            .with_header(header::SERVER_APPLICATION, SERVER_APPLICATION)
            .with_header(header::PENDING_PERIOD, PENDING_PERIOD_MS.to_string())
            .with_cache_control("private");
        if let Some(client_info) = &self.client_info {
            response = response.with_header(header::CLIENT_INFO, client_info.as_ref());
        }
        if let Some(expiration) = expiration {
            response =
                response.with_header(header::EXPIRATION_INFO, expiration.millis().to_string());
        }
        match cookies {
            Some(cookies) => self.with_cookies(response, cookies),
            None => response,
        }
    }

    fn with_cookies(&self, mut response: HttpResponse, cookies: &CookieSet) -> HttpResponse {
        let path = endpoint_path(self.endpoint);
        let attributes = if cookies.expired {
            "; Max-Age=0; secure; HttpOnly"
        } else {
            "; secure; HttpOnly"
        };
        response = response.with_header(
            hyper::header::SET_COOKIE,
            format!(
                "{COOKIE_CONTEXT}={}; path={path}{attributes}",
                cookies.context.to_cookie()
            ),
        );
        if let Some(sequence) = cookies.sequence {
            response = response.with_header(
                hyper::header::SET_COOKIE,
                format!("{COOKIE_SEQUENCE}={sequence:016x}; path={path}{attributes}"),
            );
        }
        response
    }
}
