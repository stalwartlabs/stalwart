/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    conn::ReceivedResponse,
    endpoint::Transport,
    retry::{cap_server_delay, parse_retry_after},
};
use crate::proto::reader::{PartialSuccess, RpcStatus};
use encodify::base64::{Base64, Padding, STANDARD};
use http::{
    StatusCode,
    header::{CONTENT_TYPE, RETRY_AFTER},
};
use std::{
    fmt::Write,
    time::{Duration, SystemTime},
};

const GRPC_CONTENT_TYPE: &[u8] = b"application/grpc";
const GRPC_STATUS: &str = "grpc-status";
const GRPC_MESSAGE: &str = "grpc-message";
const GRPC_STATUS_DETAILS: &str = "grpc-status-details-bin";
const GRPC_FRAME_PREFIX: usize = 5;
const MAX_REASON_BODY: usize = 256;
const BASE64: Base64 = STANDARD.with_padding(Padding::Optional);

pub const GRPC_OK: u32 = 0;
pub const GRPC_CANCELLED: u32 = 1;
pub const GRPC_UNKNOWN: u32 = 2;
pub const GRPC_DEADLINE_EXCEEDED: u32 = 4;
pub const GRPC_PERMISSION_DENIED: u32 = 7;
pub const GRPC_RESOURCE_EXHAUSTED: u32 = 8;
pub const GRPC_ABORTED: u32 = 10;
pub const GRPC_OUT_OF_RANGE: u32 = 11;
pub const GRPC_UNIMPLEMENTED: u32 = 12;
pub const GRPC_INTERNAL: u32 = 13;
pub const GRPC_UNAVAILABLE: u32 = 14;
pub const GRPC_DATA_LOSS: u32 = 15;
pub const GRPC_UNAUTHENTICATED: u32 = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Success,
    PartialSuccess {
        rejected: i64,
        message: String,
    },
    Retry {
        delay: Option<Duration>,
        reason: String,
    },
    Drop {
        reason: String,
    },
}

pub fn classify(transport: Transport, response: &ReceivedResponse, now: SystemTime) -> Verdict {
    match transport {
        Transport::Http => classify_http(response, now),
        Transport::Grpc => classify_grpc(response),
    }
}

fn classify_http(response: &ReceivedResponse, now: SystemTime) -> Verdict {
    match response.status.as_u16() {
        200..=299 => partial_success(&response.body),
        429 | 502 | 503 | 504 => Verdict::Retry {
            delay: response
                .headers
                .get(RETRY_AFTER)
                .and_then(|value| parse_retry_after(value.as_bytes(), now)),
            reason: http_reason(response),
        },
        _ => Verdict::Drop {
            reason: http_reason(response),
        },
    }
}

fn partial_success(message: &[u8]) -> Verdict {
    match PartialSuccess::parse(message) {
        Ok(Some(partial)) if partial.rejected != 0 || !partial.message.is_empty() => {
            Verdict::PartialSuccess {
                rejected: partial.rejected,
                message: String::from_utf8_lossy(capped(partial.message)).into_owned(),
            }
        }
        _ => Verdict::Success,
    }
}

fn http_reason(response: &ReceivedResponse) -> String {
    let mut reason = format!("HTTP {}", response.status);
    let is_protobuf = response
        .headers
        .get(CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"application/x-protobuf"));
    let message = if is_protobuf {
        RpcStatus::parse(&response.body)
            .ok()
            .map(|status| status.message)
            .filter(|message| !message.is_empty())
    } else {
        None
    };
    let message = capped(message.unwrap_or(&response.body));
    if !message.is_empty() {
        let _ = write!(reason, ": {}", String::from_utf8_lossy(message).trim());
    }
    reason
}

fn classify_grpc(response: &ReceivedResponse) -> Verdict {
    let is_grpc = response
        .headers
        .get(CONTENT_TYPE)
        .is_some_and(|value| is_grpc_content_type(value.as_bytes()));
    if response.status != StatusCode::OK || !is_grpc {
        let code = if response.status == StatusCode::OK {
            GRPC_UNKNOWN
        } else {
            http_to_grpc(response.status)
        };
        let reason = format!(
            "gRPC status {code} from HTTP {}{}",
            response.status,
            if is_grpc {
                ""
            } else {
                " (not a gRPC response)"
            }
        );
        return grpc_verdict(code, None, reason);
    }

    let lookup = |name: &str| -> Option<&http::HeaderValue> {
        response.headers.get(name).or_else(|| {
            response
                .trailers
                .as_ref()
                .and_then(|trailers| trailers.get(name))
        })
    };
    let Some(code) = lookup(GRPC_STATUS)
        .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
        .and_then(|value| value.trim().parse::<u32>().ok())
    else {
        return grpc_verdict(GRPC_UNKNOWN, None, "Missing grpc-status".to_string());
    };

    if code == GRPC_OK {
        return match response.body.split_first_chunk::<GRPC_FRAME_PREFIX>() {
            Some(([0, ..], message)) => partial_success(message),
            _ => Verdict::Success,
        };
    }

    let mut details_buf = Vec::new();
    let details = lookup(GRPC_STATUS_DETAILS)
        .and_then(|value| {
            BASE64
                .decode_append(value.as_bytes(), &mut details_buf)
                .ok()
        })
        .and_then(|_| RpcStatus::parse(&details_buf).ok());
    let mut reason = format!("gRPC status {code}");
    if let Some(message) = lookup(GRPC_MESSAGE) {
        reason.push_str(": ");
        percent_decode_into(message.as_bytes(), &mut reason);
    } else if let Some(message) = details
        .as_ref()
        .map(|status| status.message)
        .filter(|m| !m.is_empty())
    {
        reason.push_str(": ");
        reason.push_str(&String::from_utf8_lossy(capped(message)));
    }
    grpc_verdict(code, details.and_then(|status| status.retry_delay), reason)
}

fn grpc_verdict(code: u32, retry_delay: Option<Duration>, reason: String) -> Verdict {
    match code {
        GRPC_CANCELLED
        | GRPC_DEADLINE_EXCEEDED
        | GRPC_ABORTED
        | GRPC_OUT_OF_RANGE
        | GRPC_UNAVAILABLE
        | GRPC_DATA_LOSS => Verdict::Retry {
            delay: retry_delay.map(cap_server_delay),
            reason,
        },
        GRPC_RESOURCE_EXHAUSTED if retry_delay.is_some() => Verdict::Retry {
            delay: retry_delay.map(cap_server_delay),
            reason,
        },
        _ => Verdict::Drop { reason },
    }
}

fn http_to_grpc(status: StatusCode) -> u32 {
    match status.as_u16() {
        400 => GRPC_INTERNAL,
        401 => GRPC_UNAUTHENTICATED,
        403 => GRPC_PERMISSION_DENIED,
        404 => GRPC_UNIMPLEMENTED,
        429 | 502 | 503 | 504 => GRPC_UNAVAILABLE,
        _ => GRPC_UNKNOWN,
    }
}

fn capped(message: &[u8]) -> &[u8] {
    message.get(..MAX_REASON_BODY).unwrap_or(message)
}

fn is_grpc_content_type(value: &[u8]) -> bool {
    value
        .strip_prefix(GRPC_CONTENT_TYPE)
        .is_some_and(|rest| matches!(rest.first(), None | Some(b'+' | b';')))
}

fn percent_decode_into(value: &[u8], out: &mut String) {
    let mut decoded = Vec::with_capacity(value.len().min(MAX_REASON_BODY));
    let mut bytes = value.iter();
    while decoded.len() < MAX_REASON_BODY
        && let Some(byte) = bytes.next()
    {
        if *byte == b'%' {
            let mut lookahead = bytes.clone();
            if let (Some(high), Some(low)) = (
                lookahead.next().and_then(|b| (*b as char).to_digit(16)),
                lookahead.next().and_then(|b| (*b as char).to_digit(16)),
            ) {
                decoded.push((high * 16 + low) as u8);
                bytes = lookahead;
                continue;
            }
        }
        decoded.push(*byte);
    }
    out.push_str(&String::from_utf8_lossy(&decoded));
}
