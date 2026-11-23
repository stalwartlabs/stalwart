/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

const PATH_VERSION: &str = "v1.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Request<'a> {
    pub email: Option<Cow<'a, str>>,
    pub protocol: Result<V2Protocol, V2ErrorCode>,
    pub redirect_count: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2Protocol {
    ActiveSync,
    AutodiscoverV1,
    Ews,
    Rest,
    CloudOnly(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2ErrorCode {
    MissingProtocol,
    InvalidProtocol,
    MandatoryParameterMissing,
}

impl V2Protocol {
    pub fn parse(name: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(
            name,
            V2Protocol,
            "ActiveSync" => V2Protocol::ActiveSync,
            "AutodiscoverV1" => V2Protocol::AutodiscoverV1,
            "Ews" => V2Protocol::Ews,
            "Rest" => V2Protocol::Rest,
            "Substrate" => V2Protocol::CloudOnly("Substrate"),
            "SubstrateSearchService" => V2Protocol::CloudOnly("SubstrateSearchService"),
            "SubstrateNotificationService" => V2Protocol::CloudOnly("SubstrateNotificationService"),
            "OutlookMeetingScheduler" => V2Protocol::CloudOnly("OutlookMeetingScheduler"),
            "OutlookPay" => V2Protocol::CloudOnly("OutlookPay"),
            "Actions" => V2Protocol::CloudOnly("Actions"),
            "Connectors" => V2Protocol::CloudOnly("Connectors"),
            "ConnectorsProcessors" => V2Protocol::CloudOnly("ConnectorsProcessors"),
            "ConnectorsWebhook" => V2Protocol::CloudOnly("ConnectorsWebhook"),
            "NotesClient" => V2Protocol::CloudOnly("NotesClient"),
            "OwaPoweredExperience" => V2Protocol::CloudOnly("OwaPoweredExperience"),
            "ToDo" => V2Protocol::CloudOnly("ToDo"),
            "Weve" => V2Protocol::CloudOnly("Weve"),
            "OutlookLocationsService" => V2Protocol::CloudOnly("OutlookLocationsService"),
            "OutlookCloudSettingsService" => V2Protocol::CloudOnly("OutlookCloudSettingsService"),
            "OutlookTailoredExperiences" => V2Protocol::CloudOnly("OutlookTailoredExperiences"),
            "OwaPoweredExperienceV2" => V2Protocol::CloudOnly("OwaPoweredExperienceV2"),
            "Speedway" => V2Protocol::CloudOnly("Speedway"),
            "SpeechAndLanguagePersonalization" => V2Protocol::CloudOnly("SpeechAndLanguagePersonalization"),
            "SubstrateSignalService" => V2Protocol::CloudOnly("SubstrateSignalService"),
            "CompliancePolicyService" => V2Protocol::CloudOnly("CompliancePolicyService"),
        )
        .copied()
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            V2Protocol::ActiveSync => "ActiveSync",
            V2Protocol::AutodiscoverV1 => "AutodiscoverV1",
            V2Protocol::Ews => "Ews",
            V2Protocol::Rest => "Rest",
            V2Protocol::CloudOnly(name) => name,
        }
    }
}

impl V2ErrorCode {
    pub const HTTP_STATUS: u16 = 400;

    pub const fn as_str(self) -> &'static str {
        match self {
            V2ErrorCode::MissingProtocol => "MissingProtocol",
            V2ErrorCode::InvalidProtocol => "InvalidProtocol",
            V2ErrorCode::MandatoryParameterMissing => "MandatoryParameterMissing",
        }
    }
}

#[derive(Clone, Copy)]
enum QueryKey {
    Email,
    Protocol,
    RedirectCount,
}

pub fn parse_v2_request<'a>(path_tail: &'a str, query: Option<&'a str>) -> V2Request<'a> {
    let mut email = None;
    let mut protocol = None;
    let mut redirect_count = None;

    for pair in query.unwrap_or_default().split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key);
        let Some(key) = hashify::map_ignore_case!(
            key.as_bytes(),
            QueryKey,
            "Email" => QueryKey::Email,
            "Protocol" => QueryKey::Protocol,
            "RedirectCount" => QueryKey::RedirectCount,
        ) else {
            continue;
        };
        match key {
            QueryKey::Email => {
                if email.is_none() {
                    email = Some(percent_decode(value)).filter(|value| !value.is_empty());
                }
            }
            QueryKey::Protocol => {
                if protocol.is_none() {
                    protocol = Some(percent_decode(value));
                }
            }
            QueryKey::RedirectCount => {
                if redirect_count.is_none() {
                    redirect_count = parse_redirect_count(percent_decode(value).trim());
                }
            }
        }
    }

    if email.is_none() {
        email = path_email(path_tail);
    }

    let protocol = match protocol.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => {
            V2Protocol::parse(name.as_bytes()).ok_or(V2ErrorCode::InvalidProtocol)
        }
        _ => Err(V2ErrorCode::MissingProtocol),
    };

    V2Request {
        email,
        protocol,
        redirect_count,
    }
}

fn parse_redirect_count(value: &str) -> Option<u8> {
    if value.is_empty() || !value.bytes().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(value.parse::<u8>().unwrap_or(u8::MAX))
}

fn path_email(path_tail: &str) -> Option<Cow<'_, str>> {
    let (version, email) = path_tail.trim_start_matches('/').split_once('/')?;
    if !version.eq_ignore_ascii_case(PATH_VERSION) {
        return None;
    }
    let email = email.trim_end_matches('/');
    Some(percent_decode(email)).filter(|email| !email.is_empty() && !email.contains('/'))
}

fn percent_decode(value: &str) -> Cow<'_, str> {
    if memchr::memchr(b'%', value.as_bytes()).is_none() {
        return Cow::Borrowed(value);
    }
    let mut out = Vec::with_capacity(value.len());
    let mut pieces = value.as_bytes().split(|&ch| ch == b'%');
    out.extend_from_slice(pieces.next().unwrap_or_default());
    for piece in pieces {
        match piece {
            [hi, lo, rest @ ..] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                out.push((hex_value(*hi) << 4) | hex_value(*lo));
                out.extend_from_slice(rest);
            }
            _ => {
                out.push(b'%');
                out.extend_from_slice(piece);
            }
        }
    }
    match String::from_utf8(out) {
        Ok(decoded) => Cow::Owned(decoded),
        Err(_) => Cow::Borrowed(value),
    }
}

fn hex_value(ch: u8) -> u8 {
    match ch {
        b'0'..=b'9' => ch - b'0',
        b'a'..=b'f' => ch - b'a' + 10,
        _ => ch.wrapping_sub(b'A').wrapping_add(10),
    }
}

pub fn write_v2_success(out: &mut Vec<u8>, protocol: V2Protocol, url: &str) {
    out.extend_from_slice(b"{\"Protocol\":\"");
    out.extend_from_slice(protocol.as_str().as_bytes());
    out.extend_from_slice(b"\",\"Url\":\"");
    json_escape(url, out);
    out.extend_from_slice(b"\"}");
}

pub fn write_v2_error(out: &mut Vec<u8>, code: V2ErrorCode, message: &str) {
    out.extend_from_slice(b"{\"ErrorCode\":\"");
    out.extend_from_slice(code.as_str().as_bytes());
    out.extend_from_slice(b"\",\"ErrorMessage\":\"");
    json_escape(message, out);
    out.extend_from_slice(b"\"}");
}

fn json_escape(value: &str, out: &mut Vec<u8>) {
    out.reserve(value.len());
    for chunk in value
        .as_bytes()
        .split_inclusive(|&ch| json_needs_escape(ch))
    {
        match chunk.split_last() {
            Some((&last, head)) if json_needs_escape(last) => {
                out.extend_from_slice(head);
                match last {
                    b'"' => out.extend_from_slice(b"\\\""),
                    b'\\' => out.extend_from_slice(b"\\\\"),
                    b'\n' => out.extend_from_slice(b"\\n"),
                    b'\r' => out.extend_from_slice(b"\\r"),
                    b'\t' => out.extend_from_slice(b"\\t"),
                    _ => {
                        out.extend_from_slice(b"\\u00");
                        out.push(hex_digit(last >> 4));
                        out.push(hex_digit(last & 0x0f));
                    }
                }
            }
            _ => out.extend_from_slice(chunk),
        }
    }
}

const fn json_needs_escape(ch: u8) -> bool {
    ch < 0x20 || ch == b'"' || ch == b'\\'
}

const fn hex_digit(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + nibble - 10
    }
}
