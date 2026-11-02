/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::{USER_AGENT, manager::application::Resource};
use bytes::Bytes;
use encodify::base64::LENIENT;
use reqwest::{Method, Url, header::CONTENT_TYPE};
use std::{
    fmt::{self, Display},
    time::Duration,
};
use utils::{
    HttpLimitResponse, error_chain,
    outbound::{OutboundClient, OutboundError, OutboundPolicy, Redirects},
};

const MAX_LOGO_SIZE: usize = 1024 * 1024;
const MAX_LOGO_BASE64_LEN: usize = MAX_LOGO_SIZE.div_ceil(3) * 4 + 4;
const MAX_LOGO_REDIRECTS: usize = 5;
const LOGO_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, PartialEq, Eq)]
pub enum LogoSource {
    Inline {
        media_type: &'static str,
        contents: Vec<u8>,
    },
    Remote(Url),
}

#[derive(Debug)]
pub enum LogoLoadError {
    Rejected(LogoError),
    Download(reqwest::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoError {
    UnsupportedDataUri,
    UnsupportedMediaType,
    InvalidBase64,
    TooLarge,
    Url(OutboundError),
}

impl LogoSource {
    pub fn parse(logo: &str, policy: OutboundPolicy) -> Result<Self, LogoError> {
        let logo = logo.trim();

        if let Some(data_uri) = strip_prefix_ignore_case(logo, "data:") {
            let (media_type, contents) = data_uri
                .split_once(',')
                .and_then(|(meta, contents)| {
                    strip_suffix_ignore_case(meta, ";base64")
                        .map(|media_type| (media_type, contents))
                })
                .ok_or(LogoError::UnsupportedDataUri)?;
            let contents = decode_logo(contents)?;
            let media_type = if media_type.is_empty() {
                sniff_media_type(&contents)
            } else {
                allowed_media_type(media_type)
            }
            .ok_or(LogoError::UnsupportedMediaType)?;

            Ok(LogoSource::Inline {
                media_type,
                contents,
            })
        } else if strip_prefix_ignore_case(logo, "https://").is_some()
            || strip_prefix_ignore_case(logo, "http://").is_some()
        {
            policy
                .parse_url(logo)
                .map(LogoSource::Remote)
                .map_err(LogoError::Url)
        } else {
            let contents = decode_logo(logo)?;
            let media_type = sniff_media_type(&contents).ok_or(LogoError::UnsupportedMediaType)?;

            Ok(LogoSource::Inline {
                media_type,
                contents,
            })
        }
    }

    pub async fn load(self, policy: OutboundPolicy) -> Result<Resource<Bytes>, LogoLoadError> {
        match self {
            LogoSource::Inline {
                media_type,
                contents,
            } => Ok(Resource::new(media_type, Bytes::from(contents))),
            LogoSource::Remote(url) => download_logo(url, policy).await,
        }
    }
}

impl LogoLoadError {
    pub fn is_transient(&self) -> bool {
        matches!(self, LogoLoadError::Download(_))
    }
}

impl From<LogoLoadError> for trc::Error {
    fn from(err: LogoLoadError) -> Self {
        match err {
            LogoLoadError::Rejected(err) => err.into(),
            LogoLoadError::Download(err) => trc::ResourceEvent::DownloadExternal
                .into_err()
                .details("Failed to download logo")
                .reason(error_chain(&err)),
        }
    }
}

impl LogoError {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogoError::UnsupportedDataUri => "Unsupported data URI, expected base64 encoding",
            LogoError::UnsupportedMediaType => {
                "Unsupported logo format, expected PNG, JPEG, GIF, WebP, ICO or SVG"
            }
            LogoError::InvalidBase64 => "Invalid base64 logo",
            LogoError::TooLarge => "Logo exceeds maximum size",
            LogoError::Url(err) => err.as_str(),
        }
    }
}

impl Display for LogoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<LogoError> for trc::Error {
    fn from(err: LogoError) -> Self {
        trc::ResourceEvent::DownloadExternal
            .into_err()
            .details(err.as_str())
    }
}

async fn download_logo(url: Url, policy: OutboundPolicy) -> Result<Resource<Bytes>, LogoLoadError> {
    let response = OutboundClient::new(
        utils::http::http_client_builder(false)
            .user_agent(USER_AGENT)
            .timeout(LOGO_DOWNLOAD_TIMEOUT),
        policy,
        Redirects::Limited(MAX_LOGO_REDIRECTS),
    )
    .request_url(Method::GET, url)
    .map_err(|err| LogoLoadError::Rejected(LogoError::Url(err)))?
    .send()
    .await
    .map_err(LogoLoadError::Download)?;

    let declared_media_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|ct| ct.to_str().ok())
        .and_then(allowed_media_type);

    let contents = response
        .bytes_with_limit(MAX_LOGO_SIZE)
        .await
        .map_err(LogoLoadError::Download)?
        .ok_or(LogoLoadError::Rejected(LogoError::TooLarge))?;

    let media_type = declared_media_type
        .or_else(|| sniff_media_type(&contents))
        .ok_or(LogoLoadError::Rejected(LogoError::UnsupportedMediaType))?;

    Ok(Resource::new(media_type, Bytes::from(contents)))
}

fn decode_logo(contents: &str) -> Result<Vec<u8>, LogoError> {
    if contents.len() > MAX_LOGO_BASE64_LEN {
        return Err(LogoError::TooLarge);
    }
    LENIENT
        .decode(contents)
        .map_err(|_| LogoError::InvalidBase64)
}

fn media_type_essence(media_type: &str) -> &str {
    media_type
        .split_once(';')
        .map_or(media_type, |(essence, _)| essence)
        .trim()
}

fn allowed_media_type(media_type: &str) -> Option<&'static str> {
    hashify::map_ignore_case!(
        media_type_essence(media_type).as_bytes(),
        &'static str,
        "image/png" => "image/png",
        "image/jpeg" => "image/jpeg",
        "image/gif" => "image/gif",
        "image/webp" => "image/webp",
        "image/x-icon" => "image/x-icon",
        "image/vnd.microsoft.icon" => "image/x-icon",
        "image/svg+xml" => "image/svg+xml",
    )
    .copied()
}

fn sniff_media_type(contents: &[u8]) -> Option<&'static str> {
    if contents.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if contents.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if contents.starts_with(b"GIF8") {
        Some("image/gif")
    } else if contents.starts_with(b"RIFF") && contents.get(8..12) == Some(b"WEBP".as_slice()) {
        Some("image/webp")
    } else if contents.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        Some("image/x-icon")
    } else if is_svg(contents) {
        Some("image/svg+xml")
    } else {
        None
    }
}

fn is_svg(contents: &[u8]) -> bool {
    let contents = contents.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(contents);
    let contents = contents.trim_ascii_start();
    contents
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"<svg"))
        || contents.starts_with(b"<?xml")
}

fn strip_prefix_ignore_case<'x>(value: &'x str, prefix: &str) -> Option<&'x str> {
    value
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .and_then(|_| value.get(prefix.len()..))
}

fn strip_suffix_ignore_case<'x>(value: &'x str, suffix: &str) -> Option<&'x str> {
    value
        .len()
        .checked_sub(suffix.len())
        .and_then(|split| value.split_at_checked(split))
        .filter(|(_, tail)| tail.eq_ignore_ascii_case(suffix))
        .map(|(head, _)| head)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/enterprise/logo/tests.rs"]
mod tests;
