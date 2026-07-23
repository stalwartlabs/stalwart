/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose};
use reqwest::{
    Client,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, USER_AGENT},
};
use std::{str::FromStr, time::Duration};

pub fn build_http_client(
    raw_headers: impl IntoIterator<Item = (String, String)>,
    username: Option<&str>,
    password: Option<&str>,
    token: Option<&str>,
    content_type: Option<&str>,
    timeout: Duration,
    allow_invalid_certs: bool,
) -> Result<Client, String> {
    let mut headers = build_http_headers(raw_headers, username, password, token, content_type)?;
    headers.insert(USER_AGENT, "Stalwart/1.0.0".parse().unwrap());

    match Client::builder()
        .connect_timeout(timeout)
        .danger_accept_invalid_certs(allow_invalid_certs)
        .default_headers(headers)
        .build()
    {
        Ok(client) => Ok(client),
        Err(err) => Err(format!("Failed to build HTTP client: {}", err)),
    }
}

pub fn build_http_headers(
    raw_headers: impl IntoIterator<Item = (String, String)>,
    username: Option<&str>,
    password: Option<&str>,
    token: Option<&str>,
    content_type: Option<&str>,
) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();

    if let Some(content_type) = content_type {
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
    }

    for (header, value) in raw_headers
        .into_iter()
        .map(|(k, v)| {
            Ok((
                HeaderName::from_str(k.trim())
                    .map_err(|err| format!("Invalid header {k:?}: {err}",))?,
                HeaderValue::from_str(v.trim())
                    .map_err(|err| format!("Invalid value {v:?}: {err}",))?,
            ))
        })
        .collect::<Result<Vec<(HeaderName, HeaderValue)>, String>>()?
    {
        headers.insert(header, value);
    }

    if let (Some(name), Some(secret)) = (username, password) {
        headers.insert(
            AUTHORIZATION,
            format!(
                "Basic {}",
                general_purpose::STANDARD.encode(format!("{}:{}", name, secret))
            )
            .parse()
            .unwrap(),
        );
    } else if let Some(token) = token {
        headers.insert(AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());
    }

    Ok(headers)
}
