/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::{Config, utils::AsKey};
use base64::{Engine, engine::general_purpose};
use reqwest::{
    Client,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, USER_AGENT},
};
use std::{str::FromStr, time::Duration};

pub fn build_http_client(
    config: &mut Config,
    prefix: impl AsKey,
    content_type: Option<&str>,
) -> Option<Client> {
    let mut headers = parse_http_headers(config, prefix.clone());
    headers.insert(USER_AGENT, "Stalwart/1.0.0".parse().unwrap());

    if let Some(content_type) = content_type {
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
    }

    let prefix = prefix.as_key();
    match Client::builder()
        .connect_timeout(
            config
                .property_or_default::<Duration>((&prefix, "timeout"), "30s")
                .unwrap_or(Duration::from_secs(30)),
        )
        .danger_accept_invalid_certs(
            config
                .property_or_default::<bool>((&prefix, "tls.allow-invalid-certs"), "false")
                .unwrap_or(false),
        )
        .default_headers(headers)
        .build()
    {
        Ok(client) => Some(client),
        Err(err) => {
            config.new_build_error(&prefix, format!("Failed to build HTTP client: {err}"));
            None
        }
    }
}

pub fn parse_http_headers(config: &mut Config, prefix: impl AsKey) -> HeaderMap {
    let prefix = prefix.as_key();
    let mut headers = HeaderMap::new();

    for (header, value) in config
        .values((&prefix, "headers"))
        .map(|(_, v)| {
            if let Some((k, v)) = v.split_once(':') {
                Ok((
                    HeaderName::from_str(k.trim()).map_err(|err| {
                        format!("Invalid header found in property \"{prefix}.headers\": {err}",)
                    })?,
                    HeaderValue::from_str(v.trim()).map_err(|err| {
                        format!("Invalid header found in property \"{prefix}.headers\": {err}",)
                    })?,
                ))
            } else {
                Err(format!(
                    "Invalid header found in property \"{prefix}.headers\": {v}",
                ))
            }
        })
        .collect::<Result<Vec<(HeaderName, HeaderValue)>, String>>()
        .map_err(|e| config.new_parse_error((&prefix, "headers"), e))
        .unwrap_or_default()
    {
        headers.insert(header, value);
    }

    if let (Some(name), Some(secret)) = (
        config.value((&prefix, "auth.username")),
        config.value((&prefix, "auth.secret")),
    ) {
        headers.insert(
            AUTHORIZATION,
            format!(
                "Basic {}",
                general_purpose::STANDARD.encode(format!("{}:{}", name, secret))
            )
            .parse()
            .unwrap(),
        );
    } else if let Some(token) = config.value((&prefix, "auth.token")) {
        headers.insert(AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());
    }

    headers
}
