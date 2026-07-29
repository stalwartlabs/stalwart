/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::session::MTAHook;
use prost::Message as _;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderValue};
use utils::HttpLimitResponse;

use super::{Request, Response, proto};

const APPLICATION_PROTOBUF: &str = "application/protobuf";

pub(super) async fn send_mta_hook_request(
    mta_hook: &MTAHook,
    request: Request,
) -> Result<Response, String> {
    let is_protobuf = mta_hook
        .headers
        .get(CONTENT_TYPE)
        .is_some_and(is_protobuf_media_type);

    let mut headers = mta_hook.headers.clone();
    let body = if is_protobuf {
        if !headers.contains_key(ACCEPT) {
            headers.insert(ACCEPT, HeaderValue::from_static(APPLICATION_PROTOBUF));
        }
        proto::Request::from(request).encode_to_vec()
    } else {
        serde_json::to_vec(&request)
            .map_err(|err| format!("Failed to serialize Hook request: {}", err))?
    };

    let response = reqwest::Client::builder()
        .timeout(mta_hook.timeout)
        .danger_accept_invalid_certs(mta_hook.tls_allow_invalid_certs)
        .build()
        .map_err(|err| format!("Failed to create HTTP client: {}", err))?
        .post(&mta_hook.url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|err| format!("Hook request failed: {err}"))?;

    if response.status().is_success() {
        let is_protobuf = response
            .headers()
            .get(CONTENT_TYPE)
            .map_or(is_protobuf, is_protobuf_media_type);
        let bytes = response
            .bytes_with_limit(mta_hook.max_response_size)
            .await
            .map_err(|err| format!("Failed to parse Hook response: {}", err))?
            .ok_or_else(|| "Hook response too large".to_string())?;

        if is_protobuf {
            proto::Response::decode(bytes.as_ref())
                .map_err(|err| format!("Failed to parse Hook response: {}", err))
                .and_then(Response::try_from)
        } else {
            serde_json::from_slice(bytes.as_ref())
                .map_err(|err| format!("Failed to parse Hook response: {}", err))
        }
    } else {
        Err(format!(
            "Hook request failed with code {}: {}",
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ))
    }
}

fn is_protobuf_media_type(value: &HeaderValue) -> bool {
    value.to_str().is_ok_and(|value| {
        matches!(
            value.split(';').next().unwrap_or_default().trim(),
            "application/protobuf" | "application/x-protobuf"
        )
    })
}
