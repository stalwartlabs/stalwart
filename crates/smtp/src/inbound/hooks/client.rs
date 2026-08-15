/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::session::MTAHook;
use utils::HttpLimitResponse;

use super::{Request, Response};

pub(super) async fn send_mta_hook_request(
    mta_hook: &MTAHook,
    request: Request,
) -> Result<Response, String> {
    let response = mta_hook
        .client
        .post(&mta_hook.url)
        .timeout(mta_hook.timeout)
        .headers(mta_hook.headers.clone())
        .body(
            serde_json::to_string(&request)
                .map_err(|err| format!("Failed to serialize Hook request: {}", err))?,
        )
        .send()
        .await
        .map_err(|err| format!("Hook request failed: {err}"))?;

    if response.status().is_success() {
        serde_json::from_slice(
            response
                .bytes_with_limit(mta_hook.max_response_size)
                .await
                .map_err(|err| format!("Failed to parse Hook response: {}", err))?
                .ok_or_else(|| "Hook response too large".to_string())?
                .as_ref(),
        )
        .map_err(|err| format!("Failed to parse Hook response: {}", err))
    } else {
        Err(format!(
            "Hook request failed with code {}: {}",
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ))
    }
}
