/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::config::ConfigManager;
use crate::USER_AGENT;
use hyper::HeaderMap;
use std::time::Duration;
use utils::HttpLimitResponse;

pub mod backup;
pub mod boot;
pub mod config;
pub mod console;
pub mod reload;
pub mod restore;
pub mod webadmin;

const DEFAULT_SPAMFILTER_URL: &str =
    "https://github.com/stalwartlabs/spam-filter/releases/latest/download/spam-filter.toml";
pub const WEBADMIN_KEY: &[u8] = "STALWART_WEBADMIN".as_bytes();
pub const SPAM_TRAINER_KEY: &[u8] = "STALWART_SPAM_TRAIN_DATA.lz4".as_bytes();
pub const SPAM_CLASSIFIER_KEY: &[u8] = "STALWART_SPAM_CLASSIFIER_MODEL.lz4".as_bytes();

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
const DEFAULT_WEBADMIN_URL: &str =
    "https://github.com/stalwartlabs/webadmin/releases/latest/download/webadmin.zip";
// SPDX-SnippetEnd

#[cfg(not(feature = "enterprise"))]
const DEFAULT_WEBADMIN_URL: &str =
    "https://github.com/stalwartlabs/webadmin/releases/latest/download/webadmin-oss.zip";

impl ConfigManager {
    pub async fn fetch_resource(&self, resource_id: &str) -> Result<Vec<u8>, String> {
        if let Some(url) = self
            .get(&format!("{resource_id}.resource"))
            .await
            .map_err(|err| {
                format!("Failed to fetch configuration key '{resource_id}.resource': {err}",)
            })?
        {
            fetch_resource(&url, None, Duration::from_secs(60), MAX_SIZE).await
        } else {
            match resource_id {
                "spam-filter" => {
                    fetch_resource(
                        DEFAULT_SPAMFILTER_URL,
                        None,
                        Duration::from_secs(60),
                        MAX_SIZE,
                    )
                    .await
                }
                "webadmin" => {
                    fetch_resource(
                        DEFAULT_WEBADMIN_URL,
                        None,
                        Duration::from_secs(60),
                        MAX_SIZE,
                    )
                    .await
                }
                _ => Err(format!("Unknown resource: {resource_id}")),
            }
        }
    }
}

const MAX_SIZE: usize = 100 * 1024 * 1024;

pub async fn fetch_resource(
    url: &str,
    headers: Option<HeaderMap>,
    timeout: Duration,
    max_size: usize,
) -> Result<Vec<u8>, String> {
    if let Some(path) = url.strip_prefix("file://") {
        tokio::fs::read(path)
            .await
            .map_err(|err| format!("Failed to read {path}: {err}"))
    } else {
        let response = reqwest::Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(is_localhost_url(url))
            .user_agent(USER_AGENT)
            .build()
            .unwrap_or_default()
            .get(url)
            .headers(headers.unwrap_or_default())
            .send()
            .await
            .map_err(|err| format!("Failed to fetch {url}: {err}"))?;

        if response.status().is_success() {
            response
                .bytes_with_limit(max_size)
                .await
                .map_err(|err| format!("Failed to fetch {url}: {err}"))
                .and_then(|bytes| bytes.ok_or_else(|| format!("Resource too large: {url}")))
        } else {
            let code = response.status().canonical_reason().unwrap_or_default();
            let reason = response.text().await.unwrap_or_default();

            Err(format!(
                "Failed to fetch {url}: Code: {code}, Details: {reason}",
            ))
        }
    }
}

pub fn is_localhost_url(url: &str) -> bool {
    url.split_once("://")
        .map(|(_, url)| url.split_once('/').map_or(url, |(host, _)| host))
        .is_some_and(|host| {
            let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
            host == "localhost" || host == "127.0.0.1" || host == "[::1]"
        })
}
