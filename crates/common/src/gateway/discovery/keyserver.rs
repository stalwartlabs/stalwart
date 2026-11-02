/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MAX_KEY_RESPONSE, SourceResult};
use crate::{KV_KEY_LOOKUP, Server};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use registry::schema::{enums::KeyDiscoverySource, structs::Rate};
use reqwest::{Method, Response, StatusCode, header::RETRY_AFTER};
use std::time::Duration;
use store::dispatch::lookup::KeyValue;
use utils::HttpLimitResponse;

const VKS_BASE_URL: &str = "https://keys.openpgp.org/vks/v1/by-email/";
const VKS_BLOCK_KEY: &[u8] = &[KV_KEY_LOOKUP, 2];
const VKS_BURST: u64 = 50;
const VKS_WINDOW_SECS: u64 = 60;
const VKS_DEFAULT_BACKOFF_SECS: u64 = 300;

pub trait KeyserverLookup: Sync + Send {
    fn lookup_vks(&self, address: &str) -> impl Future<Output = SourceResult> + Send;

    fn lookup_hkp(&self, address: &str) -> impl Future<Output = SourceResult> + Send;
}

trait VksRateLimit {
    fn vks_allowed(&self) -> impl Future<Output = bool> + Send;

    fn vks_backoff(&self, response: &Response) -> impl Future<Output = ()> + Send;
}

impl KeyserverLookup for Server {
    async fn lookup_vks(&self, address: &str) -> SourceResult {
        let Some(gateway) = self.core.email.gateway.as_deref() else {
            return SourceResult::NotFound;
        };
        if !self.vks_allowed().await {
            return SourceResult::TemporaryFailure;
        }
        let url = format!(
            "{VKS_BASE_URL}{}",
            utf8_percent_encode(address, NON_ALPHANUMERIC)
        );
        let Ok(request) = gateway.http.request(Method::GET, &url) else {
            return SourceResult::TemporaryFailure;
        };
        match request.send().await {
            Ok(response) if response.status() == StatusCode::TOO_MANY_REQUESTS => {
                self.vks_backoff(&response).await;
                SourceResult::TemporaryFailure
            }
            Ok(response) if response.status() == StatusCode::OK => {
                match response.bytes_with_limit(MAX_KEY_RESPONSE).await {
                    Ok(Some(body)) => {
                        SourceResult::from_openpgp(&body, address, KeyDiscoverySource::Vks, None)
                    }
                    Ok(None) => SourceResult::TemporaryFailure,
                    Err(_) => SourceResult::TemporaryFailure,
                }
            }
            Ok(response) if response.status().is_server_error() => SourceResult::TemporaryFailure,
            Ok(_) => SourceResult::NotFound,
            Err(_) => SourceResult::TemporaryFailure,
        }
    }

    async fn lookup_hkp(&self, address: &str) -> SourceResult {
        let Some(gateway) = self.core.email.gateway.as_deref() else {
            return SourceResult::NotFound;
        };
        let mut result = SourceResult::NotFound;
        let search = utf8_percent_encode(address, NON_ALPHANUMERIC).to_string();
        for server in &gateway.hkp_servers {
            let server = server.trim_end_matches('/');
            let url = match server.strip_prefix("hkps://") {
                Some(host) => {
                    format!("https://{host}/pks/lookup?op=get&options=mr&search={search}")
                }
                None => format!("{server}/pks/lookup?op=get&options=mr&search={search}"),
            };
            let Ok(request) = gateway.http.request(Method::GET, &url) else {
                result = SourceResult::TemporaryFailure;
                continue;
            };
            match request.send().await {
                Ok(response) if response.status() == StatusCode::OK => {
                    match response.bytes_with_limit(MAX_KEY_RESPONSE).await {
                        Ok(Some(body)) => {
                            let keys = SourceResult::from_openpgp(
                                &body,
                                address,
                                KeyDiscoverySource::Hkp,
                                None,
                            );
                            if matches!(keys, SourceResult::Keys { .. }) {
                                return keys;
                            }
                        }
                        _ => result = SourceResult::TemporaryFailure,
                    }
                }
                Ok(response) if !response.status().is_server_error() => {}
                _ => result = SourceResult::TemporaryFailure,
            }
        }
        result
    }
}

impl VksRateLimit for Server {
    async fn vks_allowed(&self) -> bool {
        let store = self.in_memory_store();
        if store.key_exists(VKS_BLOCK_KEY).await.unwrap_or(false) {
            return false;
        }
        store
            .is_rate_allowed(
                KV_KEY_LOOKUP,
                b"vks",
                &Rate {
                    count: VKS_BURST,
                    period: Duration::from_secs(VKS_BURST * VKS_WINDOW_SECS).into(),
                },
            )
            .await
            .map(|retry| retry.is_none())
            .unwrap_or(false)
    }

    async fn vks_backoff(&self, response: &Response) {
        let backoff = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(VKS_DEFAULT_BACKOFF_SECS);
        if let Err(err) = self
            .in_memory_store()
            .key_set(KeyValue::new(VKS_BLOCK_KEY, Vec::new()).expires(backoff))
            .await
        {
            trc::error!(err.caused_by(trc::location!()));
        }
    }
}
