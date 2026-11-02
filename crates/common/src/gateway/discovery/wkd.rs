/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MAX_KEY_RESPONSE, SourceResult};
use crate::Server;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use registry::schema::enums::KeyDiscoverySource;
use reqwest::{Method, StatusCode};
use sha1::{Digest, Sha1};
use utils::HttpLimitResponse;

const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

pub trait WkdLookup: Sync + Send {
    fn lookup_wkd(&self, address: &str) -> impl Future<Output = SourceResult> + Send;

    fn wkd_is_advanced(&self, domain: &str) -> impl Future<Output = Option<bool>> + Send;
}

struct WkdUrl {
    host: String,
    prefix: String,
}

impl WkdLookup for Server {
    async fn lookup_wkd(&self, address: &str) -> SourceResult {
        let Some(gateway) = self.core.email.gateway.as_deref() else {
            return SourceResult::NotFound;
        };
        let Some((local_part, domain)) = address.rsplit_once('@') else {
            return SourceResult::NotFound;
        };
        let Some(advanced) = self.wkd_is_advanced(domain).await else {
            return SourceResult::TemporaryFailure;
        };
        let url = WkdUrl::new(domain, advanced).key_url(local_part);
        let Ok(request) = gateway.http.request(Method::GET, &url) else {
            return SourceResult::TemporaryFailure;
        };
        match request.send().await {
            Ok(response) if response.status() == StatusCode::OK => {
                match response.bytes_with_limit(MAX_KEY_RESPONSE).await {
                    Ok(Some(body)) => {
                        SourceResult::from_openpgp(&body, address, KeyDiscoverySource::Wkd, None)
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

    async fn wkd_is_advanced(&self, domain: &str) -> Option<bool> {
        let advanced_host = format!("openpgpkey.{domain}");
        #[cfg(not(stalwart_tests))]
        let advanced = match self
            .core
            .smtp
            .resolvers
            .dns
            .resolver()
            .lookup_ip(advanced_host.as_str())
            .await
        {
            Ok(_) => true,
            Err(err) if err.is_no_records_found() => false,
            Err(_) => return None,
        };
        #[cfg(stalwart_tests)]
        let advanced = !advanced_host.is_empty() && WkdUrl::test_advanced(domain);

        Some(advanced)
    }
}

impl WkdUrl {
    fn new(domain: &str, advanced: bool) -> Self {
        let domain = domain.to_ascii_lowercase();
        if advanced {
            WkdUrl {
                host: format!("openpgpkey.{domain}"),
                prefix: format!("/.well-known/openpgpkey/{domain}"),
            }
        } else {
            WkdUrl {
                host: domain,
                prefix: "/.well-known/openpgpkey".to_string(),
            }
        }
    }

    fn key_url(&self, local_part: &str) -> String {
        format!(
            "https://{}{}/hu/{}?l={}",
            self.host,
            self.prefix,
            local_part_hash(local_part),
            utf8_percent_encode(local_part, NON_ALPHANUMERIC)
        )
    }

    #[cfg(stalwart_tests)]
    fn test_advanced(domain: &str) -> bool {
        domain.starts_with("advanced.")
    }
}

fn local_part_hash(local_part: &str) -> String {
    let digest = Sha1::digest(local_part.to_ascii_lowercase().as_bytes());
    let mut encoded = String::with_capacity(32);
    let mut buffer = 0u32;
    let mut bits = 0;
    for &byte in digest.iter() {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            encoded.push(ZBASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    encoded
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/gateway/discovery/wkd/tests.rs"]
mod tests;
