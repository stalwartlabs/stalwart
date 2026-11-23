/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::schema::{enums::EwsVersion, structs::Exchange};
use std::time::Duration;
use store::registry::bootstrap::Bootstrap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeEndpoint {
    Ews,
    ActiveSync,
    Mapi,
    OfflineAddressBook,
}

#[derive(Debug, Clone)]
pub struct ExchangeConfig {
    pub enabled: bool,
    pub ews_version: EwsVersion,
    pub max_request_size: usize,
    pub max_devices: usize,
    pub max_heartbeat: Duration,
    pub max_object_size: usize,
}

impl ExchangeConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        Self::from(bp.setting_infallible::<Exchange>().await)
    }

    pub fn endpoint(&self, segment: &str) -> Option<ExchangeEndpoint> {
        if self.enabled {
            hashify::map_ignore_case!(segment.as_bytes(), ExchangeEndpoint,
                "ews" => ExchangeEndpoint::Ews,
                "microsoft-server-activesync" => ExchangeEndpoint::ActiveSync,
                "mapi" => ExchangeEndpoint::Mapi,
                "oab" => ExchangeEndpoint::OfflineAddressBook,
            )
            .copied()
        } else {
            None
        }
    }
}

impl From<Exchange> for ExchangeConfig {
    fn from(exchange: Exchange) -> Self {
        ExchangeConfig {
            enabled: exchange.enable,
            ews_version: exchange.ews_version,
            max_request_size: usize::try_from(exchange.max_request_size).unwrap_or(usize::MAX),
            max_devices: usize::try_from(exchange.max_devices).unwrap_or(usize::MAX),
            max_heartbeat: exchange.max_heartbeat.into_inner(),
            max_object_size: usize::try_from(exchange.max_object_size).unwrap_or(usize::MAX),
        }
    }
}
