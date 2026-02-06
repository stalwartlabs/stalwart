/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    KV_RATE_LIMIT_AUTH, KV_RATE_LIMIT_LOITER, KV_RATE_LIMIT_RCPT, KV_RATE_LIMIT_SCAN, Server,
    ipc::{BroadcastEvent, RegistryChange},
    network::ip_to_bytes,
};
use ahash::AHashSet;
use registry::{
    schema::{
        enums::BlockReason,
        structs::{self, AllowedIp, BlockedIp, Rate},
    },
    types::{datetime::UTCDateTime, ipmask::IpAddrOrMask},
};
use std::{fmt::Debug, net::IpAddr};
use store::{registry::bootstrap::Bootstrap, write::now};
use trc::AddContext;
use utils::glob::{GlobPattern, MatchType};

#[derive(Debug, Clone)]
pub struct Security {
    pub fallback_admin: Option<(String, String)>,

    pub allowed_ip_addresses: AHashSet<IpAddr>,
    pub allowed_ip_networks: Vec<IpAddrOrMask>,
    pub has_allowed_networks: bool,
    pub blocked_ip_expiration: Option<u64>,

    pub http_banned_paths: Vec<MatchType>,
    pub scanner_fail_rate: Option<Rate>,

    pub auth_fail_rate: Option<Rate>,
    pub rcpt_fail_rate: Option<Rate>,
    pub loiter_fail_rate: Option<Rate>,
}

#[derive(Default)]
pub struct BlockedIps {
    pub blocked_ip_addresses: AHashSet<IpAddr>,
    pub blocked_ip_networks: Vec<IpAddrOrMask>,
    pub has_blocked_networks: bool,
}

impl Security {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut allowed_ip_addresses = AHashSet::new();
        let mut allowed_ip_networks = Vec::new();
        let mut expired_allows = Vec::new();
        let now = now() as i64;

        for ip in bp.list_infallible::<AllowedIp>().await {
            let id = ip.id;
            let ip = ip.object;

            if ip.expires_at.is_none_or(|ip| ip.timestamp() > now) {
                if let Some(ip) = ip.address.try_to_ip() {
                    allowed_ip_addresses.insert(ip);
                } else {
                    allowed_ip_networks.push(ip.address);
                }
            } else {
                expired_allows.push((id, ip.address));
            }
        }

        if !expired_allows.is_empty() {
            for (id, _) in &expired_allows {
                if let Err(err) = bp.registry.delete(*id).await {
                    trc::error!(
                        err.details("Failed to delete expired allowed IP from registry.")
                            .caused_by(trc::location!())
                    );
                }
            }

            trc::event!(
                Security(trc::SecurityEvent::IpAllowExpired),
                Details = expired_allows
                    .into_iter()
                    .map(|(_, ip)| trc::Value::from(ip.into_inner().0))
                    .collect::<Vec<_>>()
            );
        }

        #[cfg(not(feature = "test_mode"))]
        {
            // Add loopback addresses
            allowed_ip_addresses.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            allowed_ip_addresses.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        }

        let security = bp.setting_infallible::<structs::Security>().await;
        Security {
            fallback_admin: bp.local.fallback_admin_user.as_ref().and_then(|user| {
                bp.local
                    .fallback_admin_secret
                    .as_ref()
                    .map(|secret| (user.to_string(), secret.to_string()))
            }),
            has_allowed_networks: !allowed_ip_networks.is_empty(),
            allowed_ip_addresses,
            allowed_ip_networks,
            blocked_ip_expiration: security.auth_ban_period.map(|v| v.as_secs()),
            auth_fail_rate: security.auth_ban_rate,
            rcpt_fail_rate: security.abuse_ban_rate,
            loiter_fail_rate: security.loiter_ban_rate,
            http_banned_paths: security
                .scan_ban_paths
                .iter()
                .map(|pattern| MatchType::Matches(GlobPattern::compile(pattern, true)))
                .collect(),
            scanner_fail_rate: security.scan_ban_rate,
        }
    }
}

impl Server {
    pub async fn is_rcpt_fail2banned(&self, ip: IpAddr, rcpt: &str) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.rcpt_fail_rate {
            let is_allowed = self.is_ip_allowed(&ip)
                || (self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_RCPT, &ip_to_bytes(&ip), rate, false)
                    .await?
                    .is_none()
                    && self
                        .in_memory_store()
                        .is_rate_allowed(KV_RATE_LIMIT_RCPT, rcpt.as_bytes(), rate, false)
                        .await?
                        .is_none());

            if !is_allowed {
                return self
                    .block_ip(ip, BlockReason::RcptToFailure)
                    .await
                    .map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn is_scanner_fail2banned(&self, ip: IpAddr) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.scanner_fail_rate {
            let is_allowed = self.is_ip_allowed(&ip)
                || self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_SCAN, &ip_to_bytes(&ip), rate, false)
                    .await?
                    .is_none();

            if !is_allowed {
                return self
                    .block_ip(ip, BlockReason::PortScanning)
                    .await
                    .map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn is_http_banned_path(&self, path: &str, ip: IpAddr) -> trc::Result<bool> {
        let paths = &self.core.network.security.http_banned_paths;

        if !paths.is_empty() && paths.iter().any(|p| p.matches(path)) && !self.is_ip_allowed(&ip) {
            self.block_ip(ip, BlockReason::PortScanning)
                .await
                .map(|_| true)
        } else {
            Ok(false)
        }
    }

    pub async fn is_loiter_fail2banned(&self, ip: IpAddr) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.loiter_fail_rate {
            let is_allowed = self.is_ip_allowed(&ip)
                || self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_LOITER, &ip_to_bytes(&ip), rate, false)
                    .await?
                    .is_none();

            if !is_allowed {
                return self
                    .block_ip(ip, BlockReason::Loitering)
                    .await
                    .map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn is_auth_fail2banned(&self, ip: IpAddr, login: Option<&str>) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.auth_fail_rate {
            let login = login.unwrap_or_default();
            let is_allowed = self.is_ip_allowed(&ip)
                || (self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_AUTH, &ip_to_bytes(&ip), rate, false)
                    .await?
                    .is_none()
                    && (login.is_empty()
                        || self
                            .in_memory_store()
                            .is_rate_allowed(KV_RATE_LIMIT_AUTH, login.as_bytes(), rate, false)
                            .await?
                            .is_none()));
            if !is_allowed {
                return self
                    .block_ip(ip, BlockReason::AuthFailure)
                    .await
                    .map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn block_ip(&self, ip: IpAddr, reason: BlockReason) -> trc::Result<()> {
        // Add IP to blocked list
        self.inner
            .data
            .blocked_ips
            .write()
            .blocked_ip_addresses
            .insert(ip);

        // Write blocked IP to config
        let now = now() as i64;
        let id = self
            .registry()
            .insert(&BlockedIp {
                address: IpAddrOrMask::from_ip(ip),
                created_at: UTCDateTime::from_timestamp(now),
                expires_at: self
                    .core
                    .network
                    .security
                    .blocked_ip_expiration
                    .map(|v| UTCDateTime::from_timestamp(now + v as i64)),
                reason,
            })
            .await
            .caused_by(trc::location!())?;

        // Increment version
        self.cluster_broadcast(BroadcastEvent::RegistryChange(RegistryChange::Insert(id)))
            .await;

        Ok(())
    }

    pub fn has_auth_fail2ban(&self) -> bool {
        self.core.network.security.auth_fail_rate.is_some()
    }

    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        let blocked_ips = self.inner.data.blocked_ips.read();
        (blocked_ips.blocked_ip_addresses.contains(ip)
            || (blocked_ips.has_blocked_networks
                && blocked_ips
                    .blocked_ip_networks
                    .iter()
                    .any(|network| network.matches(ip))))
            && !self.is_ip_allowed(ip)
    }

    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        self.core.network.security.allowed_ip_addresses.contains(ip)
            || (self.core.network.security.has_allowed_networks
                && self
                    .core
                    .network
                    .security
                    .allowed_ip_networks
                    .iter()
                    .any(|network| network.matches(ip)))
    }
}

impl BlockedIps {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut ips = Self::default();
        let mut expired_blocks = Vec::new();
        let now = now() as i64;

        for ip in bp.list_infallible::<BlockedIp>().await {
            let id = ip.id;
            let ip = ip.object;

            if ip.expires_at.is_none_or(|ip| ip.timestamp() > now) {
                if let Some(ip) = ip.address.try_to_ip() {
                    ips.blocked_ip_addresses.insert(ip);
                } else {
                    ips.blocked_ip_networks.push(ip.address);
                }
            } else {
                expired_blocks.push((id, ip.address));
            }
        }

        if !expired_blocks.is_empty() {
            for (id, _) in &expired_blocks {
                if let Err(err) = bp.registry.delete(*id).await {
                    trc::error!(
                        err.details("Failed to delete expired blocked IP from registry.")
                            .caused_by(trc::location!())
                    );
                }
            }
            trc::event!(
                Security(trc::SecurityEvent::IpBlockExpired),
                Details = expired_blocks
                    .into_iter()
                    .map(|(_, ip)| trc::Value::from(ip.into_inner().0))
                    .collect::<Vec<_>>()
            );
        }

        ips.has_blocked_networks = !ips.blocked_ip_networks.is_empty();
        ips
    }
}
