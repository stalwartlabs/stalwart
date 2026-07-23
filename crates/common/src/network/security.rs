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
        enums::{BlockReason, PasswordHashAlgorithm, PasswordStrength},
        prelude::{Object, ObjectType},
        structs::{self, AllowedIp, BlockedIp, Rate, SystemSettings},
    },
    types::{datetime::UTCDateTime, ipmask::IpAddrOrMask},
};
use std::{fmt::Debug, hash::Hash, net::IpAddr};
use store::{
    registry::{
        bootstrap::Bootstrap,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use trc::AddContext;
use types::id::Id;
use utils::glob::{GlobPattern, MatchType};
use zxcvbn::Score;

#[derive(Debug, Clone)]
pub struct Security {
    pub allowed_ip_addresses: AHashSet<IpWithTtl<IpAddr>>,
    pub allowed_ip_networks: Vec<IpWithTtl<IpAddrOrMask>>,
    pub has_allowed_networks: bool,
    pub auth_ban_period: Option<u64>,
    pub abuse_ban_period: Option<u64>,
    pub loiter_ban_period: Option<u64>,
    pub scan_ban_period: Option<u64>,

    pub http_banned_paths: Vec<MatchType>,
    pub scanner_fail_rate: Option<Rate>,

    pub auth_fail_rate: Option<Rate>,
    pub rcpt_fail_rate: Option<Rate>,
    pub loiter_fail_rate: Option<Rate>,

    pub default_role_ids_user: Vec<Id>,
    pub default_role_ids_group: Vec<Id>,
    pub default_role_ids_tenant: Vec<Id>,
    pub default_role_ids_admin: Vec<Id>,

    pub password_hash_algorithm: PasswordHashAlgorithm,
    pub password_max_length: u32,
    pub password_min_length: u32,
    pub password_min_strength: Score,
    pub password_default_expiration: Option<u64>,
}

#[derive(Default)]
pub struct BlockedIps {
    pub blocked_ip_addresses: AHashSet<IpWithTtl<IpAddr>>,
    pub blocked_ip_networks: Vec<IpWithTtl<IpAddrOrMask>>,
    pub has_blocked_networks: bool,
}

#[derive(Debug, Clone)]
pub struct IpWithTtl<T: PartialEq + Eq + Hash> {
    pub ip: T,
    pub expires_at: u64,
}

impl Security {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut allowed_ip_addresses = AHashSet::new();
        let mut allowed_ip_networks = Vec::new();
        let mut expired_allows = Vec::new();
        let now = now();

        for ip in bp.list_infallible::<AllowedIp>().await {
            let id = ip.id;
            let revision = ip.revision;
            let ip = ip.object;
            let expires_at = ip
                .expires_at
                .as_ref()
                .map(|dt| dt.timestamp() as u64)
                .unwrap_or(u64::MAX);

            if expires_at > now {
                if let Some(ip) = ip.address.try_to_ip() {
                    allowed_ip_addresses.insert(IpWithTtl::new(ip, expires_at));
                } else {
                    let ip_with_ttl = IpWithTtl::new(ip.address, expires_at);

                    if !allowed_ip_networks.contains(&ip_with_ttl) {
                        allowed_ip_networks.push(ip_with_ttl);
                    }
                }
            } else {
                expired_allows.push((
                    id,
                    ip.address.clone(),
                    Object {
                        inner: ip.into(),
                        revision,
                    },
                ));
            }
        }

        // Add proxy protocol IPs as allowed
        let system = bp.setting_infallible::<SystemSettings>().await;
        for ip in system.proxy_trusted_networks {
            if let Some(ip) = ip.try_to_ip() {
                allowed_ip_addresses.insert(IpWithTtl::new(ip, u64::MAX));
            } else {
                let ip_with_ttl = IpWithTtl::new(ip, u64::MAX);
                if !allowed_ip_networks.contains(&ip_with_ttl) {
                    allowed_ip_networks.push(ip_with_ttl);
                }
            }
        }

        if !expired_allows.is_empty() {
            for (id, _, object) in &expired_allows {
                if let Err(err) = bp
                    .registry
                    .write(RegistryWrite::delete_object(*id, object))
                    .await
                {
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
                    .map(|(_, ip, _)| trc::Value::from(ip.into_inner().0))
                    .collect::<Vec<_>>()
            );
        }

        #[cfg(not(feature = "test_mode"))]
        {
            // Add loopback addresses
            allowed_ip_addresses.insert(IpWithTtl::new(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                u64::MAX,
            ));
            allowed_ip_addresses.insert(IpWithTtl::new(
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                u64::MAX,
            ));
        }

        let security = bp.setting_infallible::<structs::Security>().await;
        let auth = bp.setting_infallible::<structs::Authentication>().await;
        Security {
            has_allowed_networks: !allowed_ip_networks.is_empty(),
            allowed_ip_addresses,
            allowed_ip_networks,
            auth_ban_period: security.auth_ban_period.map(|v| v.as_secs()),
            abuse_ban_period: security.abuse_ban_period.map(|v| v.as_secs()),
            loiter_ban_period: security.loiter_ban_period.map(|v| v.as_secs()),
            scan_ban_period: security.scan_ban_period.map(|v| v.as_secs()),
            auth_fail_rate: security.auth_ban_rate,
            rcpt_fail_rate: security.abuse_ban_rate,
            loiter_fail_rate: security.loiter_ban_rate,
            http_banned_paths: security
                .scan_ban_paths
                .iter()
                .map(|pattern| MatchType::Matches(GlobPattern::compile(pattern, true)))
                .collect(),
            scanner_fail_rate: security.scan_ban_rate,
            default_role_ids_user: auth.default_user_role_ids.into_inner(),
            default_role_ids_group: auth.default_group_role_ids.into_inner(),
            default_role_ids_tenant: auth.default_tenant_role_ids.into_inner(),
            default_role_ids_admin: auth.default_admin_role_ids.into_inner(),
            password_hash_algorithm: auth.password_hash_algorithm,
            password_max_length: auth.password_max_length as u32,
            password_min_length: auth.password_min_length as u32,
            password_min_strength: match auth.password_min_strength {
                PasswordStrength::Zero => Score::Zero,
                PasswordStrength::One => Score::One,
                PasswordStrength::Two => Score::Two,
                PasswordStrength::Three => Score::Three,
                PasswordStrength::Four => Score::Four,
            },
            password_default_expiration: auth.password_default_expiry.map(|v| v.as_secs()),
        }
    }

    fn ban_period(&self, reason: BlockReason) -> Option<u64> {
        match reason {
            BlockReason::RcptToFailure => self.abuse_ban_period,
            BlockReason::AuthFailure => self.auth_ban_period,
            BlockReason::Loitering => self.loiter_ban_period,
            BlockReason::PortScanning => self.scan_ban_period,
            BlockReason::Manual | BlockReason::Other => None,
        }
    }
}

impl Server {
    pub async fn is_rcpt_fail2banned(&self, ip: IpAddr, rcpt: &str) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.rcpt_fail_rate {
            let is_allowed = self.is_ip_allowed(ip)
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
            let is_allowed = self.is_ip_allowed(ip)
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

        if !paths.is_empty() && paths.iter().any(|p| p.matches(path)) && !self.is_ip_allowed(ip) {
            self.block_ip(ip, BlockReason::PortScanning)
                .await
                .map(|_| true)
        } else {
            Ok(false)
        }
    }

    pub async fn is_loiter_fail2banned(&self, ip: IpAddr) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.loiter_fail_rate {
            let is_allowed = self.is_ip_allowed(ip)
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
            let is_allowed = self.is_ip_allowed(ip)
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
        let now = now();
        let expires_at = self
            .core
            .network
            .security
            .ban_period(reason)
            .map(|v| now + v);
        self.inner
            .data
            .blocked_ips
            .write()
            .blocked_ip_addresses
            .insert(IpWithTtl::new(ip, expires_at.unwrap_or(u64::MAX)));

        // Write blocked IP to config
        let RegistryWriteResult::Success(id) = self
            .registry()
            .write(RegistryWrite::insert(
                &BlockedIp {
                    address: IpAddrOrMask::from_ip(ip),
                    created_at: UTCDateTime::from_timestamp(now as i64),
                    expires_at: expires_at.map(|ts| UTCDateTime::from_timestamp(ts as i64)),
                    reason,
                }
                .into(),
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };

        // Increment version
        self.cluster_broadcast(BroadcastEvent::RegistryChange(RegistryChange::Insert(
            ObjectType::BlockedIp.id(id),
        )))
        .await;

        Ok(())
    }

    pub fn has_auth_fail2ban(&self) -> bool {
        self.core.network.security.auth_fail_rate.is_some()
    }

    pub fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        let blocked_ips = self.inner.data.blocked_ips.read();
        (blocked_ips
            .blocked_ip_addresses
            .get(&IpWithTtl::new(ip, 0))
            .is_some_and(|v| !v.is_expired())
            || (blocked_ips.has_blocked_networks
                && blocked_ips
                    .blocked_ip_networks
                    .iter()
                    .any(|network| network.ip.matches(&ip) && !network.is_expired())))
            && !self.is_ip_allowed(ip)
    }

    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        self.core
            .network
            .security
            .allowed_ip_addresses
            .get(&IpWithTtl::new(ip, 0))
            .is_some_and(|v| !v.is_expired())
            || (self.core.network.security.has_allowed_networks
                && self
                    .core
                    .network
                    .security
                    .allowed_ip_networks
                    .iter()
                    .any(|network| network.ip.matches(&ip) && !network.is_expired()))
    }

    pub fn is_secure_password(&self, password: &str, user_inputs: &[&str]) -> Result<(), String> {
        if (password.len() as u32) > self.core.network.security.password_max_length {
            Err(format!(
                "Password must be at most {} characters long.",
                self.core.network.security.password_max_length
            ))
        } else if (password.len() as u32) < self.core.network.security.password_min_length {
            Err(format!(
                "Password must be at least {} characters long.",
                self.core.network.security.password_min_length
            ))
        } else if self.core.network.security.password_min_strength > Score::Zero {
            let entropy = zxcvbn::zxcvbn(password, user_inputs);
            if entropy.score() >= self.core.network.security.password_min_strength {
                Ok(())
            } else if let Some(feedback) = entropy.feedback() {
                Err(format!("Password is too weak. {feedback}"))
            } else {
                Err("Password is too weak.".to_string())
            }
        } else {
            Ok(())
        }
    }
}

impl BlockedIps {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut ips = Self::default();

        if bp.registry.is_recovery_mode() {
            return ips;
        }

        let mut expired_blocks = Vec::new();
        let now = now() as i64;

        for ip in bp.list_infallible::<BlockedIp>().await {
            let id = ip.id;
            let revision = ip.revision;
            let ip = ip.object;
            let expires_at = ip
                .expires_at
                .as_ref()
                .map(|dt| dt.timestamp() as u64)
                .unwrap_or(u64::MAX);

            if ip.expires_at.as_ref().is_none_or(|ip| ip.timestamp() > now) {
                if let Some(ip) = ip.address.try_to_ip() {
                    ips.blocked_ip_addresses
                        .insert(IpWithTtl::new(ip, expires_at));
                } else {
                    ips.blocked_ip_networks
                        .push(IpWithTtl::new(ip.address, expires_at));
                }
            } else {
                expired_blocks.push((
                    id,
                    ip.address.clone(),
                    Object {
                        inner: ip.into(),
                        revision,
                    },
                ));
            }
        }

        if !expired_blocks.is_empty() {
            for (id, _, object) in &expired_blocks {
                if let Err(err) = bp
                    .registry
                    .write(RegistryWrite::delete_object(*id, object))
                    .await
                {
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
                    .map(|(_, ip, _)| trc::Value::from(ip.into_inner().0))
                    .collect::<Vec<_>>()
            );
        }

        ips.has_blocked_networks = !ips.blocked_ip_networks.is_empty();
        ips
    }
}

impl<T: PartialEq + Eq + Hash> Hash for IpWithTtl<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ip.hash(state);
    }
}

impl<T: PartialEq + Eq + Hash> PartialEq for IpWithTtl<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

impl<T: PartialEq + Eq + Hash> Eq for IpWithTtl<T> {}

impl<T: PartialEq + Eq + Hash> IpWithTtl<T> {
    pub fn new(ip: T, expires_at: u64) -> Self {
        Self { ip, expires_at }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at <= now()
    }
}
