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
        prelude::{Object, ObjectInner, ObjectType},
        structs::{self, AllowedIp, BlockedIp, Rate, SystemSettings},
    },
    types::{datetime::UTCDateTime, ipmask::IpAddrOrMask},
};
use std::{fmt::Debug, hash::Hash, net::IpAddr};
use store::{
    blake3,
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
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub default_role_ids_tenant: Vec<Id>,
    // SPDX-SnippetEnd
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
                Ip = expired_allows
                    .into_iter()
                    .map(|(_, ip, _)| trc::Value::from(ip.into_inner().0))
                    .collect::<Vec<_>>()
            );
        }

        #[cfg(not(stalwart_tests))]
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

        let is_recovery_mode = bp.registry.is_recovery_mode();
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
            auth_fail_rate: security.auth_ban_rate.filter(|_| !is_recovery_mode),
            rcpt_fail_rate: security.abuse_ban_rate.filter(|_| !is_recovery_mode),
            loiter_fail_rate: security.loiter_ban_rate.filter(|_| !is_recovery_mode),
            http_banned_paths: if is_recovery_mode {
                Vec::new()
            } else {
                security
                    .scan_ban_paths
                    .iter()
                    .map(|pattern| MatchType::Matches(GlobPattern::compile(pattern, true)))
                    .collect()
            },
            scanner_fail_rate: security.scan_ban_rate.filter(|_| !is_recovery_mode),
            default_role_ids_user: auth.default_user_role_ids.into_inner(),
            default_role_ids_group: auth.default_group_role_ids.into_inner(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            default_role_ids_tenant: auth.default_tenant_role_ids.into_inner(),
            // SPDX-SnippetEnd
            default_role_ids_admin: auth.default_admin_role_ids.into_inner(),
            password_hash_algorithm: auth.password_hash_algorithm,
            password_max_length: auth.max_password_length as u32,
            password_min_length: auth.min_password_length as u32,
            password_min_strength: match auth.min_password_strength {
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

    pub fn is_default_role(&self, role_id: u32) -> bool {
        let contains = |ids: &[Id]| ids.iter().any(|id| id.document_id() == role_id);
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if contains(&self.default_role_ids_tenant) {
            return true;
        }
        // SPDX-SnippetEnd
        contains(&self.default_role_ids_user)
            || contains(&self.default_role_ids_group)
            || contains(&self.default_role_ids_admin)
    }
}

impl Server {
    pub async fn is_rcpt_fail2banned(&self, ip: IpAddr, rcpt: &str) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.rcpt_fail_rate
            && !self.is_ip_allowed(ip)
        {
            let store = self.in_memory_store();
            let ip_key = ip_to_bytes(&ip);
            let rcpt_key = blake3::hash(rcpt.as_bytes());
            let is_allowed = store
                .is_rate_allowed(KV_RATE_LIMIT_RCPT, &ip_key, rate)
                .await?
                .is_none()
                && store
                    .is_rate_allowed(KV_RATE_LIMIT_RCPT, rcpt_key.as_bytes(), rate)
                    .await?
                    .is_none();

            if !is_allowed {
                return self
                    .ban_and_reset(
                        ip,
                        BlockReason::RcptToFailure,
                        KV_RATE_LIMIT_RCPT,
                        rate,
                        &[ip_key.as_slice(), rcpt_key.as_bytes()],
                    )
                    .await;
            }
        }

        Ok(false)
    }

    pub async fn is_scanner_fail2banned(&self, ip: IpAddr) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.scanner_fail_rate {
            self.is_ip_fail2banned(ip, KV_RATE_LIMIT_SCAN, rate, BlockReason::PortScanning)
                .await
        } else {
            Ok(false)
        }
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
            self.is_ip_fail2banned(ip, KV_RATE_LIMIT_LOITER, rate, BlockReason::Loitering)
                .await
        } else {
            Ok(false)
        }
    }

    async fn is_ip_fail2banned(
        &self,
        ip: IpAddr,
        prefix: u8,
        rate: &Rate,
        reason: BlockReason,
    ) -> trc::Result<bool> {
        if self.is_ip_allowed(ip) {
            return Ok(false);
        }

        let ip_key = ip_to_bytes(&ip);
        if self
            .in_memory_store()
            .is_rate_allowed(prefix, &ip_key, rate)
            .await?
            .is_none()
        {
            Ok(false)
        } else {
            self.ban_and_reset(ip, reason, prefix, rate, &[ip_key.as_slice()])
                .await
        }
    }

    async fn ban_and_reset(
        &self,
        ip: IpAddr,
        reason: BlockReason,
        prefix: u8,
        rate: &Rate,
        keys: &[&[u8]],
    ) -> trc::Result<bool> {
        self.block_ip(ip, reason).await?;
        for key in keys {
            if let Err(err) = self.in_memory_store().rate_reset(prefix, key, rate).await {
                trc::error!(
                    err.details("Failed to reset fail2ban counter")
                        .caused_by(trc::location!())
                );
            }
        }
        Ok(true)
    }

    pub async fn is_auth_fail2banned(&self, ip: IpAddr, login: Option<&str>) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.auth_fail_rate
            && !self.is_ip_allowed(ip)
        {
            let store = self.in_memory_store();
            let ip_key = ip_to_bytes(&ip);
            let login_key = login
                .filter(|login| !login.is_empty())
                .map(|login| blake3::hash(login.as_bytes()));
            let is_allowed = store
                .is_rate_allowed(KV_RATE_LIMIT_AUTH, &ip_key, rate)
                .await?
                .is_none()
                && match &login_key {
                    Some(login_key) => store
                        .is_rate_allowed(KV_RATE_LIMIT_AUTH, login_key.as_bytes(), rate)
                        .await?
                        .is_none(),
                    None => true,
                };

            if !is_allowed {
                let keys: &[&[u8]] = match &login_key {
                    Some(login_key) => &[ip_key.as_slice(), login_key.as_bytes()],
                    None => &[ip_key.as_slice()],
                };
                return self
                    .ban_and_reset(ip, BlockReason::AuthFailure, KV_RATE_LIMIT_AUTH, rate, keys)
                    .await;
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
        let expiry = expires_at.unwrap_or(u64::MAX);
        self.inner.data.blocked_ips.write().block(ip, expiry);

        // Write blocked IP to config
        let object = Object::from(BlockedIp {
            address: IpAddrOrMask::from_ip(ip),
            created_at: UTCDateTime::from_timestamp(now as i64),
            expires_at: expires_at.map(|ts| UTCDateTime::from_timestamp(ts as i64)),
            reason,
        });
        let registry = self.registry();
        let id = match registry
            .write(RegistryWrite::insert(&object))
            .await
            .caused_by(trc::location!())?
        {
            RegistryWriteResult::Success(id) => id,
            RegistryWriteResult::PrimaryKeyConflict { existing_id, .. } => {
                let Some(current) = registry
                    .get(existing_id)
                    .await
                    .caused_by(trc::location!())?
                else {
                    return Ok(());
                };
                let ObjectInner::BlockedIp(current_ip) = &current.inner else {
                    return Ok(());
                };
                if current_ip
                    .expires_at
                    .as_ref()
                    .map_or(u64::MAX, |dt| dt.timestamp() as u64)
                    >= expiry
                {
                    return Ok(());
                }
                let RegistryWriteResult::Success(id) = registry
                    .write(RegistryWrite::update(existing_id.id(), &object, &current))
                    .await
                    .caused_by(trc::location!())?
                else {
                    return Ok(());
                };
                id
            }
            _ => return Ok(()),
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
    pub fn block(&mut self, ip: IpAddr, expires_at: u64) {
        let entry = IpWithTtl::new(ip, expires_at);
        if self
            .blocked_ip_addresses
            .get(&entry)
            .is_none_or(|current| current.expires_at < expires_at)
        {
            self.blocked_ip_addresses.replace(entry);
        }
    }

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
                    ips.block(ip, expires_at);
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
                Ip = expired_blocks
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

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/network/security/tests.rs"]
mod tests;
