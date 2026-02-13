/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    expr::if_block::IfBlock,
    network::limiter::ConcurrencyLimiter,
    storage::{ObjectQuota, TenantQuota},
};
use arcstr::ArcStr;
use directory::Credentials;
use quick_cache::Equivalent;
use registry::{
    schema::enums::{Locale, Permission},
    types::EnumType,
};
use std::{
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
};
use tinyvec::TinyVec;
use trc::ipc::bitset::Bitset;
use types::collection::Collection;
use utils::{cache::CacheItemWeight, map::bitmap::Bitmap};

pub mod access_token;
pub mod authentication;
pub mod credential;
pub mod oauth;
pub mod permissions;
pub mod rate_limit;

pub const FALLBACK_ADMIN_ID: u32 = u32::MAX;
const PERMISSIONS_BITSET_SIZE: usize = Permission::COUNT.div_ceil(std::mem::size_of::<usize>());
pub type Permissions = Bitset<PERMISSIONS_BITSET_SIZE>;

#[derive(Debug, PartialEq, Eq)]
pub struct EmailAddress {
    local_part: Box<str>,
    id_domain: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EmailAddressRef<'x> {
    local_part: &'x str,
    id_domain: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum EmailCache {
    Account(u32),
    MailingList(u32),
}

#[derive(Debug, Clone)]
pub struct DomainCache {
    pub names: Box<[ArcStr]>,
    pub id: u32,
    pub id_directory: Option<u32>,
    pub id_tenant: u32,
    pub catch_all: Option<ArcStr>,
    pub sub_addressing_custom: Option<Box<IfBlock>>,
    pub flags: u8,
}

pub const DOMAIN_FLAG_RELAY: u8 = 1;
pub const DOMAIN_FLAG_SUB_ADDRESSING: u8 = 1 << 1;

#[derive(Debug, Clone)]
pub struct AccountCache {
    pub addresses: Box<[ArcStr]>,
    pub id_tenant: Option<u32>,
    pub id_member_of: TinyVec<[u32; 3]>,
    pub quota_disk: u64,
    pub quota_objects: Option<Box<ObjectQuota>>,
    pub description: Option<Box<str>>,
    pub locale: Locale,
    pub is_user: bool,
}

#[derive(Debug, Clone)]
pub struct RoleCache {
    pub id_roles: TinyVec<[u32; 3]>,
    pub permissions: PermissionsGroup,
}

#[derive(Debug, Clone)]
pub struct MailingListCache {
    pub addresses: Box<[ArcStr]>,
    pub recipients: Arc<[ArcStr]>,
}

#[derive(Debug, Clone)]
pub struct TenantCache {
    pub id_roles: TinyVec<[u32; 3]>,
    pub quota_disk: u64,
    pub quota_objects: Option<Box<TenantQuota>>,
    pub permissions: Option<Box<PermissionsGroup>>,
}

#[derive(Debug, Clone, Default)]
pub struct PermissionsGroup {
    pub enabled: Permissions,
    pub disabled: Permissions,
    pub merge: bool,
}

#[derive(Debug, Default, Clone)]
pub struct AccessToken {
    scope_idx: usize,
    inner: Arc<AccessTokenInner>,
}

#[derive(Debug, Default)]
pub struct AccessTokenInner {
    pub(crate) account_id: u32,
    pub(crate) tenant_id: Option<u32>,
    pub(crate) member_of: TinyVec<[u32; 3]>,
    pub(crate) access_to: Box<[AccessTo]>,
    pub(crate) scopes: Box<[AccessScope]>,
    pub(crate) concurrent_http_requests: Option<ConcurrencyLimiter>,
    pub(crate) concurrent_imap_requests: Option<ConcurrencyLimiter>,
    pub(crate) concurrent_uploads: Option<ConcurrencyLimiter>,
    pub(crate) revision_account: u64,
    pub(crate) revision: u64,
    pub(crate) obj_size: u64,
}

#[derive(Debug, Default, Hash)]
pub(crate) struct AccessScope {
    pub permissions: Permissions,
    pub credential_id: u32,
    pub expires_at: u64,
}

#[derive(Debug, Default, Hash, PartialEq, Eq)]
pub(crate) struct AccessTo {
    pub account_id: u32,
    pub collections: Bitmap<Collection>,
}

#[derive(Clone)]
pub struct AccountInfo {
    pub(crate) account_id: u32,
    pub(crate) account: Arc<AccountCache>,
    pub(crate) member_of: Vec<Arc<AccountCache>>,
}

#[derive(Clone, Copy)]
pub struct AccountTenantIds {
    pub account_id: u32,
    pub tenant_id: Option<u32>,
}

pub struct AuthRequest {
    credentials: Credentials,
    session_id: u64,
    remote_ip: IpAddr,
}

impl CacheItemWeight for AccessTokenInner {
    fn weight(&self) -> u64 {
        self.obj_size
    }
}

impl CacheItemWeight for EmailAddress {
    fn weight(&self) -> u64 {
        std::mem::size_of::<EmailAddress>() as u64 + self.local_part.len() as u64
    }
}

impl CacheItemWeight for EmailCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<EmailCache>() as u64
    }
}

impl CacheItemWeight for DomainCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<DomainCache>() as u64
            + self.names.iter().map(|s| s.len() as u64).sum::<u64>()
            + self.catch_all.as_ref().map_or(0, |s| s.len() as u64)
            + self
                .sub_addressing_custom
                .as_ref()
                .map_or(0, |s| s.weight())
    }
}

impl Equivalent<EmailAddress> for EmailAddressRef<'_> {
    fn equivalent(&self, key: &EmailAddress) -> bool {
        self.local_part == &*key.local_part && self.id_domain == key.id_domain
    }
}

impl Hash for EmailAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_part.as_ref().hash(state);
        self.id_domain.hash(state);
    }
}

impl Hash for EmailAddressRef<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_part.hash(state);
        self.id_domain.hash(state);
    }
}

impl CacheItemWeight for AccountCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<AccountCache>() as u64
            + self.addresses.iter().map(|s| s.len() as u64).sum::<u64>()
            + self.description.as_ref().map_or(0, |s| s.len() as u64)
    }
}

impl CacheItemWeight for RoleCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<RoleCache>() as u64
    }
}

impl CacheItemWeight for MailingListCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<MailingListCache>() as u64
            + self.addresses.iter().map(|s| s.len() as u64).sum::<u64>()
            + self.recipients.iter().map(|s| s.len() as u64).sum::<u64>()
    }
}

impl CacheItemWeight for TenantCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<TenantCache>() as u64
            + self.permissions.as_ref().map_or(0, |p| p.weight())
    }
}

impl CacheItemWeight for PermissionsGroup {
    fn weight(&self) -> u64 {
        std::mem::size_of::<PermissionsGroup>() as u64
    }
}

pub trait BuildAccessToken {
    fn build(self) -> AccessToken;
}

impl BuildAccessToken for Arc<AccessTokenInner> {
    fn build(self) -> AccessToken {
        AccessToken {
            scope_idx: 0,
            inner: self,
        }
    }
}

impl<'x> EmailAddressRef<'x> {
    pub fn new(local_part: &'x str, id_domain: u32) -> Self {
        Self {
            local_part,
            id_domain,
        }
    }
}
