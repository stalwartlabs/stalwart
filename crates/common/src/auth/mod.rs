/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    auth::{active_script::ActiveScriptSlot, oauth::scope::OAuthScopes},
    expr::if_block::IfBlock,
    network::limiter::AccountLimits,
    storage::{ObjectQuota, encryption::AccountEncryption},
};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::storage::TenantQuota;
// SPDX-SnippetEnd
use compact_str::CompactString;
use directory::Credentials;
use quick_cache::Equivalent;
use registry::{
    schema::enums::{Locale, Permission},
    types::{EnumImpl, ipmask::IpAddrOrMask},
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
pub mod active_script;
pub mod authentication;
pub mod credential;
pub mod oauth;
pub mod passkey;
pub mod permissions;
pub mod rate_limit;
pub mod sasl;

pub const RECOVERY_ADMIN_ID: u32 = u32::MAX;
const PERMISSIONS_BITSET_SIZE: usize = Permission::COUNT.div_ceil(std::mem::size_of::<usize>() * 8);
pub type Permissions = Bitset<PERMISSIONS_BITSET_SIZE>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EmailAddress {
    pub local_part: CompactString,
    pub domain_id: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EmailAddressRef<'x> {
    local_part: &'x str,
    domain_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailCache {
    Account(u32),
    MailingList(u32),
    DisabledAccountAddress(u32),
    DisabledListAddress(u32),
}

#[derive(Debug, Clone)]
pub struct DomainCache {
    pub names: Box<[Box<str>]>,
    pub id: u32,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub id_directory: Option<u32>,
    #[cfg(feature = "enterprise")]
    pub id_tenant: Option<u32>,
    // SPDX-SnippetEnd
    pub catch_all: Option<Box<str>>,
    pub sub_addressing_custom: Option<Box<IfBlock>>,
    pub flags: u8,
}

pub const DOMAIN_FLAG_RELAY: u8 = 1;
pub const DOMAIN_FLAG_SUB_ADDRESSING: u8 = 1 << 1;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
pub const DOMAIN_FLAG_SCIM_PROVISIONING: u8 = 1 << 2;
// SPDX-SnippetEnd

#[derive(Debug, Clone, Default)]
pub struct AccountCache {
    pub name: Box<str>,
    pub id: u32,
    pub addresses: Box<[EmailAddress]>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub id_tenant: Option<u32>,
    // SPDX-SnippetEnd
    pub id_member_of: Box<[u32]>,
    pub quota_disk: u64,
    pub description: Option<Box<str>>,
    pub storage: Option<Box<AccountStorage>>,
    pub locale: Locale,
    pub flags: u64,
    pub active_script: ActiveScriptSlot,
}

#[derive(Debug, Clone, Default)]
pub struct AccountStorage {
    pub quota_objects: Option<ObjectQuota>,
    pub encryption: Option<Arc<AccountEncryption>>,
}

const _: () = assert!(size_of::<AccountCache>() <= 112);

impl AccountStorage {
    pub fn boxed(
        quota_objects: Option<ObjectQuota>,
        encryption: Option<Arc<AccountEncryption>>,
    ) -> Option<Box<Self>> {
        (quota_objects.is_some() || encryption.is_some()).then(|| {
            Box::new(AccountStorage {
                quota_objects,
                encryption,
            })
        })
    }
}

pub const ACCOUNT_IS_USER: u64 = 1;

#[derive(Debug, Clone)]
pub struct RoleCache {
    pub id_roles: TinyVec<[u32; 3]>,
    pub permissions: PermissionsGroup,
}

#[derive(Debug, Clone)]
pub struct MailingListCache {
    pub addresses: Box<[EmailAddress]>,
    pub recipients: Arc<[Box<str>]>,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone)]
pub struct TenantCache {
    pub id_roles: TinyVec<[u32; 3]>,
    pub quota_disk: u64,
    pub quota_objects: Option<Box<TenantQuota>>,
    pub permissions: Option<Box<PermissionsGroup>>,
}
// SPDX-SnippetEnd

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
    token_scope: Option<TokenScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenScope {
    Grant { grant_id: u64, scopes: OAuthScopes },
    External { scopes: OAuthScopes },
}

const _: () = assert!(size_of::<TokenScope>() <= 16);
const _: () = assert!(size_of::<Option<TokenScope>>() <= 16);

#[derive(Debug, Default, Clone)]
pub struct AccessTokenInner {
    pub(crate) account_id: u32,
    pub(crate) obj_size: u32,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub(crate) tenant_id: Option<u32>,
    // SPDX-SnippetEnd
    pub(crate) member_of: Box<[u32]>,
    pub(crate) access_to: Box<[AccessTo]>,
    pub(crate) scopes: Box<[AccessScope]>,
    pub(crate) limits: Option<Arc<AccountLimits>>,
    pub(crate) revision_account: u64,
    pub(crate) revision: u64,
    pub(crate) credential_version: u64,
}

const _: () = assert!(size_of::<AccessTokenInner>() <= 96);

#[derive(Debug, Default, Hash, Clone)]
pub struct AccessScope {
    pub permissions: Permissions,
    pub credential_id: u32,
    pub expires_at: u64,
    pub allowed_ips: Box<[IpAddrOrMask]>,
}

#[derive(Debug, Default, Hash, PartialEq, Eq, Clone)]
pub(crate) struct AccessTo {
    pub account_id: u32,
    pub collections: Bitmap<Collection>,
    pub is_writable: bool,
}

#[derive(Clone)]
pub struct AccountInfo {
    pub account_id: u32,
    pub account: Arc<AccountCache>,
    pub addresses: Vec<String>,
}

#[derive(Clone, Copy)]
pub struct ChangedBy {
    pub account_id: u32,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub tenant_id: Option<u32>,
    // SPDX-SnippetEnd
}

pub struct AuthRequest {
    pub credentials: Credentials,
    pub session_id: u64,
    pub remote_ip: IpAddr,
}

impl CacheItemWeight for AccessTokenInner {
    fn weight(&self) -> u64 {
        u64::from(self.obj_size)
    }
}

impl CacheItemWeight for EmailAddress {
    fn weight(&self) -> u64 {
        std::mem::size_of::<EmailAddress>() as u64 + self.heap_size()
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
            + self
                .names
                .iter()
                .map(|s| s.len() as u64 + std::mem::size_of::<Box<str>>() as u64)
                .sum::<u64>()
            + self.catch_all.as_ref().map_or(0, |s| s.len() as u64)
            + self
                .sub_addressing_custom
                .as_ref()
                .map_or(0, |s| s.weight())
    }
}

impl Equivalent<EmailAddress> for EmailAddressRef<'_> {
    fn equivalent(&self, key: &EmailAddress) -> bool {
        self.local_part == key.local_part.as_str() && self.domain_id == key.domain_id
    }
}

impl Hash for EmailAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_part.as_str().hash(state);
        self.domain_id.hash(state);
    }
}

impl Hash for EmailAddressRef<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_part.hash(state);
        self.domain_id.hash(state);
    }
}

impl CacheItemWeight for AccountCache {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<AccountCache>()
            + self.name.len()
            + std::mem::size_of_val::<[u32]>(&self.id_member_of)
            + self.description.as_ref().map_or(0, |s| s.len())) as u64
            + self
                .addresses
                .iter()
                .map(|address| address.weight())
                .sum::<u64>()
            + self.storage.as_ref().map_or(0, |storage| storage.weight())
    }
}

impl CacheItemWeight for AccountStorage {
    fn weight(&self) -> u64 {
        std::mem::size_of::<AccountStorage>() as u64
            + self.encryption.as_ref().map_or(0, |e| e.weight())
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
            + self
                .addresses
                .iter()
                .map(|address| address.weight())
                .sum::<u64>()
            + self
                .recipients
                .iter()
                .map(|s| s.len() as u64 + std::mem::size_of::<Box<str>>() as u64)
                .sum::<u64>()
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl CacheItemWeight for TenantCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<TenantCache>() as u64
            + self.permissions.as_ref().map_or(0, |p| p.weight())
    }
}
// SPDX-SnippetEnd

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
            token_scope: None,
        }
    }
}

impl EmailAddress {
    pub fn new(local_part: impl Into<CompactString>, domain_id: u32) -> Self {
        Self {
            local_part: local_part.into(),
            domain_id,
        }
    }

    #[inline]
    pub fn heap_size(&self) -> u64 {
        if self.local_part.is_heap_allocated() {
            self.local_part.capacity() as u64
        } else {
            0
        }
    }
}

impl<'x> EmailAddressRef<'x> {
    pub fn new(local_part: &'x str, domain_id: u32) -> Self {
        Self {
            local_part,
            domain_id,
        }
    }
}

impl AccountCache {
    pub fn domain_id(&self) -> Option<u32> {
        self.addresses.first().map(|address| address.domain_id)
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[inline]
    pub fn is_same_tenant(&self, access_token: &AccessToken) -> bool {
        self.id_tenant == access_token.tenant_id()
    }
    // SPDX-SnippetEnd

    #[cfg(not(feature = "enterprise"))]
    #[inline]
    pub fn is_same_tenant(&self, _access_token: &AccessToken) -> bool {
        true
    }
}

impl DomainCache {
    pub fn name(&self) -> &str {
        self.names.first().map(|s| s.as_ref()).unwrap_or_default()
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[inline]
    pub fn is_same_tenant(&self, other: &DomainCache) -> bool {
        self.id_tenant == other.id_tenant
    }
    // SPDX-SnippetEnd

    #[cfg(not(feature = "enterprise"))]
    #[inline]
    pub fn is_same_tenant(&self, _other: &DomainCache) -> bool {
        true
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[inline]
    pub fn allows_scim_provisioning(&self) -> bool {
        (self.flags & DOMAIN_FLAG_SCIM_PROVISIONING) != 0
    }
    // SPDX-SnippetEnd
}
