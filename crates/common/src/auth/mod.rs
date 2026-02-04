/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{expr::if_block::IfBlock, listener::limiter::ConcurrencyLimiter};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use arcstr::ArcStr;
use directory::Credentials;
use registry::{
    schema::enums::{Locale, Permission, StorageObject},
    types::EnumType,
};
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use tinyvec::TinyVec;
use trc::ipc::bitset::Bitset;
use types::collection::Collection;
use utils::{cache::CacheItemWeight, map::bitmap::Bitmap};

pub mod access_token;
pub mod authentication;
pub mod oauth;
pub mod rate_limit;
pub mod roles;
pub mod sasl;

const PERMISSIONS_BITSET_SIZE: usize = Permission::COUNT.div_ceil(std::mem::size_of::<usize>());
pub type Permissions = Bitset<PERMISSIONS_BITSET_SIZE>;
pub type ObjectQuota = [u32; StorageObject::COUNT - 1];
pub type IdMap<V> = HashMap<u32, V, nohash_hasher::BuildNoHashHasher<u32>>;

pub struct DirectoryEntries {
    pub emails: ArcSwap<EmailEntries>,
    pub domains: ArcSwap<DomainEntries>,
    pub accounts: ArcSwap<AccountEntries>,
    pub groups: ArcSwap<GroupEntries>,
    pub roles: ArcSwap<RoleEntries>,
    pub mailing_lists: ArcSwap<MailingListEntries>,
    pub tenants: ArcSwap<TenantEntries>,
    pub api_keys: ArcSwap<ApiKeyEntries>,
}

#[derive(Debug, Clone)]
pub struct EmailEntries {
    pub addresses: AHashMap<ArcStr, EmailEntry>,
}

#[derive(Debug, Clone)]
pub struct EmailEntry {
    pub id: u32,
    pub flags: u8,
}

pub const EMAIL_FLAG_ACCOUNT: u8 = 1;
pub const EMAIL_FLAG_GROUP: u8 = 1 << 1;
pub const EMAIL_FLAG_MAILING_LIST: u8 = 1 << 2;
pub const EMAIL_FLAG_ALIAS: u8 = 1 << 3;
pub const EMAIL_FLAG_EXPIRES: u8 = 1 << 4;

#[derive(Debug, Clone)]
pub struct DomainEntries {
    pub names: AHashMap<ArcStr, u32>,
    pub entries: IdMap<DomainEntry>,
    pub default: u32,
}

#[derive(Debug, Clone)]
pub struct AccountEntries {
    pub entries: IdMap<AccountEntry>,
}

#[derive(Debug, Clone)]
pub struct GroupEntries {
    pub entries: IdMap<GroupEntry>,
}

#[derive(Debug, Clone)]
pub struct RoleEntries {
    pub entries: IdMap<RoleEntry>,
}

#[derive(Debug, Clone)]
pub struct MailingListEntries {
    pub entries: IdMap<MailingListEntry>,
}

#[derive(Debug, Clone)]
pub struct TenantEntries {
    pub entries: IdMap<TenantEntry>,
}

#[derive(Debug, Clone)]
pub struct ApiKeyEntries {
    pub entries: AHashMap<ArcStr, ApiKeyEntry>,
}

#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub name: ArcStr,
    pub id_alias_of: u32,
    pub id_tenant: u32,
    pub id_directory: u32,
    pub catch_all: Option<ArcStr>,
    pub sub_addressing_custom: Option<Arc<IfBlock>>,
    pub flags: u8,
}

pub const DOMAIN_FLAG_LOCAL: u8 = 1;
pub const DOMAIN_FLAG_DEFAULT: u8 = 1 << 1;
pub const DOMAIN_FLAG_SUB_ADDRESSING: u8 = 1 << 2;
pub const DOMAIN_FLAG_WILDCARD: u8 = 1 << 3;
pub const DOMAIN_FLAG_ALIAS_LOGIN: u8 = 1 << 4;

#[derive(Debug, Clone)]
pub struct AccountEntry {
    pub addresses: Arc<[ArcStr]>,
    pub id_tenant: u32,
    pub description: Option<ArcStr>,
    pub locale: Locale,
}

#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub addresses: Arc<[ArcStr]>,
    pub id_member_of: TinyVec<[u32; 3]>,
    pub id_tenant: u32,
    pub id_roles: TinyVec<[u32; 3]>,
    pub quota_disk: u64,
    pub quota_objects: Option<Arc<ObjectQuota>>,
    pub permissions: Option<Arc<PermissionsGroup>>,
}

#[derive(Debug, Clone)]
pub struct RoleEntry {
    pub id_tenant: u32,
    pub id_roles: TinyVec<[u32; 3]>,
    pub permissions: Permissions,
}

#[derive(Debug, Clone)]
pub struct MailingListEntry {
    pub addresses: Arc<[ArcStr]>,
    pub id_tenant: u32,
    pub recipients: Arc<[ArcStr]>,
}

#[derive(Debug, Clone)]
pub struct TenantEntry {
    pub id_roles: TinyVec<[u32; 3]>,
    pub quota_disk: u64,
    pub quota_objects: Option<Arc<ObjectQuota>>,
    pub permissions: Option<Arc<PermissionsGroup>>,
}

#[derive(Debug, Clone)]
pub struct ApiKeyEntry {
    pub id: u32,
    pub id_tenant: u32,
    pub id_roles: TinyVec<[u32; 3]>,
    pub permissions: Option<Arc<PermissionsGroup>>,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct PermissionsGroup {
    pub enabled: Permissions,
    pub disabled: Permissions,
    pub merge: bool,
}

#[derive(Debug, Default)]
pub struct AccessToken {
    pub addresses: Arc<[ArcStr]>,
    pub primary_id: u32,
    pub member_of: TinyVec<[u32; 3]>,
    pub access_to: Box<[AccessTo]>,
    pub quota_disk: u64,
    pub quota_disk_tenant: u64,
    pub quota_disk_domain: u64,
    pub quota_objects: ObjectQuota,
    pub permissions: Permissions,
    pub concurrent_http_requests: Option<ConcurrencyLimiter>,
    pub concurrent_imap_requests: Option<ConcurrencyLimiter>,
    pub concurrent_uploads: Option<ConcurrencyLimiter>,
    pub revision: u64,
    pub obj_size: u64,
}

#[derive(Debug, Default)]
pub struct AccessTo {
    pub account_id: u32,
    pub collections: Bitmap<Collection>,
}

pub struct AuthRequest {
    credentials: Credentials,
    session_id: u64,
    remote_ip: IpAddr,
    return_member_of: bool,
    allow_api_access: bool,
}

impl CacheItemWeight for AccessToken {
    fn weight(&self) -> u64 {
        self.obj_size
    }
}
