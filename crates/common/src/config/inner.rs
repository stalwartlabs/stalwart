/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::server::tls::build_self_signed_cert;
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::auth::TenantCache;
// SPDX-SnippetEnd
use crate::{
    Caches, Data, GroupwareResource, GroupwareResources, MailboxCache, MessageStoreCache,
    MessageUid, TlsConnectors,
    auth::{AccessTokenInner, AccountCache, DomainCache, MailingListCache, RoleCache},
    cache::{
        RevalidateInterval,
        http_auth::{GrantRevocations, HttpAuthEntries},
        large::{LargeMessageCaches, LargeResourceCaches},
        swap::SwapReceiver,
    },
    config::{
        mailstore::spamfilter::{SpamClassifier, SpamLookup},
        server::tls::parse_certificates,
        smtp::{
            auth::DkimSigners,
            resolver::{Policy, Tlsa},
        },
    },
    manager::application::WebApplications,
    network::security::BlockedIps,
    storage::metadata::MetadataViewerCache,
};
use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use mail_auth::{DnsCache, Mx, Negative, Parameters, RecordSet, TxtRecord};
use parking_lot::RwLock;
use registry::schema::{prelude::ObjectType, structs};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use store::{LookupStores, registry::bootstrap::Bootstrap};
use tokio::sync::Semaphore;
use types::collection::SyncCollection;
use utils::{
    UnwrapFailure,
    cache::{Cache, CacheWithTtl, SpillCache},
    snowflake::{MAX_NODE_ID, SnowflakeIdGenerator},
    tls::build_tls_connector,
};

const MAX_HARVEST_TASKS: usize = 8;

impl Data {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        // Parse certificates
        let mut certificates = AHashMap::new();
        let mut subject_names = AHashSet::new();
        parse_certificates(bp, &mut certificates, &mut subject_names).await;
        if subject_names.is_empty() {
            subject_names.insert("localhost".into());
        }

        // Build and test snowflake id generator
        let node_id = bp.node_id();
        if node_id > MAX_NODE_ID {
            panic!("Node id {node_id} exceeds {MAX_NODE_ID}, panicking to avoid data corruption");
        }
        SnowflakeIdGenerator::set_node_id(node_id as u64);
        let id_generator = SnowflakeIdGenerator::new();
        if !id_generator.is_valid() {
            panic!("Invalid system time, panicking to avoid data corruption");
        }

        // Initialize apps
        let applications = WebApplications::new();
        applications.reload(bp).await;

        let blocked_ips = BlockedIps::parse(bp).await;
        let lookup_stores = LookupStores::build(bp).await;

        Data {
            spam_classifier: ArcSwap::from_pointee(SpamClassifier::default()),
            tls_certificates: ArcSwap::from_pointee(certificates),
            tls_self_signed_cert: build_self_signed_cert(
                subject_names
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<_>>(),
            )
            .or_else(|err| {
                bp.build_error(
                    ObjectType::Certificate.singleton(),
                    format!("Failed to build self-signed TLS certificate: {err}"),
                );
                build_self_signed_cert(vec!["localhost".to_string()])
            })
            .ok()
            .map(Arc::new),
            lookup_stores: ArcSwap::from_pointee(lookup_stores.stores),
            blocked_ips: RwLock::new(blocked_ips),
            jmap_id_gen: id_generator.clone(),
            queue_id_gen: id_generator.clone(),
            registry_id_gen: id_generator.clone(),
            span_id_gen: id_generator,
            queue_status: true.into(),
            applications,
            logos: Default::default(),
            smtp_connectors: TlsConnectors::try_new().failed("Failed to build TLS connectors"),
            memory_budget: Default::default(),
            harvest_tasks: Arc::new(Semaphore::new(MAX_HARVEST_TASKS)),
            asn_geo_data: Default::default(),
            password_verifier: Default::default(),
        }
    }
}

impl Caches {
    pub async fn parse(
        bp: &mut Bootstrap,
        storage: &crate::config::storage::Storage,
    ) -> (Self, SwapReceiver) {
        let cache = bp.setting_infallible::<structs::Cache>().await;
        let dav_estimate = (std::mem::size_of::<GroupwareResources>()
            + (500 * std::mem::size_of::<GroupwareResource>())) as u64;
        let (swap, swap_rx) = crate::cache::swap::SwapTier::build(bp, cache.swap, storage).await;

        let caches = Caches {
            revalidate: RevalidateInterval::new(RevalidateInterval::DEFAULT),
            access_tokens: SpillCache::new(
                cache.access_tokens,
                (std::mem::size_of::<AccessTokenInner>() + 255) as u64,
            )
            .with_name("accessTokens"),
            http_auth: HttpAuthEntries::new(cache.http_auth),
            grant_revocations: GrantRevocations::default(),
            messages: Cache::new_single_shard_with(
                cache.messages,
                (std::mem::size_of::<u32>()
                    + std::mem::size_of::<Arc<MessageStoreCache>>()
                    + (1024 * std::mem::size_of::<MessageUid>())
                    + (15 * (std::mem::size_of::<MailboxCache>() + 60))) as u64,
                swap.eviction(SyncCollection::Email),
            )
            .with_name("messages"),
            messages_large: LargeMessageCaches::new(
                cache.messages_large,
                cache.messages_large_ttl.into_inner(),
            ),
            resources_large: LargeResourceCaches::new(
                cache.groupware_large,
                cache.groupware_large_ttl.into_inner(),
            ),
            files: Cache::new_single_shard_with(
                cache.files,
                dav_estimate,
                swap.eviction(SyncCollection::FileNode),
            )
            .with_name("files"),
            events: Cache::new_single_shard_with(
                cache.events,
                dav_estimate,
                swap.eviction(SyncCollection::Calendar),
            )
            .with_name("events"),
            contacts: Cache::new_single_shard_with(
                cache.contacts,
                dav_estimate,
                swap.eviction(SyncCollection::AddressBook),
            )
            .with_name("contacts"),
            scheduling: Cache::new_single_shard_with(
                cache.scheduling,
                dav_estimate,
                swap.eviction(SyncCollection::CalendarEventNotification),
            )
            .with_name("scheduling"),
            metadata_viewers: MetadataViewerCache::new(cache.access_tokens / 4),
            emails: Cache::new(cache.email_addresses, 255u64).with_name("emailAddresses"),
            emails_negative: CacheWithTtl::new(
                cache.email_addresses_negative,
                (std::mem::size_of::<DomainCache>() + 255) as u64,
            ),
            domain_names: Cache::new(
                cache.domain_names,
                (std::mem::size_of::<DomainCache>() + 255) as u64,
            )
            .with_name("domainNames"),
            domain_names_negative: CacheWithTtl::new(
                cache.domain_names_negative,
                (std::mem::size_of::<DomainCache>() + 255) as u64,
            ),
            domains: Cache::new(
                cache.domains,
                (std::mem::size_of::<DomainCache>() + 255) as u64,
            )
            .with_name("domains"),
            accounts: Cache::new(
                cache.accounts,
                (std::mem::size_of::<AccountCache>() + 255) as u64,
            )
            .with_name("accounts"),
            roles: Cache::new(cache.roles, (std::mem::size_of::<RoleCache>() + 255) as u64)
                .with_name("roles"),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            tenants: Cache::new(
                cache.tenants,
                (std::mem::size_of::<TenantCache>() + 255) as u64,
            )
            .with_name("tenants"),
            // SPDX-SnippetEnd
            lists: Cache::new(
                cache.mailing_lists,
                (std::mem::size_of::<MailingListCache>() + 255) as u64,
            )
            .with_name("mailingLists"),
            dkim_signers: Cache::new(
                cache.dkim_signatures,
                (std::mem::size_of::<DkimSigners>() + 4096) as u64,
            )
            .with_name("dkimSignatures"),
            dns_txt: CacheWithTtl::new(
                cache.dns_txt,
                (std::mem::size_of::<TxtRecord>() + 512) as u64,
            ),
            dns_mx: CacheWithTtl::new(cache.dns_mx, ((std::mem::size_of::<Mx>() + 255) * 2) as u64),
            dns_ptr: CacheWithTtl::new(cache.dns_ptr, (std::mem::size_of::<IpAddr>() + 255) as u64),
            dns_ipv4: CacheWithTtl::new(
                cache.dns_ipv4,
                ((std::mem::size_of::<Ipv4Addr>() + 255) * 2) as u64,
            ),
            dns_ipv6: CacheWithTtl::new(
                cache.dns_ipv6,
                ((std::mem::size_of::<Ipv6Addr>() + 255) * 2) as u64,
            ),
            dns_tlsa: CacheWithTtl::new(cache.dns_tlsa, (std::mem::size_of::<Tlsa>() + 255) as u64),
            dns_mta_sts: CacheWithTtl::new(
                cache.dns_mta_sts,
                (std::mem::size_of::<Policy>() + 255) as u64,
            ),
            spam_lookup: CacheWithTtl::new(
                cache.spam_lookup,
                (std::mem::size_of::<SpamLookup>() + 255 * 2) as u64,
            ),
            directory_recipients: CacheWithTtl::new(cache.directory_recipients, 255u64),
            external_public_keys: CacheWithTtl::new(cache.external_public_keys, 4096u64),
            directory_recipients_ttl: cache.directory_recipients_ttl.into_inner(),
            negative_cache_ttl: cache.negative_ttl.into_inner(),
            swap,
        };

        (caches, swap_rx)
    }

    #[inline(always)]
    pub fn build_auth_parameters<T>(&self, params: T) -> Parameters<'_, T, Caches> {
        Parameters::new(params).with_cache(self)
    }
}

impl DnsCache for Caches {
    type Txt = CacheWithTtl<Box<str>, TxtRecord>;
    type Mx = CacheWithTtl<Box<str>, Result<RecordSet<Mx>, Negative>>;
    type Ipv4 = CacheWithTtl<Box<str>, Result<RecordSet<Ipv4Addr>, Negative>>;
    type Ipv6 = CacheWithTtl<Box<str>, Result<RecordSet<Ipv6Addr>, Negative>>;
    type Ptr = CacheWithTtl<IpAddr, Result<RecordSet<Box<str>>, Negative>>;

    fn txt(&self) -> Option<&Self::Txt> {
        Some(&self.dns_txt)
    }

    fn mx(&self) -> Option<&Self::Mx> {
        Some(&self.dns_mx)
    }

    fn ipv4(&self) -> Option<&Self::Ipv4> {
        Some(&self.dns_ipv4)
    }

    fn ipv6(&self) -> Option<&Self::Ipv6> {
        Some(&self.dns_ipv6)
    }

    fn ptr(&self) -> Option<&Self::Ptr> {
        Some(&self.dns_ptr)
    }
}

impl Default for Data {
    fn default() -> Self {
        Self {
            spam_classifier: Default::default(),
            tls_certificates: Default::default(),
            tls_self_signed_cert: Default::default(),
            blocked_ips: Default::default(),
            jmap_id_gen: Default::default(),
            queue_id_gen: Default::default(),
            span_id_gen: Default::default(),
            registry_id_gen: Default::default(),
            queue_status: true.into(),
            applications: WebApplications::new(),
            logos: Default::default(),
            smtp_connectors: TlsConnectors::try_new().unwrap(),
            memory_budget: Default::default(),
            harvest_tasks: Arc::new(Semaphore::new(MAX_HARVEST_TASKS)),
            asn_geo_data: Default::default(),
            password_verifier: Default::default(),
            lookup_stores: Default::default(),
        }
    }
}

impl TlsConnectors {
    fn try_new() -> Result<Self, String> {
        Ok(TlsConnectors {
            pki_verify: build_tls_connector(false)?,
            dummy_verify: build_tls_connector(true)?,
        })
    }
}
