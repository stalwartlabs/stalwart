/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::server::tls::build_self_signed_cert;
use crate::{
    Caches, Data, DavResource, DavResources, MailboxCache, MessageStoreCache, MessageUidCache,
    TlsConnectors,
    auth::{AccessTokenInner, AccountCache, DomainCache, MailingListCache, RoleCache, TenantCache},
    config::{
        mailstore::spamfilter::SpamClassifier,
        server::tls::parse_certificates,
        smtp::{
            auth::DkimSigner,
            resolver::{Policy, Tlsa},
        },
    },
    network::security::BlockedIps,
};
use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use mail_auth::{MX, Parameters, Txt};
use mail_send::smtp::tls::build_tls_connector;
use parking_lot::RwLock;
use registry::schema::{
    prelude::{Object, ObjectType},
    structs,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use store::{LookupStores, registry::bootstrap::Bootstrap};
use utils::{
    cache::{Cache, CacheWithTtl},
    snowflake::SnowflakeIdGenerator,
};

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
        let id_generator = SnowflakeIdGenerator::with_node_id(node_id);
        if !id_generator.is_valid() {
            panic!("Invalid system time, panicking to avoid data corruption");
        }

        let todo = "TODO: WebApplicationManager initialization";

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
            span_id_gen: id_generator,
            queue_status: true.into(),
            applications: Default::default(),
            logos: Default::default(),
            smtp_connectors: TlsConnectors::default(),
            asn_geo_data: Default::default(),
        }
    }
}

impl Caches {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let cache = bp.setting_infallible::<structs::Cache>().await;

        Caches {
            access_tokens: Cache::new(
                cache.access_tokens,
                (std::mem::size_of::<AccessTokenInner>() + 255) as u64,
            ),
            http_auth: Cache::new(cache.http_auth, (50 + std::mem::size_of::<u32>()) as u64),
            messages: Cache::new(
                cache.messages,
                (std::mem::size_of::<u32>()
                    + std::mem::size_of::<Arc<MessageStoreCache>>()
                    + (1024 * std::mem::size_of::<MessageUidCache>())
                    + (15 * (std::mem::size_of::<MailboxCache>() + 60))) as u64,
            ),
            files: Cache::new(
                cache.files,
                (std::mem::size_of::<DavResources>() + (500 * std::mem::size_of::<DavResource>()))
                    as u64,
            ),
            events: Cache::new(
                cache.events,
                (std::mem::size_of::<DavResources>() + (500 * std::mem::size_of::<DavResource>()))
                    as u64,
            ),
            contacts: Cache::new(
                cache.contacts,
                (std::mem::size_of::<DavResources>() + (500 * std::mem::size_of::<DavResource>()))
                    as u64,
            ),
            scheduling: Cache::new(
                cache.scheduling,
                (std::mem::size_of::<DavResources>() + (500 * std::mem::size_of::<DavResource>()))
                    as u64,
            ),
            emails: Cache::new(cache.email_addresses, 255u64),
            emails_negative: CacheWithTtl::new(
                cache.email_addresses_negative,
                (std::mem::size_of::<DomainCache>() + 255) as u64,
            ),
            domain_names: Cache::new(
                cache.domain_names,
                (std::mem::size_of::<DomainCache>() + 255) as u64,
            ),
            domain_names_negative: CacheWithTtl::new(
                cache.domain_names_negative,
                (std::mem::size_of::<DomainCache>() + 255) as u64,
            ),
            domains: Cache::new(
                cache.domains,
                (std::mem::size_of::<DomainCache>() + 255) as u64,
            ),
            accounts: Cache::new(
                cache.accounts,
                (std::mem::size_of::<AccountCache>() + 255) as u64,
            ),
            roles: Cache::new(cache.roles, (std::mem::size_of::<RoleCache>() + 255) as u64),
            tenants: Cache::new(
                cache.tenants,
                (std::mem::size_of::<TenantCache>() + 255) as u64,
            ),
            lists: Cache::new(
                cache.mailing_lists,
                (std::mem::size_of::<MailingListCache>() + 255) as u64,
            ),
            dkim_signers: Cache::new(
                cache.dkim_signatures,
                (std::mem::size_of::<DkimSigner>() + 255) as u64,
            ),
            dns_txt: CacheWithTtl::new(cache.dns_txt, (std::mem::size_of::<Txt>() + 255) as u64),
            dns_mx: CacheWithTtl::new(cache.dns_mx, ((std::mem::size_of::<MX>() + 255) * 2) as u64),
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
            dns_rbl: CacheWithTtl::new(
                cache.dns_rbl,
                ((std::mem::size_of::<Ipv4Addr>() + 255) * 2) as u64,
            ),
            negative_cache_ttl: cache.negative_ttl.into_inner(),
        }
    }

    #[allow(clippy::type_complexity)]
    #[inline(always)]
    pub fn build_auth_parameters<T>(
        &self,
        params: T,
    ) -> Parameters<
        '_,
        T,
        CacheWithTtl<Box<str>, Txt>,
        CacheWithTtl<Box<str>, Arc<[MX]>>,
        CacheWithTtl<Box<str>, Arc<[Ipv4Addr]>>,
        CacheWithTtl<Box<str>, Arc<[Ipv6Addr]>>,
        CacheWithTtl<IpAddr, Arc<[Box<str>]>>,
    > {
        Parameters {
            params,
            cache_txt: Some(&self.dns_txt),
            cache_mx: Some(&self.dns_mx),
            cache_ptr: Some(&self.dns_ptr),
            cache_ipv4: Some(&self.dns_ipv4),
            cache_ipv6: Some(&self.dns_ipv6),
        }
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
            queue_status: true.into(),
            applications: Default::default(),
            logos: Default::default(),
            smtp_connectors: Default::default(),
            asn_geo_data: Default::default(),
            lookup_stores: Default::default(),
        }
    }
}

impl Default for TlsConnectors {
    fn default() -> Self {
        TlsConnectors {
            pki_verify: build_tls_connector(false),
            dummy_verify: build_tls_connector(true),
        }
    }
}
