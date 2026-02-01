/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::server::tls::build_self_signed_cert;
use crate::{
    CacheSwap, Caches, Data, DavResource, DavResources, MailboxCache, MessageStoreCache,
    MessageUidCache, TlsConnectors,
    auth::{AccessToken, roles::RolePermissions},
    config::{
        mailstore::spamfilter::SpamClassifier,
        smtp::resolver::{Policy, Tlsa},
    },
    listener::blocked::BlockedIps,
    manager::{bootstrap::Bootstrap, webadmin::WebAdminManager},
};
use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use mail_auth::{MX, Parameters, Txt};
use mail_send::smtp::tls::build_tls_connector;
use parking_lot::RwLock;
use registry::schema::{prelude::Object, structs};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use utils::{
    cache::{Cache, CacheWithTtl},
    snowflake::SnowflakeIdGenerator,
};

impl Data {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        // Parse certificates
        let mut certificates = AHashMap::new();
        let mut subject_names = AHashSet::new();
        bp.parse_certificates(&mut certificates, &mut subject_names);
        if subject_names.is_empty() {
            subject_names.insert("localhost".to_string());
        }

        // Build and test snowflake id generator
        let node_id = bp.node_id();
        let id_generator = SnowflakeIdGenerator::with_node_id(node_id);
        if !id_generator.is_valid() {
            panic!("Invalid system time, panicking to avoid data corruption");
        }

        let todo = "TODO: WebAdminManager initialization";

        Data {
            spam_classifier: ArcSwap::from_pointee(SpamClassifier::default()),
            tls_certificates: ArcSwap::from_pointee(certificates),
            tls_self_signed_cert: build_self_signed_cert(
                subject_names.into_iter().collect::<Vec<_>>(),
            )
            .or_else(|err| {
                bp.build_error(
                    Object::Certificate.singleton(),
                    format!("Failed to build self-signed TLS certificate: {err}"),
                );
                build_self_signed_cert(vec!["localhost".to_string()])
            })
            .ok()
            .map(Arc::new),
            blocked_ips: RwLock::new(BlockedIps::parse(bp).await),
            jmap_id_gen: id_generator.clone(),
            queue_id_gen: id_generator.clone(),
            span_id_gen: id_generator,
            queue_status: true.into(),
            webadmin: Default::default(), /*config
                                          .value("webadmin.path")
                                          .map(|path| WebAdminManager::new(path.into()))
                                          .unwrap_or_default(),*/
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
                (std::mem::size_of::<AccessToken>() + 255) as u64,
            ),
            http_auth: Cache::new(cache.http_auth, (50 + std::mem::size_of::<u32>()) as u64),
            permissions: Cache::new(
                cache.permissions,
                std::mem::size_of::<RolePermissions>() as u64,
            ),
            messages: Cache::new(
                cache.messages,
                (std::mem::size_of::<u32>()
                    + std::mem::size_of::<CacheSwap<MessageStoreCache>>()
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
        CacheWithTtl<String, Txt>,
        CacheWithTtl<String, Arc<Vec<MX>>>,
        CacheWithTtl<String, Arc<Vec<Ipv4Addr>>>,
        CacheWithTtl<String, Arc<Vec<Ipv6Addr>>>,
        CacheWithTtl<IpAddr, Arc<Vec<String>>>,
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
            webadmin: Default::default(),
            logos: Default::default(),
            smtp_connectors: Default::default(),
            asn_geo_data: Default::default(),
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
