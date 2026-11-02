/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use crypto::{ChainStatus, ChainVerdict, Crl, TrustAnchors, TrustContext};
use registry::schema::{prelude::ObjectType, structs::SmimeTrustAnchor};
use reqwest::Method;
use std::time::Duration;
use store::registry::RegistryQuery;
use tokio::sync::OnceCell;
use types::id::Id;
use utils::HttpLimitResponse;

const CHAIN_VERIFY_DEADLINE: Duration = Duration::from_secs(45);
const MAX_CHAIN_FETCHES: usize = 4;
const MAX_ISSUER_FETCHES: usize = 8;
const MAX_INTERMEDIATE_SIZE: usize = 64 * 1024;

pub type RunTrustAnchors = OnceCell<TrustAnchors>;

pub trait SmimeTrust: Sync + Send {
    fn trust_anchors(&self) -> impl Future<Output = trc::Result<TrustAnchors>> + Send;

    fn run_trust_anchors<'x>(
        &self,
        anchors: &'x RunTrustAnchors,
    ) -> impl Future<Output = trc::Result<&'x TrustAnchors>> + Send;

    fn verify_certificate_chain(
        &self,
        certificates: &[Vec<u8>],
        anchors: &TrustAnchors,
        crls: &[Crl],
        now: u64,
    ) -> impl Future<Output = Option<ChainVerdict>> + Send;
}

impl SmimeTrust for Server {
    async fn trust_anchors(&self) -> trc::Result<TrustAnchors> {
        let mut anchors = match self.core.email.gateway.as_deref() {
            Some(gateway) if gateway.use_bundled_roots => TrustAnchors::embedded(),
            _ => TrustAnchors::empty(),
        };
        let ids = self
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::SmimeTrustAnchor))
            .await?;
        for id in ids {
            if let Some(anchor) = self.registry().object::<SmimeTrustAnchor>(id).await?
                && anchor.enable
            {
                let _ = anchors.add(anchor.certificate.as_bytes());
            }
        }
        Ok(anchors)
    }

    async fn run_trust_anchors<'x>(
        &self,
        anchors: &'x RunTrustAnchors,
    ) -> trc::Result<&'x TrustAnchors> {
        anchors.get_or_try_init(|| self.trust_anchors()).await
    }

    async fn verify_certificate_chain(
        &self,
        certificates: &[Vec<u8>],
        anchors: &TrustAnchors,
        crls: &[Crl],
        now: u64,
    ) -> Option<ChainVerdict> {
        let gateway = self.core.email.gateway.as_deref()?;
        let (leaf, supplied) = certificates.split_first()?;
        let mut fetched: Vec<Vec<u8>> = Vec::new();
        let mut attempted: Vec<Box<str>> = Vec::new();

        tokio::time::timeout(CHAIN_VERIFY_DEADLINE, async {
            for round in 0..=MAX_CHAIN_FETCHES {
                let intermediates: Vec<&[u8]> = supplied
                    .iter()
                    .chain(fetched.iter())
                    .map(Vec::as_slice)
                    .collect();
                let verdict = crypto::verify_smime_chain(
                    leaf,
                    &TrustContext {
                        anchors,
                        intermediates: &intermediates,
                        crls,
                        now,
                    },
                )
                .ok()?;
                if verdict.status != ChainStatus::Untrusted
                    || verdict.issuer_urls.is_empty()
                    || round == MAX_CHAIN_FETCHES
                {
                    return Some(verdict);
                }
                let before = fetched.len();
                for url in &verdict.issuer_urls {
                    if attempted.len() >= MAX_ISSUER_FETCHES || attempted.contains(url) {
                        continue;
                    }
                    attempted.push(url.clone());
                    if let Ok(request) = gateway.pki_http.request(Method::GET, url)
                        && let Ok(response) = request.send().await
                        && response.status().is_success()
                        && let Ok(Some(body)) =
                            response.bytes_with_limit(MAX_INTERMEDIATE_SIZE).await
                    {
                        fetched.push(body);
                    }
                }
                if fetched.len() == before {
                    return Some(verdict);
                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    }
}
