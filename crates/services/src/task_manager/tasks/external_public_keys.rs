/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::outcome::Outcome;
use common::{
    Server,
    gateway::{
        discovery::KeyDiscovery,
        store::{
            ExternalPublicKeyData, ExternalPublicKeyRow, ExternalPublicKeyStore,
            KEY_CHECK_INTERVAL, KeySourceKind, MAX_KEYS_PER_RUN,
        },
        trust::{RunTrustAnchors, SmimeTrust},
    },
};
use crypto::{ChainStatus, Crl, parse_crl};
use registry::{
    schema::{
        enums::{ExternalPublicKeyStatus, KeyTrust},
        structs::{KeySource, TaskExternalPublicKeyMaintenance},
    },
    types::datetime::UTCDateTime,
};
use reqwest::Method;
use std::time::{Duration, Instant};
use store::{ahash::AHashSet, write::now};
use trc::EncryptionEvent;
use types::id::Id;
use utils::HttpLimitResponse;

const CRL_MAX_AGE_SECS: u64 = 11 * 86400;
const MAX_CRLS_PER_RUN: usize = 64;
const RECHECK_BUDGET: Duration = KEY_CHECK_INTERVAL;

#[derive(Default)]
pub(crate) struct RevocationData {
    anchors: RunTrustAnchors,
    fetched: AHashSet<Box<str>>,
    crls: Vec<Crl>,
}

pub(crate) trait ExternalPublicKeyMaintenance: Sync + Send {
    fn external_public_key_maintenance(
        &self,
        task: &TaskExternalPublicKeyMaintenance,
    ) -> impl Future<Output = Outcome> + Send;

    fn maintain_external_public_keys(&self) -> impl Future<Output = trc::Result<()>> + Send;

    fn prepare_key_check(
        &self,
        id: Id,
        now: u64,
        fetches: &mut Vec<ExternalPublicKeyRow>,
        rechecks: &mut Vec<ExternalPublicKeyRow>,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn promote_replacement(
        &self,
        row: ExternalPublicKeyRow,
        now: u64,
    ) -> impl Future<Output = trc::Result<Option<ExternalPublicKeyRow>>> + Send;

    fn recheck_smime_key(
        &self,
        row: &ExternalPublicKeyRow,
        data: &mut RevocationData,
        now: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn fetch_crl(&self, url: &str) -> impl Future<Output = Option<Crl>> + Send;
}

impl ExternalPublicKeyMaintenance for Server {
    async fn external_public_key_maintenance(
        &self,
        _: &TaskExternalPublicKeyMaintenance,
    ) -> Outcome {
        if self.core.email.gateway.is_none() {
            return Outcome::Done(Vec::new());
        }
        match self.maintain_external_public_keys().await {
            Ok(()) => Outcome::Done(Vec::new()),
            Err(err) => Outcome::transient(err.to_string()),
        }
    }

    async fn maintain_external_public_keys(&self) -> trc::Result<()> {
        let time = now();
        let mut fetches = Vec::new();
        let mut rechecks = Vec::new();
        for id in self.due_external_public_keys(time).await? {
            if fetches.len() >= MAX_KEYS_PER_RUN || rechecks.len() >= MAX_KEYS_PER_RUN {
                break;
            }
            if let Err(err) = self
                .prepare_key_check(id, time, &mut fetches, &mut rechecks)
                .await
            {
                trc::error!(err.caused_by(trc::location!()));
            }
        }
        let mut data = RevocationData::default();
        self.fetch_external_public_keys(&fetches, &data.anchors)
            .await;
        drop(fetches);

        let deadline = Instant::now() + RECHECK_BUDGET;
        for row in rechecks {
            if Instant::now() >= deadline {
                break;
            }
            if let Err(err) = self.recheck_smime_key(&row, &mut data, now()).await {
                trc::error!(err.caused_by(trc::location!()));
            }
        }
        Ok(())
    }

    async fn prepare_key_check(
        &self,
        id: Id,
        now: u64,
        fetches: &mut Vec<ExternalPublicKeyRow>,
        rechecks: &mut Vec<ExternalPublicKeyRow>,
    ) -> trc::Result<()> {
        let Some(gateway) = self.core.email.gateway.as_deref() else {
            return Ok(());
        };
        let Some(row) = self.external_public_key_row(id).await? else {
            return Ok(());
        };
        let Some(row) = self.promote_replacement(row, now).await? else {
            return Ok(());
        };
        match &row.key.source {
            _ if row.key.status == ExternalPublicKeyStatus::Disabled => {
                let mut updated = row.key.clone();
                updated.next_check_at = None;
                self.update_external_public_key(&row, updated).await
            }
            KeySource::Automatic(_) => {
                fetches.push(row);
                Ok(())
            }
            KeySource::HarvestedSmime
                if row.key.trust != KeyTrust::Manual && row.key.key.is_some() =>
            {
                rechecks.push(row);
                Ok(())
            }
            _ => {
                let mut updated = row.key.clone();
                updated.schedule_next_check(gateway, now);
                self.update_external_public_key(&row, updated).await
            }
        }
    }

    async fn promote_replacement(
        &self,
        row: ExternalPublicKeyRow,
        now: u64,
    ) -> trc::Result<Option<ExternalPublicKeyRow>> {
        if !row.key.replacement_due(now) {
            return Ok(Some(row));
        }
        let mut updated = row.key.clone();
        updated.promote_next_key();
        if !updated.source.is_automatic() {
            updated.trust = KeyTrust::Unverified;
        }
        if let Some(gateway) = self.core.email.gateway.as_deref() {
            updated.schedule_next_check(gateway, now);
        }
        self.update_external_public_key(&row, updated).await?;
        self.external_public_key_row(row.id).await
    }

    async fn recheck_smime_key(
        &self,
        row: &ExternalPublicKeyRow,
        data: &mut RevocationData,
        now: u64,
    ) -> trc::Result<()> {
        let Some(gateway) = self.core.email.gateway.as_deref() else {
            return Ok(());
        };
        let key = &row.key;
        let Ok(certificates) = crypto::split_certificates(&key.key_bytes()) else {
            let mut updated = key.clone();
            updated.schedule_next_check(gateway, now);
            return self.update_external_public_key(row, updated).await;
        };
        let anchors = self.run_trust_anchors(&data.anchors).await?;

        let Some(mut verdict) = self
            .verify_certificate_chain(&certificates, anchors, &data.crls, now)
            .await
        else {
            let mut updated = key.clone();
            updated.schedule_next_check(gateway, now);
            return self.update_external_public_key(row, updated).await;
        };
        let mut fetched = false;
        for url in &verdict.crl_urls {
            if data.fetched.len() < MAX_CRLS_PER_RUN && data.fetched.insert(url.clone()) {
                match self.fetch_crl(url).await {
                    Some(crl) => {
                        data.crls.push(crl);
                        fetched = true;
                    }
                    None => {
                        trc::event!(
                            Encryption(EncryptionEvent::CrlFetchFailed),
                            Url = url.to_string()
                        );
                    }
                }
            }
        }
        if fetched
            && let Some(updated) = self
                .verify_certificate_chain(&certificates, anchors, &data.crls, now)
                .await
        {
            verdict = updated;
        }

        if verdict.status == ChainStatus::RevocationUnknown
            && verdict
                .crl_urls
                .iter()
                .any(|url| !data.fetched.contains(url))
        {
            return Ok(());
        }

        let last_checked = key
            .last_checked
            .map_or(0, |checked| checked.timestamp() as u64);
        let unresolved = match verdict.status {
            ChainStatus::RevocationUnknown => true,
            ChainStatus::Untrusted => !verdict.issuer_urls.is_empty(),
            _ => false,
        };
        let mut updated = key.clone();
        match verdict.status {
            ChainStatus::Valid => {
                updated.trust = KeyTrust::Verified;
                updated.last_checked = Some(UTCDateTime::from_timestamp(now as i64));
            }
            _ if unresolved
                && key.trust == KeyTrust::Verified
                && now.saturating_sub(last_checked) < CRL_MAX_AGE_SECS => {}
            ChainStatus::Revoked => {
                if let Some(fingerprint) = key.fingerprint.clone() {
                    updated.revoke(&[fingerprint]);
                }
                updated.trust = KeyTrust::Unverified;
                updated.last_checked = Some(UTCDateTime::from_timestamp(now as i64));
            }
            _ => updated.trust = KeyTrust::Unverified,
        }
        updated.schedule_next_check(gateway, now);
        self.update_external_public_key(row, updated).await
    }

    async fn fetch_crl(&self, url: &str) -> Option<Crl> {
        let gateway = self.core.email.gateway.as_deref()?;
        let response = gateway
            .pki_http
            .request(Method::GET, url)
            .ok()?
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let body = response
            .bytes_with_limit(gateway.max_crl_size)
            .await
            .ok()??;
        parse_crl(&body).ok()
    }
}
