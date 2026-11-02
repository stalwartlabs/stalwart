/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    resolver::{KeyCacheKey, KeyResolver},
    store::{ExternalPublicKeyStore, KeyCandidate, KeyChange, LAST_SEEN_RESOLUTION},
    trust::SmimeTrust,
};
use crate::{
    Server,
    expr::{Bump, Variable, functions::ResolveVariable},
};
use crypto::{ChainStatus, HarvestSource, HarvestedKey};
use mail_parser::{HeaderName, Message, MessageParser};
use registry::schema::{
    enums::{ExpressionVariable, KeyTrust},
    structs::KeySource,
};
use store::write::now;
use trc::EncryptionEvent;

struct HarvestSender<'x>(&'x str);

pub trait KeyHarvest: Sync + Send {
    fn harvest_enabled(&self) -> bool;

    fn harvest_candidate(&self, message: &Message<'_>) -> bool;

    fn spawn_harvest(&self, raw_message: Vec<u8>, session_id: u64);

    fn harvest_message(
        &self,
        raw_message: &[u8],
        session_id: u64,
    ) -> impl Future<Output = ()> + Send;

    fn harvested_candidate(
        &self,
        harvested: &HarvestedKey,
        from: &str,
        now: u64,
    ) -> impl Future<Output = Option<KeyCandidate>> + Send;
}

impl KeyHarvest for Server {
    fn harvest_enabled(&self) -> bool {
        self.core
            .email
            .gateway
            .as_deref()
            .is_some_and(|gateway| gateway.harvest_enabled)
    }

    fn harvest_candidate(&self, message: &Message<'_>) -> bool {
        message.headers().contains(HeaderName::Autocrypt)
            || message
                .root_part()
                .content_type()
                .and_then(|content_type| content_type.subtype())
                .is_some_and(|subtype| {
                    hashify::set_ignore_case!(
                        subtype.as_bytes(),
                        "signed",
                        "pkcs7-mime",
                        "x-pkcs7-mime"
                    )
                })
    }

    fn spawn_harvest(&self, raw_message: Vec<u8>, session_id: u64) {
        let Ok(permit) = self.inner.data.harvest_tasks.clone().try_acquire_owned() else {
            return;
        };
        let server = self.clone();
        tokio::spawn(async move {
            server.harvest_message(&raw_message, session_id).await;
            drop(permit);
        });
    }

    async fn harvest_message(&self, raw_message: &[u8], session_id: u64) {
        let Some(gateway) = self.core.email.gateway.as_deref() else {
            return;
        };
        let Some(message) = MessageParser::default().parse(raw_message) else {
            return;
        };
        let Some(from) = message
            .from()
            .and_then(|from| from.first())
            .and_then(|from| from.address())
        else {
            return;
        };
        let key = KeyCacheKey::new(from);
        if !self
            .eval_if::<bool, _>(
                &gateway.harvest,
                &HarvestSender(&key.address),
                &mut Bump::new(),
                session_id,
            )
            .await
            .unwrap_or_default()
        {
            return;
        }
        let time = now();
        for harvested in crypto::harvest(&message, from, time) {
            let Some(fingerprint) = crypto::parse_public_keys(&harvested.key, time)
                .ok()
                .and_then(|parsed| parsed.fingerprints.first().map(|f| f.to_hex()))
            else {
                continue;
            };
            if let Ok(Some(entry)) = self.key_entry(&key).await
                && entry.knows(&fingerprint)
                && time.saturating_sub(entry.last_seen) < LAST_SEEN_RESOLUTION
            {
                continue;
            }
            let Some(candidate) = self.harvested_candidate(&harvested, from, time).await else {
                continue;
            };
            match self.store_key_candidate(candidate).await {
                Ok(KeyChange::Stored | KeyChange::Replaced) => {
                    trc::event!(
                        Encryption(EncryptionEvent::KeyHarvested),
                        SpanId = session_id,
                        From = from.to_string(),
                        Fingerprint = fingerprint.clone(),
                    );
                }
                Ok(KeyChange::PendingApproval) => {
                    trc::event!(
                        Encryption(EncryptionEvent::KeyChange),
                        SpanId = session_id,
                        From = from.to_string(),
                        Fingerprint = fingerprint.clone(),
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    trc::error!(err.span_id(session_id).caused_by(trc::location!()));
                }
            }
        }
    }

    async fn harvested_candidate(
        &self,
        harvested: &HarvestedKey,
        from: &str,
        now: u64,
    ) -> Option<KeyCandidate> {
        let (key, trust, source) = match harvested.source {
            HarvestSource::SmimeSignature if !harvested.signature_verified => return None,
            HarvestSource::SmimeSignature => {
                let certificates = harvested.chain();
                let anchors = self.trust_anchors().await.ok()?;
                let trust = match self
                    .verify_certificate_chain(&certificates, &anchors, &[], now)
                    .await
                    .map(|verdict| verdict.status)
                {
                    Some(ChainStatus::Valid | ChainStatus::RevocationUnknown) => KeyTrust::Verified,
                    _ => KeyTrust::Unverified,
                };
                (certificates.concat(), trust, KeySource::HarvestedSmime)
            }
            HarvestSource::Autocrypt if harvested.signature_verified => (
                harvested.key.to_vec(),
                KeyTrust::Harvested,
                KeySource::HarvestedPgp,
            ),
            HarvestSource::Autocrypt => (
                harvested.key.to_vec(),
                KeyTrust::Unverified,
                KeySource::Autocrypt,
            ),
        };
        let parsed = crypto::parse_public_keys(&key, now).ok()?;
        Some(KeyCandidate {
            address: from.into(),
            key,
            parsed,
            source,
            trust,
            valid_until: None,
            capabilities: harvested.smime_capabilities.clone(),
            signed_at: harvested.signing_time,
        })
    }
}

impl ResolveVariable for HarvestSender<'_> {
    fn resolve_variable<'a>(&'a self, variable: ExpressionVariable, _: &'a Bump) -> Variable<'a> {
        match variable {
            ExpressionVariable::Sender => self.0.into(),
            ExpressionVariable::SenderDomain => self
                .0
                .rsplit_once('@')
                .map_or("", |(_, domain)| domain)
                .into(),
            _ => "".into(),
        }
    }
}
