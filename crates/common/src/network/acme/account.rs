/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::jose::{Body, eab_sign, sign};
use crate::network::acme::http::{acme_client, get_header, https};
use crate::network::acme::{AcmeError, AcmeResult, Directory};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm};
use encodify::base64::URL_SAFE_NO_PAD;
use registry::schema::{enums::AcmeChallengeType, structs::AcmeProvider};
use registry::types::map::Map;
use reqwest::Method;
use utils::sanitize_email;

static ALG: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_FIXED_SIGNING;

#[derive(Clone)]
pub struct EabSettings {
    pub kid: String,
    pub hmac_key: Vec<u8>,
}

#[derive(Debug, serde::Serialize)]
pub struct NewAccountPayload<'x> {
    #[serde(rename = "termsOfServiceAgreed")]
    tos_agreed: bool,
    contact: &'x [String],
    #[serde(rename = "externalAccountBinding")]
    #[serde(skip_serializing_if = "Option::is_none")]
    eab: Option<Body>,
}

pub async fn acme_create_account(
    provider: &mut AcmeProvider,
    eab: Option<EabSettings>,
) -> AcmeResult<()> {
    if provider.contact.is_empty() {
        return Err(AcmeError::Invalid(
            "At least one contact email is required".to_string(),
        ));
    }

    let mut contact_urls = Vec::with_capacity(provider.contact.len());
    for contact in provider.contact.iter_mut() {
        let email = sanitize_email(contact.trim().strip_prefix("mailto:").unwrap_or(contact))
            .ok_or_else(|| AcmeError::Invalid(format!("Invalid contact email: {}", contact)))?;
        contact_urls.push(format!("mailto:{email}"));
        *contact = email;
    }

    let client = acme_client(provider);
    let directory = Directory::discover(&client, &provider.directory).await?;
    if provider.challenge_type == AcmeChallengeType::DnsPersist01 {
        directory.meta.require_persist_support()?;
    }
    let account_key = EcdsaKeyPair::generate_pkcs8(ALG, &SystemRandom::new()).unwrap();
    let key_pair = EcdsaKeyPair::from_pkcs8(ALG, account_key.as_ref())
        .map_err(|err| AcmeError::Crypto(format!("Failed to create ECDSA key pair: {}", err)))?;
    let eab = if let Some(eab) = &eab {
        eab_sign(&key_pair, &eab.kid, &eab.hmac_key, &directory.new_account)?.into()
    } else {
        None
    };

    let payload = serde_json::to_string(&NewAccountPayload {
        tos_agreed: true,
        contact: &contact_urls,
        eab,
    })
    .unwrap_or_default();
    let body = sign(
        &key_pair,
        None,
        directory.nonce(&client).await?,
        &directory.new_account,
        &payload,
    )?;

    provider.account_uri = get_header(
        &https(&client, &directory.new_account, Method::POST, Some(body)).await?,
        "Location",
    )?;
    provider.account_key = URL_SAFE_NO_PAD.encode(account_key.as_ref());
    provider.account_hash_prefix = directory.meta.account_hash_prefix;
    provider.issuer_domain_names = Map::new(directory.meta.issuer_domain_names);
    provider.caa_identities = Map::new(directory.meta.caa_identities);

    Ok(())
}

impl EabSettings {
    pub fn new(kid: impl Into<String>, hmac_key: impl AsRef<[u8]>) -> AcmeResult<Self> {
        let key = URL_SAFE_NO_PAD
            .decode(hmac_key.as_ref())
            .map_err(|err| AcmeError::Invalid(format!("Failed to decode EAB HMAC key: {}", err)))?;
        Ok(Self {
            kid: kid.into(),
            hmac_key: key,
        })
    }
}
