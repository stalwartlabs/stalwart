/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::jose::{Body, eab_sign, sign};
use crate::network::acme::http::{get_header, https};
use crate::network::acme::{AcmeError, AcmeResult, Directory};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm};
use base64::Engine;
use base64::engine::general_purpose::{self, URL_SAFE_NO_PAD};
use registry::schema::structs::AcmeProvider;
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

    for contact in provider.contact.iter_mut() {
        let email = sanitize_email(contact.trim().strip_prefix("mailto:").unwrap_or(contact))
            .ok_or_else(|| AcmeError::Invalid(format!("Invalid contact email: {}", contact)))?;
        *contact = format!("mailto:{}", email);
    }

    let directory = Directory::discover(&provider.directory, provider.max_retries as u32).await?;
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
        contact: provider.contact.as_slice(),
        eab,
    })
    .unwrap_or_default();
    let body = sign(
        &key_pair,
        None,
        directory.nonce(provider.max_retries as u32).await?,
        &directory.new_account,
        &payload,
    )?;

    provider.account_uri = get_header(
        &https(
            &directory.new_account,
            Method::POST,
            Some(body),
            provider.max_retries as u32,
        )
        .await?,
        "Location",
    )?;
    provider.account_key = URL_SAFE_NO_PAD.encode(account_key.as_ref());

    Ok(())
}

impl EabSettings {
    pub fn new(kid: impl Into<String>, hmac_key: impl AsRef<[u8]>) -> AcmeResult<Self> {
        let key = general_purpose::URL_SAFE_NO_PAD
            .decode(hmac_key.as_ref())
            .map_err(|err| AcmeError::Invalid(format!("Failed to decode EAB HMAC key: {}", err)))?;
        Ok(Self {
            kid: kid.into(),
            hmac_key: key,
        })
    }
}
