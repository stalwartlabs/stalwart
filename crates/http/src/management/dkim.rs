/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::str::FromStr;

use common::{Server, auth::AccessToken, config::smtp::auth::simple_pem_parse};
use directory::{Permission, backend::internal::manage};
use hyper::Method;
use mail_auth::{
    common::crypto::{Ed25519Key, RsaKey, Sha256},
    dkim::generate::DkimKeyPair,
};
use mail_builder::encoders::base64::base64_encode;
use mail_parser::DateTime;
use pkcs8::Document;
use rsa::pkcs1::DecodeRsaPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use store::write::now;

use http_proto::{request::decode_path_element, *};
use std::future::Future;

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
pub enum Algorithm {
    Rsa,
    Ed25519,
}

#[derive(Debug, Serialize, Deserialize)]
struct DkimSignature {
    id: Option<String>,
    algorithm: Algorithm,
    domain: String,
    selector: Option<String>,
}

pub trait DkimManagement: Sync + Send {
    fn handle_manage_dkim(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_get_public_key(
        &self,
        path: Vec<&str>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_create_signature(
        &self,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn create_dkim_key(
        &self,
        algo: Algorithm,
        id: impl AsRef<str> + Send,
        domain: impl Into<String> + Send,
        selector: impl Into<String> + Send,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl DkimManagement for Server {
    async fn handle_manage_dkim(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match *req.method() {
            Method::GET => {
                // Validate the access token
                access_token.assert_has_permission(Permission::DkimSignatureGet)?;

                self.handle_get_public_key(path).await
            }
            Method::POST => {
                // Validate the access token
                access_token.assert_has_permission(Permission::DkimSignatureCreate)?;

                self.handle_create_signature(body).await
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    async fn handle_get_public_key(&self, path: Vec<&str>) -> trc::Result<HttpResponse> {
        let signature_id = match path.get(1) {
            Some(signature_id) => decode_path_element(signature_id),
            None => {
                return Err(trc::ResourceEvent::NotFound.into_err());
            }
        };

        let (pk, algo) = match (
            self.core
                .storage
                .config
                .get(&format!("signature.{signature_id}.private-key"))
                .await,
            self.core
                .storage
                .config
                .get(&format!("signature.{signature_id}.algorithm"))
                .await
                .map(|algo| algo.and_then(|algo| algo.parse::<Algorithm>().ok())),
        ) {
            (Ok(Some(pk)), Ok(Some(algorithm))) => (pk, algorithm),
            (Err(err), _) | (_, Err(err)) => return Err(err.caused_by(trc::location!())),
            _ => return Err(trc::ResourceEvent::NotFound.into_err()),
        };

        Ok(JsonResponse::new(json!({
            "data": obtain_dkim_public_key(algo, &pk)?,
        }))
        .into_http_response())
    }

    async fn handle_create_signature(&self, body: Option<Vec<u8>>) -> trc::Result<HttpResponse> {
        let request =
            match serde_json::from_slice::<DkimSignature>(body.as_deref().unwrap_or_default()) {
                Ok(request) => request,
                Err(err) => {
                    return Err(
                        trc::EventType::Resource(trc::ResourceEvent::BadParameters).reason(err)
                    );
                }
            };

        let algo_str = match request.algorithm {
            Algorithm::Rsa => "rsa",
            Algorithm::Ed25519 => "ed25519",
        };
        let id = request
            .id
            .unwrap_or_else(|| format!("{algo_str}-{}", request.domain));
        let selector = request.selector.unwrap_or_else(|| {
            let dt = DateTime::from_timestamp(now() as i64);
            format!(
                "{:04}{:02}{}",
                dt.year,
                dt.month,
                if Algorithm::Rsa == request.algorithm {
                    "r"
                } else {
                    "e"
                }
            )
        });

        // Make sure the signature does not exist already
        if let Some(value) = self
            .core
            .storage
            .config
            .get(&format!("signature.{id}.private-key"))
            .await?
        {
            return Err(manage::err_exists(
                format!("signature.{id}.private-key"),
                value,
            ));
        }

        // Create signature
        self.create_dkim_key(request.algorithm, id, request.domain, selector)
            .await?;

        Ok(JsonResponse::new(json!({
            "data": (),
        }))
        .into_http_response())
    }

    async fn create_dkim_key(
        &self,
        algo: Algorithm,
        id: impl AsRef<str>,
        domain: impl Into<String>,
        selector: impl Into<String>,
    ) -> trc::Result<()> {
        let id = id.as_ref();
        let (algorithm, pk_type) = match algo {
            Algorithm::Rsa => ("rsa-sha256", "RSA PRIVATE KEY"),
            Algorithm::Ed25519 => ("ed25519-sha256", "PRIVATE KEY"),
        };
        let mut pk = format!("-----BEGIN {pk_type}-----\n").into_bytes();
        let mut lf_count = 65;
        for ch in base64_encode(
            match algo {
                Algorithm::Rsa => DkimKeyPair::generate_rsa(2048),
                Algorithm::Ed25519 => DkimKeyPair::generate_ed25519(),
            }
            .map_err(|err| {
                manage::error("Failed to generate key", err.to_string().into())
                    .caused_by(trc::location!())
            })?
            .private_key(),
        )
        .unwrap_or_default()
        {
            pk.push(ch);
            lf_count -= 1;
            if lf_count == 0 {
                pk.push(b'\n');
                lf_count = 65;
            }
        }
        if lf_count != 65 {
            pk.push(b'\n');
        }
        pk.extend_from_slice(format!("-----END {pk_type}-----\n").as_bytes());

        self.core
            .storage
            .config
            .set(
                [
                    (
                        format!("signature.{id}.private-key"),
                        String::from_utf8(pk).unwrap(),
                    ),
                    (format!("signature.{id}.domain"), domain.into()),
                    (format!("signature.{id}.selector"), selector.into()),
                    (format!("signature.{id}.algorithm"), algorithm.to_string()),
                    (
                        format!("signature.{id}.canonicalization"),
                        "relaxed/relaxed".to_string(),
                    ),
                    (format!("signature.{id}.headers.0"), "From".to_string()),
                    (format!("signature.{id}.headers.1"), "To".to_string()),
                    (format!("signature.{id}.headers.2"), "Date".to_string()),
                    (format!("signature.{id}.headers.3"), "Subject".to_string()),
                    (
                        format!("signature.{id}.headers.4"),
                        "Message-ID".to_string(),
                    ),
                    (format!("signature.{id}.report"), "false".to_string()),
                ],
                true,
            )
            .await
    }
}

pub fn obtain_dkim_public_key(algo: Algorithm, pk: &str) -> trc::Result<String> {
    match simple_pem_parse(pk) {
        Some(der) => match algo {
            Algorithm::Rsa => match RsaKey::<Sha256>::from_der(&der).and_then(|key| {
                Document::from_pkcs1_der(&key.public_key())
                    .map_err(|err| mail_auth::Error::CryptoError(err.to_string()))
            }) {
                Ok(pk) => Ok(
                    String::from_utf8(base64_encode(pk.as_bytes()).unwrap_or_default())
                        .unwrap_or_default(),
                ),
                Err(err) => Err(manage::error(
                    "Failed to read RSA DER",
                    err.to_string().into(),
                )),
            },
            Algorithm::Ed25519 => {
                match Ed25519Key::from_pkcs8_maybe_unchecked_der(&der)
                    .map_err(|err| mail_auth::Error::CryptoError(err.to_string()))
                {
                    Ok(pk) => Ok(String::from_utf8(
                        base64_encode(&pk.public_key()).unwrap_or_default(),
                    )
                    .unwrap_or_default()),
                    Err(err) => Err(manage::error("Crypto error", err.to_string().into())),
                }
            }
        },
        None => Err(manage::error("Failed to decode private key", None::<u32>)),
    }
}

impl FromStr for Algorithm {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('-').map(|(algo, _)| algo) {
            Some("rsa") => Ok(Algorithm::Rsa),
            Some("ed25519") => Ok(Algorithm::Ed25519),
            _ => Err(()),
        }
    }
}
