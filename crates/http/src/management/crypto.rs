/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use directory::backend::internal::manage;
use email::message::crypto::{
    ENCRYPT_TRAIN_SPAM_FILTER, EncryptMessage, EncryptMessageError, EncryptionMethod,
    EncryptionParams, EncryptionType, try_parse_certs,
};
use http_proto::*;
use mail_builder::encoders::base64::base64_encode_mime;
use mail_parser::MessageParser;
use serde_json::json;
use std::{future::Future, sync::Arc};
use store::{
    Deserialize, Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder},
};
use trc::AddContext;
use types::{collection::Collection, field::PrincipalField};

pub trait CryptoHandler: Sync + Send {
    fn handle_crypto_get(
        &self,
        access_token: Arc<AccessToken>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_crypto_post(
        &self,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl CryptoHandler for Server {
    async fn handle_crypto_get(&self, access_token: Arc<AccessToken>) -> trc::Result<HttpResponse> {
        let ec = if let Some(params_) = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                access_token.primary_id(),
                Collection::Principal,
                0,
                PrincipalField::EncryptionKeys,
            ))
            .await?
        {
            let params = params_
                .unarchive::<EncryptionParams>()
                .caused_by(trc::location!())?;
            let algo = params.algo();
            let method = params.method();
            let allow_spam_training = params.can_train_spam_filter();
            let mut certs = Vec::new();
            certs.extend_from_slice(b"-----STALWART CERTIFICATE-----\r\n");
            let _ = base64_encode_mime(&params_.into_inner(), &mut certs, false);
            certs.extend_from_slice(b"\r\n");
            let certs = String::from_utf8(certs).unwrap_or_default();

            match method {
                EncryptionMethod::PGP => EncryptionType::PGP {
                    algo,
                    certs,
                    allow_spam_training,
                },
                EncryptionMethod::SMIME => EncryptionType::SMIME {
                    algo,
                    certs,
                    allow_spam_training,
                },
            }
        } else {
            EncryptionType::Disabled
        };

        Ok(JsonResponse::new(json!({
            "data": ec,
        }))
        .into_http_response())
    }

    async fn handle_crypto_post(
        &self,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> trc::Result<HttpResponse> {
        let request = serde_json::from_slice::<EncryptionType>(body.as_deref().unwrap_or_default())
            .map_err(|err| trc::ResourceEvent::BadParameters.into_err().reason(err))?;

        let (method, algo, mut certs, allow_spam_training) = match request {
            EncryptionType::PGP {
                algo,
                certs,
                allow_spam_training,
            } => (EncryptionMethod::PGP, algo, certs, allow_spam_training),
            EncryptionType::SMIME {
                algo,
                certs,
                allow_spam_training,
            } => (EncryptionMethod::SMIME, algo, certs, allow_spam_training),
            EncryptionType::Disabled => {
                // Disable encryption at rest
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(access_token.primary_id())
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .clear(PrincipalField::EncryptionKeys);
                self.core.storage.data.write(batch.build_all()).await?;
                return Ok(JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response());
            }
        };
        if !certs.ends_with("\n") {
            certs.push('\n');
        }

        // Make sure Encryption is enabled
        if !self.core.jmap.encrypt {
            return Err(manage::unsupported(
                "Encryption-at-rest has been disabled by the system administrator",
            ));
        }

        // Parse certificates
        let certs = try_parse_certs(method, certs.into_bytes())
            .map_err(|err| manage::error(err, None::<u32>))?;
        let num_certs = certs.len();
        let params = Archiver::new(EncryptionParams {
            flags: method.flags()
                | algo.flags()
                | if allow_spam_training {
                    ENCRYPT_TRAIN_SPAM_FILTER
                } else {
                    0
                },
            certs,
        })
        .serialize()
        .caused_by(trc::location!())?;

        // Try a test encryption
        if let Err(EncryptMessageError::Error(message)) = MessageParser::new()
            .parse("Subject: test\r\ntest\r\n".as_bytes())
            .unwrap()
            .encrypt(
                <Archive<AlignedBytes> as Deserialize>::deserialize(params.as_slice())?
                    .unarchive::<EncryptionParams>()?,
            )
            .await
        {
            return Err(manage::error(message, None::<u32>));
        }

        // Save encryption params
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(access_token.primary_id())
            .with_collection(Collection::Principal)
            .with_document(0)
            .set(PrincipalField::EncryptionKeys, params);
        self.core.storage.data.write(batch.build_all()).await?;

        Ok(JsonResponse::new(json!({
            "data": num_certs,
        }))
        .into_http_response())
    }
}
