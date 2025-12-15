/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::message::crypto::{
    ENCRYPT_ALGO_AES128, ENCRYPT_ALGO_AES256, ENCRYPT_METHOD_PGP, ENCRYPT_METHOD_SMIME,
    EncryptionParams,
};
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::{collection::Collection, field::PrincipalField};

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum EncryptionMethod {
    PGP,
    SMIME,
}

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    Copy,
    serde::Serialize,
    serde::Deserialize,
)]
#[rkyv(derive(Clone, Copy))]
pub enum Algorithm {
    Aes128,
    Aes256,
}

#[derive(
    Clone,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct LegacyEncryptionParams {
    pub method: EncryptionMethod,
    pub algo: Algorithm,
    pub certs: Vec<Vec<u8>>,
}

pub(crate) async fn migrate_encryption_params_v014(
    server: &Server,
    account_id: u32,
) -> trc::Result<u64> {
    let Some(params) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey {
            account_id,
            collection: Collection::Principal.into(),
            document_id: 0,
            class: ValueClass::from(PrincipalField::EncryptionKeys),
        })
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(0);
    };

    match params.deserialize_untrusted::<LegacyEncryptionParams>() {
        Ok(legacy) => {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .set(
                    PrincipalField::EncryptionKeys,
                    Archiver::new(EncryptionParams::from(legacy))
                        .serialize()
                        .caused_by(trc::location!())?,
                );

            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            Ok(1)
        }
        Err(err) => {
            if params.deserialize_untrusted::<EncryptionParams>().is_err() {
                return Err(err.account_id(account_id).caused_by(trc::location!()));
            }
            Ok(0)
        }
    }
}

impl From<LegacyEncryptionParams> for EncryptionParams {
    fn from(legacy: LegacyEncryptionParams) -> Self {
        EncryptionParams {
            flags: match legacy.method {
                EncryptionMethod::PGP => ENCRYPT_METHOD_PGP,
                EncryptionMethod::SMIME => ENCRYPT_METHOD_SMIME,
            } | match legacy.algo {
                Algorithm::Aes128 => ENCRYPT_ALGO_AES128,
                Algorithm::Aes256 => ENCRYPT_ALGO_AES256,
            },
            certs: legacy
                .certs
                .into_iter()
                .map(|c| c.into_boxed_slice())
                .collect(),
        }
    }
}
