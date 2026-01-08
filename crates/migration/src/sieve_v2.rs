/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::sieve::{SieveScript, VacationResponse};
use store::{
    Serialize, SerializeInfallible, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder},
};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    collection::Collection,
    field::{Field, PrincipalField},
};

use crate::get_document_ids;

pub(crate) async fn migrate_sieve_v013(server: &Server, account_id: u32) -> trc::Result<u64> {
    // Obtain email ids
    let script_ids = get_document_ids(server, account_id, Collection::SieveScript)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_scripts = script_ids.len();
    if num_scripts == 0 {
        return Ok(0);
    }
    let mut num_migrated = 0;

    for script_id in &script_ids {
        match server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::SieveScript,
                script_id,
            ))
            .await
        {
            Ok(Some(legacy)) => match legacy.deserialize_untrusted::<SieveScriptV2>() {
                Ok(old_sieve) => {
                    let script = SieveScript {
                        name: old_sieve.name,
                        blob_hash: old_sieve.blob_hash,
                        size: old_sieve.size,
                        vacation_response: old_sieve.vacation_response,
                    };

                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::SieveScript)
                        .with_document(script_id)
                        .unindex(Field::new(0u8), vec![u8::from(old_sieve.is_active)])
                        .set(
                            Field::ARCHIVE,
                            Archiver::new(script)
                                .serialize()
                                .caused_by(trc::location!())?,
                        );

                    if old_sieve.is_active {
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::Principal)
                            .with_document(0)
                            .set(PrincipalField::ActiveScriptId, script_id.serialize());
                    }
                    num_migrated += 1;

                    server
                        .store()
                        .write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                }
                Err(_) => {
                    if let Err(err) = legacy.deserialize_untrusted::<SieveScript>() {
                        return Err(err.account_id(script_id).caused_by(trc::location!()));
                    }
                }
            },
            Ok(None) => (),
            Err(err) => {
                return Err(err.account_id(script_id).caused_by(trc::location!()));
            }
        }
    }

    Ok(num_migrated)
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct SieveScriptV2 {
    pub name: String,
    pub is_active: bool,
    pub blob_hash: BlobHash,
    pub size: u32,
    pub vacation_response: Option<VacationResponse>,
}
