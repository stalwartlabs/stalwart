/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::SieveScript;
use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use store::write::BatchBuilder;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{collection::Collection, field::SieveField};

pub trait SieveScriptDelete: Sync + Send {
    fn sieve_script_delete(
        &self,
        account_id: u32,
        document_id: u32,
        access_token: &AccessToken,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl SieveScriptDelete for Server {
    async fn sieve_script_delete(
        &self,
        account_id: u32,
        document_id: u32,
        access_token: &AccessToken,
        batch: &mut BatchBuilder,
    ) -> trc::Result<bool> {
        // Fetch record
        if let Some(obj_) = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::SieveScript,
                document_id,
            ))
            .await?
        {
            // Delete record
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript)
                .with_document(document_id)
                .clear(SieveField::Ids)
                .custom(
                    ObjectIndexBuilder::<_, ()>::new()
                        .with_current(
                            obj_.to_unarchived::<SieveScript>()
                                .caused_by(trc::location!())?,
                        )
                        .with_access_token(access_token),
                )
                .caused_by(trc::location!())?
                .commit_point();

            Ok(true)
        } else {
            Ok(false)
        }
    }
}
