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
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::collection::Collection;

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
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::SieveScript,
                document_id,
            ))
            .await?
        {
            // Delete record
            let script = obj_
                .to_unarchived::<SieveScript>()
                .caused_by(trc::location!())?;
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript);
            if !script.inner.metadata_kinds().is_empty() {
                self.preload_container_cleanup(
                    None,
                    account_id,
                    Collection::SieveScript,
                    &RoaringBitmap::from_iter([document_id]),
                )
                .await
                .caused_by(trc::location!())?
                .release_or_assert_absent(batch, account_id, document_id);
            }
            batch
                .with_document(document_id)
                .custom(
                    ObjectIndexBuilder::<_, ()>::new()
                        .with_current(script)
                        .with_changed_by(access_token.account_tenant_ids()),
                )
                .caused_by(trc::location!())?
                .commit_point();

            Ok(true)
        } else {
            Ok(false)
        }
    }
}
