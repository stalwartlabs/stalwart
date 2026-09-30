/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::AccountTenantIds,
    storage::metadata::{StoredEntries, StoredEntry},
};
use store::{roaring::RoaringBitmap, write::BatchBuilder};
use trc::AddContext;
use types::{collection::Collection, metadata::MetadataKinds};

#[derive(Debug)]
pub struct MetadataCleanup {
    collection: Collection,
    mode: CleanupMode,
}

#[derive(Debug)]
enum CleanupMode {
    Immediate,
    Preloaded(PreloadedEntries),
}

#[derive(Debug)]
struct PreloadedEntries {
    tenant_id: Option<u32>,
    entries: StoredEntries,
}

impl MetadataCleanup {
    pub(crate) fn immediate(collection: Collection) -> Self {
        MetadataCleanup {
            collection,
            mode: CleanupMode::Immediate,
        }
    }

    pub async fn preload(
        server: &Server,
        changed_by: AccountTenantIds,
        account_id: u32,
        collection: Collection,
        items: impl IntoIterator<Item = (u32, MetadataKinds)>,
    ) -> trc::Result<Self> {
        let flagged = items
            .into_iter()
            .filter_map(|(document_id, kinds)| (!kinds.is_empty()).then_some(document_id))
            .collect::<RoaringBitmap>();
        MetadataCleanup::preload_flagged(server, changed_by, account_id, collection, &flagged).await
    }

    async fn preload_flagged(
        server: &Server,
        changed_by: AccountTenantIds,
        account_id: u32,
        collection: Collection,
        flagged: &RoaringBitmap,
    ) -> trc::Result<Self> {
        let entries = server
            .stored_metadata_entries(account_id, collection, flagged)
            .await
            .caused_by(trc::location!())?;
        MetadataCleanup::with_stored(server, changed_by, account_id, collection, entries).await
    }

    pub async fn with_entries(
        server: &Server,
        changed_by: AccountTenantIds,
        account_id: u32,
        collection: Collection,
        entries: impl IntoIterator<Item = StoredEntry>,
    ) -> trc::Result<Self> {
        MetadataCleanup::with_stored(
            server,
            changed_by,
            account_id,
            collection,
            entries.into_iter().collect(),
        )
        .await
    }

    async fn with_stored(
        server: &Server,
        changed_by: AccountTenantIds,
        account_id: u32,
        collection: Collection,
        entries: StoredEntries,
    ) -> trc::Result<Self> {
        let tenant_id = if entries.is_empty() {
            None
        } else {
            owner_tenant(server, changed_by, account_id).await?
        };
        Ok(MetadataCleanup::preloaded(collection, tenant_id, entries))
    }

    fn preloaded(collection: Collection, tenant_id: Option<u32>, entries: StoredEntries) -> Self {
        MetadataCleanup {
            collection,
            mode: CleanupMode::Preloaded(PreloadedEntries { tenant_id, entries }),
        }
    }

    pub(crate) async fn remove(
        &self,
        server: &Server,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: u32,
        kinds: MetadataKinds,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        match &self.mode {
            CleanupMode::Preloaded(preloaded)
                if preloaded.release(self.collection, account_id, document_id, batch) =>
            {
                Ok(())
            }
            _ if kinds.is_empty() => Ok(()),
            _ => {
                let tenant_id = owner_tenant(server, changed_by, account_id).await?;
                server
                    .destroy_metadata(
                        batch,
                        account_id,
                        tenant_id,
                        self.collection,
                        &RoaringBitmap::from_iter([document_id]),
                    )
                    .await
                    .caused_by(trc::location!())
            }
        }
    }
}

impl PreloadedEntries {
    fn release(
        &self,
        collection: Collection,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> bool {
        if let Some(entry) = self.entries.get(document_id) {
            batch
                .with_account_id(account_id)
                .with_collection(collection);
            entry.release(batch, self.tenant_id);
            true
        } else {
            false
        }
    }
}

async fn owner_tenant(
    server: &Server,
    changed_by: AccountTenantIds,
    account_id: u32,
) -> trc::Result<Option<u32>> {
    if changed_by.account_id == account_id {
        Ok(changed_by.tenant_id)
    } else {
        server
            .account(account_id)
            .await
            .caused_by(trc::location!())
            .map(|account| account.id_tenant)
    }
}

#[cfg(test)]
mod tests;
