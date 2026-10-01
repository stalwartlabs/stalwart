/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    BatchCursor, MetadataViewerEntry, StoredEntries, StoredEntry, add_quota, metadata_key,
    purge::PrivateKey,
};
use crate::{
    Server, auth::AccountTenantIds, cache::invalidate::CacheInvalidationBuilder,
    ipc::CacheInvalidation,
};
use store::{
    IterateParams,
    roaring::RoaringBitmap,
    write::{BatchBuilder, LogCollection, assert::AssertValue, metadata::MetadataClass},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    metadata::MetadataKinds,
};

#[derive(Debug)]
pub struct ContainerCleanup {
    collection: Collection,
    tenant_id: Option<u32>,
    entries: StoredEntries,
}

struct QuotaRefund {
    tenant_id: Option<u32>,
    bytes: i64,
}

impl ContainerCleanup {
    pub fn empty(collection: Collection) -> Self {
        ContainerCleanup {
            collection,
            tenant_id: None,
            entries: StoredEntries::default(),
        }
    }

    pub fn release_or_assert_absent(
        &self,
        batch: &mut BatchBuilder,
        account_id: u32,
        document_id: u32,
    ) {
        if !self.release(batch, account_id, document_id) {
            batch
                .with_account_id(account_id)
                .with_collection(self.collection)
                .with_document(document_id)
                .assert_value(MetadataClass::Shared, AssertValue::None);
        }
    }

    fn release(&self, batch: &mut BatchBuilder, account_id: u32, document_id: u32) -> bool {
        let Some(entry) = self.entries.get(document_id) else {
            return false;
        };
        batch
            .with_account_id(account_id)
            .with_collection(self.collection);
        entry.release(batch, self.tenant_id);
        true
    }
}

impl Server {
    pub async fn preload_container_cleanup(
        &self,
        changed_by: Option<AccountTenantIds>,
        account_id: u32,
        collection: Collection,
        flagged: &RoaringBitmap,
    ) -> trc::Result<ContainerCleanup> {
        if flagged.is_empty() {
            return Ok(ContainerCleanup::empty(collection));
        }
        let entries = self
            .stored_metadata_entries(account_id, collection, flagged)
            .await
            .caused_by(trc::location!())?;
        self.container_cleanup(changed_by, account_id, collection, entries)
            .await
    }

    pub async fn container_cleanup_from(
        &self,
        changed_by: AccountTenantIds,
        account_id: u32,
        collection: Collection,
        entries: impl IntoIterator<Item = StoredEntry>,
    ) -> trc::Result<ContainerCleanup> {
        self.container_cleanup(
            Some(changed_by),
            account_id,
            collection,
            entries.into_iter().collect(),
        )
        .await
    }

    async fn container_cleanup(
        &self,
        changed_by: Option<AccountTenantIds>,
        account_id: u32,
        collection: Collection,
        entries: StoredEntries,
    ) -> trc::Result<ContainerCleanup> {
        let tenant_id = if entries.is_empty() {
            None
        } else {
            self.owner_tenant(changed_by, account_id).await?
        };
        Ok(ContainerCleanup {
            collection,
            tenant_id,
            entries,
        })
    }

    pub async fn release_or_read(
        &self,
        cleanup: &ContainerCleanup,
        batch: &mut BatchBuilder,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: u32,
        kinds: MetadataKinds,
    ) -> trc::Result<()> {
        if cleanup.release(batch, account_id, document_id) || kinds.is_empty() {
            return Ok(());
        }
        let tenant_id = self.owner_tenant(Some(changed_by), account_id).await?;
        if let Some(entry) = self
            .stored_entry(
                account_id,
                cleanup.collection,
                MetadataClass::Shared,
                document_id,
            )
            .await
            .caused_by(trc::location!())?
        {
            let cursor = BatchCursor::save(batch);
            batch
                .with_account_id(account_id)
                .with_collection(cleanup.collection);
            entry.release(batch, tenant_id);
            cursor.restore(batch);
        }
        Ok(())
    }

    async fn owner_tenant(
        &self,
        changed_by: Option<AccountTenantIds>,
        account_id: u32,
    ) -> trc::Result<Option<u32>> {
        match changed_by {
            Some(changed_by) if changed_by.account_id == account_id => Ok(changed_by.tenant_id),
            _ => self
                .account(account_id)
                .await
                .caused_by(trc::location!())
                .map(|account| account.id_tenant),
        }
    }

    pub async fn destroy_viewer_metadata(&self, viewer_id: u32) -> trc::Result<()> {
        let owners = self.metadata_owners(viewer_id).await?;
        if owners.is_empty() {
            return Ok(());
        }

        let store = &self.core.storage.data;
        let class = MetadataClass::Private { viewer: viewer_id };
        let mut batch = BatchBuilder::new();
        for &(owner_id, collection) in &owners {
            let collection_id = u8::from(collection);
            store
                .delete_range(
                    metadata_key(owner_id, collection_id, 0, class),
                    metadata_key(owner_id, collection_id, u32::MAX, class),
                )
                .await
                .caused_by(trc::location!())?;
            batch
                .with_account_id(owner_id)
                .with_collection(collection)
                .clear(MetadataClass::Viewer { viewer: viewer_id });
        }

        let mut logs = owners
            .iter()
            .map(|(owner_id, collection)| (*owner_id, u8::from(SyncCollection::from(*collection))))
            .collect::<Vec<_>>();
        logs.sort_unstable();
        logs.dedup();
        for (owner_id, sync_collection) in logs {
            let log = LogCollection::Private {
                collection: SyncCollection::from(sync_collection),
                viewer: viewer_id,
            };
            store
                .delete_range(log.log_key(owner_id, 0), log.log_key(owner_id, u64::MAX))
                .await
                .caused_by(trc::location!())?;
        }

        store
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
        self.invalidate_caches(CacheInvalidation::PrivateMetadata(viewer_id).into())
            .await
    }

    pub async fn destroy_owner_metadata(&self, owner_id: u32) -> trc::Result<()> {
        let mut viewers = self.all_metadata_viewers(owner_id).await?;
        if viewers.is_empty() {
            return Ok(());
        }
        viewers.sort_unstable_by_key(|link| link.viewer_id);

        let mut usage: Vec<(u32, i64)> = Vec::new();
        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    metadata_key(owner_id, 0, 0, MetadataClass::Private { viewer: 0 }),
                    metadata_key(
                        owner_id,
                        u8::MAX,
                        u32::MAX,
                        MetadataClass::Private { viewer: u32::MAX },
                    ),
                )
                .ascending(),
                |key, value| {
                    let viewer_id = PrivateKey::parse(key)?.viewer_id;
                    let size = value.len() as i64;
                    match usage.last_mut() {
                        Some((last, total)) if *last == viewer_id => *total += size,
                        _ => usage.push((viewer_id, size)),
                    }
                    Ok(true)
                },
            )
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(owner_id))?;

        let mut batch = BatchBuilder::new();
        let mut invalidations = CacheInvalidationBuilder::default();
        for links in viewers.chunk_by(|a, b| a.viewer_id == b.viewer_id) {
            let Some(viewer_id) = links.first().map(|link| link.viewer_id) else {
                continue;
            };
            let bytes = usage
                .binary_search_by_key(&viewer_id, |(viewer_id, _)| *viewer_id)
                .ok()
                .and_then(|position| usage.get(position))
                .map_or(0, |(_, bytes)| *bytes);
            let refund = if bytes != 0 {
                self.try_account(viewer_id)
                    .await?
                    .map(|account| QuotaRefund {
                        tenant_id: account.id_tenant,
                        bytes,
                    })
            } else {
                None
            };
            release_viewer(&mut batch, owner_id, links, refund);
            invalidations.invalidate(CacheInvalidation::PrivateMetadata(viewer_id));
        }

        let result = self
            .core
            .storage
            .data
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!());
        self.invalidate_caches(invalidations).await?;
        result.map(|_| ())
    }

    pub async fn metadata_used_quota(&self, account_id: u32) -> trc::Result<i64> {
        let store = &self.core.storage.data;
        let mut total = 0i64;
        store
            .iterate(
                IterateParams::new(
                    metadata_key(account_id, 0, 0, MetadataClass::Shared),
                    metadata_key(account_id, u8::MAX, u32::MAX, MetadataClass::Shared),
                ),
                |_, value| {
                    total += value.len() as i64;
                    Ok(true)
                },
            )
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))?;

        for (owner_id, collection) in self.metadata_owners(account_id).await? {
            let collection = u8::from(collection);
            let class = MetadataClass::Private { viewer: account_id };
            store
                .iterate(
                    IterateParams::new(
                        metadata_key(owner_id, collection, 0, class),
                        metadata_key(owner_id, collection, u32::MAX, class),
                    ),
                    |_, value| {
                        total += value.len() as i64;
                        Ok(true)
                    },
                )
                .await
                .add_context(|err| err.caused_by(trc::location!()).account_id(owner_id))?;
        }

        Ok(total)
    }
}

fn release_viewer(
    batch: &mut BatchBuilder,
    owner_id: u32,
    links: &[MetadataViewerEntry],
    refund: Option<QuotaRefund>,
) {
    let Some(viewer_id) = links.first().map(|link| link.viewer_id) else {
        return;
    };
    batch.with_account_id(viewer_id);
    if let Some(refund) = refund {
        add_quota(batch, refund.tenant_id, -refund.bytes);
    }
    for link in links {
        batch
            .with_collection(link.collection)
            .clear(MetadataClass::Owner { owner: owner_id });
    }
    batch.with_account_id(owner_id);
    for link in links {
        batch
            .with_collection(link.collection)
            .clear(MetadataClass::Viewer { viewer: viewer_id });
    }
    batch.commit_point();
}

#[cfg(test)]
mod tests;
