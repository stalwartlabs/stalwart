/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{BatchCursor, add_quota, metadata_key, purge::PrivateKey};
use crate::{Server, cache::invalidate::CacheInvalidationBuilder, ipc::CacheInvalidation};
use store::{
    IterateParams,
    dispatch::DocumentSet,
    write::{BatchBuilder, LogCollection, metadata::MetadataClass},
};
use trc::AddContext;
use types::collection::{Collection, SyncCollection};

impl Server {
    pub async fn destroy_metadata<I>(
        &self,
        batch: &mut BatchBuilder,
        account_id: u32,
        tenant_id: Option<u32>,
        collection: Collection,
        documents: &I,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
    {
        let shared = self
            .stored_entries(account_id, collection, MetadataClass::Shared, documents)
            .await?;
        if shared.is_empty() {
            return Ok(());
        }

        let cursor = BatchCursor::save(batch);
        batch
            .with_account_id(account_id)
            .with_collection(collection);
        for entry in &shared {
            entry.release(batch, tenant_id);
        }
        cursor.restore(batch);
        Ok(())
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
        let viewers = self.all_metadata_viewers(owner_id).await?;
        if viewers.is_empty() {
            return Ok(());
        }

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
                ),
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
        for (viewer_id, total) in usage {
            if let Some(account) = self.try_account(viewer_id).await? {
                batch.with_account_id(viewer_id);
                add_quota(&mut batch, account.id_tenant, -total);
            }
        }

        let mut invalidations = CacheInvalidationBuilder::default();
        for entry in &viewers {
            batch
                .with_account_id(entry.viewer_id)
                .with_collection(entry.collection)
                .clear(MetadataClass::Owner { owner: owner_id });
            invalidations.invalidate(CacheInvalidation::PrivateMetadata(entry.viewer_id));
        }

        self.core
            .storage
            .data
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
        self.invalidate_caches(invalidations).await
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
