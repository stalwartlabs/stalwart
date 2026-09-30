/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{add_quota, metadata_key};
use crate::{Server, cache::invalidate::CacheInvalidationBuilder, ipc::CacheInvalidation};
use store::{
    Deserialize, IterateParams, SerializeInfallible, U32_LEN, ValueKey,
    dispatch::{DocumentSet, ScanShape},
    roaring::RoaringBitmap,
    write::{
        BatchBuilder, LogCollection, MergeResult, ValueClass,
        key::DeserializeBigEndian,
        metadata::{MetadataClass, ViewerState},
    },
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::Field,
};

const PRIVATE_KEY_SUFFIX: usize = U32_LEN + 1 + U32_LEN;
const ORPHAN_CHUNK: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PrivateKey {
    pub(super) collection: u8,
    pub(super) viewer_id: u32,
    pub(super) document_id: u32,
}

impl Server {
    pub async fn purge_private_metadata(
        &self,
        owner_id: u32,
        max_history: Option<usize>,
    ) -> trc::Result<()> {
        let viewers = self.all_metadata_viewers(owner_id).await?;
        if viewers.is_empty() {
            return Ok(());
        }

        if viewers.iter().any(|entry| entry.state.containers > 0) {
            self.purge_orphaned_private_metadata(owner_id).await?;
        }

        if let Some(max_history) = max_history {
            let mut logs = viewers
                .iter()
                .map(|entry| {
                    (
                        entry.viewer_id,
                        u8::from(SyncCollection::from(entry.collection)),
                    )
                })
                .collect::<Vec<_>>();
            logs.sort_unstable();
            logs.dedup();
            for (viewer, collection) in logs {
                self.truncate_change_log(
                    owner_id,
                    LogCollection::Private {
                        collection: SyncCollection::from(collection),
                        viewer,
                    },
                    max_history,
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn purge_orphaned_private_metadata(&self, owner_id: u32) -> trc::Result<()> {
        let mut containers = Vec::new();
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
                .no_values(),
                |key, _| {
                    containers.push(PrivateKey::parse(key)?);
                    Ok(true)
                },
            )
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(owner_id))?;
        containers.sort_unstable();

        let mut orphaned_viewers = Vec::new();
        for by_collection in containers.chunk_by(|a, b| a.collection == b.collection) {
            let Some(first) = by_collection.first() else {
                continue;
            };
            let collection = Collection::from(first.collection);
            if !is_object_collection(collection) {
                continue;
            }
            let candidates = by_collection
                .iter()
                .map(|key| key.document_id)
                .collect::<RoaringBitmap>();
            let existing = self
                .existing_documents(owner_id, collection, &candidates)
                .await?;
            if existing.len() == candidates.len() {
                continue;
            }

            for by_viewer in by_collection.chunk_by(|a, b| a.viewer_id == b.viewer_id) {
                let orphans = by_viewer
                    .iter()
                    .map(|key| key.document_id)
                    .filter(|document_id| !existing.contains(*document_id))
                    .collect::<RoaringBitmap>();
                let Some(viewer_id) = by_viewer.first().map(|key| key.viewer_id) else {
                    continue;
                };
                if !orphans.is_empty() {
                    self.remove_orphaned_containers(owner_id, viewer_id, collection, &orphans)
                        .await?;
                    orphaned_viewers.push(viewer_id);
                }
            }
        }

        if orphaned_viewers.is_empty() {
            return Ok(());
        }
        orphaned_viewers.sort_unstable();
        orphaned_viewers.dedup();
        let mut invalidations = CacheInvalidationBuilder::default();
        for viewer_id in orphaned_viewers {
            invalidations.invalidate(CacheInvalidation::PrivateMetadata(viewer_id));
        }
        self.invalidate_caches(invalidations).await
    }

    async fn remove_orphaned_containers(
        &self,
        owner_id: u32,
        viewer_id: u32,
        collection: Collection,
        orphans: &RoaringBitmap,
    ) -> trc::Result<()> {
        let class = MetadataClass::Private { viewer: viewer_id };
        let entries = self
            .stored_entries(owner_id, collection, class, orphans)
            .await?;
        if entries.is_empty() {
            return Ok(());
        }
        let account = self.try_account(viewer_id).await?;

        let mut batch = BatchBuilder::new();
        for chunk in entries.chunks(ORPHAN_CHUNK) {
            batch.with_account_id(owner_id).with_collection(collection);
            let mut total = 0i64;
            for entry in chunk {
                entry.clear(&mut batch, class);
                total += i64::from(entry.size);
            }
            let count = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
            decrement_containers(
                &mut batch,
                MetadataClass::Viewer { viewer: viewer_id },
                count,
            );
            batch.with_account_id(viewer_id);
            decrement_containers(&mut batch, MetadataClass::Owner { owner: owner_id }, count);
            if let Some(account) = &account {
                add_quota(&mut batch, account.id_tenant, -total);
            }

            if batch.is_large_batch() {
                self.write_orphan_batch(&mut batch).await?;
                batch = BatchBuilder::new();
            }
        }

        if !batch.is_empty() {
            self.write_orphan_batch(&mut batch).await?;
        }
        Ok(())
    }

    async fn write_orphan_batch(&self, batch: &mut BatchBuilder) -> trc::Result<()> {
        match self.core.storage.data.write_batch(batch).await {
            Ok(_) => Ok(()),
            Err(err) if err.is_assertion_failure() => {
                trc::event!(
                    Store(trc::StoreEvent::AssertValueFailed),
                    Details = "Private metadata changed during the orphan sweep",
                    CausedBy = trc::location!()
                );
                Ok(())
            }
            Err(err) => Err(err.caused_by(trc::location!())),
        }
    }

    async fn existing_documents(
        &self,
        account_id: u32,
        collection: Collection,
        documents: &RoaringBitmap,
    ) -> trc::Result<RoaringBitmap> {
        let collection = u8::from(collection);
        let key = |document_id| ValueKey {
            account_id,
            collection,
            document_id,
            class: ValueClass::Property(Field::ARCHIVE.into()),
        };
        let mut existing = RoaringBitmap::new();
        let mut collect = |key: &[u8], _: &[u8]| {
            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
            if documents.contains(document_id) {
                existing.insert(document_id);
            }
            Ok(true)
        };
        let store = &self.core.storage.data;

        match documents.scan_shape() {
            ScanShape::Range(from_document_id, to_document_id) => {
                store
                    .iterate(
                        IterateParams::new(key(from_document_id), key(to_document_id)).no_values(),
                        &mut collect,
                    )
                    .await
            }
            ScanShape::Ranges(ranges) => {
                store
                    .iterate_many(
                        ranges
                            .into_iter()
                            .map(|(from_document_id, to_document_id)| {
                                IterateParams::new(key(from_document_id), key(to_document_id))
                                    .no_values()
                            })
                            .collect(),
                        &mut collect,
                    )
                    .await
            }
        }
        .add_context(|err| {
            err.caused_by(trc::location!())
                .account_id(account_id)
                .collection(collection)
        })?;

        Ok(existing)
    }
}

fn is_object_collection(collection: Collection) -> bool {
    matches!(
        collection,
        Collection::Email
            | Collection::Mailbox
            | Collection::SieveScript
            | Collection::Calendar
            | Collection::CalendarEvent
            | Collection::AddressBook
            | Collection::ContactCard
            | Collection::FileNode
    )
}

impl PrivateKey {
    pub(super) fn parse(key: &[u8]) -> trc::Result<Self> {
        key.len()
            .checked_sub(PRIVATE_KEY_SUFFIX)
            .and_then(|offset| key.get(offset..))
            .and_then(|suffix| suffix.split_first_chunk::<U32_LEN>())
            .and_then(|(viewer, rest)| {
                let (collection, document) = rest.split_first()?;
                Some(PrivateKey {
                    collection: *collection,
                    viewer_id: u32::from_be_bytes(*viewer),
                    document_id: u32::from_be_bytes(document.try_into().ok()?),
                })
            })
            .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))
    }
}

fn decrement_containers(batch: &mut BatchBuilder, class: MetadataClass, count: u32) {
    batch.merge_fnc(class, move |_, current| {
        let Some(current) = current else {
            return Ok(MergeResult::Skip);
        };
        let mut state = ViewerState::deserialize(current)?;
        state.containers = state.containers.saturating_sub(count);
        Ok(MergeResult::Update(state.serialize()))
    });
}
