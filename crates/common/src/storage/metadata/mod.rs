/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod cleanup;
mod purge;
mod quota;
mod read;
mod stored;
mod viewer;

pub use read::MetadataViewerEntry;
pub use stored::{StoredEntries, StoredEntry};
pub use viewer::{MetadataViewer, MetadataViewerCache, ViewerStates};

use crate::Server;
use store::{
    Deserialize, IterateParams, SerializeInfallible, ValueKey,
    dispatch::{DocumentSet, ScanShape},
    write::{
        ArchiveVersion, AssignedIds, BatchBuilder, MergeResult, PendingId, ValueClass,
        assert::AssertValue,
        metadata::{MetadataBuf, MetadataClass, StoredMetadata, ViewerState},
    },
};
use trc::AddContext;
use types::{
    collection::{ChangeGroup, Collection, SyncCollection},
    metadata::{EncodedMetadata, MetadataKinds, MetadataView},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoredContainer {
    pub size: u32,
    pub kinds: MetadataKinds,
    pub hash: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataLog {
    Item { prefix: Option<PendingId> },
    Container,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetadataPresence {
    pub before: MetadataKinds,
    pub after: MetadataKinds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataWrite {
    pub account_id: u32,
    pub tenant_id: Option<u32>,
    pub collection: Collection,
    pub document_id: PendingId,
    pub previous: Option<StoredContainer>,
    pub next: Option<EncodedMetadata>,
    pub log: MetadataLog,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateMetadataWrite {
    pub owner_id: u32,
    pub viewer_id: u32,
    pub viewer_tenant_id: Option<u32>,
    pub collection: Collection,
    pub previous: Option<StoredContainer>,
    pub next: Option<EncodedMetadata>,
    pub log: MetadataLog,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PrivateMetadataCommit {
    changes: Vec<PrivateMetadataChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivateMetadataChange {
    owner_id: u32,
    viewer_id: u32,
    collection: Collection,
    is_logged: bool,
    containers: i32,
}

struct BatchCursor {
    account_id: Option<u32>,
    collection: Option<Collection>,
    document_id: Option<PendingId>,
}

impl StoredContainer {
    pub fn new(view: &MetadataView<'_>, stored: &[u8]) -> trc::Result<Self> {
        Ok(StoredContainer {
            size: u32::try_from(stored.len()).unwrap_or(u32::MAX),
            kinds: view.kinds(),
            hash: StoredMetadata::trailer_hash(stored)?,
        })
    }

    pub fn assertion(previous: Option<&StoredContainer>) -> AssertValue {
        previous.map_or(AssertValue::None, |previous| {
            AssertValue::Archive(ArchiveVersion::Hashed {
                hash: previous.hash,
            })
        })
    }
}

impl From<&MetadataBuf> for StoredContainer {
    fn from(container: &MetadataBuf) -> Self {
        StoredContainer {
            size: container.stored_len(),
            kinds: container.kinds(),
            hash: container.hash(),
        }
    }
}

impl MetadataPresence {
    fn new(previous: Option<&StoredContainer>, next: Option<&EncodedMetadata>) -> Self {
        MetadataPresence {
            before: previous.map_or(MetadataKinds::NONE, |previous| previous.kinds),
            after: next.map_or(MetadataKinds::NONE, |next| next.kinds()),
        }
    }

    pub fn has_changed(&self) -> bool {
        self.before != self.after
    }

    pub fn has_changed_for(&self, kinds: MetadataKinds) -> bool {
        self.before.bits() & kinds.bits() != self.after.bits() & kinds.bits()
    }
}

impl BatchCursor {
    fn save(batch: &BatchBuilder) -> Self {
        BatchCursor {
            account_id: batch.last_account_id(),
            collection: batch.last_collection(),
            document_id: batch.last_document_id(),
        }
    }

    fn restore(self, batch: &mut BatchBuilder) {
        if let Some(account_id) = self.account_id {
            batch.with_account_id(account_id);
        }
        if let Some(collection) = self.collection {
            batch.with_collection(collection);
        }
        if let Some(document_id) = self.document_id
            && batch.last_document_id() != Some(document_id)
        {
            batch.with_pending_document(document_id);
        }
    }
}

fn add_quota(batch: &mut BatchBuilder, tenant_id: Option<u32>, delta: i64) {
    if delta != 0 {
        batch.add(ValueClass::Quota, delta);
        if let Some(tenant_id) = tenant_id {
            batch.add(ValueClass::TenantQuota(tenant_id), delta);
        }
    }
}

fn stored_size(stored: Option<&StoredMetadata>) -> i64 {
    stored.map_or(0, |stored| stored.len() as i64)
}

fn previous_size(previous: Option<&StoredContainer>) -> i64 {
    previous.map_or(0, |previous| i64::from(previous.size))
}

fn merge_viewer_state(
    batch: &mut BatchBuilder,
    class: MetadataClass,
    owner_id: u32,
    group: ChangeGroup,
    is_logged: bool,
    containers: i32,
) {
    batch.merge_fnc(class, move |ids: &AssignedIds, current| {
        let change_id = is_logged.then(|| ids.change_id(owner_id, group)).flatten();
        next_viewer_state(current, change_id, containers)
            .map(|state| MergeResult::Update(state.serialize()))
    });
}

fn next_viewer_state(
    current: Option<&[u8]>,
    change_id: Option<u64>,
    containers: i32,
) -> trc::Result<ViewerState> {
    let mut state = current
        .map(ViewerState::deserialize)
        .transpose()?
        .unwrap_or_default();
    if let Some(change_id) = change_id {
        state.change_id = state.change_id.max(change_id);
    }
    state.containers = state.containers.saturating_add_signed(containers);
    Ok(state)
}

impl MetadataWrite {
    pub fn build(self, batch: &mut BatchBuilder) -> trc::Result<MetadataPresence> {
        let presence = MetadataPresence::new(self.previous.as_ref(), self.next.as_ref());
        if self.previous.is_none() && self.next.is_none() {
            return Ok(presence);
        }

        let stored = self.next.map(StoredMetadata::new).transpose()?;
        let delta = stored_size(stored.as_ref()) - previous_size(self.previous.as_ref());
        let cursor = BatchCursor::save(batch);

        batch
            .with_account_id(self.account_id)
            .with_collection(self.collection)
            .with_pending_document(self.document_id)
            .assert_value(
                MetadataClass::Shared,
                StoredContainer::assertion(self.previous.as_ref()),
            );
        match stored {
            Some(stored) => batch.set(MetadataClass::Shared, stored.into_bytes()),
            None => batch.clear(MetadataClass::Shared),
        };
        add_quota(batch, self.tenant_id, delta);

        let sync_collection = SyncCollection::from(self.collection);
        match self.log {
            MetadataLog::Item { prefix } => batch.log_item_metadata(sync_collection, prefix),
            MetadataLog::Container => batch.log_container_metadata(sync_collection),
            MetadataLog::None => batch,
        };

        cursor.restore(batch);
        Ok(presence)
    }
}

impl PrivateMetadataWrite {
    pub fn build(
        self,
        document_id: PendingId,
        batch: &mut BatchBuilder,
        commit: &mut PrivateMetadataCommit,
    ) -> trc::Result<MetadataPresence> {
        let presence = MetadataPresence::new(self.previous.as_ref(), self.next.as_ref());
        if self.previous.is_none() && self.next.is_none() {
            return Ok(presence);
        }

        let stored = self.next.map(StoredMetadata::new).transpose()?;
        let delta = stored_size(stored.as_ref()) - previous_size(self.previous.as_ref());
        let containers: i32 = match (self.previous.is_some(), stored.is_some()) {
            (false, true) => 1,
            (true, false) => -1,
            _ => 0,
        };
        let viewer = self.viewer_id;
        let owner = self.owner_id;
        let sync_collection = SyncCollection::from(self.collection);
        let cursor = BatchCursor::save(batch);

        batch
            .with_account_id(owner)
            .with_collection(self.collection)
            .with_pending_document(document_id)
            .assert_value(
                MetadataClass::Private { viewer },
                StoredContainer::assertion(self.previous.as_ref()),
            );
        match stored {
            Some(stored) => batch.set(MetadataClass::Private { viewer }, stored.into_bytes()),
            None => batch.clear(MetadataClass::Private { viewer }),
        };

        let is_logged = match self.log {
            MetadataLog::Item { prefix } => {
                batch.log_private_item_metadata(sync_collection, viewer, prefix);
                true
            }
            MetadataLog::Container => {
                batch.log_private_container_metadata(sync_collection, viewer);
                true
            }
            MetadataLog::None => false,
        };

        if is_logged || containers != 0 {
            let group = sync_collection.change_group();
            merge_viewer_state(
                batch,
                MetadataClass::Viewer { viewer },
                owner,
                group,
                is_logged,
                containers,
            );
            batch.with_account_id(viewer);
            merge_viewer_state(
                batch,
                MetadataClass::Owner { owner },
                owner,
                group,
                is_logged,
                containers,
            );
            commit.record(PrivateMetadataChange {
                owner_id: owner,
                viewer_id: viewer,
                collection: self.collection,
                is_logged,
                containers,
            });
        }

        if delta != 0 {
            batch.with_account_id(viewer);
            add_quota(batch, self.viewer_tenant_id, delta);
        }

        cursor.restore(batch);
        Ok(presence)
    }
}

impl PrivateMetadataCommit {
    fn record(&mut self, change: PrivateMetadataChange) {
        if let Some(existing) = self.changes.iter_mut().find(|existing| {
            existing.owner_id == change.owner_id
                && existing.viewer_id == change.viewer_id
                && existing.collection == change.collection
        }) {
            existing.is_logged |= change.is_logged;
            existing.containers = existing.containers.saturating_add(change.containers);
        } else {
            self.changes.push(change);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

fn metadata_key(
    account_id: u32,
    collection: u8,
    document_id: u32,
    class: MetadataClass,
) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection,
        document_id,
        class: ValueClass::Metadata(class),
    }
}

impl Server {
    async fn iterate_documents<I, CB>(
        &self,
        account_id: u32,
        collection: u8,
        class: MetadataClass,
        documents: &I,
        cb: &mut CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Send + Sync,
    {
        let key = |document_id| metadata_key(account_id, collection, document_id, class);
        let store = &self.core.storage.data;

        match documents.scan_shape() {
            ScanShape::Range(from_document_id, to_document_id) => {
                store
                    .iterate(
                        IterateParams::new(key(from_document_id), key(to_document_id)),
                        cb,
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
                            })
                            .collect(),
                        cb,
                    )
                    .await
            }
        }
        .add_context(|err| {
            err.caused_by(trc::location!())
                .account_id(account_id)
                .collection(collection)
        })
    }
}

#[cfg(test)]
mod tests;
