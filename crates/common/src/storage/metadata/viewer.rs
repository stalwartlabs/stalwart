/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PrivateMetadataChange, PrivateMetadataCommit, metadata_key};
use crate::{
    Server,
    auth::AccessToken,
    ipc::{BroadcastEvent, CacheInvalidation, PushNotification, ViewerStateChange},
};
use jmap_proto::request::capability::{Capability, CapabilityIds};
use registry::schema::enums::Permission;
use std::sync::{
    Arc,
    atomic::{AtomicU32, AtomicU64, Ordering},
};
use store::{
    Deserialize, IterateParams, U32_LEN,
    write::{
        AssignedIds,
        metadata::{MetadataClass, ViewerState},
    },
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    type_state::{DataType, StateChange},
};
use utils::{
    cache::{Cache, CacheItemWeight},
    map::bitmap::Bitmap,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataViewer(u32);

pub struct MetadataViewerCache {
    states: Cache<u32, Arc<ViewerStates>>,
    epoch: AtomicU64,
}

#[derive(Debug, Default)]
pub struct ViewerStates {
    entries: Box<[ViewerStateEntry]>,
}

#[derive(Debug)]
struct ViewerStateEntry {
    owner_id: u32,
    collection: u8,
    change_id: AtomicU64,
    containers: AtomicU32,
}

const OWNER_KEY_SUFFIX: usize = U32_LEN + 1;
pub(super) const CACHE_SLOT_SIZE: usize = 32;
pub(super) const CACHE_INDEX_SIZE: usize = 8;
const ARC_COUNTERS_SIZE: usize = 2 * size_of::<usize>();
const VALUE_SLOT_SIZE: usize = CACHE_SLOT_SIZE - size_of::<u32>();
const ESTIMATED_ENTRIES: usize = 2;

impl MetadataViewer {
    pub fn account_id(self) -> u32 {
        self.0
    }
}

impl MetadataViewerCache {
    pub fn new(weight_capacity: u64) -> Self {
        MetadataViewerCache {
            states: Cache::new(
                weight_capacity,
                size_of::<u32>() as u64 + ViewerStates::footprint(ESTIMATED_ENTRIES),
            )
            .with_name("metadataViewers"),
            epoch: AtomicU64::new(0),
        }
    }

    pub fn invalidate(&self, viewer_id: u32) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.states.remove(&viewer_id);
    }

    pub fn clear(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.states.clear();
    }

    pub(super) fn get(&self, viewer_id: u32) -> Option<Arc<ViewerStates>> {
        self.states.get(&viewer_id)
    }

    pub(super) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub(super) fn insert(&self, viewer_id: u32, states: Arc<ViewerStates>, epoch: u64) {
        if self.epoch() == epoch {
            self.states.insert(viewer_id, states);
        }
    }

    pub(super) fn apply(&self, change: &PrivateMetadataChange, change_id: Option<u64>) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let Some(states) = self.states.peek(&change.viewer_id) else {
            return;
        };
        match states.entry(change.owner_id, change.collection) {
            Some(entry) => {
                if let Some(change_id) = change_id {
                    entry.change_id.fetch_max(change_id, Ordering::AcqRel);
                }
                if let Ok(added) = u32::try_from(change.containers)
                    && added > 0
                {
                    let _ = entry.containers.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |containers| Some(containers.saturating_add(added)),
                    );
                }
            }
            None => {
                self.states.remove(&change.viewer_id);
            }
        }
    }
}

impl ViewerStates {
    pub fn get(&self, owner_id: u32, collection: Collection) -> ViewerState {
        self.entry(owner_id, collection)
            .map(ViewerStateEntry::load)
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn entry(&self, owner_id: u32, collection: Collection) -> Option<&ViewerStateEntry> {
        let key = (owner_id, u8::from(collection));
        self.entries
            .binary_search_by_key(&key, |entry| (entry.owner_id, entry.collection))
            .ok()
            .and_then(|index| self.entries.get(index))
    }

    fn footprint(entries: usize) -> u64 {
        (VALUE_SLOT_SIZE
            + CACHE_INDEX_SIZE
            + ARC_COUNTERS_SIZE
            + size_of::<ViewerStates>()
            + (entries * size_of::<ViewerStateEntry>())) as u64
    }

    pub(super) fn new(entries: impl IntoIterator<Item = (u32, u8, ViewerState)>) -> Self {
        ViewerStates {
            entries: entries
                .into_iter()
                .map(|(owner_id, collection, state)| {
                    ViewerStateEntry::new(owner_id, collection, state)
                })
                .collect(),
        }
    }
}

impl ViewerStateEntry {
    fn new(owner_id: u32, collection: u8, state: ViewerState) -> Self {
        ViewerStateEntry {
            owner_id,
            collection,
            change_id: AtomicU64::new(state.change_id),
            containers: AtomicU32::new(state.containers),
        }
    }

    fn load(&self) -> ViewerState {
        ViewerState {
            change_id: self.change_id.load(Ordering::Acquire),
            containers: self.containers.load(Ordering::Acquire),
        }
    }
}

impl CacheItemWeight for ViewerStates {
    fn weight(&self) -> u64 {
        ViewerStates::footprint(self.entries.len())
    }
}

impl Server {
    pub fn jmap_metadata_aware(
        &self,
        access_token: &AccessToken,
        using: CapabilityIds,
        data_type: DataType,
    ) -> bool {
        using.contains(Capability::Metadata)
            && self.core.metadata.data_types.contains(data_type)
            && access_token.has_permission(Permission::JmapMetadataGet)
    }

    pub fn jmap_metadata_viewer(
        &self,
        access_token: &AccessToken,
        using: CapabilityIds,
        data_type: DataType,
    ) -> Option<MetadataViewer> {
        (self.core.metadata.private_metadata
            && self.jmap_metadata_aware(access_token, using, data_type)
            && access_token.has_permission(Permission::JmapMetadataPrivate))
        .then(|| MetadataViewer(access_token.account_id()))
    }

    pub fn imap_metadata_viewer(&self, access_token: &AccessToken) -> Option<MetadataViewer> {
        (self.core.metadata.private_metadata
            && access_token.has_permission(Permission::ImapMetadataPrivate))
        .then(|| MetadataViewer(access_token.account_id()))
    }

    pub async fn metadata_viewer_state(
        &self,
        viewer: MetadataViewer,
        owner_id: u32,
        collection: Collection,
    ) -> trc::Result<ViewerState> {
        self.metadata_viewer_states(viewer)
            .await
            .map(|states| states.get(owner_id, collection))
    }

    pub async fn metadata_viewer_states(
        &self,
        viewer: MetadataViewer,
    ) -> trc::Result<Arc<ViewerStates>> {
        let cache = &self.inner.cache.metadata_viewers;
        if let Some(states) = cache.get(viewer.0) {
            return Ok(states);
        }

        let epoch = cache.epoch();
        let states = Arc::new(self.load_viewer_states(viewer.0).await?);
        cache.insert(viewer.0, states.clone(), epoch);
        Ok(states)
    }

    pub async fn private_metadata_committed(
        &self,
        commit: PrivateMetadataCommit,
        assigned_ids: &AssignedIds,
    ) {
        if commit.is_empty() {
            return;
        }

        let cache = &self.inner.cache.metadata_viewers;
        let mut viewers = Vec::with_capacity(1);
        let mut pushes: Vec<(u32, u32, SyncCollection, Bitmap<DataType>)> = Vec::new();
        for change in &commit.changes {
            let sync_collection = SyncCollection::from(change.collection);
            let change_id = change
                .is_logged
                .then(|| assigned_ids.change_id(change.owner_id, sync_collection))
                .flatten();
            cache.apply(change, change_id);

            if !viewers.contains(&change.viewer_id) {
                viewers.push(change.viewer_id);
            }

            if change_id.is_some()
                && let Ok(data_type) = DataType::try_from(change.collection)
            {
                match pushes.iter_mut().find(|(owner_id, viewer_id, pushed, _)| {
                    *owner_id == change.owner_id
                        && *viewer_id == change.viewer_id
                        && *pushed == sync_collection
                }) {
                    Some((_, _, _, types)) => types.insert(data_type),
                    None => pushes.push((
                        change.owner_id,
                        change.viewer_id,
                        sync_collection,
                        Bitmap::from_iter([data_type]),
                    )),
                }
            }
        }

        self.cluster_broadcast(BroadcastEvent::CacheInvalidate(
            viewers
                .into_iter()
                .map(CacheInvalidation::PrivateMetadata)
                .collect(),
        ))
        .await;

        for (owner_id, viewer_id, sync_collection, types) in pushes {
            if let Some(change_id) = assigned_ids.change_id(owner_id, sync_collection) {
                self.broadcast_push_notification(PushNotification::ViewerStateChange(
                    ViewerStateChange {
                        viewer_id,
                        change: StateChange {
                            account_id: owner_id,
                            change_id,
                            types,
                        },
                    },
                ))
                .await;
            }
        }
    }

    async fn load_viewer_states(&self, viewer_id: u32) -> trc::Result<ViewerStates> {
        let mut entries = Vec::new();
        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    metadata_key(viewer_id, 0, 0, MetadataClass::Owner { owner: 0 }),
                    metadata_key(
                        viewer_id,
                        u8::MAX,
                        0,
                        MetadataClass::Owner { owner: u32::MAX },
                    ),
                ),
                |key, value| {
                    let (owner_id, collection) = parse_owner_key(key)?;
                    entries.push((owner_id, collection, ViewerState::deserialize(value)?));
                    Ok(true)
                },
            )
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(viewer_id))?;
        Ok(ViewerStates::new(entries))
    }
}

pub(super) fn parse_owner_key(key: &[u8]) -> trc::Result<(u32, u8)> {
    key.len()
        .checked_sub(OWNER_KEY_SUFFIX)
        .and_then(|offset| key.get(offset..))
        .and_then(|suffix| suffix.split_first_chunk::<U32_LEN>())
        .and_then(|(owner, collection)| Some((u32::from_be_bytes(*owner), *collection.first()?)))
        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))
}

#[cfg(test)]
mod tests;
