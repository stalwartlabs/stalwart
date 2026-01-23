/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use coordinator::Coordinator;
use directory::Directory;
use std::sync::Arc;
use store::{BlobStore, InMemoryStore, PurgeSchedule, SearchStore, Store};

use crate::manager::config::ConfigManager;

#[derive(Default, Clone)]
pub struct Storage {
    pub data: Store,
    pub blob: BlobStore,
    pub fts: SearchStore,
    pub lookup: InMemoryStore,
    pub pubsub: Coordinator,
    pub directory: Arc<Directory>,
    pub directories: AHashMap<String, Arc<Directory>>,
    pub purge_schedules: Vec<PurgeSchedule>,
    pub config: ConfigManager,

    pub stores: AHashMap<String, Store>,
    pub blobs: AHashMap<String, BlobStore>,
    pub lookups: AHashMap<String, InMemoryStore>,
    pub ftss: AHashMap<String, SearchStore>,
}
