/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use coordinator::Coordinator;
use directory::Directory;
use std::{collections::HashMap, sync::Arc};
use store::{BlobStore, InMemoryStore, RegistryStore, SearchStore, Store};

pub type IdMap<V> = HashMap<u32, Arc<V>, nohash_hasher::BuildNoHashHasher<u32>>;

#[derive(Clone)]
pub struct Storage {
    pub registry: RegistryStore,
    pub data: Store,
    pub blob: BlobStore,
    pub fts: SearchStore,
    pub memory: InMemoryStore,
    pub coordinator: Coordinator,
    pub directory: Option<Arc<Directory>>,
    pub directories: IdMap<Directory>,
}
