/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use coordinator::Coordinator;
use directory::{Directories, Directory};
use std::{collections::HashMap, sync::Arc};
use store::{
    BlobStore, InMemoryStore, RegistryStore, SearchStore, Store, registry::bootstrap::Bootstrap,
};

pub type IdMap<V> = HashMap<u32, Arc<V>, nohash_hasher::BuildNoHashHasher<u32>>;

#[derive(Clone)]
pub struct Storage {
    pub registry: RegistryStore,
    pub data: Store,
    pub blob: BlobStore,
    pub search: SearchStore,
    pub memory: InMemoryStore,
    pub metrics: Store,
    pub tracing: Store,
    pub coordinator: Coordinator,
    pub directory: Option<Arc<Directory>>,
    pub directories: IdMap<Directory>,
}

impl Storage {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let memory = InMemoryStore::build(bp).await.unwrap_or_default();
        let directory = Directories::build(bp).await;

        Storage {
            registry: bp.registry.clone(),
            data: bp.data_store.clone(),
            blob: BlobStore::build(bp).await.unwrap_or_default(),
            search: SearchStore::build(bp).await.unwrap_or_default(),
            coordinator: Coordinator::build(bp, &memory).await.unwrap_or_default(),
            memory,
            tracing: Store::build_tracing(bp).await.unwrap_or_default(),
            metrics: Store::build_metrics(bp).await.unwrap_or_default(),
            directory: directory.default_directory,
            directories: directory.directories,
        }
    }
}
