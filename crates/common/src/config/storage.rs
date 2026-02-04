/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::IdMap;
use coordinator::Coordinator;
use directory::Directory;
use std::sync::Arc;
use store::{BlobStore, InMemoryStore, RegistryStore, SearchStore, Store};

#[derive(Clone)]
pub struct Storage {
    pub registry: RegistryStore,
    pub data: Store,
    pub blob: BlobStore,
    pub fts: SearchStore,
    pub lookup: InMemoryStore,
    pub pubsub: Coordinator,
    pub directories: IdMap<Arc<Directory>>,
}
