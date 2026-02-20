/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use directory::Directory;
use registry::{
    schema::{
        enums::{StorageQuota, TenantStorageQuota},
        prelude::Object,
    },
    types::EnumType,
};
use std::sync::Arc;
use store::{
    BlobStore, InMemoryStore, RegistryStore, SearchStore, Store, registry::RegistryQuery,
    roaring::RoaringBitmap,
};

pub mod archive;
pub mod blob;
pub mod dav;
pub mod document;
pub mod index;
pub mod quota;
pub mod state;
pub mod transaction;

#[derive(Debug, Clone)]
pub struct ObjectQuota([u32; StorageQuota::COUNT - 1]);

#[derive(Debug, Clone)]
pub struct TenantQuota([u32; TenantStorageQuota::COUNT - 1]);

impl Server {
    #[inline(always)]
    pub fn registry(&self) -> &RegistryStore {
        &self.core.storage.registry
    }

    #[inline(always)]
    pub fn store(&self) -> &Store {
        &self.core.storage.data
    }

    #[inline(always)]
    pub fn blob_store(&self) -> &BlobStore {
        &self.core.storage.blob
    }

    #[inline(always)]
    pub fn search_store(&self) -> &SearchStore {
        &self.core.storage.search
    }

    #[inline(always)]
    pub fn in_memory_store(&self) -> &InMemoryStore {
        &self.core.storage.memory
    }

    #[inline(always)]
    pub fn tracing_store(&self) -> &Store {
        &self.core.storage.tracing
    }

    #[inline(always)]
    pub fn metrics_store(&self) -> &Store {
        &self.core.storage.metrics
    }

    #[inline(always)]
    pub fn get_directory(&self, id: &u32) -> Option<&Arc<Directory>> {
        self.core.storage.directories.get(id)
    }

    #[inline(always)]
    pub fn get_default_directory(&self) -> Option<&Arc<Directory>> {
        self.core.storage.directory.as_ref()
    }

    #[inline(always)]
    pub fn get_lookup_store(&self, name: &str) -> Option<InMemoryStore> {
        if !name.is_empty() && name != "*" {
            self.inner.data.lookup_stores.load().get(name).cloned()
        } else {
            self.in_memory_store().clone().into()
        }
    }

    pub async fn total_accounts(&self) -> trc::Result<u64> {
        self.registry()
            .query::<RoaringBitmap>(RegistryQuery::new(Object::Account))
            .await
            .map(|r| r.len())
    }

    pub async fn total_domains(&self) -> trc::Result<u64> {
        self.registry()
            .query::<RoaringBitmap>(RegistryQuery::new(Object::Domain))
            .await
            .map(|r| r.len())
    }

    #[cfg(not(feature = "enterprise"))]
    pub async fn logo_resource(
        &self,
        _: &str,
    ) -> trc::Result<Option<crate::manager::application::Resource<Vec<u8>>>> {
        Ok(None)
    }
}
