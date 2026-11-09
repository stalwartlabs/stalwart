/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use directory::Directory;
use registry::{
    schema::{enums::StorageQuota, prelude::ObjectType},
    types::EnumImpl,
};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use registry::schema::enums::TenantStorageQuota;
// SPDX-SnippetEnd
use registry::schema::enums::TaskType;
use std::sync::Arc;
use store::{
    BlobStore, InMemoryStore, IterateParams, RegistryStore, SearchStore, Store, U16_LEN, ValueKey,
    write::{TaskId, TaskQueueClass, ValueClass, key::DeserializeBigEndian, now},
};
use trc::AddContext;

pub mod archive;
pub mod batch;
pub mod blob;
pub mod chunk;
pub mod dav;
pub mod document;
pub mod encryption;
pub mod index;
pub mod metadata;
pub mod quota;
pub mod search;
pub mod state;
pub mod transaction;

#[derive(Debug, Clone)]
pub struct ObjectQuota([u32; StorageQuota::COUNT]);

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone)]
pub struct TenantQuota([u32; TenantStorageQuota::COUNT - 1]);
// SPDX-SnippetEnd

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

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[inline(always)]
    pub fn tracing_store(&self) -> &Store {
        &self.core.storage.tracing
    }

    #[cfg(feature = "enterprise")]
    #[inline(always)]
    pub fn metrics_store(&self) -> &Store {
        &self.core.storage.metrics
    }
    // SPDX-SnippetEnd

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

    pub async fn total_accounts(&self) -> trc::Result<usize> {
        self.registry().count_object(ObjectType::Account).await
    }

    pub async fn total_domains(&self) -> trc::Result<usize> {
        self.registry().count_object(ObjectType::Domain).await
    }

    pub async fn total_tasks_pending(&self) -> trc::Result<(u64, u64)> {
        let (Some(first), Some(last)) = (TaskType::ALL.first(), TaskType::ALL.last()) else {
            return Ok((0, 0));
        };
        const DUE_OFFSET: usize = size_of::<u8>() + U16_LEN;
        let now = now();
        let mut pending = 0u64;
        let mut due = 0u64;
        let mut scanned = 0u64;
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
                        id: TaskId::Assigned(0),
                        typ: *first,
                        due: 0,
                    })),
                    ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
                        id: TaskId::Assigned(u64::MAX),
                        typ: *last,
                        due: u64::MAX,
                    })),
                )
                .no_values(),
                |key, _| {
                    scanned += 1;
                    let task_due = key.deserialize_be_u64(DUE_OFFSET)?;
                    if task_due != u64::MAX {
                        pending += 1;
                        if task_due <= now {
                            due += 1;
                        }
                    }
                    Ok(scanned < search::MAX_PENDING_SCAN)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| (pending, due))
    }

    #[cfg(not(feature = "enterprise"))]
    pub async fn logo_resource(
        &self,
        _: &str,
    ) -> trc::Result<Option<crate::manager::application::Resource<bytes::Bytes>>> {
        Ok(None)
    }
}
