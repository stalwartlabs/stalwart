/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{add_quota, metadata_key};
use crate::Server;
use std::slice;
use store::{
    Deserialize, U32_LEN,
    dispatch::DocumentSet,
    write::{
        ArchiveVersion, BatchBuilder,
        assert::AssertValue,
        key::DeserializeBigEndian,
        metadata::{MetadataBuf, MetadataClass, StoredMetadata},
    },
};
use trc::AddContext;
use types::collection::Collection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry {
    pub document_id: u32,
    pub size: u32,
    pub hash: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredEntries {
    entries: Vec<StoredEntry>,
}

struct StoredValue(StoredEntry);

impl Deserialize for StoredValue {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(StoredValue(StoredEntry::new(0, bytes)))
    }
}

impl StoredEntry {
    pub fn new(document_id: u32, stored: &[u8]) -> Self {
        StoredEntry {
            document_id,
            size: u32::try_from(stored.len()).unwrap_or(u32::MAX),
            hash: StoredMetadata::trailer_hash(stored).ok(),
        }
    }

    pub fn from_container(document_id: u32, container: &MetadataBuf) -> Self {
        StoredEntry {
            document_id,
            size: container.stored_len(),
            hash: Some(container.hash()),
        }
    }

    pub fn clear(&self, batch: &mut BatchBuilder, class: MetadataClass) {
        batch.with_document(self.document_id);
        if let Some(hash) = self.hash {
            batch.assert_value(class, AssertValue::Archive(ArchiveVersion::Hashed { hash }));
        }
        batch.clear(class);
    }

    pub fn release(&self, batch: &mut BatchBuilder, tenant_id: Option<u32>) {
        self.clear(batch, MetadataClass::Shared);
        add_quota(batch, tenant_id, -i64::from(self.size));
    }
}

impl StoredEntries {
    fn new(mut entries: Vec<StoredEntry>) -> Self {
        if !entries.is_sorted_by_key(|entry| entry.document_id) {
            entries.sort_unstable_by_key(|entry| entry.document_id);
        }
        StoredEntries { entries }
    }

    pub fn get(&self, document_id: u32) -> Option<&StoredEntry> {
        self.entries
            .binary_search_by_key(&document_id, |entry| entry.document_id)
            .ok()
            .and_then(|position| self.entries.get(position))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn iter(&self) -> slice::Iter<'_, StoredEntry> {
        self.entries.iter()
    }
}

impl FromIterator<StoredEntry> for StoredEntries {
    fn from_iter<T: IntoIterator<Item = StoredEntry>>(iter: T) -> Self {
        StoredEntries::new(iter.into_iter().collect())
    }
}

impl Server {
    pub async fn stored_metadata_entries<I>(
        &self,
        account_id: u32,
        collection: Collection,
        documents: &I,
    ) -> trc::Result<StoredEntries>
    where
        I: DocumentSet + Send + Sync,
    {
        self.stored_entries(account_id, collection, MetadataClass::Shared, documents)
            .await
            .map(StoredEntries::new)
    }

    pub(super) async fn stored_entries<I>(
        &self,
        account_id: u32,
        collection: Collection,
        class: MetadataClass,
        documents: &I,
    ) -> trc::Result<Vec<StoredEntry>>
    where
        I: DocumentSet + Send + Sync,
    {
        let mut entries = Vec::new();
        match documents.len() {
            0 => return Ok(entries),
            1 => {
                return self
                    .stored_entry(account_id, collection, class, documents.min())
                    .await
                    .map(|entry| entry.into_iter().collect());
            }
            _ => {}
        }
        let mut collect = |key: &[u8], value: &[u8]| {
            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
            if documents.contains(document_id) {
                entries.push(StoredEntry::new(document_id, value));
            }
            Ok(true)
        };
        self.iterate_documents(
            account_id,
            u8::from(collection),
            class,
            documents,
            &mut collect,
        )
        .await?;
        Ok(entries)
    }

    pub(super) async fn stored_entry(
        &self,
        account_id: u32,
        collection: Collection,
        class: MetadataClass,
        document_id: u32,
    ) -> trc::Result<Option<StoredEntry>> {
        self.core
            .storage
            .data
            .get_value::<StoredValue>(metadata_key(
                account_id,
                u8::from(collection),
                document_id,
                class,
            ))
            .await
            .map(|value| {
                value.map(|StoredValue(entry)| StoredEntry {
                    document_id,
                    ..entry
                })
            })
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .document_id(document_id)
            })
    }
}

#[cfg(test)]
mod tests;
