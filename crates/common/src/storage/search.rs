/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{KV_LOCK_SEARCH_INDEX, Server};
use store::{
    U32_LEN, U64_LEN, ValueKey,
    write::{
        SearchIndex, SearchIndexClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
        serialize::RawValue,
    },
};
use trc::AddContext;

#[derive(Debug, Clone, Default)]
pub struct SearchIndexStatus {
    pub next_retry: u64,
    pub attempts: u32,
    pub reason: String,
}

impl SearchIndexStatus {
    pub fn deserialize(value: &[u8]) -> trc::Result<Self> {
        Ok(SearchIndexStatus {
            next_retry: value.deserialize_be_u64(0)?,
            attempts: value.deserialize_be_u32(U64_LEN)?,
            reason: value
                .get(U64_LEN + U32_LEN..)
                .map(String::from_utf8_lossy)
                .unwrap_or_default()
                .into_owned(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        KeySerializer::new(U64_LEN + U32_LEN + self.reason.len())
            .write(self.next_retry)
            .write(self.attempts)
            .write(self.reason.as_bytes())
            .finalize()
    }
}

impl Server {
    pub async fn search_index_status(
        &self,
        index: SearchIndex,
        partition: u32,
    ) -> trc::Result<Option<SearchIndexStatus>> {
        match self
            .store()
            .get_value::<RawValue>(ValueKey::from(ValueClass::SearchIndex(
                SearchIndexClass::QueueStatus { index, partition },
            )))
            .await
            .caused_by(trc::location!())?
        {
            Some(value) => SearchIndexStatus::deserialize(value.0.as_slice()).map(Some),
            None => Ok(None),
        }
    }

    pub async fn try_lock_search_index(
        &self,
        index: SearchIndex,
        partition: u32,
        expiry: u64,
    ) -> bool {
        match self
            .in_memory_store()
            .try_lock(
                KV_LOCK_SEARCH_INDEX,
                &search_index_lock_key(index, partition),
                expiry,
            )
            .await
        {
            Ok(result) => result,
            Err(err) => {
                trc::error!(
                    err.details("Failed to lock search index partition")
                        .ctx(trc::Key::Type, index.name())
                        .ctx(trc::Key::Id, partition)
                        .caused_by(trc::location!())
                );

                false
            }
        }
    }

    pub async fn renew_search_index_lock(
        &self,
        index: SearchIndex,
        partition: u32,
        expiry: u64,
    ) -> bool {
        match self
            .in_memory_store()
            .renew_lock(
                KV_LOCK_SEARCH_INDEX,
                &search_index_lock_key(index, partition),
                expiry,
            )
            .await
        {
            Ok(_) => true,
            Err(err) => {
                trc::error!(
                    err.details("Failed to renew search index partition lock")
                        .ctx(trc::Key::Type, index.name())
                        .ctx(trc::Key::Id, partition)
                        .caused_by(trc::location!())
                );

                false
            }
        }
    }

    pub async fn unlock_search_index(&self, index: SearchIndex, partition: u32) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(
                KV_LOCK_SEARCH_INDEX,
                &search_index_lock_key(index, partition),
            )
            .await
        {
            trc::error!(
                err.details("Failed to unlock search index partition")
                    .ctx(trc::Key::Type, index.name())
                    .ctx(trc::Key::Id, partition)
                    .caused_by(trc::location!())
            );
        }
    }
}

fn search_index_lock_key(index: SearchIndex, partition: u32) -> [u8; U32_LEN + 1] {
    let mut key = [index.to_u8(); U32_LEN + 1];
    key[1..].copy_from_slice(&partition.to_be_bytes());
    key
}
