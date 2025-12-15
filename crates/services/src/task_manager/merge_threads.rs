/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, storage::index::ObjectIndexBuilder};
use email::message::{
    ingest::{MergeThreadIds, ThreadMerge},
    metadata::MessageData,
};
use std::time::Duration;
use store::{
    IndexKeyPrefix, IterateParams, U32_LEN, ValueKey,
    ahash::{AHashMap, AHashSet},
    rand::Rng,
    write::{
        AlignedBytes, Archive, BatchBuilder, IndexPropertyClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::EmailField,
};

const MAX_RETRIES: usize = 5;

pub trait MergeThreadsTask: Sync + Send {
    fn merge_threads(
        &self,
        account_id: u32,
        threads: &MergeThreadIds<AHashSet<u32>>,
    ) -> impl Future<Output = bool> + Send;
}

impl MergeThreadsTask for Server {
    async fn merge_threads(
        &self,
        account_id: u32,
        threads: &MergeThreadIds<AHashSet<u32>>,
    ) -> bool {
        match merge_threads(self, account_id, threads).await {
            Ok(_) => true,
            Err(err) => {
                trc::error!(
                    err.account_id(account_id)
                        .details("Failed to merge threads")
                );
                false
            }
        }
    }
}

async fn merge_threads(
    server: &Server,
    account_id: u32,
    merge_threads: &MergeThreadIds<AHashSet<u32>>,
) -> trc::Result<()> {
    let key_len = IndexKeyPrefix::len() + merge_threads.thread_hash.len() + U32_LEN;
    let document_id_pos = key_len - U32_LEN;
    let mut thread_merge = ThreadMerge::new();
    let mut thread_index = AHashMap::new();
    let mut try_count = 0;

    'retry: loop {
        // Find thread ids
        server
            .store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
                            property: EmailField::Threading.into(),
                            hash: merge_threads.thread_hash,
                        }),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: u32::MAX,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
                            property: EmailField::Threading.into(),
                            hash: merge_threads.thread_hash,
                        }),
                    },
                )
                .ascending(),
                |key, value| {
                    if key.len() == key_len {
                        let thread_id = value.deserialize_be_u32(0)?;
                        if merge_threads.merge_ids.contains(&thread_id) {
                            let document_id = key.deserialize_be_u32(document_id_pos)?;

                            thread_merge.add(thread_id, document_id);
                            thread_index.insert(document_id, value.to_vec());
                        }
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if thread_merge.num_thread_ids() < 2 {
            // Another process merged the threads already?
            return Ok(());
        }
        let thread_id = thread_merge.merge_thread_id();

        // Delete all but the most common threadId
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Thread);

        for &delete_thread_id in thread_merge.thread_ids() {
            if delete_thread_id != thread_id {
                batch
                    .with_document(delete_thread_id)
                    .log_container_delete(SyncCollection::Thread);
            }
        }

        // Move messages to the new threadId
        batch.with_collection(Collection::Email);

        for (&group_thread_id, document_ids) in thread_merge.thread_groups() {
            if thread_id != group_thread_id {
                for &document_id in document_ids {
                    if let Some(data_) = server
                        .store()
                        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                            account_id,
                            Collection::Email,
                            document_id,
                        ))
                        .await
                        .caused_by(trc::location!())?
                    {
                        let data = data_
                            .to_unarchived::<MessageData>()
                            .caused_by(trc::location!())?;
                        if data.inner.thread_id != group_thread_id {
                            try_count += 1;
                            continue 'retry;
                        }

                        // Update thread id
                        let mut new_data = data
                            .deserialize::<MessageData>()
                            .caused_by(trc::location!())?;
                        new_data.thread_id = thread_id;
                        batch
                            .with_document(document_id)
                            .custom(
                                ObjectIndexBuilder::new()
                                    .with_current(data)
                                    .with_changes(new_data),
                            )
                            .caused_by(trc::location!())?;

                        // Update thread index property
                        let mut thread_index = thread_index.remove(&document_id).unwrap();
                        thread_index[0..U32_LEN].copy_from_slice(&thread_id.to_be_bytes());
                        batch.set(
                            ValueClass::IndexProperty(IndexPropertyClass::Hash {
                                property: EmailField::Threading.into(),
                                hash: merge_threads.thread_hash,
                            }),
                            thread_index,
                        );
                    }
                }
            }
        }

        match server.commit_batch(batch).await {
            Ok(_) => return Ok(()),
            Err(err) if err.is_assertion_failure() && try_count < MAX_RETRIES => {
                let backoff = store::rand::rng().random_range(50..=300);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                try_count += 1;
            }
            Err(err) => {
                return Err(err.caused_by(trc::location!()));
            }
        }
    }
}
