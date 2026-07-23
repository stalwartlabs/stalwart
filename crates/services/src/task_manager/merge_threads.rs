/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::TaskResult;
use common::{Server, storage::index::ObjectIndexBuilder};
use email::message::{
    ingest::{ThreadMerge, has_message_id},
    metadata::MessageData,
};
use registry::schema::structs::TaskMergeThreads;
use std::{str::FromStr, time::Duration};
use store::{
    IterateParams, Key, U32_LEN, ValueKey,
    ahash::AHashMap,
    rand::Rng,
    write::{
        AlignedBytes, Archive, BatchBuilder, IndexPropertyClass, MergeResult, Params, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::EmailField,
};
use utils::cheeky_hash::CheekyHash;

const MAX_RETRIES: usize = 5;

pub(crate) trait MergeThreadsTask: Sync + Send {
    fn merge_threads(&self, threads: &TaskMergeThreads) -> impl Future<Output = TaskResult> + Send;
}

impl MergeThreadsTask for Server {
    async fn merge_threads(&self, threads: &TaskMergeThreads) -> TaskResult {
        match merge_threads(self, threads).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.account_id(threads.account_id.document_id())
                        .details("Failed to merge threads")
                );
                result
            }
        }
    }
}

async fn merge_threads(
    server: &Server,
    task_merge_threads: &TaskMergeThreads,
) -> trc::Result<TaskResult> {
    let Ok(thread_hash) = CheekyHash::from_str(&task_merge_threads.thread_name) else {
        return Ok(TaskResult::permanent("Invalid thread hash"));
    };
    let Ok(mut message_ids) = task_merge_threads
        .message_ids
        .iter()
        .map(|id| CheekyHash::from_str(id))
        .collect::<Result<Vec<_>, _>>()
    else {
        return Ok(TaskResult::permanent("Invalid message ids"));
    };
    message_ids.sort_unstable();

    let account_id = task_merge_threads.account_id.document_id();
    let mut try_count = 0;

    let from_key = ValueKey {
        account_id,
        collection: Collection::Email.into(),
        document_id: 0,
        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
            property: EmailField::Threading.into(),
            hash: thread_hash,
        }),
    };
    let to_key = ValueKey {
        account_id,
        collection: Collection::Email.into(),
        document_id: u32::MAX,
        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
            property: EmailField::Threading.into(),
            hash: thread_hash,
        }),
    };
    let mut prefix = from_key.serialize(0);
    let key_len = prefix.len();
    let document_id_pos = key_len - U32_LEN;
    prefix.truncate(document_id_pos);

    'retry: loop {
        // Merge threads
        let mut thread_merge = ThreadMerge::new();
        let mut same_subject_messages: AHashMap<u32, Vec<u32>> = AHashMap::new();

        // Find thread ids
        server
            .store()
            .iterate(
                IterateParams::new(from_key.clone(), to_key.clone()).ascending(),
                |key, value| {
                    if key.len() == key_len && key.starts_with(&prefix) {
                        // Find matching references
                        let references = value.get(U32_LEN..).unwrap_or_default();
                        let thread_id = value.deserialize_be_u32(0)?;
                        let document_id = key.deserialize_be_u32(document_id_pos)?;

                        if has_message_id(&message_ids, references) {
                            thread_merge.add(thread_id, document_id);
                        } else {
                            // Keep track of messages with the same subject for potential future merges
                            same_subject_messages
                                .entry(thread_id)
                                .or_default()
                                .push(document_id);
                        }
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if thread_merge.num_thread_ids() < 2 {
            // Another process merged the threads already?
            return Ok(TaskResult::Success(vec![]));
        }

        // Add other messages with the same subject to the merge if they share a
        // thread id with a message that has a matching message id
        for thread_id in thread_merge.thread_ids().copied().collect::<Vec<_>>() {
            if let Some(document_ids) = same_subject_messages.get(&thread_id) {
                for &document_id in document_ids {
                    thread_merge.add(thread_id, document_id);
                }
            }
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
                        batch.merge_fnc(
                            ValueClass::IndexProperty(IndexPropertyClass::Hash {
                                property: EmailField::Threading.into(),
                                hash: thread_hash,
                            }),
                            Params::with_capacity(3)
                                .with_u64(thread_id as u64)
                                .with_u64(group_thread_id as u64),
                            |params, _, bytes| {
                                let new_thread_id = params.u64(0) as u32;
                                let old_thread_id = params.u64(1) as u32;

                                let mut thread_index = bytes
                                    .filter(|v| v.len() > U32_LEN)
                                    .ok_or_else(|| {
                                        trc::StoreEvent::AssertValueFailed
                                            .into_err()
                                            .details("Message no longer exists.")
                                            .caused_by(trc::location!())
                                    })?
                                    .to_vec();

                                if thread_index.as_slice().deserialize_be_u32(0)? != old_thread_id {
                                    return Err(
                                        trc::StoreEvent::AssertValueFailed
                                            .into_err()
                                            .details("Thread id mismatch, likely due to concurrent modification.")
                                            .caused_by(trc::location!())
                                    );
                                }

                                thread_index[0..U32_LEN].copy_from_slice(&new_thread_id.to_be_bytes());

                                Ok(MergeResult::Update(thread_index))
                            },
                        );
                    }
                }
            }
        }

        match server.commit_batch(batch).await {
            Ok(_) => return Ok(TaskResult::Success(vec![])),
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
