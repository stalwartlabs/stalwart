/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{
    ValueKey,
    write::{key::DeserializeBigEndian, *},
    *,
};
use trc::AddContext;
use types::blob_hash::{BLOB_HASH_LEN, BlobHash};

pub async fn store_destroy(store: &Store) {
    store_destroy_sql_indexes(store).await;

    for subspace in [
        SUBSPACE_ACL,
        SUBSPACE_DIRECTORY,
        SUBSPACE_TASK_QUEUE,
        SUBSPACE_INDEXES,
        SUBSPACE_BLOB_EXTRA,
        SUBSPACE_BLOB_LINK,
        SUBSPACE_LOGS,
        SUBSPACE_IN_MEMORY_COUNTER,
        SUBSPACE_IN_MEMORY_VALUE,
        SUBSPACE_COUNTER,
        SUBSPACE_PROPERTY,
        SUBSPACE_SETTINGS,
        SUBSPACE_BLOBS,
        SUBSPACE_QUEUE_MESSAGE,
        SUBSPACE_QUEUE_EVENT,
        SUBSPACE_QUOTA,
        SUBSPACE_REPORT_OUT,
        SUBSPACE_REPORT_IN,
        SUBSPACE_TELEMETRY_SPAN,
        SUBSPACE_TELEMETRY_METRIC,
        SUBSPACE_SEARCH_INDEX,
    ] {
        if subspace == SUBSPACE_SEARCH_INDEX && store.is_pg_or_mysql() {
            continue;
        }

        store
            .delete_range(
                AnyKey {
                    subspace,
                    key: vec![0u8],
                },
                AnyKey {
                    subspace,
                    key: vec![u8::MAX; 16],
                },
            )
            .await
            .unwrap();
    }
}

pub async fn search_store_destroy(store: &SearchStore) {
    match &store {
        SearchStore::Store(store) => {
            store_destroy_sql_indexes(store).await;
        }
        SearchStore::ElasticSearch(store) => {
            if let Err(err) = store.drop_indexes().await {
                eprintln!("Failed to drop elasticsearch indexes: {}", err);
            }
            store.create_indexes(3, 0, false).await.unwrap();
        }
        SearchStore::MeiliSearch(store) => {
            if let Err(err) = store.drop_indexes().await {
                eprintln!("Failed to drop meilisearch indexes: {}", err);
            }
            store.create_indexes().await.unwrap();
        }
    }
}

#[allow(unused_variables)]
async fn store_destroy_sql_indexes(store: &Store) {
    #[cfg(any(feature = "postgres", feature = "mysql"))]
    {
        if store.is_pg_or_mysql() {
            for index in [
                SearchIndex::Email,
                SearchIndex::Calendar,
                SearchIndex::Contacts,
                SearchIndex::Tracing,
            ] {
                #[cfg(feature = "postgres")]
                let table = index.psql_table();
                #[cfg(feature = "mysql")]
                let table = index.mysql_table();

                store
                    .sql_query::<usize>(&format!("TRUNCATE TABLE {table}"), vec![])
                    .await
                    .unwrap();
            }
        }
    }
}

pub async fn store_blob_expire_all(store: &Store) {
    // Delete all temporary hashes
    let from_key = ValueKey {
        account_id: 0,
        collection: 0,
        document_id: 0,
        class: ValueClass::Blob(BlobOp::Commit {
            hash: BlobHash::default(),
        }),
    };
    let to_key = ValueKey {
        account_id: u32::MAX,
        collection: u8::MAX,
        document_id: u32::MAX,
        class: ValueClass::Blob(BlobOp::Link {
            hash: BlobHash::new_max(),
            to: BlobLink::Document,
        }),
    };
    let mut batch = BatchBuilder::new();
    let mut last_account_id = u32::MAX;
    store
        .iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                if key.len() == BLOB_HASH_LEN + U32_LEN + U64_LEN {
                    let account_id = key
                        .deserialize_be_u32(BLOB_HASH_LEN)
                        .caused_by(trc::location!())?;
                    if account_id != last_account_id {
                        last_account_id = account_id;
                        batch.with_account_id(account_id);
                    }
                    let hash =
                        BlobHash::try_from_hash_slice(key.get(..BLOB_HASH_LEN).unwrap()).unwrap();
                    let until = key
                        .deserialize_be_u64(BLOB_HASH_LEN + U32_LEN)
                        .caused_by(trc::location!())?;

                    match value.first().copied() {
                        Some(BlobLink::QUOTA_LINK) => {
                            batch.clear(ValueClass::Blob(BlobOp::Quota {
                                hash: hash.clone(),
                                until,
                            }));
                        }
                        Some(BlobLink::UNDELETE_LINK) => {
                            batch.clear(ValueClass::Blob(BlobOp::Undelete {
                                hash: hash.clone(),
                                until,
                            }));
                        }
                        Some(BlobLink::SPAM_SAMPLE_LINK) => {
                            batch.clear(ValueClass::Blob(BlobOp::SpamSample {
                                hash: hash.clone(),
                                until,
                            }));
                        }
                        _ => {}
                    }

                    batch.clear(ValueClass::Blob(BlobOp::Link {
                        hash,
                        to: BlobLink::Temporary { until },
                    }));
                }

                Ok(true)
            },
        )
        .await
        .unwrap();
    store.write(batch.build_all()).await.unwrap();
}

pub async fn store_lookup_expire_all(store: &Store) {
    // Delete all temporary counters
    let from_key = ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![0u8])));
    let to_key = ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![u8::MAX; 10])));

    let mut expired_keys = Vec::new();
    let mut expired_counters = Vec::new();

    store
        .iterate(IterateParams::new(from_key, to_key), |key, value| {
            let expiry = value.deserialize_be_u64(0).caused_by(trc::location!())?;
            if expiry == 0 {
                expired_counters.push(key.to_vec());
            } else if expiry != u64::MAX {
                expired_keys.push(key.to_vec());
            }
            Ok(true)
        })
        .await
        .unwrap();

    if !expired_keys.is_empty() {
        let mut batch = BatchBuilder::new();
        for key in expired_keys {
            batch.any_op(Operation::Value {
                class: ValueClass::InMemory(InMemoryClass::Key(key)),
                op: ValueOp::Clear,
            });
            if batch.is_large_batch() {
                store.write(batch.build_all()).await.unwrap();
                batch = BatchBuilder::new();
            }
        }
        if !batch.is_empty() {
            store.write(batch.build_all()).await.unwrap();
        }
    }

    if !expired_counters.is_empty() {
        let mut batch = BatchBuilder::new();
        for key in expired_counters {
            batch.any_op(Operation::Value {
                class: ValueClass::InMemory(InMemoryClass::Counter(key.clone())),
                op: ValueOp::Clear,
            });
            batch.any_op(Operation::Value {
                class: ValueClass::InMemory(InMemoryClass::Key(key)),
                op: ValueOp::Clear,
            });
            if batch.is_large_batch() {
                store.write(batch.build_all()).await.unwrap();
                batch = BatchBuilder::new();
            }
        }
        if !batch.is_empty() {
            store.write(batch.build_all()).await.unwrap();
        }
    }
}

#[allow(unused_variables)]
pub async fn store_assert_is_empty(store: &Store, blob_store: BlobStore, include_directory: bool) {
    store_blob_expire_all(store).await;
    store_lookup_expire_all(store).await;
    store.purge_blobs(blob_store).await.unwrap();
    store.purge_store().await.unwrap();

    let store = store.clone();
    let mut failed = false;

    for (subspace, with_values) in [
        (SUBSPACE_ACL, true),
        (SUBSPACE_DIRECTORY, true),
        (SUBSPACE_TASK_QUEUE, true),
        (SUBSPACE_IN_MEMORY_VALUE, true),
        (SUBSPACE_IN_MEMORY_COUNTER, false),
        (SUBSPACE_PROPERTY, true),
        (SUBSPACE_SETTINGS, true),
        (SUBSPACE_QUEUE_MESSAGE, true),
        (SUBSPACE_QUEUE_EVENT, true),
        (SUBSPACE_REPORT_OUT, true),
        (SUBSPACE_REPORT_IN, true),
        (SUBSPACE_BLOB_EXTRA, true),
        (SUBSPACE_BLOB_LINK, true),
        (SUBSPACE_BLOBS, true),
        (SUBSPACE_COUNTER, false),
        (SUBSPACE_QUOTA, false),
        (SUBSPACE_INDEXES, false),
        (SUBSPACE_TELEMETRY_SPAN, true),
        (SUBSPACE_TELEMETRY_METRIC, true),
        (SUBSPACE_SEARCH_INDEX, true),
    ] {
        if (subspace == SUBSPACE_SEARCH_INDEX && store.is_pg_or_mysql())
            || (subspace == SUBSPACE_DIRECTORY && !include_directory)
        {
            continue;
        }

        let from_key = AnyKey {
            subspace,
            key: vec![0u8],
        };
        let to_key = AnyKey {
            subspace,
            key: vec![u8::MAX; 10],
        };

        store
            .iterate(
                IterateParams::new(from_key, to_key).set_values(with_values),
                |key, value| {
                    match subspace {
                        SUBSPACE_COUNTER if key.len() == U32_LEN + 1 || key.len() == U32_LEN => {
                            // Message ID and change ID counters
                            return Ok(true);
                        }
                        SUBSPACE_INDEXES => {
                            println!(
                                concat!(
                                    "Found index key, account {}, collection {}, ",
                                    "document {}, property {}, value {:?}: {:?}"
                                ),
                                u32::from_be_bytes(key[0..4].try_into().unwrap()),
                                key[4],
                                u32::from_be_bytes(key[key.len() - 4..].try_into().unwrap()),
                                key[5],
                                String::from_utf8_lossy(&key[6..key.len() - 4]),
                                key
                            );
                        }
                        _ => {
                            println!(
                                "Found key in {:?}: {:?} ({:?}) = {:?} ({:?})",
                                char::from(subspace),
                                key,
                                String::from_utf8_lossy(key),
                                value,
                                String::from_utf8_lossy(value)
                            );
                        }
                    }
                    failed = true;

                    Ok(true)
                },
            )
            .await
            .unwrap();
    }

    // Delete logs and counters
    store
        .delete_range(
            AnyKey {
                subspace: SUBSPACE_LOGS,
                key: &[0u8],
            },
            AnyKey {
                subspace: SUBSPACE_LOGS,
                key: &[
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                ],
            },
        )
        .await
        .unwrap();

    store
        .delete_range(
            AnyKey {
                subspace: SUBSPACE_COUNTER,
                key: &[0u8],
            },
            AnyKey {
                subspace: SUBSPACE_COUNTER,
                key: (u32::MAX / 2).to_be_bytes().as_slice(),
            },
        )
        .await
        .unwrap();

    if failed {
        panic!("Store is not empty.");
    }
}
