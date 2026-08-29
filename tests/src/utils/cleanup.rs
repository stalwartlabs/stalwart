/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ::registry::{
    schema::prelude::{OBJ_SINGLETON, ObjectType},
    types::EnumImpl,
};
use store::{
    ValueKey,
    write::{key::DeserializeBigEndian, *},
    *,
};
use trc::AddContext;
use types::blob_hash::{BLOB_HASH_LEN, BlobHash};

pub async fn store_destroy(store: &Store) {
    store_destroy_sql_indexes(store).await;

    for subspace in Subspace::ALL.iter().copied() {
        if subspace.is_internal_fts() && store.is_pg_or_mysql() {
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
            search_subspace_destroy(store).await;
        }
        #[cfg(feature = "postgres")]
        SearchStore::PostgreSQL(store) => {
            store_destroy_sql_indexes(&Store::PostgreSQL(store.clone())).await;
        }
        #[cfg(feature = "mysql")]
        SearchStore::MySQL(store) => {
            store_destroy_sql_indexes(&Store::MySQL(store.clone())).await;
        }
        #[cfg(any(feature = "postgres", feature = "mysql"))]
        SearchStore::SQLReadReplica(store) => {
            store_destroy_sql_indexes(store.primary_store()).await;
        }
        SearchStore::ElasticSearch(store) => {
            if let Err(err) = store.drop_indexes().await {
                eprintln!("Failed to drop elasticsearch indexes: {}", err);
            }
            store.create_indexes().await.unwrap();
        }
        SearchStore::MeiliSearch(store) => {
            if let Err(err) = store.drop_indexes().await {
                eprintln!("Failed to drop meilisearch indexes: {}", err);
            }
            store.create_indexes().await.unwrap();
        }
    }
}

async fn search_subspace_destroy(store: &Store) {
    for subspace in [
        Subspace::SearchTerm,
        Subspace::SearchDocument,
        Subspace::SearchQueue,
    ] {
        store
            .delete_range(
                AnyKey {
                    subspace,
                    key: vec![0u8],
                },
                AnyKey {
                    subspace,
                    key: vec![u8::MAX; 32],
                },
            )
            .await
            .unwrap();
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

                let _ = store
                    .sql_query::<usize>(&format!("TRUNCATE TABLE {table}"), vec![])
                    .await;
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
            |key, _| {
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
    store.write_batch(&mut batch).await.unwrap();
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
                store.write_batch(&mut batch).await.unwrap();
                batch = BatchBuilder::new();
            }
        }
        if !batch.is_empty() {
            store.write_batch(&mut batch).await.unwrap();
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
                store.write_batch(&mut batch).await.unwrap();
                batch = BatchBuilder::new();
            }
        }
        if !batch.is_empty() {
            store.write_batch(&mut batch).await.unwrap();
        }
    }
}

#[allow(unused_variables)]
pub async fn store_assert_is_empty(store: &Store, blob_store: BlobStore, include_registry: bool) {
    store_blob_expire_all(store).await;
    store_lookup_expire_all(store).await;
    for shard_idx in 0..=u8::MAX {
        store
            .purge_blobs(blob_store.clone(), shard_idx)
            .await
            .unwrap();
    }
    store.purge_store().await.unwrap();

    let store = store.clone();
    let mut failed = false;
    let mut delete_batch = BatchBuilder::new();

    for subspace in Subspace::ALL.iter().copied().filter(|subspace| {
        !matches!(
            subspace,
            Subspace::Logs | Subspace::System | Subspace::GlobalCounter
        )
    }) {
        if subspace.is_internal_fts() && store.is_pg_or_mysql() {
            continue;
        }

        let with_values = matches!(subspace.shape(), Shape::Value);

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
                        Subspace::Counter
                            if key.len() == U32_LEN
                                || key.len() == U32_LEN + 1
                                || key.len() == U32_LEN + 2 =>
                        {
                            // Document id, quota and per-group change id counters
                            delete_batch.clear(ValueClass::Any(AnyClass {
                                subspace,
                                key: key.to_vec(),
                            }));
                            return Ok(true);
                        }
                        Subspace::Indexes => {
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
                        Subspace::Registry | Subspace::Directory | Subspace::SpamSamples => {
                            let object_id =
                                ObjectType::from_id(key.deserialize_be_u16(0).unwrap()).unwrap();

                            if include_registry && is_allowed_registry_type(object_id) {
                                return Ok(true);
                            }
                            let item_id = key.deserialize_be_u64(U16_LEN).unwrap();

                            println!(
                                "Found registry item for object type {:?} and id {}",
                                object_id, item_id
                            );
                        }
                        Subspace::RegistryIndex => {
                            let mut id = key.deserialize_be_u16(0).unwrap();
                            if id == u16::MAX {
                                id = key.deserialize_be_u16(U16_LEN).unwrap();
                            }

                            let object_id = ObjectType::from_id(id).unwrap();

                            if include_registry && is_allowed_registry_type(object_id) {
                                return Ok(true);
                            }

                            println!(
                                "Found registry index for object type {:?}: {:?}",
                                object_id, key
                            );
                        }
                        Subspace::RegistryPrimaryKey => {
                            let mut id = key.deserialize_be_u16(0).unwrap();
                            if id == u16::MAX {
                                id = value.deserialize_be_u16(0).unwrap();
                            }
                            let object_id = ObjectType::from_id(id).unwrap();
                            if include_registry && is_allowed_registry_type(object_id) {
                                return Ok(true);
                            }

                            println!(
                                "Found registry primary key for object type {:?}: {:?}",
                                object_id, key
                            );
                        }
                        _ => {
                            println!(
                                "Found key in {:?}: {:?} ({:?}) = {:?} ({:?})",
                                subspace.name(),
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
                subspace: Subspace::Logs,
                key: &[0u8],
            },
            AnyKey {
                subspace: Subspace::Logs,
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

    if !delete_batch.is_empty() {
        store.write_batch(&mut delete_batch).await.unwrap();
    }

    if failed {
        panic!("Store is not empty.");
    }
}

fn is_allowed_registry_type(object_type: ObjectType) -> bool {
    (object_type.flags() & OBJ_SINGLETON) != 0
        || matches!(
            object_type,
            ObjectType::Role
                | ObjectType::Account
                | ObjectType::NetworkListener
                | ObjectType::MtaDeliverySchedule
                | ObjectType::MtaRoute
                | ObjectType::MtaTlsStrategy
                | ObjectType::MtaVirtualQueue
                | ObjectType::MtaConnectionStrategy
                | ObjectType::MtaInboundThrottle
                | ObjectType::Tracer
                | ObjectType::Domain
        )
}
