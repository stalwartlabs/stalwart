/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    cleanup::{store_assert_is_empty, store_destroy},
    server::TestServer,
    temp_dir::TempDir,
};
use ::registry::schema::enums::CompressionAlgo;
use ahash::AHashSet;
use common::{DATABASE_SCHEMA_VERSION, manager::backup::BackupParams};
use store::{
    rand,
    write::{
        AnyClass, AnyKey, BatchBuilder, BlobLink, BlobOp, Operation, QueueClass, QueueEvent,
        RegistryClass, ValueClass,
    },
    *,
};
use types::{
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::{Field, MailboxField},
};

pub async fn test(test: &TestServer) {
    // Make sure the store is empty
    store_assert_is_empty(test.server.store(), test.server.blob_store().clone(), true).await;
    let db = test.server.store().clone();

    // Create blobs
    println!("Creating blobs...");
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        }),
        DATABASE_SCHEMA_VERSION.serialize(),
    );
    let mut blob_hashes = Vec::new();
    for blob_size in [16, 128, 1024, 2056, 102400] {
        let data = random_bytes(blob_size);
        let hash = BlobHash::generate(data.as_slice());
        blob_hashes.push(hash.clone());
        test.server
            .blob_store()
            .put_blob(hash.as_ref(), &data, CompressionAlgo::Lz4)
            .await
            .unwrap();
        batch.set(ValueClass::Blob(BlobOp::Commit { hash }), vec![]);
    }
    db.write(batch.build_all()).await.unwrap();

    // Create account data
    println!("Creating account data...");
    for account_id in 0u32..10u32 {
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);

        // Create properties of different sizes
        for collection in [
            Collection::Email,
            Collection::Mailbox,
            Collection::Thread,
            Collection::Identity,
        ] {
            batch.with_collection(collection);

            for document_id in [0, 10, 20, 30, 40] {
                batch.with_document(document_id);

                if collection == Collection::Mailbox {
                    batch
                        .set(
                            ValueClass::Property(Field::ARCHIVE.into()),
                            random_bytes(10),
                        )
                        .add(
                            ValueClass::Property(MailboxField::UidCounter.into()),
                            rand::random(),
                        );
                }

                for (idx, value_size) in [16, 128, 1024, 2056, 102400].into_iter().enumerate() {
                    batch.set(ValueClass::Property(idx as u8), random_bytes(value_size));
                }

                for grant_account_id in 0u32..10u32 {
                    if account_id != grant_account_id {
                        batch.set(
                            ValueClass::Acl(grant_account_id),
                            vec![account_id as u8, grant_account_id as u8, document_id as u8],
                        );
                    }
                }

                for hash in &blob_hashes {
                    batch.set(
                        ValueClass::Blob(BlobOp::Link {
                            hash: hash.clone(),
                            to: BlobLink::Document,
                        }),
                        vec![],
                    );
                }

                batch.log_item_insert(SyncCollection::from(collection), None);

                for field in 0..5 {
                    batch.any_op(Operation::Index {
                        field,
                        key: random_bytes(field as usize + 2),
                        set: true,
                    });
                }
            }
        }

        db.write(batch.build_all()).await.unwrap();
    }

    // Create queue, config and lookup data
    println!("Creating queue, config and lookup data...");
    let mut batch = BatchBuilder::new();
    for idx in [1, 2, 3, 4, 5] {
        batch.set(
            ValueClass::Queue(QueueClass::Message(rand::random())),
            random_bytes(idx),
        );
        batch.set(
            ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: rand::random(),
                queue_id: rand::random(),
                queue_name: rand::random(),
            })),
            random_bytes(idx),
        );
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: 0,
                item_id: 1,
            }),
            random_bytes(idx + 10),
        );
        batch.set(
            ValueClass::Registry(RegistryClass::IndexId {
                object_id: idx as u16,
                item_id: idx as u64 * 100,
            }),
            vec![],
        );
        for index_id in 0u16..3 {
            batch.set(
                ValueClass::Registry(RegistryClass::Index {
                    object_id: idx as u16,
                    index_id,
                    key: random_bytes(idx + index_id as usize),
                    item_id: idx as u64 * 100,
                }),
                vec![],
            );
        }
    }
    db.write(batch.build_all()).await.unwrap();

    // Create directory data
    println!("Creating directory data...");
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(u32::MAX)
        .with_collection(Collection::Principal);

    for account_id in [1, 2, 3, 4, 5] {
        batch
            .with_document(account_id)
            .add(ValueClass::Quota, account_id as i64 * 1000);
    }
    db.write(batch.build_all()).await.unwrap();

    // Obtain store hash
    println!("Calculating store hash...");
    let snapshot = Snapshot::new(&db).await;
    assert!(!snapshot.keys.is_empty(), "Store hash counts are empty",);

    // Export store
    println!("Exporting store...");
    let temp_dir = TempDir::new("art_vandelay_tests", true);
    test.server
        .core
        .backup(BackupParams::new(temp_dir.path.clone()))
        .await;

    // Destroy store
    println!("Destroying store...");
    store_destroy(&db).await;
    store_assert_is_empty(&db, db.clone().into(), true).await;

    // Import store
    println!("Importing store...");
    test.server.core.restore(temp_dir.path.clone()).await;

    // Verify hash
    print!("Verifying store hash...");
    snapshot.assert_is_eq(&Snapshot::new(&db).await);
    println!(" GREAT SUCCESS!");

    // Destroy store
    store_destroy(&db).await;
    store_assert_is_empty(&db, db.clone().into(), true).await;
    temp_dir.delete();
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    keys: AHashSet<KeyValue>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct KeyValue {
    subspace: u8,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl Snapshot {
    async fn new(db: &Store) -> Self {
        let is_sql = db.is_sql();

        let mut keys = AHashSet::new();

        for (subspace, with_values) in [
            (SUBSPACE_ACL, true),
            (SUBSPACE_TASK_QUEUE, true),
            (SUBSPACE_INDEXES, false),
            (SUBSPACE_DELETED_ITEMS, true),
            (SUBSPACE_SPAM_SAMPLES, true),
            (SUBSPACE_BLOB_LINK, true),
            (SUBSPACE_BLOBS, true),
            (SUBSPACE_LOGS, true),
            (SUBSPACE_COUNTER, !is_sql),
            (SUBSPACE_IN_MEMORY_COUNTER, !is_sql),
            (SUBSPACE_IN_MEMORY_VALUE, true),
            (SUBSPACE_PROPERTY, true),
            (SUBSPACE_REGISTRY, true),
            (SUBSPACE_REGISTRY_IDX, !is_sql),
            (SUBSPACE_REGISTRY_PK, true),
            (SUBSPACE_QUEUE_MESSAGE, true),
            (SUBSPACE_QUEUE_EVENT, true),
            (SUBSPACE_QUOTA, !is_sql),
            (SUBSPACE_REPORT_OUT, true),
            (SUBSPACE_REPORT_IN, true),
        ] {
            let from_key = AnyKey {
                subspace,
                key: vec![0u8],
            };
            let to_key = AnyKey {
                subspace,
                key: vec![u8::MAX; 10],
            };

            db.iterate(
                IterateParams::new(from_key, to_key).set_values(with_values),
                |key, value| {
                    keys.insert(KeyValue {
                        subspace,
                        key: key.to_vec(),
                        value: value.to_vec(),
                    });

                    Ok(true)
                },
            )
            .await
            .unwrap();
        }

        Snapshot { keys }
    }

    fn assert_is_eq(&self, other: &Self) {
        let mut is_err = false;
        for key in &self.keys {
            if !other.keys.contains(key) {
                println!(
                    "Subspace {}, Key {:?} not found in restored snapshot",
                    char::from(key.subspace),
                    key.key,
                );
                is_err = true;
            }
        }
        for key in &other.keys {
            if !self.keys.contains(key) {
                println!(
                    "Subspace {}, Key {:?} not found in original snapshot",
                    char::from(key.subspace),
                    key.key,
                );
                is_err = true;
            }
        }

        if is_err {
            panic!("Snapshot mismatch");
        }
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}
