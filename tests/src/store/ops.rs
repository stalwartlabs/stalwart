/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use std::collections::HashSet;
use store::{
    Store, ValueKey,
    rand::{self, Rng},
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, DirectoryClass, MergeResult, Params,
        ValueClass,
    },
};
use types::collection::{Collection, SyncCollection};

use crate::store::cleanup::store_assert_is_empty;

// FDB max value
const MAX_VALUE_SIZE: usize = 100000;

#[cfg(feature = "foundationdb")]
fn value_gen(chunks: impl IntoIterator<Item = (u8, usize)>) -> Vec<u8> {
    let mut value = Vec::new();
    for (byte, size) in chunks {
        value.extend(std::iter::repeat_n(byte, size));
    }
    value
}

pub async fn test(db: Store) {
    #[cfg(feature = "foundationdb")]
    if matches!(db, Store::FoundationDb(_)) {
        use types::collection::Collection;

        println!("Running FoundationDB chunked iterator test...");
        let kvs = [
            ("a", value_gen([(b'a', 1)])),
            ("b", value_gen([(b'b', MAX_VALUE_SIZE), (b'0', 1)])),
            (
                "c",
                value_gen([
                    (b'c', MAX_VALUE_SIZE),
                    (b'1', MAX_VALUE_SIZE),
                    (b'2', MAX_VALUE_SIZE),
                ]),
            ),
            (
                "d",
                value_gen([(b'd', MAX_VALUE_SIZE), (b'3', MAX_VALUE_SIZE)]),
            ),
            ("e", value_gen([(b'e', 1)])),
        ];
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(0)
            .with_collection(Collection::Email)
            .with_document(0);

        for (key, value) in &kvs {
            batch.set(ValueClass::Config(key.as_bytes().to_vec()), value.clone());
        }
        db.write(batch.build_all()).await.unwrap();

        // Iterate over all keys
        let mut results = Vec::new();
        db.iterate(
            store::IterateParams::new(
                ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Config(b"".to_vec()),
                },
                ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Config(b"\xFF".to_vec()),
                },
            ),
            |key, value| {
                results.push((String::from_utf8(key.to_vec()).unwrap(), value.to_vec()));
                Ok(true)
            },
        )
        .await
        .unwrap();

        assert_eq!(results.len(), kvs.len());

        db.delete_range(
            ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Config(b"".to_vec()),
            },
            ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Config(b"\xFF".to_vec()),
            },
        )
        .await
        .unwrap();

        if std::env::var("SLOW_FDB_TRX").is_ok() {
            println!("Running FoundationDB slow transaction tests...");
            // Create 900000 keys
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(0);
            for n in 0..900000 {
                batch.set(
                    ValueClass::Config(format!("key{n:10}").into_bytes()),
                    format!("value{n:10}").into_bytes(),
                );

                if n % 10000 == 0 {
                    db.write(batch.build_all()).await.unwrap();
                    batch = BatchBuilder::new();
                    batch
                        .with_account_id(0)
                        .with_collection(Collection::Email)
                        .with_document(0);
                }
            }
            db.write(batch.build_all()).await.unwrap();

            println!("Created 900.000 keys...");

            // Iterate over all keys
            let mut n = 0;
            db.iterate(
                store::IterateParams::new(
                    ValueKey {
                        account_id: 0,
                        collection: 0,
                        document_id: 0,
                        class: ValueClass::Config(b"".to_vec()),
                    },
                    ValueKey {
                        account_id: 0,
                        collection: 0,
                        document_id: 0,
                        class: ValueClass::Config(b"\xFF".to_vec()),
                    },
                ),
                |key, value| {
                    assert_eq!(std::str::from_utf8(key).unwrap(), format!("key{n:10}"));
                    assert_eq!(std::str::from_utf8(value).unwrap(), format!("value{n:10}"));
                    n += 1;
                    if n % 10000 == 0 {
                        println!("Iterated over {n} keys");
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                    Ok(true)
                },
            )
            .await
            .unwrap();

            // Delete 100 keys
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(0);
            for n in 0..900000 {
                batch.clear(ValueClass::Config(format!("key{n:10}").into_bytes()));

                if n % 10000 == 0 {
                    db.write(batch.build_all()).await.unwrap();
                    batch = BatchBuilder::new();
                    batch
                        .with_account_id(0)
                        .with_collection(Collection::Email)
                        .with_document(0);
                }
            }
            db.write(batch.build_all()).await.unwrap();
        }
    }

    // Merge values 1000 times concurrently
    let mut handles = Vec::new();
    println!("Merge values 1000 times concurrently...");
    for _ in 0..1000 {
        handles.push({
            let db = db.clone();
            tokio::spawn(async move {
                for _ in 0..5 {
                    let mut builder = BatchBuilder::new();
                    builder
                        .with_account_id(0)
                        .with_collection(Collection::Email)
                        .with_document(0)
                        .merge_fnc(
                            ValueClass::Property(3),
                            Params::with_capacity(0),
                            |_, _, bytes| {
                                if let Some(bytes) = bytes {
                                    Ok(MergeResult::Update(
                                        (u64::from_be_bytes(bytes.try_into().unwrap()) + 1)
                                            .to_be_bytes()
                                            .to_vec(),
                                    ))
                                } else {
                                    Ok(MergeResult::Update(0u64.to_be_bytes().to_vec()))
                                }
                            },
                        );

                    match db.write(builder.build_all()).await {
                        Ok(_) => {
                            break;
                        }
                        Err(e) if e.is_assertion_failure() => {
                            // Retry on assertion failures
                            continue;
                        }
                        Err(e) => {
                            panic!("Merge failed: {:?}", e);
                        }
                    }
                }
            })
        });
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(
        999,
        db.get_value::<u64>(ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Property(3),
        })
        .await
        .unwrap()
        .unwrap()
    );

    // Increment a counter 1000 times concurrently
    let mut handles = Vec::new();
    let mut assigned_ids = HashSet::new();
    println!("Incrementing counter 1000 times concurrently...");
    for _ in 0..1000 {
        handles.push({
            let db = db.clone();
            tokio::spawn(async move {
                let mut builder = BatchBuilder::new();
                builder
                    .with_account_id(0)
                    .with_collection(Collection::Email)
                    .with_document(0)
                    .add_and_get(ValueClass::Directory(DirectoryClass::UsedQuota(0)), 1);
                db.write(builder.build_all())
                    .await
                    .unwrap()
                    .last_counter_id()
                    .unwrap()
            })
        });
    }

    for handle in handles {
        let assigned_id = handle.await.unwrap();
        assert!(
            assigned_ids.insert(assigned_id),
            "counter assigned {assigned_id} twice or more times."
        );
    }
    assert_eq!(assigned_ids.len(), 1000);
    assert_eq!(
        db.get_counter(ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Directory(DirectoryClass::UsedQuota(0)),
        })
        .await
        .unwrap(),
        1000
    );

    // Concurrent changelog
    let mut handles = Vec::new();
    let mut assigned_ids = AHashSet::new();
    print!("Incrementing changeId 1000 times concurrently...");
    let time = std::time::Instant::now();
    for document_id in 0..1000 {
        handles.push({
            let db = db.clone();
            tokio::spawn(async move {
                let mut builder = BatchBuilder::new();
                let value = if document_id != 0 {
                    (0..rand::rng().random_range(1..=100))
                        .map(|_| rand::rng().random_range(0..=255))
                        .collect::<Vec<u8>>()
                } else {
                    vec![0u8; 100000]
                };

                let (offset, archived_value) = Archiver::new(value).serialize_versioned().unwrap();

                builder
                    .with_account_id(0)
                    .with_collection(Collection::Email)
                    .with_document(document_id)
                    .set_fnc(
                        ValueClass::Property(5),
                        Params::with_capacity(2)
                            .with_bytes(archived_value)
                            .with_u64(offset),
                        |params, ids| {
                            let change_id = ids.current_change_id()?;
                            let archive = params.bytes(0);
                            let offset = params.u64(1);

                            let mut bytes = Vec::with_capacity(archive.len());
                            bytes.extend_from_slice(&archive[..offset as usize]);
                            bytes.extend_from_slice(&change_id.to_be_bytes()[..]);
                            bytes.push(archive.last().copied().unwrap()); // Marker
                            Ok(bytes)
                        },
                    )
                    .log_container_insert(SyncCollection::Email);
                db.write(builder.build_all())
                    .await
                    .unwrap()
                    .last_change_id(0)
                    .unwrap()
            })
        });
    }
    for handle in handles {
        let assigned_id = handle.await.unwrap();
        assert!(
            assigned_ids.insert(assigned_id),
            "counter assigned {assigned_id} twice or more times: {:?}.",
            assigned_ids
        );
    }
    assert_eq!(assigned_ids.len(), 1000);
    println!(" done in {:?}ms", time.elapsed().as_millis());
    let mut change_ids = AHashSet::new();
    for document_id in 0..1000 {
        let archive = db
            .get_value::<Archive<AlignedBytes>>(ValueKey {
                account_id: 0,
                collection: 0,
                document_id,
                class: ValueClass::Property(5),
            })
            .await
            .unwrap()
            .unwrap();
        change_ids.insert(archive.version.change_id().unwrap());
        archive.unarchive_untrusted::<Vec<u8>>().unwrap();
    }
    assert_eq!(change_ids, assigned_ids);

    println!("Running chunking tests...");
    for (test_num, value) in [
        vec![b'A'; 0],
        vec![b'A'; 1],
        vec![b'A'; 100],
        vec![b'A'; MAX_VALUE_SIZE],
        vec![b'B'; MAX_VALUE_SIZE + 1],
        vec![b'C'; MAX_VALUE_SIZE]
            .into_iter()
            .chain(vec![b'D'; MAX_VALUE_SIZE])
            .chain(vec![b'E'; MAX_VALUE_SIZE])
            .collect::<Vec<_>>(),
        vec![b'F'; MAX_VALUE_SIZE]
            .into_iter()
            .chain(vec![b'G'; MAX_VALUE_SIZE])
            .chain(vec![b'H'; MAX_VALUE_SIZE + 1])
            .collect::<Vec<_>>(),
    ]
    .into_iter()
    .enumerate()
    {
        // Write value
        let test_len = value.len();
        db.write(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(0)
                .set(ValueClass::Property(1), value.as_slice())
                .set(ValueClass::Property(0), "check1".as_bytes())
                .set(ValueClass::Property(2), "check2".as_bytes())
                .build_all(),
        )
        .await
        .unwrap();

        // Fetch value
        assert_eq!(
            String::from_utf8(value).unwrap(),
            db.get_value::<String>(ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Property(1),
            })
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("no value for test {test_num} with value length {test_len}")),
            "failed for test {test_num} with value length {test_len}"
        );

        // Delete value
        db.write(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(0)
                .clear(ValueClass::Property(1))
                .build_all(),
        )
        .await
        .unwrap();

        // Make sure value is deleted
        assert_eq!(
            None,
            db.get_value::<String>(ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Property(1),
            })
            .await
            .unwrap()
        );

        // Make sure other values are still there
        for (class, value) in [
            (ValueClass::Property(0), "check1"),
            (ValueClass::Property(2), "check2"),
        ] {
            assert_eq!(
                Some(value.to_string()),
                db.get_value::<String>(ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class,
                })
                .await
                .unwrap()
            );
        }

        // Delete everything
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(0)
            .with_collection(Collection::Email)
            .with_account_id(0)
            .with_document(0)
            .clear(ValueClass::Property(0))
            .clear(ValueClass::Property(2))
            .clear(ValueClass::Property(3))
            .clear(ValueClass::Directory(DirectoryClass::UsedQuota(0)))
            .clear(ValueClass::ChangeId);

        for document_id in 0..1000 {
            batch
                .with_document(document_id)
                .clear(ValueClass::Property(5));
        }

        db.write(batch.build_all()).await.unwrap();

        // Make sure everything is deleted
        store_assert_is_empty(&db, db.clone().into(), false).await;
    }
}
