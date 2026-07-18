/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{cleanup::store_assert_is_empty, server::TestServer};
use ahash::AHashSet;
use std::collections::HashSet;
use store::{
    ValueKey,
    rand::{self, Rng},
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, MergeResult, Params, ValueClass},
};
use types::collection::Collection;
use types::collection::SyncCollection;

// FDB max value
const MAX_VALUE_SIZE: usize = 100000;

fn registry_item_key(object_id: u16, item_id: u64) -> ValueKey<ValueClass> {
    use store::write::RegistryClass;
    ValueKey {
        account_id: 0,
        collection: 0,
        document_id: 0,
        class: ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
    }
}

fn parse_registry_item_key(key: &[u8]) -> (u16, u64) {
    (
        u16::from_be_bytes(key[0..2].try_into().unwrap()),
        u64::from_be_bytes(key[2..10].try_into().unwrap()),
    )
}

async fn test_iterate_many(db: &store::Store) {
    use store::IterateParams;
    use store::write::RegistryClass;

    println!("Running iterate_many tests...");
    let ranges_spec: &[(u16, u64)] = &[(1010, 4), (1020, 1), (1030, 25), (1050, 3)];
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(0)
        .with_collection(Collection::Email)
        .with_document(0);
    for (object_id, count) in ranges_spec {
        for item_id in 0..*count {
            batch.set(
                ValueClass::Registry(RegistryClass::Item {
                    object_id: *object_id,
                    item_id,
                }),
                format!("value{object_id}-{item_id}").into_bytes(),
            );
        }
    }
    for item_id in 0..130u64 {
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: 1060,
                item_id,
            }),
            format!("point{item_id}").into_bytes(),
        );
    }
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: 1070,
            item_id: 0,
        }),
        vec![b'x'; 250_000],
    );
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: 1070,
            item_id: 1,
        }),
        b"small".to_vec(),
    );
    db.write(batch.build_all()).await.unwrap();

    // Multi-range scan with an empty range in between, per-range order preserved
    let ranges = [1010u16, 1015, 1020, 1030, 1050]
        .iter()
        .map(|object_id| {
            IterateParams::new(
                registry_item_key(*object_id, 0),
                registry_item_key(*object_id, u64::MAX),
            )
        })
        .collect::<Vec<_>>();
    let mut results: Vec<(u16, u64, String)> = Vec::new();
    db.iterate_many(ranges, |key, value| {
        let (object_id, item_id) = parse_registry_item_key(key);
        results.push((
            object_id,
            item_id,
            String::from_utf8(value.to_vec()).unwrap(),
        ));
        Ok(true)
    })
    .await
    .unwrap();

    let mut last_per_range: AHashSet<(u16, u64)> = AHashSet::new();
    let mut last_item: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();
    for (object_id, item_id, _) in &results {
        if let Some(last) = last_item.get(object_id) {
            assert!(
                item_id > last,
                "per-range order violated for object {object_id}: {item_id} after {last}"
            );
        }
        last_item.insert(*object_id, *item_id);
        assert!(
            last_per_range.insert((*object_id, *item_id)),
            "duplicate delivery for ({object_id}, {item_id})"
        );
    }
    let mut sorted_results = results;
    sorted_results.sort();
    let mut expected = Vec::new();
    for (object_id, count) in ranges_spec {
        for item_id in 0..*count {
            expected.push((*object_id, item_id, format!("value{object_id}-{item_id}")));
        }
    }
    assert_eq!(sorted_results, expected);

    // Early abort stops all ranges
    let mut seen = 0;
    db.iterate_many(
        vec![
            IterateParams::new(
                registry_item_key(1010, 0),
                registry_item_key(1010, u64::MAX),
            ),
            IterateParams::new(
                registry_item_key(1030, 0),
                registry_item_key(1030, u64::MAX),
            ),
        ],
        |_, _| {
            seen += 1;
            Ok(seen < 3)
        },
    )
    .await
    .unwrap();
    assert_eq!(seen, 3, "early abort did not stop iteration");

    let mut inverted = 0;
    db.iterate_many(
        vec![IterateParams::new(
            registry_item_key(1030, 10),
            registry_item_key(1030, 0),
        )],
        |_, _| {
            inverted += 1;
            Ok(true)
        },
    )
    .await
    .unwrap();
    assert_eq!(inverted, 0, "inverted range must yield no rows");

    // Point ranges, exceeding the SQL per-statement range limit
    let ranges = (0..130u64)
        .map(|item_id| {
            IterateParams::new(
                registry_item_key(1060, item_id),
                registry_item_key(1060, item_id),
            )
        })
        .collect::<Vec<_>>();
    let mut point_results = Vec::new();
    db.iterate_many(ranges, |key, value| {
        let (object_id, item_id) = parse_registry_item_key(key);
        assert_eq!(object_id, 1060);
        assert_eq!(value, format!("point{item_id}").as_bytes());
        point_results.push(item_id);
        Ok(true)
    })
    .await
    .unwrap();
    point_results.sort_unstable();
    assert_eq!(point_results, (0..130u64).collect::<Vec<_>>());

    // Large values are reassembled inside multi-range scans
    let mut large_results = Vec::new();
    db.iterate_many(
        vec![IterateParams::new(
            registry_item_key(1070, 0),
            registry_item_key(1070, u64::MAX),
        )],
        |key, value| {
            let (_, item_id) = parse_registry_item_key(key);
            large_results.push((item_id, value.to_vec()));
            Ok(true)
        },
    )
    .await
    .unwrap();
    assert_eq!(large_results.len(), 2);
    assert_eq!(large_results[0].0, 0);
    assert_eq!(large_results[0].1, vec![b'x'; 250_000]);
    assert_eq!(large_results[1].0, 1);
    assert_eq!(large_results[1].1, b"small".to_vec());

    db.delete_range(
        registry_item_key(1000, 0),
        registry_item_key(u16::MAX, u64::MAX),
    )
    .await
    .unwrap();
}

#[cfg(feature = "foundationdb")]
fn value_gen(chunks: impl IntoIterator<Item = (u8, usize)>) -> Vec<u8> {
    let mut value = Vec::new();
    for (byte, size) in chunks {
        value.extend(std::iter::repeat_n(byte, size));
    }
    value
}

pub async fn test(test: &TestServer) {
    let db = test.server.store().clone();

    test_iterate_many(&db).await;

    #[cfg(feature = "foundationdb")]
    if matches!(db, store::Store::FoundationDb(_)) {
        use store::write::RegistryClass;
        println!("Running FoundationDB chunked iterator test...");
        let kvs = [
            (1, value_gen([(b'a', 1)])),
            (2, value_gen([(b'b', MAX_VALUE_SIZE), (b'0', 1)])),
            (
                3,
                value_gen([
                    (b'c', MAX_VALUE_SIZE),
                    (b'1', MAX_VALUE_SIZE),
                    (b'2', MAX_VALUE_SIZE),
                ]),
            ),
            (
                4,
                value_gen([(b'd', MAX_VALUE_SIZE), (b'3', MAX_VALUE_SIZE)]),
            ),
            (5, value_gen([(b'e', 1)])),
        ];
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(0)
            .with_collection(Collection::Email)
            .with_document(0);

        for (key, value) in &kvs {
            batch.set(
                ValueClass::Registry(RegistryClass::Item {
                    object_id: *key,
                    item_id: 0,
                }),
                value.clone(),
            );
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
                    class: ValueClass::Registry(RegistryClass::Item {
                        object_id: 0,
                        item_id: 0,
                    }),
                },
                ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Registry(RegistryClass::Item {
                        object_id: u16::MAX,
                        item_id: u64::MAX,
                    }),
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
                class: ValueClass::Registry(RegistryClass::Item {
                    object_id: 0,
                    item_id: 0,
                }),
            },
            ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Registry(RegistryClass::Item {
                    object_id: u16::MAX,
                    item_id: u64::MAX,
                }),
            },
        )
        .await
        .unwrap();

        // Read-your-writes through the cached read version: overwrite a key in a tight loop
        println!("Running FoundationDB read-your-writes test...");
        for n in 0u64..200 {
            db.write(
                BatchBuilder::new()
                    .with_account_id(0)
                    .with_collection(Collection::Email)
                    .with_document(0)
                    .set(
                        ValueClass::Registry(RegistryClass::Item {
                            object_id: 100,
                            item_id: 0,
                        }),
                        n.to_be_bytes().to_vec(),
                    )
                    .build_all(),
            )
            .await
            .unwrap();

            let got = db
                .get_value::<u64>(ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Registry(RegistryClass::Item {
                        object_id: 100,
                        item_id: 0,
                    }),
                })
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, n, "stale read: wrote {n} but read back {got}");
        }
        db.write(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(0)
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id: 100,
                    item_id: 0,
                }))
                .build_all(),
        )
        .await
        .unwrap();

        // Read-version cache monotonicity under concurrency: while a writer increments a counter
        println!("Running FoundationDB read-version monotonicity test...");
        let n_increments = 500u64;

        let writer = {
            let db = db.clone();
            tokio::spawn(async move {
                for _ in 0..n_increments {
                    db.write(
                        BatchBuilder::new()
                            .with_account_id(0)
                            .with_collection(Collection::Email)
                            .with_document(5000)
                            .add_and_get(ValueClass::Quota, 1)
                            .build_all(),
                    )
                    .await
                    .unwrap();
                }
            })
        };

        let mut readers = Vec::new();
        for _ in 0..16 {
            let db = db.clone();
            readers.push(tokio::spawn(async move {
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
                let mut last = 0i64;
                while std::time::Instant::now() < deadline {
                    let current = db
                        .get_counter(ValueKey {
                            account_id: 0,
                            collection: 0,
                            document_id: 5000,
                            class: ValueClass::Quota,
                        })
                        .await
                        .unwrap();
                    assert!(
                        current >= last,
                        "read version regressed: counter went from {last} to {current}"
                    );
                    last = current;
                }
            }));
        }

        writer.await.unwrap();
        for reader in readers {
            reader.await.unwrap();
        }

        assert_eq!(
            db.get_counter(ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 5000,
                class: ValueClass::Quota,
            })
            .await
            .unwrap(),
            n_increments as i64,
            "counter did not reach the expected total"
        );
        db.write(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(5000)
                .clear(ValueClass::Quota)
                .build_all(),
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
                    ValueClass::Registry(RegistryClass::Item {
                        object_id: 0,
                        item_id: n,
                    }),
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
                        class: ValueClass::Registry(RegistryClass::Item {
                            object_id: 0,
                            item_id: 0,
                        }),
                    },
                    ValueKey {
                        account_id: 0,
                        collection: 0,
                        document_id: 0,
                        class: ValueClass::Registry(RegistryClass::Item {
                            object_id: 0,
                            item_id: u64::MAX,
                        }),
                    },
                ),
                |key, value| {
                    let (_, item_id) = parse_registry_item_key(key);
                    assert_eq!(item_id, n);
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
            assert_eq!(n, 900000);

            println!("Running FoundationDB slow iterate_many test...");
            let third = 300000u64;
            let ranges = vec![
                store::IterateParams::new(registry_item_key(0, 0), registry_item_key(0, third - 1)),
                store::IterateParams::new(
                    registry_item_key(0, third),
                    registry_item_key(0, 2 * third - 1),
                ),
                store::IterateParams::new(
                    registry_item_key(0, 2 * third),
                    registry_item_key(0, u64::MAX),
                ),
            ];
            let mut buckets: Vec<HashSet<u64>> = vec![HashSet::new(); 3];
            let mut delivered = 0u64;
            let mut redelivered = 0u64;
            db.iterate_many(ranges, |key, value| {
                let (_, item_id) = parse_registry_item_key(key);
                assert_eq!(
                    std::str::from_utf8(value).unwrap(),
                    format!("value{item_id:10}")
                );
                let bucket = (item_id / third).min(2) as usize;
                if !buckets[bucket].insert(item_id) {
                    redelivered += 1;
                }
                delivered += 1;
                if delivered.is_multiple_of(100000) {
                    println!("Delivered {delivered} rows ({redelivered} redelivered)");
                    std::thread::sleep(std::time::Duration::from_millis(2000));
                }
                Ok(true)
            })
            .await
            .unwrap();
            for (bucket, seen) in buckets.iter().enumerate() {
                assert_eq!(
                    seen.len() as u64,
                    third,
                    "bucket {bucket} is missing rows after retries"
                );
            }
            println!(
                "Slow iterate_many delivered {delivered} rows, {redelivered} redelivered after retries"
            );

            // Delete 100 keys
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(0);
            for n in 0..900000 {
                batch.clear(ValueClass::Registry(RegistryClass::Item {
                    object_id: 0,
                    item_id: n,
                }));

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
                    .add_and_get(ValueClass::Quota, 1);
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
            class: ValueClass::Quota,
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
            .clear(ValueClass::Quota)
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
