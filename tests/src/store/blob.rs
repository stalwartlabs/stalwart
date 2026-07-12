/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{cleanup::store_destroy, server::TestServerBuilder};
use ahash::AHashMap;
use email::message::metadata::MessageMetadata;
use registry::{
    schema::{enums::CompressionAlgo, structs::Jmap},
    types::duration::Duration,
};
use services::task_manager::destroy_account::destroy_account_blobs;
use store::{
    BlobStore, Serialize, SerializeInfallible,
    write::{Archiver, BatchBuilder, BlobLink, BlobOp, ValueClass, now},
};
use types::{blob::BlobClass, blob_hash::BlobHash, collection::Collection, field::EmailField};

#[tokio::test]
pub async fn blob_tests() {
    let test = TestServerBuilder::new("blob_tests")
        .await
        .with_object(Jmap {
            upload_quota: 1024,
            upload_ttl: Duration::from_millis(1000),
            ..Default::default()
        })
        .await
        .build()
        .await;

    let store = test.server.core.storage.data.clone();
    let blob_store = test.server.core.storage.blob.clone();

    println!(
        "Testing blob store {} with data store {}...",
        std::env::var("BLOB_STORE").unwrap_or_else(|_| "default".to_string()),
        std::env::var("STORE").unwrap()
    );

    // Test blob quota
    assert!(test.server.blob_has_quota(0, 1024).await.unwrap().allowed);
    assert!(!test.server.blob_has_quota(0, 1024).await.unwrap().allowed);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert!(test.server.blob_has_quota(0, 1024).await.unwrap().allowed);

    // Test and reset store
    test_store(blob_store.clone()).await;
    store_destroy(&store).await;

    // Blob hash exists
    let hash = BlobHash::generate(b"abc".as_slice());
    assert!(!store.blob_exists(&hash).await.unwrap());

    // Reserve blob
    let until = now() + 1;
    store
        .write(
            BatchBuilder::new()
                .with_account_id(0)
                .set(
                    BlobOp::Link {
                        to: BlobLink::Temporary { until },
                        hash: hash.clone(),
                    },
                    1024u32.serialize(),
                )
                .build_all(),
        )
        .await
        .unwrap();

    // Uncommitted blob, should not exist
    assert!(!store.blob_exists(&hash).await.unwrap());

    // Write blob to store
    blob_store
        .put_blob(hash.as_ref(), b"abc", CompressionAlgo::Lz4)
        .await
        .unwrap();

    // Commit blob
    store
        .write(
            BatchBuilder::new()
                .set(BlobOp::Commit { hash: hash.clone() }, Vec::new())
                .build_all(),
        )
        .await
        .unwrap();

    // Blob hash should now exist
    assert!(store.blob_exists(&hash).await.unwrap());
    assert!(
        blob_store
            .get_blob(hash.as_ref(), 0..usize::MAX)
            .await
            .unwrap()
            .is_some()
    );

    // AccountId 0 should be able to read blob
    assert!(
        store
            .blob_has_access(
                &hash,
                BlobClass::Reserved {
                    account_id: 0,
                    expires: until
                }
            )
            .await
            .unwrap()
    );

    // AccountId 1 should not be able to read blob
    assert!(
        !store
            .blob_has_access(
                &hash,
                BlobClass::Reserved {
                    account_id: 1,
                    expires: until
                }
            )
            .await
            .unwrap()
    );

    // Purge expired blobs
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    store
        .purge_blobs_all_shards(blob_store.clone())
        .await
        .unwrap();

    // Blob hash should no longer exist
    assert!(!store.blob_exists(&hash).await.unwrap());

    // AccountId 0 should not be able to read blob
    assert!(
        !store
            .blob_has_access(
                &hash,
                BlobClass::Reserved {
                    account_id: 0,
                    expires: until
                }
            )
            .await
            .unwrap()
    );

    // Blob should no longer be in store
    assert!(
        blob_store
            .get_blob(hash.as_ref(), 0..usize::MAX)
            .await
            .unwrap()
            .is_none()
    );

    // Upload one linked blob to accountId 1, two linked blobs to accountId 0, and three unlinked (reserved) blobs to accountId 2
    let expiry_times = AHashMap::from_iter([
        (b"abc", now() - 10),
        (b"efg", now() + 10),
        (b"hij", now() + 10),
    ]);
    for (document_id, (blob, _)) in [
        (b"123", vec![]),
        (b"456", vec![]),
        (b"789", vec![]),
        (b"abc", 5000u32.serialize()),
        (b"efg", 1000u32.serialize()),
        (b"hij", 2000u32.serialize()),
    ]
    .into_iter()
    .enumerate()
    {
        let hash = BlobHash::generate(blob.as_slice());
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(if document_id > 0 { 0 } else { 1 })
            .with_collection(Collection::Email)
            .with_document(document_id as u32);
        if let Some(until) = expiry_times.get(blob) {
            batch.set(
                BlobOp::Link {
                    hash: hash.clone(),
                    to: BlobLink::Temporary { until: *until },
                },
                vec![],
            );
        } else {
            batch
                .set(
                    BlobOp::Link {
                        hash: hash.clone(),
                        to: BlobLink::Document,
                    },
                    vec![],
                )
                .set(
                    ValueClass::Property(EmailField::Metadata.into()),
                    Archiver::new(MessageMetadata {
                        contents: Default::default(),
                        blob_hash: hash.clone(),
                        blob_body_offset: Default::default(),
                        preview: Default::default(),
                        raw_headers: Default::default(),
                    })
                    .serialize()
                    .unwrap(),
                );
        };
        batch.set(BlobOp::Commit { hash: hash.clone() }, vec![]);

        store.write(batch.build_all()).await.unwrap();
        blob_store
            .put_blob(hash.as_ref(), blob.as_slice(), CompressionAlgo::Lz4)
            .await
            .unwrap();
    }

    // Purge expired blobs and make sure nothing else is deleted
    store
        .purge_blobs_all_shards(blob_store.clone())
        .await
        .unwrap();
    for (pos, (blob, blob_class)) in [
        (
            b"abc",
            BlobClass::Reserved {
                account_id: 0,
                expires: expiry_times[&b"abc"],
            },
        ),
        (
            b"123",
            BlobClass::Linked {
                account_id: 1,
                collection: 0,
                document_id: 0,
            },
        ),
        (
            b"456",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 1,
            },
        ),
        (
            b"789",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 2,
            },
        ),
        (
            b"efg",
            BlobClass::Reserved {
                account_id: 0,
                expires: expiry_times[&b"efg"],
            },
        ),
        (
            b"hij",
            BlobClass::Reserved {
                account_id: 0,
                expires: expiry_times[&b"hij"],
            },
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let hash = BlobHash::generate(blob.as_slice());
        let ct = pos == 0;
        assert!(store.blob_has_access(&hash, blob_class).await.unwrap() ^ ct);
        assert!(store.blob_exists(&hash).await.unwrap() ^ ct);
        assert!(
            blob_store
                .get_blob(hash.as_ref(), 0..usize::MAX)
                .await
                .unwrap()
                .is_some()
                ^ ct
        );
    }

    // AccountId 0 should not have access to accountId 1's blobs
    assert!(
        !store
            .blob_has_access(
                BlobHash::generate(b"123".as_slice()),
                BlobClass::Linked {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                }
            )
            .await
            .unwrap()
    );

    // Unlink blob
    store
        .write(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(2)
                .clear(BlobOp::Link {
                    hash: BlobHash::generate(b"789".as_slice()),
                    to: BlobLink::Document,
                })
                .build_all(),
        )
        .await
        .unwrap();

    // Purge and make sure blob is deleted
    store
        .purge_blobs_all_shards(blob_store.clone())
        .await
        .unwrap();
    for (pos, (blob, blob_class)) in [
        (
            b"789",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 2,
            },
        ),
        (
            b"123",
            BlobClass::Linked {
                account_id: 1,
                collection: 0,
                document_id: 0,
            },
        ),
        (
            b"456",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 1,
            },
        ),
        (
            b"efg",
            BlobClass::Reserved {
                account_id: 0,
                expires: expiry_times[&b"efg"],
            },
        ),
        (
            b"hij",
            BlobClass::Reserved {
                account_id: 0,
                expires: expiry_times[&b"hij"],
            },
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let ct = pos == 0;
        let hash = BlobHash::generate(blob.as_slice());
        assert!(store.blob_has_access(&hash, blob_class).await.unwrap() ^ ct);
        assert!(store.blob_exists(&hash).await.unwrap() ^ ct);
        assert!(
            blob_store
                .get_blob(hash.as_ref(), 0..usize::MAX)
                .await
                .unwrap()
                .is_some()
                ^ ct
        );
    }

    // Unlink all blobs from accountId 1 and purge
    destroy_account_blobs(&test.server, 1).await.unwrap();
    store
        .purge_blobs_all_shards(blob_store.clone())
        .await
        .unwrap();

    // Make sure only accountId 0's blobs are left
    for (pos, (blob, blob_class)) in [
        (
            b"123",
            BlobClass::Linked {
                account_id: 1,
                collection: 0,
                document_id: 0,
            },
        ),
        (
            b"456",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 1,
            },
        ),
        (
            b"efg",
            BlobClass::Reserved {
                account_id: 0,
                expires: expiry_times[&b"efg"],
            },
        ),
        (
            b"hij",
            BlobClass::Reserved {
                account_id: 0,
                expires: expiry_times[&b"hij"],
            },
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let ct = pos == 0;
        let hash = BlobHash::generate(blob.as_slice());
        assert!(store.blob_has_access(&hash, blob_class).await.unwrap() ^ ct);
        assert!(store.blob_exists(&hash).await.unwrap() ^ ct);
        assert!(
            blob_store
                .get_blob(hash.as_ref(), 0..usize::MAX)
                .await
                .unwrap()
                .is_some()
                ^ ct
        );
    }

    test.temp_dir.delete();
}

async fn test_store(store: BlobStore) {
    // Test small blob
    const DATA: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce erat nisl, dignissim a porttitor id, varius nec arcu. Sed mauris.";
    let hash = BlobHash::generate(DATA);

    store
        .put_blob(hash.as_slice(), DATA, CompressionAlgo::Lz4)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(
            store
                .get_blob(hash.as_slice(), 0..usize::MAX)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(DATA).unwrap()
    );
    assert_eq!(
        String::from_utf8(
            store
                .get_blob(hash.as_slice(), 11..57)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&DATA[11..57]).unwrap()
    );
    assert!(store.delete_blob(hash.as_slice()).await.unwrap());
    assert!(
        store
            .get_blob(hash.as_slice(), 0..usize::MAX)
            .await
            .unwrap()
            .is_none()
    );

    // Test large blob
    let mut data = Vec::with_capacity(50 * 1024 * 1024);
    while data.len() < 50 * 1024 * 1024 {
        data.extend_from_slice(DATA);
        let marker = format!(" [{}] ", data.len());
        data.extend_from_slice(marker.as_bytes());
    }
    let hash = BlobHash::generate(&data);
    store
        .put_blob(hash.as_slice(), &data, CompressionAlgo::Lz4)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(
            store
                .get_blob(hash.as_slice(), 0..usize::MAX)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&data).unwrap()
    );

    assert_eq!(
        String::from_utf8(
            store
                .get_blob(hash.as_slice(), 3000111..4000999)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&data[3000111..4000999]).unwrap()
    );
    assert!(store.delete_blob(hash.as_slice()).await.unwrap());
    assert!(
        store
            .get_blob(hash.as_slice(), 0..usize::MAX)
            .await
            .unwrap()
            .is_none()
    );
}
