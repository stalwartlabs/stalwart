/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use std::borrow::Cow;
use store::{
    Deserialize, IterateParams, SerializeInfallible, Store, U32_LEN, ValueKey,
    dispatch::{DocumentSet, ScanShape},
    query::log::{Change, PartialChange, Query},
    roaring::RoaringBitmap,
    write::{
        ArchiveVersion, BatchBuilder, LogCollection, MergeResult, PendingId, ValueClass,
        assert::AssertValue,
        metadata::{MetadataBuf, MetadataClass, StoredMetadata, ViewerState},
    },
};
use types::{
    collection::{Collection, SyncCollection},
    field::Field,
    metadata::MetadataBuilder,
};

const OWNER: u32 = 0x0100_00FF;
const NEIGHBOUR: u32 = OWNER + 1;
const VIEWER_A: u32 = 0x0200_0005;
const VIEWER_B: u32 = VIEWER_A + 1;
const OWNERS: [u32; 2] = [OWNER, NEIGHBOUR];
const VIEWERS: [u32; 2] = [VIEWER_A, VIEWER_B];
const COLLECTIONS: [Collection; 3] = [Collection::Email, Collection::Mailbox, Collection::FileNode];
const SHARED_DOCUMENTS: [u32; 5] = [0, 1, 255, 256, u32::MAX - 1];
const PRIVATE_DOCUMENTS: [u32; 2] = [1, 256];
const THREAD: u32 = 9;
const CHUNKED_LEN: usize = 250_000;

pub async fn test(test: &TestServer) {
    let db = test.server.store().clone();

    println!("Running metadata key range tests...");
    key_ranges(&db).await;
    println!("Running metadata assertion tests...");
    assertions(&db).await;
    println!("Running metadata viewer state tests...");
    viewer_states(&db).await;
    println!("Running metadata private log tests...");
    private_logs(test, &db).await;
    println!("Running metadata large container tests...");
    large_containers(&db).await;
    println!("Running metadata chunked range end tests...");
    chunked_range_ends(test, &db).await;
    println!("Running metadata account destruction tests...");
    destroy_accounts(&db).await;
}

fn key(
    account_id: u32,
    collection: Collection,
    document_id: u32,
    class: MetadataClass,
) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: collection.into(),
        document_id,
        class: ValueClass::Metadata(class),
    }
}

fn first(account_id: u32, class: MetadataClass) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: 0,
        document_id: 0,
        class: ValueClass::Metadata(class),
    }
}

fn last(account_id: u32, class: MetadataClass) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: u8::MAX,
        document_id: u32::MAX,
        class: ValueClass::Metadata(class),
    }
}

fn container(value: &[u8]) -> Vec<u8> {
    let mut builder = MetadataBuilder::new();
    builder.set_imap(Cow::Borrowed("/comment"), value);
    StoredMetadata::new(builder.encode().expect("non-empty container"))
        .expect("serializable container")
        .into_bytes()
}

fn label(
    account_id: u32,
    collection: Collection,
    document_id: u32,
    viewer: Option<u32>,
) -> Vec<u8> {
    format!(
        "{account_id}/{}/{document_id}/{viewer:?}",
        u8::from(collection)
    )
    .into_bytes()
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect()
}

fn hashed(stored: &[u8]) -> AssertValue {
    AssertValue::Archive(ArchiveVersion::Hashed {
        hash: StoredMetadata::trailer_hash(stored).expect("container trailer"),
    })
}

fn state(change_id: u64, containers: u32) -> ViewerState {
    ViewerState {
        change_id,
        containers,
    }
}

fn suffix_u32(key: &[u8], offset_from_end: usize) -> u32 {
    let end = key.len() - offset_from_end;
    u32::from_be_bytes(key[end - U32_LEN..end].try_into().expect("four key bytes"))
}

async fn scan(
    db: &Store,
    from: ValueKey<ValueClass>,
    to: ValueKey<ValueClass>,
    ascending: bool,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    db.iterate(
        IterateParams::new(from, to).set_ascending(ascending),
        |key, value| {
            rows.push((key.to_vec(), value.to_vec()));
            Ok(true)
        },
    )
    .await
    .expect("range scan");
    rows
}

async fn read(db: &Store, key: ValueKey<ValueClass>) -> Option<Vec<u8>> {
    db.get_value::<MetadataBuf>(key)
        .await
        .expect("container read")
        .and_then(|container| container.view().imap_entry("/comment").map(<[u8]>::to_vec))
}

async fn commit(db: &Store, batch: &mut BatchBuilder) -> store::write::AssignedIds {
    db.write_batch(batch).await.expect("batch commits")
}

async fn rejected(db: &Store, batch: &mut BatchBuilder, case: &str) {
    match db.write_batch(batch).await {
        Ok(_) => panic!("{case}: the batch was expected to fail its assertion"),
        Err(err) => assert!(
            err.is_assertion_failure(),
            "{case}: expected an assertion failure, got {err:?}"
        ),
    }
}

async fn key_ranges(db: &Store) {
    let mut batch = BatchBuilder::new();
    for account_id in OWNERS {
        batch.with_account_id(account_id);
        for collection in COLLECTIONS {
            batch.with_collection(collection);
            for document_id in SHARED_DOCUMENTS {
                batch.with_document(document_id).set(
                    MetadataClass::Shared,
                    container(&label(account_id, collection, document_id, None)),
                );
            }
            for viewer in VIEWERS {
                for document_id in PRIVATE_DOCUMENTS {
                    batch.with_document(document_id).set(
                        MetadataClass::Private { viewer },
                        container(&label(account_id, collection, document_id, Some(viewer))),
                    );
                }
                batch.set(
                    MetadataClass::Viewer { viewer },
                    state(u64::from(viewer), 2).serialize(),
                );
                batch.set(
                    MetadataClass::Owner { owner: viewer },
                    state(u64::from(account_id), 1).serialize(),
                );
            }
        }
        batch
            .with_collection(Collection::CalendarEventNotification)
            .with_document(0)
            .set(ValueClass::Property(Field::ARCHIVE.into()), vec![1u8; 8])
            .with_collection(Collection::Email)
            .with_document(u32::MAX - 1)
            .set(ValueClass::Property(Field::ARCHIVE.into()), vec![2u8; 8]);
    }
    commit(db, &mut batch).await;

    for account_id in OWNERS {
        for collection in COLLECTIONS {
            let shared = scan(
                db,
                key(account_id, collection, 0, MetadataClass::Shared),
                key(account_id, collection, u32::MAX, MetadataClass::Shared),
                true,
            )
            .await;
            assert_eq!(
                shared
                    .iter()
                    .map(|(key, _)| suffix_u32(key, 0))
                    .collect::<Vec<_>>(),
                SHARED_DOCUMENTS,
                "shared containers of {account_id}/{collection:?}"
            );
            for ((_, value), document_id) in shared.iter().zip(SHARED_DOCUMENTS) {
                assert_eq!(
                    MetadataBuf::deserialize(value)
                        .expect("readable container")
                        .view()
                        .imap_entry("/comment"),
                    Some(label(account_id, collection, document_id, None).as_slice())
                );
            }

            let mut reversed = scan(
                db,
                key(account_id, collection, 0, MetadataClass::Shared),
                key(account_id, collection, u32::MAX, MetadataClass::Shared),
                false,
            )
            .await;
            reversed.reverse();
            assert_eq!(reversed, shared, "descending scans return the same rows");

            let mut selected = Vec::new();
            db.iterate_many(
                vec![
                    IterateParams::new(
                        key(account_id, collection, 0, MetadataClass::Shared),
                        key(account_id, collection, 1, MetadataClass::Shared),
                    ),
                    IterateParams::new(
                        key(account_id, collection, 256, MetadataClass::Shared),
                        key(account_id, collection, 256, MetadataClass::Shared),
                    ),
                ],
                |key, _| {
                    selected.push(suffix_u32(key, 0));
                    Ok(true)
                },
            )
            .await
            .expect("multi range scan");
            assert_eq!(selected, [0, 1, 256]);

            for viewer in VIEWERS {
                let class = MetadataClass::Private { viewer };
                let private = scan(
                    db,
                    key(account_id, collection, 0, class),
                    key(account_id, collection, u32::MAX, class),
                    true,
                )
                .await;
                assert_eq!(
                    private
                        .iter()
                        .map(|(key, _)| suffix_u32(key, 0))
                        .collect::<Vec<_>>(),
                    PRIVATE_DOCUMENTS,
                    "private containers of {account_id}/{collection:?}/{viewer}"
                );
                for document_id in PRIVATE_DOCUMENTS {
                    assert_eq!(
                        read(db, key(account_id, collection, document_id, class)).await,
                        Some(label(account_id, collection, document_id, Some(viewer)))
                    );
                }
                assert_eq!(
                    db.get_value::<ViewerState>(key(
                        account_id,
                        collection,
                        0,
                        MetadataClass::Viewer { viewer }
                    ))
                    .await
                    .expect("viewer state read"),
                    Some(state(u64::from(viewer), 2))
                );
                assert_eq!(
                    db.get_value::<ViewerState>(key(
                        account_id,
                        collection,
                        0,
                        MetadataClass::Owner { owner: viewer }
                    ))
                    .await
                    .expect("owner state read"),
                    Some(state(u64::from(account_id), 1))
                );
            }
        }

        let all_shared = scan(
            db,
            first(account_id, MetadataClass::Shared),
            last(account_id, MetadataClass::Shared),
            true,
        )
        .await;
        assert_eq!(
            all_shared
                .iter()
                .map(|(key, _)| (key[key.len() - U32_LEN - 1], suffix_u32(key, 0)))
                .collect::<Vec<_>>(),
            COLLECTIONS
                .iter()
                .flat_map(|collection| SHARED_DOCUMENTS
                    .iter()
                    .map(|document_id| (u8::from(*collection), *document_id)))
                .collect::<Vec<_>>(),
            "all shared containers of {account_id}"
        );

        let all_private = scan(
            db,
            first(account_id, MetadataClass::Private { viewer: 0 }),
            last(account_id, MetadataClass::Private { viewer: u32::MAX }),
            true,
        )
        .await;
        assert_eq!(
            all_private
                .iter()
                .map(|(key, _)| (
                    suffix_u32(key, U32_LEN + 1),
                    key[key.len() - U32_LEN - 1],
                    suffix_u32(key, 0)
                ))
                .collect::<Vec<_>>(),
            VIEWERS
                .iter()
                .flat_map(|viewer| COLLECTIONS.iter().flat_map(|collection| {
                    PRIVATE_DOCUMENTS
                        .iter()
                        .map(|document_id| (*viewer, u8::from(*collection), *document_id))
                }))
                .collect::<Vec<_>>(),
            "all private containers of {account_id}"
        );

        let viewers = scan(
            db,
            first(account_id, MetadataClass::Viewer { viewer: 0 }),
            last(account_id, MetadataClass::Viewer { viewer: u32::MAX }),
            true,
        )
        .await;
        assert_eq!(
            viewers
                .iter()
                .map(|(key, _)| (key[key.len() - U32_LEN - 1], suffix_u32(key, 0)))
                .collect::<Vec<_>>(),
            COLLECTIONS
                .iter()
                .flat_map(|collection| VIEWERS
                    .iter()
                    .map(|viewer| (u8::from(*collection), *viewer)))
                .collect::<Vec<_>>(),
            "viewer keys of {account_id}"
        );

        let owners = scan(
            db,
            first(account_id, MetadataClass::Owner { owner: 0 }),
            last(account_id, MetadataClass::Owner { owner: u32::MAX }),
            true,
        )
        .await;
        assert_eq!(
            owners
                .iter()
                .map(|(key, _)| (suffix_u32(key, 1), key[key.len() - 1]))
                .collect::<Vec<_>>(),
            VIEWERS
                .iter()
                .flat_map(|owner| COLLECTIONS
                    .iter()
                    .map(|collection| (*owner, u8::from(*collection))))
                .collect::<Vec<_>>(),
            "owner keys of {account_id}"
        );
    }
}

async fn assertions(db: &Store) {
    let shared = MetadataClass::Shared;
    let target = key(OWNER, Collection::Calendar, 10, shared);
    let one = container(b"one");
    let two = container(b"two");
    let three = container(b"three");
    let zstd = container(&b"compressible ".repeat(400));
    assert!(
        zstd.len() < 1024,
        "the large container is stored compressed"
    );

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(10)
        .assert_value(shared, AssertValue::None)
        .set(shared, one.clone());
    commit(db, &mut batch).await;
    assert_eq!(read(db, target.clone()).await, Some(b"one".to_vec()));

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(10)
        .assert_value(shared, AssertValue::None)
        .set(shared, two.clone());
    rejected(db, &mut batch, "absence asserted on an existing container").await;
    assert_eq!(read(db, target.clone()).await, Some(b"one".to_vec()));

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(10)
        .assert_value(shared, hashed(&one))
        .set(shared, two.clone());
    commit(db, &mut batch).await;

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(10)
        .assert_value(shared, hashed(&one))
        .set(shared, three.clone());
    rejected(db, &mut batch, "stale hash asserted").await;
    assert_eq!(read(db, target.clone()).await, Some(b"two".to_vec()));

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(10)
        .assert_value(shared, hashed(&two))
        .clear(shared)
        .assert_value(shared, AssertValue::None)
        .set(shared, three.clone());
    commit(db, &mut batch).await;
    assert_eq!(read(db, target.clone()).await, Some(b"three".to_vec()));

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(10)
        .clear(shared)
        .assert_value(shared, hashed(&three));
    rejected(db, &mut batch, "hash asserted after the batch's own clear").await;
    assert_eq!(read(db, target.clone()).await, Some(b"three".to_vec()));

    let scratch = key(OWNER, Collection::Calendar, 11, shared);
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(11)
        .assert_value(shared, AssertValue::None)
        .set(shared, one.clone())
        .assert_value(shared, hashed(&one))
        .clear(shared);
    commit(db, &mut batch).await;
    assert_eq!(read(db, scratch.clone()).await, None);

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(11)
        .set(shared, one.clone())
        .assert_value(shared, AssertValue::None);
    rejected(db, &mut batch, "absence asserted after the batch's own set").await;
    assert_eq!(read(db, scratch.clone()).await, None);

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(11)
        .assert_value(shared, AssertValue::None)
        .set(shared, one.clone())
        .set(shared, two.clone());
    commit(db, &mut batch).await;
    assert_eq!(read(db, scratch.clone()).await, Some(b"two".to_vec()));

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(11)
        .assert_value(shared, hashed(&two))
        .clear(shared)
        .set(shared, one.clone())
        .set(shared, three.clone());
    commit(db, &mut batch).await;
    assert_eq!(read(db, scratch.clone()).await, Some(b"three".to_vec()));

    let merged = key(OWNER, Collection::Calendar, 12, shared);
    let inserted = one.clone();
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(12)
        .assert_value(shared, AssertValue::None)
        .merge_fnc(shared, move |_, current| {
            Ok(match current {
                None => MergeResult::Update(inserted.clone()),
                Some(_) => MergeResult::Skip,
            })
        })
        .set(shared, two.clone());
    commit(db, &mut batch).await;
    assert_eq!(read(db, merged.clone()).await, Some(b"two".to_vec()));

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(11)
        .assert_value(shared, hashed(&three))
        .set(shared, zstd.clone());
    commit(db, &mut batch).await;
    assert_eq!(
        read(db, scratch.clone()).await,
        Some(b"compressible ".repeat(400))
    );

    let AssertValue::Archive(ArchiveVersion::Hashed { hash }) = hashed(&zstd) else {
        unreachable!()
    };
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(11)
        .assert_value(
            shared,
            AssertValue::Archive(ArchiveVersion::Hashed {
                hash: hash.wrapping_add(1),
            }),
        )
        .clear(shared);
    rejected(
        db,
        &mut batch,
        "wrong hash asserted on a compressed container",
    )
    .await;

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(11)
        .assert_value(shared, hashed(&zstd))
        .clear(shared)
        .clear(shared)
        .with_document(10)
        .assert_value(shared, hashed(&three))
        .clear(shared)
        .clear(shared)
        .with_document(12)
        .assert_value(shared, hashed(&two))
        .clear(shared);
    commit(db, &mut batch).await;
    assert_eq!(read(db, scratch).await, None);
    assert_eq!(read(db, target).await, None);
    assert_eq!(read(db, merged).await, None);

    let private = MetadataClass::Private { viewer: VIEWER_A };
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(10)
        .assert_value(private, AssertValue::None)
        .set(private, one.clone())
        .assert_value(shared, AssertValue::None);
    commit(db, &mut batch).await;

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(10)
        .assert_value(private, AssertValue::None)
        .set(private, two);
    rejected(
        db,
        &mut batch,
        "absence asserted on an existing private container",
    )
    .await;

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Calendar)
        .with_document(10)
        .assert_value(private, hashed(&one))
        .clear(private);
    commit(db, &mut batch).await;
    assert_eq!(
        read(db, key(OWNER, Collection::Calendar, 10, private)).await,
        None
    );
}

fn merge_state(batch: &mut BatchBuilder, class: MetadataClass, owner: u32, containers: i32) {
    batch.merge_fnc(class, move |ids, current| {
        let mut state = current
            .map(ViewerState::deserialize)
            .transpose()?
            .unwrap_or_default();
        if let Some(change_id) = ids.change_id(owner, SyncCollection::Calendar) {
            state.change_id = state.change_id.max(change_id);
        }
        state.containers = state.containers.saturating_add_signed(containers);
        Ok(if state.containers == 0 {
            MergeResult::Delete
        } else {
            MergeResult::Update(state.serialize())
        })
    });
}

async fn viewer_states(db: &Store) {
    let viewer = MetadataClass::Viewer { viewer: VIEWER_A };
    let owner = MetadataClass::Owner { owner: OWNER };
    let viewer_key = key(OWNER, Collection::CalendarEvent, 0, viewer);
    let owner_key = key(VIEWER_A, Collection::CalendarEvent, 0, owner);

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::CalendarEvent)
        .with_document(1)
        .log_private_item_metadata(SyncCollection::Calendar, VIEWER_A, None);
    merge_state(&mut batch, viewer, OWNER, 1);
    batch.with_document(2);
    merge_state(&mut batch, viewer, OWNER, 1);
    batch.with_account_id(VIEWER_A);
    merge_state(&mut batch, owner, OWNER, 1);
    merge_state(&mut batch, owner, OWNER, 1);
    let ids = commit(db, &mut batch).await;
    let change_id = ids
        .change_id(OWNER, SyncCollection::Calendar)
        .expect("a private row allocates a change id");

    for state_key in [viewer_key.clone(), owner_key.clone()] {
        assert_eq!(
            db.get_value::<ViewerState>(state_key)
                .await
                .expect("state read"),
            Some(state(change_id, 2)),
            "two merges of one key in one batch both apply"
        );
    }

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::CalendarEvent)
        .with_document(1);
    merge_state(&mut batch, viewer, OWNER, -1);
    batch.with_account_id(VIEWER_A);
    merge_state(&mut batch, owner, OWNER, -1);
    commit(db, &mut batch).await;
    for state_key in [viewer_key.clone(), owner_key.clone()] {
        assert_eq!(
            db.get_value::<ViewerState>(state_key)
                .await
                .expect("state read"),
            Some(state(change_id, 1)),
            "a commit without a log row keeps the change id"
        );
    }

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::CalendarEvent)
        .with_document(1);
    merge_state(&mut batch, viewer, OWNER, -1);
    merge_state(&mut batch, viewer, OWNER, 3);
    batch.with_account_id(VIEWER_A);
    merge_state(&mut batch, owner, OWNER, -1);
    commit(db, &mut batch).await;
    assert_eq!(
        db.get_value::<ViewerState>(viewer_key)
            .await
            .expect("state read"),
        Some(state(0, 3)),
        "a merge after the batch's own delete starts from an absent value"
    );
    assert_eq!(
        db.get_value::<ViewerState>(owner_key)
            .await
            .expect("state read"),
        None
    );
}

async fn private_logs(test: &TestServer, db: &Store) {
    let log_a = LogCollection::Private {
        collection: SyncCollection::Email,
        viewer: VIEWER_A,
    };
    let log_b = LogCollection::Private {
        collection: SyncCollection::Email,
        viewer: VIEWER_B,
    };
    let shared_log = LogCollection::Sync(SyncCollection::Email);
    let thread = Some(PendingId::Assigned(THREAD));
    let item = |document_id: u32| (u64::from(THREAD) << 32) | u64::from(document_id);

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Email)
        .with_document(3)
        .log_private_item_metadata(SyncCollection::Email, VIEWER_A, thread)
        .with_document(5)
        .log_private_item_metadata(SyncCollection::Email, VIEWER_B, thread)
        .with_document(6)
        .log_item_metadata(SyncCollection::Email, thread)
        .with_document(8)
        .log_item_update(SyncCollection::Email, thread)
        .with_collection(Collection::Mailbox)
        .with_document(4)
        .log_private_container_metadata(SyncCollection::Email, VIEWER_A)
        .with_document(7)
        .log_container_metadata(SyncCollection::Email);
    let ids = commit(db, &mut batch).await;
    let first_id = ids
        .change_id(OWNER, SyncCollection::Email)
        .expect("change id");

    let changes = db
        .changes(OWNER, log_a, Query::All)
        .await
        .expect("private log");
    assert_eq!(
        changes.changes,
        [
            Change::UpdateContainerPartial(4, PartialChange::METADATA),
            Change::UpdateItemMetadata(item(3)),
        ]
    );
    assert_eq!(
        (changes.from_change_id, changes.to_change_id),
        (first_id, first_id)
    );

    let changes = db
        .changes(OWNER, log_b, Query::All)
        .await
        .expect("private log");
    assert_eq!(changes.changes, [Change::UpdateItemMetadata(item(5))]);

    let changes = db
        .changes(OWNER, shared_log, Query::All)
        .await
        .expect("shared log");
    assert_eq!(
        changes.changes,
        [
            Change::UpdateItem(item(8)),
            Change::UpdateContainerPartial(7, PartialChange::METADATA),
            Change::UpdateItemMetadata(item(6)),
        ]
    );
    assert_eq!(
        (changes.from_change_id, changes.to_change_id),
        (first_id, first_id)
    );

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(Collection::Email)
        .with_document(3)
        .log_private_item_metadata(SyncCollection::Email, VIEWER_A, thread);
    let ids = commit(db, &mut batch).await;
    let second_id = ids
        .change_id(OWNER, SyncCollection::Email)
        .expect("a private row allocates a change id");
    assert_eq!(
        second_id,
        first_id + 1,
        "private rows use the owner's counter"
    );

    assert_eq!(
        db.get_last_change_id(OWNER, shared_log)
            .await
            .expect("last id"),
        Some(first_id),
        "a private row never reaches the shared log"
    );
    assert_eq!(
        db.get_last_change_id(OWNER, log_a).await.expect("last id"),
        Some(second_id)
    );
    assert_eq!(
        db.get_last_change_id(OWNER, log_b).await.expect("last id"),
        Some(first_id)
    );
    assert_eq!(
        db.get_last_change_id(NEIGHBOUR, log_a)
            .await
            .expect("last id"),
        None
    );

    let changes = db
        .changes(OWNER, log_a, Query::Since(first_id))
        .await
        .expect("private log");
    assert_eq!(changes.changes, [Change::UpdateItemMetadata(item(3))]);
    assert_eq!(
        (changes.from_change_id, changes.to_change_id),
        (second_id, second_id)
    );

    let changes = db
        .changes(OWNER, log_a, Query::Since(second_id))
        .await
        .expect("private log");
    assert!(changes.changes.is_empty());
    assert_eq!(
        (changes.from_change_id, changes.to_change_id),
        (second_id, second_id)
    );

    assert_eq!(
        test.server
            .truncate_change_log(OWNER, log_a, 1)
            .await
            .expect("private log truncated"),
        Some(first_id)
    );
    let changes = db
        .changes(OWNER, log_a, Query::All)
        .await
        .expect("private log");
    assert!(changes.is_truncated);
    assert!(changes.needs_full_rebuild(first_id - 1));
    let changes = db
        .changes(OWNER, log_a, Query::Since(first_id))
        .await
        .expect("private log");
    assert!(!changes.is_truncated);
    assert_eq!(changes.changes, [Change::UpdateItemMetadata(item(3))]);
    for log in [log_b, shared_log] {
        let changes = db.changes(OWNER, log, Query::All).await.expect("log");
        assert!(
            !changes.is_truncated,
            "{log:?} is truncated with another log"
        );
        assert!(!changes.changes.is_empty());
    }
}

async fn large_containers(db: &Store) {
    let shared = MetadataClass::Shared;
    let collection = Collection::AddressBook;
    let from = key(OWNER, collection, 0, shared);
    let to = key(OWNER, collection, u32::MAX, shared);
    let big = noise(CHUNKED_LEN, 1);
    let bigger = noise(CHUNKED_LEN + 120_000, 2);
    let big_stored = container(&big);
    let bigger_stored = container(&bigger);
    assert!(
        big_stored.len() > CHUNKED_LEN,
        "incompressible containers are stored verbatim"
    );

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(collection)
        .with_document(1)
        .assert_value(shared, AssertValue::None)
        .set(shared, big_stored.clone())
        .with_document(2)
        .assert_value(shared, AssertValue::None)
        .set(shared, bigger_stored.clone())
        .with_document(3)
        .assert_value(shared, AssertValue::None)
        .set(shared, container(b"small"));
    commit(db, &mut batch).await;

    let rows = scan(db, from.clone(), to.clone(), true).await;
    assert_eq!(
        rows.iter()
            .map(|(key, value)| (suffix_u32(key, 0), value.len()))
            .collect::<Vec<_>>(),
        [
            (1, big_stored.len()),
            (2, bigger_stored.len()),
            (3, container(b"small").len())
        ]
    );
    assert_eq!(read(db, key(OWNER, collection, 1, shared)).await, Some(big));
    assert_eq!(
        read(db, key(OWNER, collection, 2, shared)).await,
        Some(bigger)
    );

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OWNER)
        .with_collection(collection)
        .with_document(2)
        .assert_value(shared, hashed(&bigger_stored))
        .set(shared, container(b"shrunk"))
        .with_document(1)
        .assert_value(shared, hashed(&big_stored))
        .clear(shared);
    commit(db, &mut batch).await;

    let rows = scan(db, from, to, true).await;
    assert_eq!(
        rows.iter()
            .map(|(key, value)| (suffix_u32(key, 0), value.len()))
            .collect::<Vec<_>>(),
        [
            (2, container(b"shrunk").len()),
            (3, container(b"small").len())
        ]
    );
    assert_eq!(
        read(db, key(OWNER, collection, 2, shared)).await,
        Some(b"shrunk".to_vec())
    );
    assert_eq!(read(db, key(OWNER, collection, 1, shared)).await, None);
}

async fn chunked_range_ends(test: &TestServer, db: &Store) {
    let collection = Collection::ContactCard;
    let private = MetadataClass::Private { viewer: VIEWER_A };
    let sparse = RoaringBitmap::from_iter([5u32, 900_000]);
    let spread = (0..1_100u32)
        .map(|step| step * 100)
        .collect::<RoaringBitmap>();
    assert_eq!(
        sparse.scan_shape(),
        ScanShape::Ranges(vec![(5, 5), (900_000, 900_000)])
    );
    assert_eq!(spread.scan_shape(), ScanShape::Range(0, 109_900));

    let documents = [5u32, 100, 109_900, 900_000];
    let shared_values = documents
        .iter()
        .map(|document_id| (*document_id, noise(CHUNKED_LEN, u64::from(*document_id))))
        .collect::<Vec<_>>();
    let private_values = documents
        .iter()
        .map(|document_id| {
            (
                *document_id,
                noise(CHUNKED_LEN + 1, u64::from(*document_id) + 1),
            )
        })
        .collect::<Vec<_>>();
    for (class, values) in [
        (MetadataClass::Shared, &shared_values),
        (private, &private_values),
    ] {
        for (document_id, value) in values {
            let stored = container(value);
            assert!(stored.len() > CHUNKED_LEN, "stored verbatim and chunked");
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(OWNER)
                .with_collection(collection)
                .with_document(*document_id)
                .assert_value(class, AssertValue::None)
                .set(class, stored);
            commit(db, &mut batch).await;
        }
    }

    for (set, expected) in [(&sparse, [5u32, 900_000]), (&spread, [100, 109_900])] {
        let mut shared_rows = Vec::new();
        test.server
            .metadata_containers(OWNER, collection, set, |document_id, view, _| {
                shared_rows.push((document_id, view.imap_entry("/comment").map(<[u8]>::to_vec)));
                Ok(true)
            })
            .await
            .expect("shared containers read");
        assert_eq!(
            shared_rows,
            shared_values
                .iter()
                .filter(|(document_id, _)| expected.contains(document_id))
                .map(|(document_id, value)| (*document_id, Some(value.clone())))
                .collect::<Vec<_>>(),
            "shared containers of {expected:?}"
        );

        let mut private_rows = Vec::new();
        test.server
            .private_metadata_containers(
                OWNER,
                VIEWER_A,
                collection,
                set,
                |document_id, view, _| {
                    private_rows
                        .push((document_id, view.imap_entry("/comment").map(<[u8]>::to_vec)));
                    Ok(true)
                },
            )
            .await
            .expect("private containers read");
        assert_eq!(
            private_rows,
            private_values
                .iter()
                .filter(|(document_id, _)| expected.contains(document_id))
                .map(|(document_id, value)| (*document_id, Some(value.clone())))
                .collect::<Vec<_>>(),
            "private containers of {expected:?}"
        );
    }
}

async fn destroy_accounts(db: &Store) {
    for account_id in [OWNER, NEIGHBOUR, VIEWER_A, VIEWER_B] {
        db.danger_destroy_account(account_id)
            .await
            .expect("account destroyed");
    }

    for account_id in [OWNER, NEIGHBOUR, VIEWER_A, VIEWER_B] {
        for (from, to) in [
            (MetadataClass::Shared, MetadataClass::Shared),
            (
                MetadataClass::Private { viewer: 0 },
                MetadataClass::Private { viewer: u32::MAX },
            ),
            (
                MetadataClass::Viewer { viewer: 0 },
                MetadataClass::Viewer { viewer: u32::MAX },
            ),
            (
                MetadataClass::Owner { owner: 0 },
                MetadataClass::Owner { owner: u32::MAX },
            ),
        ] {
            assert!(
                scan(db, first(account_id, from), last(account_id, to), true)
                    .await
                    .is_empty(),
                "metadata keys of {account_id} survive its destruction"
            );
        }
        for viewer in VIEWERS {
            assert_eq!(
                db.get_last_change_id(
                    account_id,
                    LogCollection::Private {
                        collection: SyncCollection::Email,
                        viewer,
                    }
                )
                .await
                .expect("last id"),
                None,
                "private log rows of {account_id} survive its destruction"
            );
        }
    }
}
