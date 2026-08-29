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
    rand::{self, RngExt},
    write::{
        Archive, ArchiveBytes, Archiver, BatchBuilder, Compression, Dictionary, MergeResult, Patch,
        PatchSource, ValueClass,
    },
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
    db.write_batch(&mut batch).await.unwrap();

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

const ID_ACCOUNT_BASE: u32 = 0x0400_0000;
const ID_APPEND_ACCOUNT: u32 = ID_ACCOUNT_BASE + 1;
const ID_WIDE_ACCOUNT: u32 = ID_ACCOUNT_BASE + 2;
const ID_DUP_ACCOUNT: u32 = ID_ACCOUNT_BASE + 3;
const ID_GROUP_ACCOUNT: u32 = ID_ACCOUNT_BASE + 4;
const ID_LOG_ACCOUNT: u32 = ID_ACCOUNT_BASE + 5;

fn document_id_counter(account_id: u32, collection: Collection) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: u8::from(collection),
        document_id: 0,
        class: ValueClass::DocumentId,
    }
}

fn uid_counter(account_id: u32, mailbox_id: u32) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: 0,
        document_id: mailbox_id,
        class: ValueClass::MailboxUid,
    }
}

fn change_id_counter(account_id: u32, collection: SyncCollection) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: 0,
        document_id: 0,
        class: ValueClass::ChangeId(collection.change_group()),
    }
}

fn versioned_archive(value: &str) -> (u32, Vec<u8>) {
    let (offset, bytes) = Archiver::with_compression(
        value.as_bytes().to_vec(),
        Compression::Zstd(Some(Dictionary::Common)),
    )
    .serialize_versioned()
    .unwrap();
    (offset as u32, bytes)
}

async fn test_id_assignment(db: &store::Store) {
    use store::write::PendingId;

    println!("Running single-transaction id assignment tests...");

    // 1000 concurrent batches, each reserving one document id, must agree on 1..=1000.
    // Every one of them contends for the same counter, so the run is full of retries: if a
    // retried attempt kept the ids of the attempt it replaced the counter would overshoot.
    const CONCURRENT_CREATES: u32 = 1000;
    let mut handles = Vec::new();
    for _ in 0..CONCURRENT_CREATES {
        let db = db.clone();
        handles.push(tokio::spawn(async move {
            let mut batch = BatchBuilder::new();
            let slot = batch.reserve_document_id(ID_ACCOUNT_BASE, Collection::Email);
            batch
                .with_account_id(ID_ACCOUNT_BASE)
                .with_collection(Collection::Email)
                .create_document(slot)
                .set(ValueClass::Property(1), b"created".to_vec());
            db.write_batch(&mut batch).await.unwrap().slot(slot)
        }));
    }

    let mut created = HashSet::new();
    for handle in handles {
        let document_id = handle.await.unwrap();
        assert!(
            created.insert(document_id),
            "document id {document_id} was assigned twice"
        );
    }
    assert_eq!(created.len(), CONCURRENT_CREATES as usize);
    assert_eq!(
        created.iter().copied().min().unwrap(),
        1,
        "document ids must start at 1"
    );
    assert_eq!(
        created.iter().copied().max().unwrap(),
        CONCURRENT_CREATES,
        "document ids are not contiguous, an attempt burned an id"
    );
    assert_eq!(
        db.get_counter(document_id_counter(ID_ACCOUNT_BASE, Collection::Email))
            .await
            .unwrap(),
        CONCURRENT_CREATES as i64,
        "a retried attempt kept its ids, the counter overshot"
    );

    // A batch that fails its assertion must advance no counter at all
    const ASSERT_MAILBOX: u32 = 3;
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(ID_ACCOUNT_BASE)
        .with_collection(Collection::Email)
        .with_document(0)
        .set(ValueClass::Property(2), b"present".to_vec())
        .log_container_insert(SyncCollection::Email);
    db.write_batch(&mut batch).await.unwrap();

    let documents_before = db
        .get_counter(document_id_counter(ID_ACCOUNT_BASE, Collection::Email))
        .await
        .unwrap();
    let uids_before = db
        .get_counter(uid_counter(ID_ACCOUNT_BASE, ASSERT_MAILBOX))
        .await
        .unwrap();
    let changes_before = db
        .get_counter(change_id_counter(ID_ACCOUNT_BASE, SyncCollection::Email))
        .await
        .unwrap();

    let mut batch = BatchBuilder::new();
    let doc_slot = batch.reserve_document_id(ID_ACCOUNT_BASE, Collection::Email);
    let uid_slot = batch.reserve_uid(ID_ACCOUNT_BASE, ASSERT_MAILBOX);
    batch
        .with_account_id(ID_ACCOUNT_BASE)
        .with_collection(Collection::Email)
        .create_document(doc_slot)
        .set(
            ValueClass::Property(3),
            (
                vec![0u8; 4],
                vec![Patch {
                    offset: 0,
                    source: PatchSource::SlotBeU32(uid_slot),
                }],
            ),
        )
        .log_item_insert(
            SyncCollection::Email,
            Some(PendingId::Assigned(ASSERT_MAILBOX)),
        )
        .with_document(0)
        .assert_value(ValueClass::Property(2), ());
    let err = db.write_batch(&mut batch).await.unwrap_err();
    assert!(
        err.is_assertion_failure(),
        "expected an assertion failure, got {err:?}"
    );

    assert_eq!(
        db.get_counter(document_id_counter(ID_ACCOUNT_BASE, Collection::Email))
            .await
            .unwrap(),
        documents_before,
        "a failed assertion advanced the document id counter"
    );
    assert_eq!(
        db.get_counter(uid_counter(ID_ACCOUNT_BASE, ASSERT_MAILBOX))
            .await
            .unwrap(),
        uids_before,
        "a failed assertion advanced the uid counter"
    );
    assert_eq!(
        db.get_counter(change_id_counter(ID_ACCOUNT_BASE, SyncCollection::Email))
            .await
            .unwrap(),
        changes_before,
        "a failed assertion advanced the change id counter"
    );
    assert_eq!(
        db.get_value::<store::write::serialize::RawValue>(ValueKey {
            account_id: ID_ACCOUNT_BASE,
            collection: u8::from(Collection::Email),
            document_id: documents_before as u32 + 1,
            class: ValueClass::Property(3),
        })
        .await
        .unwrap()
        .map(|v| v.0),
        None,
        "a failed assertion still wrote the document"
    );

    // The id the failed batch would have taken must go to the next writer
    let mut batch = BatchBuilder::new();
    let slot = batch.reserve_document_id(ID_ACCOUNT_BASE, Collection::Email);
    batch
        .with_account_id(ID_ACCOUNT_BASE)
        .with_collection(Collection::Email)
        .create_document(slot)
        .set(ValueClass::Property(1), b"after".to_vec());
    assert_eq!(
        db.write_batch(&mut batch).await.unwrap().slot(slot),
        documents_before as u32 + 1,
        "the failed batch burned an id"
    );

    // Concurrent appends to one mailbox: uid order must not invert against change id order
    // (RFC 9051 section 2.3.1.1)
    const APPEND_MAILBOX: u32 = 9;
    const CONCURRENT_APPENDS: u32 = 250;
    let mut handles = Vec::new();
    for _ in 0..CONCURRENT_APPENDS {
        let db = db.clone();
        handles.push(tokio::spawn(async move {
            let mut batch = BatchBuilder::new();
            let uid_slot = batch.reserve_uid(ID_APPEND_ACCOUNT, APPEND_MAILBOX);
            let doc_slot = batch.reserve_document_id(ID_APPEND_ACCOUNT, Collection::Email);
            batch
                .with_account_id(ID_APPEND_ACCOUNT)
                .with_collection(Collection::Email)
                .create_document(doc_slot)
                .set(
                    ValueClass::Property(1),
                    (
                        vec![0u8; 4],
                        vec![Patch {
                            offset: 0,
                            source: PatchSource::SlotBeU32(uid_slot),
                        }],
                    ),
                )
                .log_item_insert(
                    SyncCollection::Email,
                    Some(PendingId::Assigned(APPEND_MAILBOX)),
                );
            let ids = db.write_batch(&mut batch).await.unwrap();
            (
                ids.last_change_id(ID_APPEND_ACCOUNT, SyncCollection::Email.change_group()),
                ids.slot(uid_slot),
                ids.slot(doc_slot),
            )
        }));
    }

    let mut appended = Vec::new();
    for handle in handles {
        appended.push(handle.await.unwrap());
    }
    appended.sort_unstable();

    let mut prev_change_id = 0u64;
    let mut prev_uid = 0u32;
    for (change_id, uid, _) in &appended {
        assert!(
            *change_id > prev_change_id,
            "change id {change_id} was handed out twice"
        );
        assert_eq!(
            *uid,
            prev_uid + 1,
            "uid {uid} is out of order at change id {change_id}"
        );
        prev_change_id = *change_id;
        prev_uid = *uid;
    }
    assert_eq!(appended.len(), CONCURRENT_APPENDS as usize);
    assert_eq!(
        db.get_counter(uid_counter(ID_APPEND_ACCOUNT, APPEND_MAILBOX))
            .await
            .unwrap(),
        CONCURRENT_APPENDS as i64,
        "a retried append burned a uid"
    );

    // The stamped uid must match the one handed back to the caller
    for (_, uid, document_id) in &appended {
        let stored = db
            .get_value::<store::write::serialize::RawValue>(ValueKey {
                account_id: ID_APPEND_ACCOUNT,
                collection: u8::from(Collection::Email),
                document_id: *document_id,
                class: ValueClass::Property(1),
            })
            .await
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(
            u32::from_be_bytes(stored.try_into().unwrap()),
            *uid,
            "document {document_id} was stamped with a different uid"
        );
    }

    // A reservation set larger than MAX_CONCURRENT_ALLOCATIONS, to exercise chunked allocation
    const WIDE_MAILBOXES: u32 = 40;
    let wide_collections = [
        Collection::Email,
        Collection::Mailbox,
        Collection::Calendar,
        Collection::ContactCard,
    ];
    for round in 1..=3u32 {
        let mut batch = BatchBuilder::new();
        let mut slots = Vec::new();
        for mailbox_id in 0..WIDE_MAILBOXES {
            slots.push(batch.reserve_uid(ID_WIDE_ACCOUNT, mailbox_id));
        }
        for collection in wide_collections {
            slots.push(batch.reserve_document_id(ID_WIDE_ACCOUNT, collection));
        }
        assert!(slots.len() > store::write::MAX_CONCURRENT_ALLOCATIONS);

        batch
            .with_account_id(ID_WIDE_ACCOUNT)
            .with_collection(Collection::Email)
            .with_document(0)
            .set(ValueClass::Property(1), b"wide".to_vec());
        let ids = db.write_batch(&mut batch).await.unwrap();

        for (index, slot) in slots.iter().enumerate() {
            assert_eq!(
                ids.slot(*slot),
                round,
                "slot {index} of {} got the wrong id in round {round}",
                slots.len()
            );
        }
    }

    // Two reservations of the same class in one batch must own separate ranges.
    // This is the JMAP Email/set shape: message 1 into mailboxes A and B, then message 2 into A.
    const DUP_A: u32 = 11;
    const DUP_B: u32 = 12;
    let mut batch = BatchBuilder::new();
    let a1 = batch.reserve_uid(ID_DUP_ACCOUNT, DUP_A);
    let b1 = batch.reserve_uid(ID_DUP_ACCOUNT, DUP_B);
    let a2 = batch.reserve_uid(ID_DUP_ACCOUNT, DUP_A);
    let b2 = batch.reserve_uid(ID_DUP_ACCOUNT, DUP_B);
    let a3 = batch.reserve_uid(ID_DUP_ACCOUNT, DUP_A);
    let email1 = batch.reserve_document_id(ID_DUP_ACCOUNT, Collection::Email);
    let mailbox1 = batch.reserve_document_id(ID_DUP_ACCOUNT, Collection::Mailbox);
    let email2 = batch.reserve_document_id(ID_DUP_ACCOUNT, Collection::Email);
    batch
        .with_account_id(ID_DUP_ACCOUNT)
        .with_collection(Collection::Email)
        .with_document(0)
        .set(ValueClass::Property(1), b"dup".to_vec());
    let ids = db.write_batch(&mut batch).await.unwrap();

    assert_eq!(
        [ids.slot(a1), ids.slot(a2), ids.slot(a3)],
        [1, 2, 3],
        "repeated uid reservations for one mailbox were handed the same range"
    );
    assert_eq!(
        [ids.slot(b1), ids.slot(b2)],
        [1, 2],
        "repeated uid reservations for one mailbox were handed the same range"
    );
    assert_eq!(
        [ids.slot(email1), ids.slot(email2)],
        [1, 2],
        "repeated document id reservations were handed the same range"
    );
    assert_eq!(ids.slot(mailbox1), 1);
    assert_eq!(
        db.get_counter(uid_counter(ID_DUP_ACCOUNT, DUP_A))
            .await
            .unwrap(),
        3,
        "the uid counter fell behind the ids it handed out"
    );
    assert_eq!(
        db.get_counter(uid_counter(ID_DUP_ACCOUNT, DUP_B))
            .await
            .unwrap(),
        2,
        "the uid counter fell behind the ids it handed out"
    );
    assert_eq!(
        db.get_counter(document_id_counter(ID_DUP_ACCOUNT, Collection::Email))
            .await
            .unwrap(),
        2
    );

    // Contiguous reservations of the same class coalesce, and must still be numbered in order
    let mut batch = BatchBuilder::new();
    let run = (0..5)
        .map(|_| batch.reserve_uid(ID_DUP_ACCOUNT, DUP_A))
        .collect::<Vec<_>>();
    batch
        .with_account_id(ID_DUP_ACCOUNT)
        .with_collection(Collection::Email)
        .with_document(0)
        .set(ValueClass::Property(1), b"run".to_vec());
    let ids = db.write_batch(&mut batch).await.unwrap();
    assert_eq!(
        run.iter().map(|slot| ids.slot(*slot)).collect::<Vec<_>>(),
        vec![4, 5, 6, 7, 8],
        "a coalesced reservation was numbered out of order"
    );

    // A batch touching two change groups stamps each archive with its own group's change id
    for _ in 0..3 {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(ID_GROUP_ACCOUNT)
            .with_collection(Collection::Email)
            .with_document(0)
            .log_container_insert(SyncCollection::Email);
        db.write_batch(&mut batch).await.unwrap();
    }

    let (email_offset, email_archive) = versioned_archive("email");
    let (calendar_offset, calendar_archive) = versioned_archive("calendar");
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(ID_GROUP_ACCOUNT)
        .with_collection(Collection::Email)
        .with_document(1)
        .set(
            ValueClass::Property(6),
            (
                email_archive,
                vec![Patch {
                    offset: email_offset,
                    source: PatchSource::ChangeIdBe,
                }],
            ),
        )
        .log_container_insert(SyncCollection::Email)
        .with_collection(Collection::Calendar)
        .with_document(1)
        .set(
            ValueClass::Property(6),
            (
                calendar_archive,
                vec![Patch {
                    offset: calendar_offset,
                    source: PatchSource::ChangeIdBe,
                }],
            ),
        )
        .log_container_insert(SyncCollection::Calendar);
    let ids = db.write_batch(&mut batch).await.unwrap();

    let email_change_id =
        ids.last_change_id(ID_GROUP_ACCOUNT, SyncCollection::Email.change_group());
    let calendar_change_id =
        ids.last_change_id(ID_GROUP_ACCOUNT, SyncCollection::Calendar.change_group());
    assert_eq!(email_change_id, 4, "the email change group did not advance");
    assert_eq!(
        calendar_change_id, 1,
        "the calendar change group shared the email counter"
    );

    for (collection, want) in [
        (Collection::Email, email_change_id),
        (Collection::Calendar, calendar_change_id),
    ] {
        let stored = db
            .get_value::<Archive<ArchiveBytes>>(ValueKey {
                account_id: ID_GROUP_ACCOUNT,
                collection: u8::from(collection),
                document_id: 1,
                class: ValueClass::Property(6),
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.version.change_id(),
            Some(want),
            "{collection:?} was stamped with another change group's id"
        );
        stored.unarchive_untrusted::<Vec<u8>>().unwrap();
    }

    // A changelog row holding pending ids must resolve to the ids the batch was assigned
    let mut batch = BatchBuilder::new();
    let mailbox_slot = batch.reserve_document_id(ID_LOG_ACCOUNT, Collection::Mailbox);
    let email_slot = batch.reserve_document_id(ID_LOG_ACCOUNT, Collection::Email);
    batch
        .with_account_id(ID_LOG_ACCOUNT)
        .with_collection(Collection::Mailbox)
        .create_document(mailbox_slot)
        .set(ValueClass::Property(1), b"mailbox".to_vec())
        .log_container_insert(SyncCollection::Email)
        .with_collection(Collection::Email)
        .create_document(email_slot)
        .set(ValueClass::Property(1), b"email".to_vec())
        .log_item_insert(SyncCollection::Email, Some(PendingId::Slot(mailbox_slot)));
    let ids = db.write_batch(&mut batch).await.unwrap();
    let mailbox_id = ids.slot(mailbox_slot) as u64;
    let email_id = ids.slot(email_slot) as u64;

    let logged = db
        .changes(
            ID_LOG_ACCOUNT,
            store::write::LogCollection::Sync(SyncCollection::Email),
            store::query::log::Query::All,
        )
        .await
        .unwrap();
    let mut got = logged.changes.clone();
    got.sort_by_key(|change| format!("{change:?}"));
    let mut want = vec![
        store::query::log::Change::InsertContainer(mailbox_id),
        store::query::log::Change::InsertItem((mailbox_id << 32) | email_id),
    ];
    want.sort_by_key(|change| format!("{change:?}"));
    assert_eq!(
        want, got,
        "the changelog kept the pending marker instead of the assigned ids"
    );

    // Cleanup
    for subspace in [
        store::Subspace::Counter,
        store::Subspace::Property,
        store::Subspace::Logs,
    ] {
        db.delete_range(
            store::write::AnyKey {
                subspace,
                key: ID_ACCOUNT_BASE.to_be_bytes().to_vec(),
            },
            store::write::AnyKey {
                subspace,
                key: [
                    (ID_ACCOUNT_BASE + 0xFF).to_be_bytes().as_slice(),
                    &[u8::MAX; 12],
                ]
                .concat(),
            },
        )
        .await
        .unwrap();
    }
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
    test_id_assignment(&db).await;

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
        db.write_batch(&mut batch).await.unwrap();

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
            db.write_batch(
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
                    ),
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
        db.write_batch(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(0)
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id: 100,
                    item_id: 0,
                })),
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
                    db.write_batch(
                        BatchBuilder::new()
                            .with_account_id(0)
                            .with_collection(Collection::Email)
                            .with_document(5000)
                            .add_and_get(ValueClass::Quota, 1),
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
        db.write_batch(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(5000)
                .clear(ValueClass::Quota),
        )
        .await
        .unwrap();

        // Overwriting a chunked value with a shorter one must not leave orphaned chunks behind
        println!("Running FoundationDB orphaned chunk test...");
        const ORPHAN_FIELD: u8 = 200;
        const CHUNKED_ACCOUNT: u32 = 0x7FFF_FF00;
        let chunked_field = u8::from(types::field::Field::ARCHIVE);
        let orphan_range = |document_id: u32| ValueKey {
            account_id: CHUNKED_ACCOUNT,
            collection: 0,
            document_id,
            class: ValueClass::Property(chunked_field),
        };
        let marker = value_gen([(b'z', 16)]);
        db.write_batch(
            BatchBuilder::new()
                .with_account_id(CHUNKED_ACCOUNT)
                .with_collection(Collection::Email)
                .with_document(1)
                .set(ValueClass::Property(chunked_field), marker.clone()),
        )
        .await
        .unwrap();

        for (byte, size) in [
            (b'a', MAX_VALUE_SIZE * 3),
            (b'b', MAX_VALUE_SIZE * 2),
            (b'c', MAX_VALUE_SIZE / 2),
            (b'd', MAX_VALUE_SIZE * 3 / 2),
            (b'e', MAX_VALUE_SIZE),
            (b'f', 1),
            (b'g', MAX_VALUE_SIZE * 4),
            (b'h', 0),
        ] {
            let value = value_gen([(byte, size)]);
            db.write_batch(
                BatchBuilder::new()
                    .with_account_id(CHUNKED_ACCOUNT)
                    .with_collection(Collection::Email)
                    .with_document(0)
                    .set(ValueClass::Property(chunked_field), value.clone()),
            )
            .await
            .unwrap();

            let mut results = Vec::new();
            db.iterate(
                store::IterateParams::new(orphan_range(0), orphan_range(u32::MAX)),
                |key, value| {
                    results.push((key.to_vec(), value.to_vec()));
                    Ok(true)
                },
            )
            .await
            .unwrap();

            assert_eq!(
                results.len(),
                2,
                "orphaned chunks surfaced as extra rows after writing {size} bytes"
            );
            assert_eq!(
                results[0].1.len(),
                value.len(),
                "stale chunk spliced onto the value after writing {size} bytes"
            );
            assert_eq!(results[0].1, value, "value mismatch for {size} bytes");
            assert_eq!(
                results[1].1, marker,
                "neighbouring document corrupted after writing {size} bytes"
            );
            assert_eq!(
                results[0].0.len(),
                results[1].0.len(),
                "chunk key returned as a document key after writing {size} bytes"
            );
        }

        // A short key sharing a subspace with longer structured keys must never clear them,
        // as the database schema version does in the property subspace
        println!("Running FoundationDB short key test...");
        for document_id in [0u32, 1, 0xFFFF, 0x10000] {
            db.write_batch(
                BatchBuilder::new()
                    .with_account_id(document_id)
                    .with_collection(Collection::Email)
                    .with_document(document_id)
                    .set(ValueClass::Property(ORPHAN_FIELD), marker.clone()),
            )
            .await
            .unwrap();
        }

        db.write_batch(BatchBuilder::new().set(
            ValueClass::Any(store::write::AnyClass {
                subspace: store::Subspace::Property,
                key: vec![0u8],
            }),
            vec![1u8],
        ))
        .await
        .unwrap();

        for document_id in [0u32, 1, 0xFFFF, 0x10000] {
            let key = ValueKey {
                account_id: document_id,
                collection: 0,
                document_id,
                class: ValueClass::Property(ORPHAN_FIELD),
            };
            let mut found = Vec::new();
            db.iterate(
                store::IterateParams::new(key.clone(), key.clone()),
                |_, value| {
                    found.push(value.to_vec());
                    Ok(true)
                },
            )
            .await
            .unwrap();

            assert_eq!(
                found,
                vec![marker.clone()],
                "property key for account {document_id} was cleared by a shorter key"
            );

            db.write_batch(
                BatchBuilder::new()
                    .with_account_id(document_id)
                    .with_collection(Collection::Email)
                    .with_document(document_id)
                    .clear(ValueClass::Property(ORPHAN_FIELD)),
            )
            .await
            .unwrap();
        }

        db.write_batch(
            BatchBuilder::new().clear(ValueClass::Any(store::write::AnyClass {
                subspace: store::Subspace::Property,
                key: vec![0u8],
            })),
        )
        .await
        .unwrap();

        db.delete_range(orphan_range(0), orphan_range(u32::MAX))
            .await
            .unwrap();

        // Variable-length keys must never be chunk-cleared: a lookup key one byte longer than
        // another is a distinct key, not a chunk of it
        println!("Running FoundationDB in-memory sibling key test...");
        use store::write::InMemoryClass;
        let in_memory_key = |key: &[u8]| {
            ValueClass::InMemory(InMemoryClass::Key(
                [b"sibling".as_slice(), key].concat().to_vec(),
            ))
        };
        db.write_batch(
            BatchBuilder::new()
                .set(in_memory_key(b""), value_gen([(b'p', 64)]))
                .set(in_memory_key(b"x"), marker.clone()),
        )
        .await
        .unwrap();

        for op in 0..2 {
            let mut batch = BatchBuilder::new();
            if op == 0 {
                batch.set(in_memory_key(b""), value_gen([(b'q', 8)]));
            } else {
                batch.clear(in_memory_key(b""));
            }
            db.write_batch(&mut batch).await.unwrap();

            assert_eq!(
                db.get_value::<store::write::serialize::RawValue>(ValueKey::from(in_memory_key(
                    b"x"
                )))
                .await
                .unwrap()
                .map(|v| v.0),
                Some(marker.clone()),
                "sibling lookup key was destroyed by a chunk range clear"
            );
        }

        db.write_batch(BatchBuilder::new().clear(in_memory_key(b"x")))
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
                    db.write_batch(&mut batch).await.unwrap();
                    batch = BatchBuilder::new();
                    batch
                        .with_account_id(0)
                        .with_collection(Collection::Email)
                        .with_document(0);
                }
            }
            db.write_batch(&mut batch).await.unwrap();

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
                    db.write_batch(&mut batch).await.unwrap();
                    batch = BatchBuilder::new();
                    batch
                        .with_account_id(0)
                        .with_collection(Collection::Email)
                        .with_document(0);
                }
            }
            db.write_batch(&mut batch).await.unwrap();
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
                        .merge_fnc(ValueClass::Property(3), |_, bytes| {
                            if let Some(bytes) = bytes {
                                Ok(MergeResult::Update(
                                    (u64::from_be_bytes(bytes.try_into().unwrap()) + 1)
                                        .to_be_bytes()
                                        .to_vec(),
                                ))
                            } else {
                                Ok(MergeResult::Update(0u64.to_be_bytes().to_vec()))
                            }
                        });

                    match db.write_batch(&mut builder).await {
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
                db.write_batch(&mut builder)
                    .await
                    .unwrap()
                    .last_counter_id()
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

                let (offset, archived_value) =
                    Archiver::with_compression(value, Compression::Zstd(Some(Dictionary::Common)))
                        .serialize_versioned()
                        .unwrap();

                builder
                    .with_account_id(0)
                    .with_collection(Collection::Email)
                    .with_document(document_id)
                    .set(
                        ValueClass::Property(5),
                        (
                            archived_value,
                            vec![Patch {
                                offset: offset as u32,
                                source: PatchSource::ChangeIdBe,
                            }],
                        ),
                    )
                    .log_container_insert(SyncCollection::Email);
                db.write_batch(&mut builder)
                    .await
                    .unwrap()
                    .last_change_id(0, SyncCollection::Email.change_group())
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
            .get_value::<Archive<ArchiveBytes>>(ValueKey {
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
    const CHUNK_FIELD: u8 = 50;
    debug_assert_eq!(CHUNK_FIELD, u8::from(types::field::Field::ARCHIVE));
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
        db.write_batch(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(0)
                .set(ValueClass::Property(CHUNK_FIELD), value.as_slice())
                .set(ValueClass::Property(0), "check1".as_bytes())
                .set(ValueClass::Property(2), "check2".as_bytes()),
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
                class: ValueClass::Property(CHUNK_FIELD),
            })
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("no value for test {test_num} with value length {test_len}")),
            "failed for test {test_num} with value length {test_len}"
        );

        // Delete value
        db.write_batch(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(Collection::Email)
                .with_document(0)
                .clear(ValueClass::Property(CHUNK_FIELD)),
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
                class: ValueClass::Property(CHUNK_FIELD),
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
            .clear(ValueClass::ChangeId(SyncCollection::Email.change_group()));

        for document_id in 0..1000 {
            batch
                .with_document(document_id)
                .clear(ValueClass::Property(5));
        }

        db.write_batch(&mut batch).await.unwrap();

        // Make sure everything is deleted
        store_assert_is_empty(&db, db.clone().into(), false).await;
    }
}
