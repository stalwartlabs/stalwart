/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MetadataLog, MetadataPresence, MetadataViewerCache, MetadataWrite, PrivateMetadataChange,
    PrivateMetadataCommit, PrivateMetadataWrite, StoredContainer, ViewerStates, metadata_key,
    next_viewer_state, purge::PrivateKey, viewer::parse_owner_key,
};
use std::{borrow::Cow, sync::Arc};
use store::{
    Key, SerializeInfallible,
    write::{
        ArchiveVersion, BatchBuilder, Operation, PendingId, SetValue, ValueClass, ValueOp,
        assert::AssertValue,
        metadata::{MetadataBuf, MetadataClass, StoredMetadata, ViewerState},
    },
};
use types::{
    collection::Collection,
    metadata::{EncodedMetadata, MetadataBuilder, MetadataKinds},
};

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Account(u32),
    Collection(Collection),
    Document(PendingId),
    Assert(MetadataClass, AssertValue),
    Set(MetadataClass, Vec<u8>),
    Clear(MetadataClass),
    Merge(MetadataClass),
    Quota(i64),
    TenantQuota(u32, i64),
}

fn ops(batch: &BatchBuilder) -> Vec<Op> {
    batch
        .ops()
        .iter()
        .filter_map(|op| match op {
            Operation::AccountId { account_id } => Some(Op::Account(*account_id)),
            Operation::Collection { collection } => Some(Op::Collection(*collection)),
            Operation::DocumentId { document_id } => Some(Op::Document(*document_id)),
            Operation::AssertValue {
                class: ValueClass::Metadata(class),
                assert_value,
            } => Some(Op::Assert(*class, *assert_value)),
            Operation::Value {
                class: ValueClass::Metadata(class),
                op,
            } => match op {
                ValueOp::Set(SetValue::Fixed(bytes)) => Some(Op::Set(*class, bytes.clone())),
                ValueOp::Clear => Some(Op::Clear(*class)),
                ValueOp::MergeFnc(_) => Some(Op::Merge(*class)),
                _ => None,
            },
            Operation::Value {
                class: ValueClass::Quota,
                op: ValueOp::AtomicAdd(value),
            } => Some(Op::Quota(*value)),
            Operation::Value {
                class: ValueClass::TenantQuota(tenant_id),
                op: ValueOp::AtomicAdd(value),
            } => Some(Op::TenantQuota(*tenant_id, *value)),
            _ => None,
        })
        .collect()
}

fn container(value: &str) -> EncodedMetadata {
    let mut builder = MetadataBuilder::new();
    builder.set_imap(Cow::Borrowed("/comment"), value.as_bytes());
    builder.encode().expect("non-empty")
}

fn stored(value: &str) -> (Vec<u8>, StoredContainer) {
    let bytes = StoredMetadata::new(container(value))
        .expect("serializable")
        .into_bytes();
    let previous = StoredContainer::from(&MetadataBuf::read(&bytes).expect("readable"));
    (bytes, previous)
}

fn cursor(batch: &mut BatchBuilder) {
    batch
        .with_account_id(40)
        .with_collection(Collection::Email)
        .with_document(41);
}

fn assert_cursor(batch: &BatchBuilder) {
    assert_eq!(batch.last_account_id(), Some(40));
    assert_eq!(batch.last_collection(), Some(Collection::Email));
    assert_eq!(batch.last_document_id(), Some(PendingId::Assigned(41)));
}

#[test]
fn shared_writes_assert_the_container_they_replace() {
    let (bytes, previous) = stored("previous");
    assert_eq!(previous.size as usize, bytes.len());
    assert_eq!(previous.kinds, MetadataKinds::IMAP);
    assert!(
        StoredContainer::assertion(Some(&previous)).matches(&bytes),
        "the assertion accepts the stored container"
    );
    assert_eq!(
        StoredContainer::assertion(Some(&previous)),
        AssertValue::Archive(ArchiveVersion::Hashed {
            hash: previous.hash
        })
    );

    let next = container("next");
    let next_bytes = StoredMetadata::new(next.clone())
        .expect("serializable")
        .into_bytes();
    let mut batch = BatchBuilder::new();
    cursor(&mut batch);
    let presence = MetadataWrite {
        account_id: 1,
        tenant_id: Some(7),
        collection: Collection::Mailbox,
        previous: Some(previous),
        next: Some(next),
        log: MetadataLog::Container,
    }
    .build(PendingId::Assigned(3), &mut batch)
    .expect("built");
    assert!(!presence.has_changed());

    let delta = next_bytes.len() as i64 - bytes.len() as i64;
    assert_eq!(
        ops(&batch)[3..],
        [
            Op::Account(1),
            Op::Collection(Collection::Mailbox),
            Op::Document(PendingId::Assigned(3)),
            Op::Assert(
                MetadataClass::Shared,
                AssertValue::Archive(ArchiveVersion::Hashed {
                    hash: previous.hash
                })
            ),
            Op::Set(MetadataClass::Shared, next_bytes),
            Op::Quota(delta),
            Op::TenantQuota(7, delta),
            Op::Account(40),
            Op::Collection(Collection::Email),
            Op::Document(PendingId::Assigned(41)),
        ]
    );
    assert_cursor(&batch);

    let mut batch = BatchBuilder::new();
    MetadataWrite {
        account_id: 1,
        tenant_id: None,
        collection: Collection::Email,
        previous: None,
        next: Some(container("new")),
        log: MetadataLog::Item { prefix: None },
    }
    .build(PendingId::Assigned(3), &mut batch)
    .expect("built");
    assert!(ops(&batch).contains(&Op::Assert(MetadataClass::Shared, AssertValue::None)));

    let mut batch = BatchBuilder::new();
    MetadataWrite {
        account_id: 1,
        tenant_id: None,
        collection: Collection::Email,
        previous: Some(previous),
        next: None,
        log: MetadataLog::Item { prefix: None },
    }
    .build(PendingId::Assigned(3), &mut batch)
    .expect("built");
    let written = ops(&batch);
    assert!(written.contains(&Op::Clear(MetadataClass::Shared)));
    assert!(written.contains(&Op::Quota(-(bytes.len() as i64))));
}

#[test]
fn private_writes_merge_both_viewer_keys_and_record_the_commit() {
    let (bytes, previous) = stored("previous");
    let mut commit = PrivateMetadataCommit::default();
    let mut batch = BatchBuilder::new();
    cursor(&mut batch);
    PrivateMetadataWrite {
        owner_id: 1,
        viewer_id: 9,
        viewer_tenant_id: Some(5),
        collection: Collection::Email,
        previous: None,
        next: Some(container("first")),
        log: MetadataLog::Item { prefix: None },
    }
    .build(PendingId::Assigned(3), &mut batch, &mut commit)
    .expect("built");

    let written = ops(&batch);
    let private = MetadataClass::Private { viewer: 9 };
    let assert_at = written
        .iter()
        .position(|op| *op == Op::Assert(private, AssertValue::None))
        .expect("asserted");
    assert!(matches!(written.get(assert_at + 1), Some(Op::Set(class, _)) if *class == private));
    let viewer_at = written
        .iter()
        .position(|op| *op == Op::Merge(MetadataClass::Viewer { viewer: 9 }))
        .expect("viewer key merged");
    let owner_at = written
        .iter()
        .position(|op| *op == Op::Merge(MetadataClass::Owner { owner: 1 }))
        .expect("owner key merged");
    assert!(written[..viewer_at].contains(&Op::Account(1)));
    assert_eq!(written.get(owner_at - 1), Some(&Op::Account(9)));
    assert!(
        written[owner_at..]
            .iter()
            .any(|op| matches!(op, Op::TenantQuota(5, delta) if *delta > 0))
    );
    assert_cursor(&batch);

    PrivateMetadataWrite {
        owner_id: 1,
        viewer_id: 9,
        viewer_tenant_id: Some(5),
        collection: Collection::Email,
        previous: Some(previous),
        next: None,
        log: MetadataLog::Item { prefix: None },
    }
    .build(PendingId::Assigned(4), &mut batch, &mut commit)
    .expect("built");
    assert!(ops(&batch).contains(&Op::Quota(-(bytes.len() as i64))));

    PrivateMetadataWrite {
        owner_id: 1,
        viewer_id: 9,
        viewer_tenant_id: None,
        collection: Collection::Mailbox,
        previous: None,
        next: Some(container("mailbox")),
        log: MetadataLog::Container,
    }
    .build(PendingId::Assigned(2), &mut batch, &mut commit)
    .expect("built");

    assert_eq!(
        commit.changes,
        vec![
            PrivateMetadataChange {
                owner_id: 1,
                viewer_id: 9,
                collection: Collection::Email,
                is_logged: true,
                containers: 0,
            },
            PrivateMetadataChange {
                owner_id: 1,
                viewer_id: 9,
                collection: Collection::Mailbox,
                is_logged: true,
                containers: 1,
            },
        ]
    );
}

#[test]
fn viewer_state_merges_keep_the_newest_change() {
    let state = next_viewer_state(None, Some(10), 1).expect("merged");
    assert_eq!(
        state,
        ViewerState {
            change_id: 10,
            containers: 1
        }
    );
    let current = ViewerState {
        change_id: 20,
        containers: 3,
    }
    .serialize();
    assert_eq!(
        next_viewer_state(Some(&current), Some(12), -1).expect("merged"),
        ViewerState {
            change_id: 20,
            containers: 2
        }
    );
    assert_eq!(
        next_viewer_state(Some(&current), None, -5).expect("merged"),
        ViewerState {
            change_id: 20,
            containers: 0
        }
    );
    assert!(next_viewer_state(Some(&[1, 2, 3]), None, 0).is_err());
}

fn change(owner_id: u32, collection: Collection, containers: i32) -> PrivateMetadataChange {
    PrivateMetadataChange {
        owner_id,
        viewer_id: 9,
        collection,
        is_logged: true,
        containers,
    }
}

#[test]
fn viewer_cache_updates_in_place() {
    let states = ViewerStates::new([
        (
            1,
            u8::from(Collection::Email),
            ViewerState {
                change_id: 10,
                containers: 1,
            },
        ),
        (
            5,
            u8::from(Collection::Calendar),
            ViewerState {
                change_id: 4,
                containers: 0,
            },
        ),
    ]);
    assert_eq!(states.get(1, Collection::Email).change_id, 10);
    assert_eq!(states.get(5, Collection::Calendar).change_id, 4);
    assert_eq!(states.get(5, Collection::Email), ViewerState::default());

    let cache = MetadataViewerCache::new(1 << 20);
    let epoch = cache.epoch(9);
    cache.insert(9, Arc::new(states), epoch);

    cache.apply(&change(1, Collection::Email, 1), Some(12));
    cache.apply(&change(1, Collection::Email, 0), Some(11));
    let current = cache.get(9).expect("cached");
    assert_eq!(
        current.get(1, Collection::Email),
        ViewerState {
            change_id: 12,
            containers: 2
        }
    );

    cache.apply(&change(5, Collection::Calendar, 0), None);
    assert_eq!(current.get(5, Collection::Calendar).change_id, 4);

    cache.apply(&change(2, Collection::Email, 1), Some(13));
    assert!(cache.get(9).is_none(), "an unknown owner forces a reload");
}

#[test]
fn viewer_cache_rejects_loads_that_raced_a_commit() {
    let cache = MetadataViewerCache::new(1 << 20);
    let epoch = cache.epoch(9);
    cache.apply(&change(1, Collection::Email, 1), Some(3));
    cache.insert(9, Arc::new(ViewerStates::default()), epoch);
    assert!(cache.get(9).is_none());

    let epoch = cache.epoch(9);
    cache.insert(9, Arc::new(ViewerStates::default()), epoch);
    assert!(cache.get(9).is_some_and(|states| states.is_empty()));

    cache.invalidate(9);
    assert!(cache.get(9).is_none());
    cache.insert(9, Arc::new(ViewerStates::default()), epoch);
    assert!(cache.get(9).is_none());
}

#[test]
fn viewer_cache_reloads_after_a_removal() {
    let cache = MetadataViewerCache::new(1 << 20);
    let mut stored = ViewerState::default();
    let reload = |cache: &MetadataViewerCache, stored: ViewerState| {
        let epoch = cache.epoch(9);
        let states = ViewerStates::new([(1, u8::from(Collection::Email), stored)]);
        cache.insert(9, Arc::new(states), epoch);
    };
    reload(&cache, stored);

    for cycle in 1..=100u64 {
        for (containers, change_id) in [(1, cycle * 2), (-1, cycle * 2 + 1)] {
            stored = next_viewer_state(Some(&stored.serialize()), Some(change_id), containers)
                .expect("merged");
            cache.apply(&change(1, Collection::Email, containers), Some(change_id));
            match cache.get(9) {
                Some(states) => assert_eq!(states.get(1, Collection::Email), stored),
                None => {
                    assert!(containers < 0, "only a removal drops the entry");
                    reload(&cache, stored);
                }
            }
        }
    }

    assert_eq!(
        cache.get(9).expect("cached").get(1, Collection::Email),
        ViewerState {
            change_id: 201,
            containers: 0
        }
    );
}

#[test]
fn metadata_keys_parse_back() {
    let owner = metadata_key(
        9,
        u8::from(Collection::Calendar),
        0,
        MetadataClass::Owner { owner: 77 },
    );
    for flags in [0, 1] {
        assert_eq!(
            parse_owner_key(&owner.serialize(flags)).expect("parsed"),
            (77, u8::from(Collection::Calendar))
        );
        let private = metadata_key(
            1,
            u8::from(Collection::Email),
            1234,
            MetadataClass::Private { viewer: 42 },
        );
        assert_eq!(
            PrivateKey::parse(&private.serialize(flags)).expect("parsed"),
            PrivateKey {
                collection: u8::from(Collection::Email),
                viewer_id: 42,
                document_id: 1234,
            }
        );
    }
    assert!(parse_owner_key(&[1, 2]).is_err());
    assert!(PrivateKey::parse(&[1, 2, 3]).is_err());
}

#[test]
fn presence_changes_compare_the_tracked_kinds() {
    let none = MetadataKinds::NONE;
    let jmap = MetadataKinds::JMAP;
    let dav = MetadataKinds::DAV;
    let imap = MetadataKinds::IMAP;
    let both = jmap.union(imap);

    for (before, after, tracked, expected) in [
        (jmap, both, both, true),
        (both, jmap, both, true),
        (imap, jmap, both, true),
        (none, imap, both, true),
        (both, none, both, true),
        (both, both, both, false),
        (none, none, both, false),
        (jmap, jmap.union(dav), both, false),
        (jmap, both, jmap, false),
        (both, imap, jmap, true),
        (none, dav, jmap, false),
        (none, jmap, jmap, true),
        (jmap, none, jmap, true),
    ] {
        assert_eq!(
            MetadataPresence { before, after }.has_changed_for(tracked),
            expected,
            "{before:?} -> {after:?} tracking {tracked:?}"
        );
    }
}
