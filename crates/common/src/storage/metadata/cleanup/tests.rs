/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ContainerCleanup, MetadataViewerEntry, QuotaRefund, StoredEntry, release_viewer};
use store::write::{
    ArchiveVersion, BatchBuilder, Operation, PendingId, ValueClass, ValueOp,
    assert::AssertValue,
    metadata::{MetadataClass, ViewerState},
};
use types::collection::Collection;

const OWNER: u32 = 3;
const VIEWERS: u32 = 1000;

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Account(u32),
    Collection(Collection),
    Quota(i64),
    TenantQuota(u32, i64),
    Assert(AssertValue),
    Clear(MetadataClass),
}

fn ops(operations: &[Operation]) -> Vec<Op> {
    operations
        .iter()
        .filter_map(|op| match op {
            Operation::AccountId { account_id } => Some(Op::Account(*account_id)),
            Operation::Collection { collection } => Some(Op::Collection(*collection)),
            Operation::AssertValue {
                class: ValueClass::Metadata(MetadataClass::Shared),
                assert_value,
            } => Some(Op::Assert(*assert_value)),
            Operation::Value {
                class: ValueClass::Metadata(class),
                op: ValueOp::Clear,
            } => Some(Op::Clear(*class)),
            Operation::Value {
                class: ValueClass::Quota,
                op: ValueOp::AtomicAdd(delta),
            } => Some(Op::Quota(*delta)),
            Operation::Value {
                class: ValueClass::TenantQuota(tenant_id),
                op: ValueOp::AtomicAdd(delta),
            } => Some(Op::TenantQuota(*tenant_id, *delta)),
            _ => None,
        })
        .collect()
}

fn links(viewer_id: u32) -> [MetadataViewerEntry; 2] {
    [Collection::Email, Collection::Mailbox].map(|collection| MetadataViewerEntry {
        collection,
        viewer_id,
        state: ViewerState::default(),
    })
}

#[test]
fn a_viewer_is_refunded_and_unlinked_on_both_sides() {
    let mut batch = BatchBuilder::new();
    release_viewer(
        &mut batch,
        OWNER,
        &links(9),
        Some(QuotaRefund {
            tenant_id: Some(5),
            bytes: 70,
        }),
    );
    assert_eq!(
        ops(batch.ops()),
        [
            Op::Account(9),
            Op::Quota(-70),
            Op::TenantQuota(5, -70),
            Op::Collection(Collection::Email),
            Op::Clear(MetadataClass::Owner { owner: OWNER }),
            Op::Collection(Collection::Mailbox),
            Op::Clear(MetadataClass::Owner { owner: OWNER }),
            Op::Account(OWNER),
            Op::Collection(Collection::Email),
            Op::Clear(MetadataClass::Viewer { viewer: 9 }),
            Op::Collection(Collection::Mailbox),
            Op::Clear(MetadataClass::Viewer { viewer: 9 }),
        ]
    );

    let mut batch = BatchBuilder::new();
    release_viewer(&mut batch, OWNER, &links(9), None);
    assert!(
        !ops(batch.ops())
            .iter()
            .any(|op| matches!(op, Op::Quota(_) | Op::TenantQuota(..)))
    );
    assert_eq!(
        ops(batch.ops())
            .iter()
            .filter(|op| matches!(op, Op::Clear(_)))
            .count(),
        4
    );
}

#[test]
fn commit_points_never_separate_a_refund_from_its_viewer_keys() {
    let mut batch = BatchBuilder::new();
    for viewer_id in 0..VIEWERS {
        release_viewer(
            &mut batch,
            OWNER,
            &links(viewer_id),
            Some(QuotaRefund {
                tenant_id: None,
                bytes: i64::from(viewer_id) + 1,
            }),
        );
    }

    let mut transactions = 0;
    let mut released = 0;
    let mut points = batch.commit_points();
    for point in points.iter() {
        let mut account_id = None;
        let mut refunded = Vec::new();
        let mut unlinked = Vec::new();
        for op in ops(&batch.ops()[point.offset_start..point.offset_end]) {
            match op {
                Op::Account(id) => account_id = Some(id),
                Op::Quota(_) => refunded.extend(account_id),
                Op::Clear(MetadataClass::Viewer { viewer }) if unlinked.last() != Some(&viewer) => {
                    unlinked.push(viewer);
                }
                _ => {}
            }
        }
        assert_eq!(refunded, unlinked);
        released += refunded.len();
        transactions += 1;
    }
    assert_eq!(released, VIEWERS as usize);
    assert!(transactions > 1, "the batch was expected to split");
}

fn entry(document_id: u32, size: u32) -> StoredEntry {
    StoredEntry {
        document_id,
        size,
        hash: Some(document_id * 1000),
    }
}

fn preloaded(tenant_id: Option<u32>, entries: &[StoredEntry]) -> ContainerCleanup {
    ContainerCleanup {
        collection: Collection::ContactCard,
        tenant_id,
        entries: entries.iter().copied().collect(),
    }
}

fn released(tenant_id: Option<u32>, document_id: u32, size: i64) -> Vec<Op> {
    let mut released = vec![
        Op::Account(OWNER),
        Op::Collection(Collection::ContactCard),
        Op::Assert(AssertValue::Archive(ArchiveVersion::Hashed {
            hash: document_id * 1000,
        })),
        Op::Clear(MetadataClass::Shared),
        Op::Quota(-size),
    ];
    released.extend(tenant_id.map(|tenant_id| Op::TenantQuota(tenant_id, -size)));
    released
}

#[test]
fn preloaded_entries_are_released_per_document() {
    let cleanup = preloaded(Some(9), &[entry(12, 300), entry(4, 40), entry(7, 70)]);
    let mut batch = BatchBuilder::new();
    assert!(cleanup.release(&mut batch, OWNER, 7));
    assert_eq!(ops(batch.ops()), released(Some(9), 7, 70));
    assert_eq!(batch.last_document_id(), Some(PendingId::Assigned(7)));

    let mut batch = BatchBuilder::new();
    assert!(!cleanup.release(&mut batch, OWNER, 5));
    assert!(batch.is_empty());

    let mut batch = BatchBuilder::new();
    assert!(preloaded(None, &[entry(1, 10)]).release(&mut batch, OWNER, 1));
    assert_eq!(ops(batch.ops()), released(None, 1, 10));
}

#[test]
fn flagged_items_missing_from_the_preload_assert_absence() {
    let cleanup = preloaded(Some(6), &[entry(2, 90)]);
    let mut batch = BatchBuilder::new();
    cleanup.release_or_assert_absent(&mut batch, OWNER, 2);
    assert_eq!(ops(batch.ops()), released(Some(6), 2, 90));

    for cleanup in [cleanup, ContainerCleanup::empty(Collection::ContactCard)] {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(OWNER)
            .with_collection(Collection::ContactCard);
        cleanup.release_or_assert_absent(&mut batch, OWNER, 3);
        assert_eq!(
            ops(batch.ops()),
            [
                Op::Account(OWNER),
                Op::Collection(Collection::ContactCard),
                Op::Assert(AssertValue::None),
            ]
        );
        assert_eq!(batch.last_document_id(), Some(PendingId::Assigned(3)));
    }
}
