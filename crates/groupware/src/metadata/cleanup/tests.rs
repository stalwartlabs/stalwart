/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use store::write::{
    ArchiveVersion, Operation, PendingId, ValueClass, ValueOp, assert::AssertValue,
    metadata::MetadataClass,
};

const ACCOUNT_ID: u32 = 3;

fn entry(document_id: u32, size: u32) -> StoredEntry {
    StoredEntry {
        document_id,
        size,
        hash: Some(document_id * 1000),
    }
}

fn removed(cleanup: &MetadataCleanup, document_id: u32) -> BatchBuilder {
    let CleanupMode::Preloaded(preloaded) = &cleanup.mode else {
        panic!("expected a preloaded cleanup");
    };
    let mut batch = BatchBuilder::new();
    assert_eq!(
        preloaded.release(cleanup.collection, ACCOUNT_ID, document_id, &mut batch),
        !batch.is_empty()
    );
    batch
}

fn quota_deltas(batch: &BatchBuilder) -> Vec<(ValueClass, i64)> {
    batch
        .ops()
        .iter()
        .filter_map(|op| match op {
            Operation::Value {
                class: class @ (ValueClass::Quota | ValueClass::TenantQuota(_)),
                op: ValueOp::AtomicAdd(delta),
            } => Some((class.clone(), *delta)),
            _ => None,
        })
        .collect()
}

fn container_ops(batch: &BatchBuilder) -> Vec<Option<AssertValue>> {
    batch
        .ops()
        .iter()
        .filter_map(|op| match op {
            Operation::AssertValue {
                class: ValueClass::Metadata(MetadataClass::Shared),
                assert_value,
            } => Some(Some(*assert_value)),
            Operation::Value {
                class: ValueClass::Metadata(MetadataClass::Shared),
                op: ValueOp::Clear,
            } => Some(None),
            _ => None,
        })
        .collect()
}

#[test]
fn preloaded_entries_are_released_per_document() {
    let cleanup = MetadataCleanup::preloaded(
        Collection::ContactCard,
        Some(9),
        [entry(12, 300), entry(4, 40), entry(7, 70)]
            .into_iter()
            .collect(),
    );

    let batch = removed(&cleanup, 7);
    assert_eq!(
        quota_deltas(&batch),
        [(ValueClass::Quota, -70), (ValueClass::TenantQuota(9), -70)]
    );
    assert_eq!(batch.last_account_id(), Some(ACCOUNT_ID));
    assert_eq!(batch.last_collection(), Some(Collection::ContactCard));
    assert_eq!(batch.last_document_id(), Some(PendingId::Assigned(7)));
    assert_eq!(
        container_ops(&batch),
        [
            Some(AssertValue::Archive(ArchiveVersion::Hashed { hash: 7000 })),
            None
        ],
        "the clear asserts the preloaded hash first"
    );

    assert!(removed(&cleanup, 5).is_empty());
    let without_tenant = MetadataCleanup::preloaded(
        Collection::FileNode,
        None,
        [entry(1, 10)].into_iter().collect(),
    );
    assert_eq!(
        quota_deltas(&removed(&without_tenant, 1)),
        [(ValueClass::Quota, -10)]
    );
}
