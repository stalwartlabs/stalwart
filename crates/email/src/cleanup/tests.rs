/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::FlaggedContainers;
use crate::message::messagedata::MessageData;
use common::{
    MessageUid,
    storage::{index::CurrentObject, metadata::StoredEntry},
};
use store::write::{
    ArchiveVersion, BatchBuilder, Operation, ValueClass, ValueOp, assert::AssertValue,
    metadata::MetadataClass,
};
use types::{collection::Collection, metadata::MetadataKinds};

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Assert(AssertValue),
    ClearContainer,
    ClearArchive,
    Quota(i64),
    TenantQuota(u32, i64),
}

fn ops(batch: &BatchBuilder) -> Vec<Op> {
    batch
        .ops()
        .iter()
        .filter_map(|op| match op {
            Operation::AssertValue {
                class: ValueClass::Metadata(MetadataClass::Shared),
                assert_value,
            } => Some(Op::Assert(*assert_value)),
            Operation::Value {
                class: ValueClass::Metadata(MetadataClass::Shared),
                op: ValueOp::Clear,
            } => Some(Op::ClearContainer),
            Operation::Value {
                class: ValueClass::Property(_),
                op: ValueOp::Clear,
            } => Some(Op::ClearArchive),
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

fn containers() -> FlaggedContainers {
    FlaggedContainers {
        tenant_id: Some(6),
        entries: [StoredEntry {
            document_id: 2,
            size: 90,
            hash: Some(77),
        }]
        .into_iter()
        .collect(),
    }
}

fn email_batch() -> BatchBuilder {
    let mut batch = BatchBuilder::new();
    batch.with_account_id(1).with_collection(Collection::Email);
    batch
}

#[test]
fn preloaded_containers_are_released_with_their_hash() {
    let mut batch = email_batch();
    containers().remove(&mut batch, 2);
    assert_eq!(
        ops(&batch),
        [
            Op::Assert(AssertValue::Archive(ArchiveVersion::Hashed { hash: 77 })),
            Op::ClearContainer,
            Op::Quota(-90),
            Op::TenantQuota(6, -90),
        ]
    );
}

#[test]
fn flagged_items_missing_from_the_preload_assert_absence() {
    let mut batch = email_batch();
    containers().remove(&mut batch, 3);
    assert_eq!(ops(&batch), [Op::Assert(AssertValue::None)]);

    let mut batch = email_batch();
    FlaggedContainers::default().remove(&mut batch, 2);
    assert_eq!(ops(&batch), [Op::Assert(AssertValue::None)]);
}

#[test]
fn the_container_assertion_precedes_the_safety_net_clear() {
    let mut message = MessageData {
        mailboxes: [MessageUid {
            mailbox_id: 3,
            uid: 9,
        }]
        .into_iter()
        .collect(),
        keywords: 0,
        keywords_extra: Vec::new(),
        thread_id: 4,
        size: 1024,
        received_at: 1_700_000_000,
        sent_at: 0,
        change_id: 1,
    };
    message.set_metadata_kinds(MetadataKinds::JMAP);

    let mut batch = email_batch();
    containers().remove(&mut batch, 2);
    message.clear(&mut batch);
    let ops = ops(&batch);
    assert_eq!(
        ops.first(),
        Some(&Op::Assert(AssertValue::Archive(ArchiveVersion::Hashed {
            hash: 77
        })))
    );
    assert_eq!(
        ops.iter().filter(|op| **op == Op::ClearContainer).count(),
        2,
        "the release and the safety net both clear the container"
    );
}
