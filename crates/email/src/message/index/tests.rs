/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::messagedata::MessageData;
use common::{
    MessageUid,
    storage::{index::CurrentObject, metadata::ContainerCleanup},
};
use store::write::{
    BatchBuilder, Operation, ValueClass, ValueOp, assert::AssertValue, metadata::MetadataClass,
};
use types::{collection::Collection, metadata::MetadataKinds};

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Assert(AssertValue),
    ClearContainer,
    ClearArchive,
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
            _ => None,
        })
        .collect()
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

    let mut batch = BatchBuilder::new();
    batch.with_account_id(1).with_collection(Collection::Email);
    ContainerCleanup::empty(Collection::Email).release_or_assert_absent(&mut batch, 1, 2);
    message.clear(&mut batch);
    assert_eq!(
        ops(&batch),
        [
            Op::Assert(AssertValue::None),
            Op::ClearArchive,
            Op::ClearContainer
        ]
    );
}
