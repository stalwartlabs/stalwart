/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{StoredEntries, StoredEntry};
use std::borrow::Cow;
use store::write::{
    ArchiveVersion, BatchBuilder, Operation, PendingId, ValueClass, ValueOp,
    assert::AssertValue,
    metadata::{MetadataBuf, MetadataClass, StoredMetadata},
};
use types::{collection::Collection, metadata::MetadataBuilder};

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Document(PendingId),
    Assert(MetadataClass, AssertValue),
    Clear(MetadataClass),
    Quota(i64),
    TenantQuota(u32, i64),
}

fn ops(batch: &BatchBuilder) -> Vec<Op> {
    batch
        .ops()
        .iter()
        .filter_map(|op| match op {
            Operation::DocumentId { document_id } => Some(Op::Document(*document_id)),
            Operation::AssertValue {
                class: ValueClass::Metadata(class),
                assert_value,
            } => Some(Op::Assert(*class, *assert_value)),
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

fn stored(repeat: usize) -> Vec<u8> {
    let mut builder = MetadataBuilder::new();
    builder.set_imap(Cow::Borrowed("/comment"), "abc".repeat(repeat).as_bytes());
    StoredMetadata::new(builder.encode().expect("non-empty"))
        .expect("serializable")
        .into_bytes()
}

fn account_batch() -> BatchBuilder {
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(3)
        .with_collection(Collection::ContactCard);
    batch
}

#[test]
fn entries_carry_the_stored_length_and_trailer_hash() {
    for repeat in [1, 2000] {
        let bytes = stored(repeat);
        let entry = StoredEntry::new(7, &bytes);
        assert_eq!(entry.document_id, 7);
        assert_eq!(entry.size as usize, bytes.len());
        assert_eq!(
            entry.hash,
            Some(StoredMetadata::trailer_hash(&bytes).expect("trailer"))
        );
        assert_eq!(
            StoredEntry::from_container(7, &MetadataBuf::read(&bytes).expect("readable")),
            entry
        );
    }
    assert_eq!(
        StoredEntry::new(7, &[1, 2]),
        StoredEntry {
            document_id: 7,
            size: 2,
            hash: None
        }
    );
}

#[test]
fn releasing_asserts_the_hash_before_clearing_and_returns_the_quota() {
    let bytes = stored(1);
    let entry = StoredEntry::new(12, &bytes);
    let hash = entry.hash.expect("trailer");
    let size = i64::try_from(bytes.len()).expect("small");

    let mut batch = account_batch();
    entry.release(&mut batch, Some(9));
    assert_eq!(
        ops(&batch),
        [
            Op::Document(PendingId::Assigned(12)),
            Op::Assert(
                MetadataClass::Shared,
                AssertValue::Archive(ArchiveVersion::Hashed { hash })
            ),
            Op::Clear(MetadataClass::Shared),
            Op::Quota(-size),
            Op::TenantQuota(9, -size),
        ]
    );
    assert_eq!(batch.last_account_id(), Some(3));
    assert_eq!(batch.last_collection(), Some(Collection::ContactCard));

    let mut batch = account_batch();
    StoredEntry::new(4, &[1, 2]).release(&mut batch, None);
    assert_eq!(
        ops(&batch),
        [
            Op::Document(PendingId::Assigned(4)),
            Op::Clear(MetadataClass::Shared),
            Op::Quota(-2),
        ]
    );
}

#[test]
fn private_clears_assert_their_own_class() {
    let bytes = stored(1);
    let entry = StoredEntry::new(5, &bytes);
    let class = MetadataClass::Private { viewer: 8 };
    let mut batch = account_batch();
    entry.clear(&mut batch, class);
    assert_eq!(
        ops(&batch),
        [
            Op::Document(PendingId::Assigned(5)),
            Op::Assert(
                class,
                AssertValue::Archive(ArchiveVersion::Hashed {
                    hash: entry.hash.expect("trailer")
                })
            ),
            Op::Clear(class),
        ]
    );
}

#[test]
fn entries_are_found_by_document_id() {
    let entry = |document_id, size| StoredEntry {
        document_id,
        size,
        hash: Some(document_id),
    };
    let entries = [entry(12, 300), entry(4, 40), entry(7, 70)]
        .into_iter()
        .collect::<StoredEntries>();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.document_id)
            .collect::<Vec<_>>(),
        [4, 7, 12]
    );
    assert_eq!(entries.get(7), Some(&entry(7, 70)));
    assert_eq!(entries.get(5), None);
    assert!(StoredEntries::default().is_empty());
    assert_eq!(StoredEntries::default().get(4), None);
}
