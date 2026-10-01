/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{has_room_for, quota_outcome, stored_len};
use crate::storage::metadata::StoredContainer;
use std::{borrow::Cow, future::ready, iter};
use store::write::metadata::{METADATA_COMPRESS_WATERMARK, MetadataBuf, StoredMetadata};
use trc::{LimitEvent, StoreEvent};
use types::metadata::{EncodedMetadata, MetadataBuilder, MetadataEdit, STORAGE_TRAILER_CAPACITY};

const BELOW_WATERMARK: usize = METADATA_COMPRESS_WATERMARK - 1;
const AT_WATERMARK: usize = METADATA_COMPRESS_WATERMARK;
const PROBE_LEN: usize = 512;

#[derive(Clone, Copy)]
enum Fill {
    Repeated,
    Noise,
}

impl Fill {
    fn bytes(self, len: usize) -> Vec<u8> {
        match self {
            Fill::Repeated => vec![b'a'; len],
            Fill::Noise => {
                let mut state = 0x9e37_79b9_7f4a_7c15_u64;
                iter::repeat_with(|| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()
                })
                .flatten()
                .take(len)
                .collect()
            }
        }
    }
}

fn encode(value: &[u8]) -> EncodedMetadata {
    let mut builder = MetadataBuilder::new();
    builder.set_imap(Cow::Borrowed("/comment"), value);
    builder.encode().expect("non-empty")
}

fn container(len: usize, fill: Fill) -> EncodedMetadata {
    let overhead = encode(&[0; PROBE_LEN]).len() - PROBE_LEN;
    let container = encode(&fill.bytes(len - overhead));
    assert_eq!(container.len(), len);
    container
}

fn bound(next: &EncodedMetadata) -> u64 {
    (next.len() + STORAGE_TRAILER_CAPACITY) as u64
}

fn serialized_len(next: &EncodedMetadata) -> u64 {
    StoredMetadata::new(next.clone())
        .expect("serializable")
        .len() as u64
}

async fn check(previous: Option<u64>, next: &EncodedMetadata, headroom: u64) -> (bool, Vec<u64>) {
    check_edit(MetadataEdit::Write, previous, next, headroom).await
}

async fn check_edit(
    edit: MetadataEdit,
    previous: Option<u64>,
    next: &EncodedMetadata,
    headroom: u64,
) -> (bool, Vec<u64>) {
    let previous = previous.map(|size| StoredContainer {
        size: u32::try_from(size).expect("container size"),
        ..Default::default()
    });
    let mut requests = Vec::new();
    let has_room = has_room_for(edit, previous.as_ref(), next, |growth| {
        requests.push(growth);
        ready(Ok(growth <= headroom))
    })
    .await
    .expect("quota check");
    (has_room, requests)
}

#[test]
fn borrowed_stored_length_matches_the_serialized_container() {
    for fill in [Fill::Repeated, Fill::Noise] {
        for len in [BELOW_WATERMARK, AT_WATERMARK, 4 * AT_WATERMARK] {
            let next = container(len, fill);
            assert_eq!(
                stored_len(&next).expect("measurable"),
                serialized_len(&next),
                "{len}"
            );
        }
    }
}

#[tokio::test]
async fn growth_within_previous_size_needs_no_quota() {
    for next in [
        container(BELOW_WATERMARK, Fill::Repeated),
        container(AT_WATERMARK, Fill::Repeated),
    ] {
        let bound = bound(&next);
        for previous in [bound, bound + 1] {
            assert_eq!(check(Some(previous), &next, 0).await, (true, vec![]));
        }
    }
}

#[tokio::test]
async fn growth_is_charged_up_to_the_stored_bound() {
    let next = container(BELOW_WATERMARK, Fill::Repeated);
    let bound = bound(&next);
    assert_eq!(serialized_len(&next), bound);
    assert_eq!(check(None, &next, bound).await, (true, vec![bound]));
    assert_eq!(check(Some(bound - 1), &next, 1).await, (true, vec![1]));
    assert_eq!(check(Some(bound - 1), &next, 0).await, (false, vec![1]));
}

#[tokio::test]
async fn small_container_over_quota_is_not_compressed() {
    let next = container(BELOW_WATERMARK, Fill::Repeated);
    let bound = bound(&next);
    assert_eq!(check(None, &next, bound - 1).await, (false, vec![bound]));
}

#[tokio::test]
async fn large_container_over_bound_retries_with_exact_size() {
    let next = container(AT_WATERMARK, Fill::Repeated);
    let bound = bound(&next);
    let stored = serialized_len(&next);
    assert!(stored < bound);
    assert_eq!(check(None, &next, bound).await, (true, vec![bound]));
    assert_eq!(
        check(None, &next, stored).await,
        (true, vec![bound, stored])
    );
    assert_eq!(
        check(None, &next, stored - 1).await,
        (false, vec![bound, stored])
    );
    assert_eq!(
        check(Some(1), &next, stored - 1).await,
        (true, vec![bound - 1, stored - 1])
    );
}

#[tokio::test]
async fn large_container_within_previous_after_compression_needs_no_quota() {
    let next = container(AT_WATERMARK, Fill::Repeated);
    let bound = bound(&next);
    for previous in [serialized_len(&next), bound - 1] {
        assert_eq!(
            check(Some(previous), &next, 0).await,
            (true, vec![bound - previous])
        );
    }
}

#[tokio::test]
async fn incompressible_container_is_charged_its_bound() {
    let next = container(AT_WATERMARK, Fill::Noise);
    let bound = bound(&next);
    assert_eq!(serialized_len(&next), bound);
    assert_eq!(check(None, &next, bound).await, (true, vec![bound]));
    assert_eq!(
        check(None, &next, bound - 1).await,
        (false, vec![bound, bound])
    );
}

#[tokio::test]
async fn removal_that_decompresses_the_container_needs_no_quota() {
    let mut seed = MetadataBuilder::new();
    seed.set_imap(Cow::Borrowed("/a"), &Fill::Repeated.bytes(PROBE_LEN));
    seed.set_imap(Cow::Borrowed("/b"), &Fill::Repeated.bytes(PROBE_LEN));
    let stored = StoredMetadata::new(seed.encode().expect("non-empty"))
        .expect("serializable")
        .into_bytes();
    let buf = MetadataBuf::read(&stored).expect("readable");
    let previous = u64::from(StoredContainer::from(&buf).size);

    let mut builder = MetadataBuilder::from_view(&buf.view());
    builder.remove_imap("/b");
    let edit = builder.edit();
    let next = builder.encode().expect("non-empty");
    let bound = bound(&next);

    assert_eq!(edit, MetadataEdit::RemovalOnly);
    assert!(buf.view().as_bytes().len() >= METADATA_COMPRESS_WATERMARK);
    assert!(next.len() < METADATA_COMPRESS_WATERMARK);
    assert_eq!(serialized_len(&next), bound);
    assert!(bound > previous);
    assert_eq!(
        check_edit(edit, Some(previous), &next, 0).await,
        (true, vec![])
    );
    assert_eq!(
        check_edit(MetadataEdit::Write, Some(previous), &next, 0).await,
        (false, vec![bound - previous])
    );
}

#[tokio::test]
async fn removal_without_a_previous_container_is_charged() {
    let next = container(BELOW_WATERMARK, Fill::Repeated);
    let bound = bound(&next);
    assert_eq!(
        check_edit(MetadataEdit::RemovalOnly, None, &next, 0).await,
        (false, vec![bound])
    );
}

#[test]
fn only_account_and_tenant_quota_mean_exceeded() {
    assert!(quota_outcome(Ok(())).expect("available"));
    for event in [LimitEvent::Quota, LimitEvent::TenantQuota] {
        assert!(!quota_outcome(Err(event.into_err())).expect("exceeded"));
    }
    for err in [
        LimitEvent::BlobQuota.into_err(),
        StoreEvent::DataCorruption.into_err(),
    ] {
        let event = err.event_type();
        assert!(quota_outcome(Err(err)).is_err_and(|err| err.matches(event)));
    }
}
