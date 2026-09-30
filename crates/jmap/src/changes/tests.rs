/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    page::{
        LogRead, MetadataChanges, Page, PartialProperties, UpdatedProperties, ViewerChange,
        ViewerChanges, fill_page, merge_private,
    },
    state::max_state,
};
use jmap_proto::{method::changes::ChangesResponse, object::NullObject, types::state::State};
use store::query::log::{Change, Changes, PartialChange};
use types::id::Id;

fn changes(
    list: Vec<Change>,
    from_change_id: u64,
    to_change_id: u64,
    kind_change_id: Option<u64>,
) -> Changes {
    let mut changes = Changes::default();
    changes.changes = list;
    changes.from_change_id = from_change_id;
    changes.to_change_id = to_change_id;
    changes.item_change_id = kind_change_id;
    changes.container_change_id = kind_change_id;
    changes
}

fn response() -> ChangesResponse<NullObject> {
    ChangesResponse {
        account_id: Id::from(1u32),
        old_state: State::Initial,
        new_state: State::Initial,
        has_more_changes: false,
        created: vec![],
        updated: vec![],
        destroyed: vec![],
        updated_properties: None,
    }
}

fn page(
    list: &[ViewerChange],
    items_sent: usize,
    max_changes: usize,
    metadata: MetadataChanges,
    partial: PartialProperties,
) -> (Page, ChangesResponse<NullObject>) {
    let mut response = response();
    let page = fill_page(
        list.iter().copied(),
        items_sent,
        max_changes,
        metadata,
        partial,
        &mut response,
    );
    (page, response)
}

fn ids(ids: &[u64]) -> Vec<Id> {
    ids.iter().copied().map(Id::from).collect()
}

fn properties(bits: &[UpdatedProperties]) -> UpdatedProperties {
    bits.iter()
        .fold(UpdatedProperties::default(), |result, bit| {
            result.union(*bit)
        })
}

#[test]
fn private_rows_merge_into_the_shared_stream() {
    let shared = vec![
        Change::InsertItem(1),
        Change::UpdateItemMetadata(2),
        Change::UpdateItem(3),
        Change::InsertContainer(9),
    ];
    let private = vec![
        Change::UpdateItemMetadata(2),
        Change::UpdateItemMetadata(3),
        Change::UpdateItemMetadata(4),
        Change::UpdateItemMetadata(1),
        Change::UpdateContainerPartial(9, PartialChange::METADATA),
    ];

    assert_eq!(
        merge_private(shared.clone(), private.clone(), false),
        vec![
            ViewerChange::Shared(Change::InsertItem(1)),
            ViewerChange::SharedAndPrivate(Change::UpdateItemMetadata(2)),
            ViewerChange::Shared(Change::UpdateItem(3)),
            ViewerChange::Private(Change::UpdateItemMetadata(4)),
        ]
    );
    assert_eq!(
        merge_private(shared, private, true),
        vec![ViewerChange::Shared(Change::InsertContainer(9))]
    );
    assert_eq!(
        merge_private(
            vec![Change::UpdateContainerPartial(5, PartialChange::PROPERTIES)],
            vec![Change::UpdateContainerPartial(5, PartialChange::METADATA)],
            true
        ),
        vec![ViewerChange::SharedAndPrivate(
            Change::UpdateContainerPartial(5, PartialChange::PROPERTIES)
        )]
    );
}

#[test]
fn updated_properties_follow_every_id_on_the_page() {
    let metadata_only = [
        ViewerChange::SharedAndPrivate(Change::UpdateItemMetadata(2)),
        ViewerChange::Private(Change::UpdateItemMetadata(4)),
        ViewerChange::Shared(Change::UpdateItemMetadata(6)),
    ];
    let (result, response) = page(
        &metadata_only,
        0,
        10,
        MetadataChanges::Reported,
        PartialProperties::Unknown,
    );
    assert_eq!(response.updated, ids(&[2, 4, 6]));
    assert_eq!(
        result.updated_properties,
        Some(properties(&[
            UpdatedProperties::METADATA,
            UpdatedProperties::PRIVATE_METADATA
        ]))
    );

    let (result, _) = page(
        &metadata_only[1..2],
        0,
        10,
        MetadataChanges::Reported,
        PartialProperties::Unknown,
    );
    assert_eq!(
        result.updated_properties,
        Some(UpdatedProperties::PRIVATE_METADATA)
    );

    let mixed = [
        ViewerChange::Shared(Change::UpdateItemMetadata(2)),
        ViewerChange::Shared(Change::UpdateItem(3)),
    ];
    let (result, _) = page(
        &mixed,
        0,
        10,
        MetadataChanges::Reported,
        PartialProperties::Unknown,
    );
    assert_eq!(result.updated_properties, None);

    let (result, response) = page(
        &mixed,
        0,
        1,
        MetadataChanges::Reported,
        PartialProperties::Unknown,
    );
    assert!(result.has_more);
    assert_eq!(response.updated, ids(&[2]));
    assert_eq!(result.updated_properties, Some(UpdatedProperties::METADATA));

    let created_only = [ViewerChange::Shared(Change::InsertItem(8))];
    let (result, response) = page(
        &created_only,
        0,
        10,
        MetadataChanges::Reported,
        PartialProperties::Unknown,
    );
    assert_eq!(response.created, ids(&[8]));
    assert_eq!(result.updated_properties, None);
}

#[test]
fn mailbox_counts_join_the_metadata_union() {
    let changes = [
        ViewerChange::Shared(Change::UpdateContainerPartial(1, PartialChange::PROPERTIES)),
        ViewerChange::Shared(Change::UpdateContainerPartial(2, PartialChange::METADATA)),
        ViewerChange::Private(Change::UpdateContainerPartial(3, PartialChange::METADATA)),
    ];
    let (result, _) = page(
        &changes,
        0,
        10,
        MetadataChanges::Reported,
        PartialProperties::Counts,
    );
    assert_eq!(
        result.updated_properties,
        Some(properties(&[
            UpdatedProperties::COUNTS,
            UpdatedProperties::METADATA,
            UpdatedProperties::PRIVATE_METADATA
        ]))
    );

    let (result, _) = page(
        &changes,
        0,
        10,
        MetadataChanges::Reported,
        PartialProperties::Unknown,
    );
    assert_eq!(result.updated_properties, None);
}

#[test]
fn metadata_only_changes_are_dropped_before_paging() {
    let changes = [
        ViewerChange::Shared(Change::UpdateItemMetadata(1)),
        ViewerChange::Shared(Change::UpdateItem(2)),
        ViewerChange::Private(Change::UpdateItemMetadata(3)),
        ViewerChange::Shared(Change::UpdateItem(4)),
        ViewerChange::SharedAndPrivate(Change::UpdateItemMetadata(5)),
        ViewerChange::Shared(Change::DeleteItem(6)),
    ];
    for metadata in [MetadataChanges::Ignored, MetadataChanges::Unsupported] {
        let (result, response) = page(&changes, 0, 2, metadata, PartialProperties::Unknown);
        assert_eq!(response.updated, ids(&[2, 4]));
        assert!(result.has_more);

        let (result, response) = page(&changes, 2, 2, metadata, PartialProperties::Unknown);
        assert!(response.updated.is_empty());
        assert_eq!(response.destroyed, ids(&[6]));
        assert!(!result.has_more);
        assert_eq!(result.updated_properties, None);
    }

    let mailboxes = [
        ViewerChange::Shared(Change::UpdateContainerPartial(
            1,
            PartialChange::PROPERTIES.union(PartialChange::METADATA),
        )),
        ViewerChange::Shared(Change::UpdateContainerPartial(2, PartialChange::METADATA)),
    ];
    let (result, response) = page(
        &mailboxes,
        0,
        10,
        MetadataChanges::Unsupported,
        PartialProperties::Counts,
    );
    assert_eq!(response.updated, ids(&[1]));
    assert_eq!(result.updated_properties, Some(UpdatedProperties::COUNTS));

    let (result, response) = page(
        &mailboxes,
        0,
        10,
        MetadataChanges::Ignored,
        PartialProperties::Counts,
    );
    assert_eq!(response.updated, ids(&[1]));
    assert_eq!(result.updated_properties, None);
}

#[test]
fn private_since_states_validate_against_either_log() {
    let skipped = LogRead::default();
    assert!(skipped.is_valid_since());
    assert!(!skipped.is_truncated());
    assert!(skipped.is_empty());

    let private_only = LogRead {
        shared: Some(changes(vec![], 0, 0, None)),
        private: Some(changes(vec![Change::UpdateItemMetadata(3)], 7, 9, Some(9))),
    };
    assert!(private_only.is_valid_since());
    assert_eq!(private_only.first_change_id(), 7);
    assert_eq!(private_only.last_change_id(false), 9);
    assert_eq!(private_only.private_change_id(false), 9);

    let invalid = LogRead {
        shared: Some(changes(vec![], 0, 0, None)),
        private: None,
    };
    assert!(!invalid.is_valid_since());

    let mut truncated = changes(vec![], 4, 4, None);
    truncated.is_truncated = true;
    let truncated = LogRead {
        shared: Some(changes(vec![Change::UpdateItem(1)], 5, 6, Some(6))),
        private: Some(truncated),
    };
    assert!(truncated.is_truncated());

    let both = LogRead {
        shared: Some(changes(
            vec![Change::UpdateItem(1), Change::UpdateItemMetadata(2)],
            12,
            20,
            Some(18),
        )),
        private: Some(changes(
            vec![Change::UpdateItemMetadata(2), Change::UpdateItemMetadata(3)],
            11,
            15,
            Some(15),
        )),
    };
    assert_eq!(both.first_change_id(), 11);
    assert_eq!(both.last_change_id(false), 18);
    assert_eq!(both.private_change_id(true), 15);
    assert_eq!(both.total(false), 3);
    match both.into_changes(false) {
        ViewerChanges::Merged(merged) => assert_eq!(
            merged,
            vec![
                ViewerChange::Shared(Change::UpdateItem(1)),
                ViewerChange::SharedAndPrivate(Change::UpdateItemMetadata(2)),
                ViewerChange::Private(Change::UpdateItemMetadata(3)),
            ]
        ),
        ViewerChanges::Shared(_) => panic!("private rows were not merged"),
    }

    let shared_only = LogRead {
        shared: Some(changes(
            vec![Change::UpdateItem(1), Change::InsertContainer(2)],
            1,
            2,
            Some(1),
        )),
        private: None,
    };
    assert_eq!(shared_only.total(false), 1);
    assert!(matches!(
        shared_only.into_changes(false),
        ViewerChanges::Shared(list) if list.len() == 2
    ));
}

#[test]
fn state_is_the_newest_of_shared_and_private() {
    assert_eq!(max_state(State::Initial, 0), State::Initial);
    assert_eq!(max_state(State::Initial, 5), State::Exact(5));
    assert_eq!(max_state(State::Exact(3), 5), State::Exact(5));
    assert_eq!(max_state(State::Exact(7), 5), State::Exact(7));
    let intermediate = State::new_intermediate(1, 2, 3);
    assert_eq!(max_state(intermediate.clone(), 9), intermediate);
}
