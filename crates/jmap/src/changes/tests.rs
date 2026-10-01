/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    page::{
        Coverage, LogBounds, LogRead, MetadataChanges, Page, PageChange, PartialProperties,
        UpdatedProperties, ViewerChange, ViewerChanges, fill_page, merge_private, private_query,
    },
    state::{ViewerChangeId, max_state},
};
use jmap_proto::{method::changes::ChangesResponse, object::NullObject, types::state::State};
use store::query::log::{Change, Changes, PartialChange, Query};
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
    assert_eq!(result.updated_properties, Some(UpdatedProperties::COUNTS));

    let counts_and_private = [
        ViewerChange::SharedAndPrivate(Change::UpdateContainerPartial(
            1,
            PartialChange::PROPERTIES,
        )),
        ViewerChange::Private(Change::UpdateContainerPartial(3, PartialChange::METADATA)),
    ];
    let (result, response) = page(
        &counts_and_private,
        0,
        10,
        MetadataChanges::Ignored,
        PartialProperties::Counts,
    );
    assert_eq!(response.updated, ids(&[1]));
    assert_eq!(result.updated_properties, Some(UpdatedProperties::COUNTS));

    let full = [
        ViewerChange::Shared(Change::UpdateContainerPartial(1, PartialChange::PROPERTIES)),
        ViewerChange::Shared(Change::UpdateContainer(2)),
    ];
    let (result, _) = page(
        &full,
        0,
        10,
        MetadataChanges::Ignored,
        PartialProperties::Counts,
    );
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
    assert_eq!(
        private_only.bounds(false),
        LogBounds {
            first_change_id: 7,
            last_change_id: 9,
            private_change_id: 9,
        }
    );

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
    assert_eq!(both.bounds(false).first_change_id, 11);
    assert_eq!(both.bounds(false).last_change_id, 18);
    assert_eq!(both.bounds(true).private_change_id, 15);
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

#[test]
fn viewer_samples_combine_with_the_shared_state() {
    assert_eq!(
        ViewerChangeId::default().state(State::Exact(4)),
        State::Exact(4)
    );
    assert_eq!(
        ViewerChangeId::default().state(State::Initial),
        State::Initial
    );
    assert_eq!(
        ViewerChangeId::default().assert_state(State::Exact(4), &Some(State::Exact(4))),
        Ok(State::Exact(4))
    );
    assert!(
        ViewerChangeId::default()
            .assert_state(State::Exact(4), &Some(State::Exact(5)))
            .is_err()
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Log {
    Shared,
    Private,
}

struct Timeline(Vec<(u64, Log, Change)>);

impl Timeline {
    fn read(&self, log: Log, query: Query, committed: usize) -> Changes {
        let (exclusive, from, to) = match query {
            Query::All => (false, 0, u64::MAX),
            Query::Since(change_id) => (true, change_id, u64::MAX),
            Query::SinceInclusive(change_id) => (false, change_id, u64::MAX),
            Query::RangeInclusive(from, to) => (false, from, to),
        };
        let mut result = Changes::default();
        for (change_id, row_log, change) in self.0.iter().take(committed) {
            if *row_log != log || *change_id < from || *change_id > to {
                continue;
            }
            if exclusive && *change_id == from {
                result.from_change_id = *change_id;
                result.to_change_id = *change_id;
                continue;
            }
            if result.changes.is_empty() {
                result.from_change_id = *change_id;
            }
            result.to_change_id = *change_id;
            result.item_change_id = Some(*change_id);
            result.changes.push(*change);
        }
        result
    }

    fn last(&self, log: Log, committed: usize) -> u64 {
        self.0
            .iter()
            .take(committed)
            .filter(|(_, row_log, _)| *row_log == log)
            .map(|(change_id, _, _)| *change_id)
            .max()
            .unwrap_or_default()
    }

    fn position(&self, change_id: u64) -> usize {
        self.0
            .iter()
            .position(|(id, _, _)| *id == change_id)
            .map_or(self.0.len(), |position| position + 1)
    }

    fn missing(
        &self,
        since: u64,
        state: &State,
        response: &ChangesResponse<NullObject>,
    ) -> Vec<u64> {
        let State::Exact(state) = state else {
            panic!("unexpected state {state:?}");
        };
        self.0
            .iter()
            .filter(|(change_id, _, _)| *change_id > since && change_id <= state)
            .filter_map(|(change_id, _, change)| {
                let id = Id::from(change.item_id()?);
                (!response.updated.contains(&id) && !response.created.contains(&id))
                    .then_some(*change_id)
            })
            .collect()
    }
}

struct Cut {
    shared_at: usize,
    private_at: usize,
    viewer_at: usize,
}

fn run(
    timeline: &Timeline,
    since: State,
    cut: &Cut,
    max_changes: usize,
) -> (ChangesResponse<NullObject>, Vec<ViewerChange>) {
    let viewer_change_id = timeline.last(Log::Private, cut.viewer_at);
    let (query, read_shared, read_private, known, current, coverage) = match &since {
        State::Initial => (
            Query::All,
            true,
            viewer_change_id > 0,
            viewer_change_id,
            State::Initial,
            Coverage::Latest { viewer_change_id },
        ),
        State::Exact(since) => {
            let since = *since;
            let shared_change_id = timeline.last(Log::Shared, cut.viewer_at);
            (
                Query::Since(since),
                since < shared_change_id || since > viewer_change_id,
                viewer_change_id > since,
                viewer_change_id.max(shared_change_id),
                max_state(State::Exact(shared_change_id), viewer_change_id),
                Coverage::Latest { viewer_change_id },
            )
        }
        State::Intermediate(state) => (
            Query::RangeInclusive(state.from_id, state.to_id),
            true,
            viewer_change_id >= state.from_id,
            viewer_change_id,
            State::Initial,
            Coverage::Range,
        ),
    };
    let items_sent = match &since {
        State::Intermediate(state) => state.items_sent,
        _ => 0,
    };
    let shared = read_shared.then(|| timeline.read(Log::Shared, query, cut.shared_at));
    let private = private_query(query, shared.as_ref(), known)
        .filter(|_| read_private)
        .map(|query| timeline.read(Log::Private, query, cut.private_at));
    let log = LogRead { shared, private };
    let bounds = log.bounds(false);
    let merged = match log.into_changes(false) {
        ViewerChanges::Merged(merged) => merged,
        ViewerChanges::Shared(shared) => shared.into_iter().map(ViewerChange::Shared).collect(),
    };
    let mut response = response();
    let page = fill_page(
        merged.iter().copied(),
        items_sent,
        max_changes,
        MetadataChanges::Reported,
        PartialProperties::Unknown,
        &mut response,
    );
    response.has_more_changes = page.has_more;
    response.new_state = bounds.new_state(
        current,
        page.has_more.then_some(items_sent + max_changes),
        coverage,
    );
    (response, merged)
}

fn race() -> Timeline {
    Timeline(vec![
        (96, Log::Shared, Change::UpdateItem(1)),
        (97, Log::Private, Change::UpdateItemMetadata(2)),
        (98, Log::Shared, Change::UpdateItem(3)),
        (99, Log::Shared, Change::UpdateItem(4)),
        (100, Log::Shared, Change::UpdateItem(5)),
        (101, Log::Shared, Change::UpdateItem(6)),
        (102, Log::Private, Change::UpdateItemMetadata(7)),
        (103, Log::Private, Change::UpdateItemMetadata(8)),
        (104, Log::Shared, Change::UpdateItem(9)),
    ])
}

#[test]
fn private_reads_stop_at_a_consistent_cut() {
    let timeline = race();
    let before_101 = timeline.position(100);
    let after_102 = timeline.position(102);
    let after_103 = timeline.position(103);
    let everything = timeline.0.len();

    for (since, cut) in [
        (
            State::Exact(95),
            Cut {
                viewer_at: before_101,
                shared_at: before_101,
                private_at: after_102,
            },
        ),
        (
            State::Initial,
            Cut {
                viewer_at: before_101,
                shared_at: before_101,
                private_at: after_102,
            },
        ),
        (
            State::Exact(95),
            Cut {
                viewer_at: before_101,
                shared_at: after_102,
                private_at: everything,
            },
        ),
        (
            State::Exact(97),
            Cut {
                viewer_at: after_103,
                shared_at: after_103,
                private_at: everything,
            },
        ),
        (
            State::Exact(100),
            Cut {
                viewer_at: after_102,
                shared_at: after_102,
                private_at: everything,
            },
        ),
    ] {
        let since_id = match since {
            State::Exact(since) => since,
            _ => 0,
        };
        let (response, _) = run(&timeline, since.clone(), &cut, 100);
        assert!(!response.has_more_changes);
        assert_eq!(
            timeline.missing(since_id, &response.new_state, &response),
            Vec::<u64>::new(),
            "since {since:?}: changes at or below {:?} were not reported",
            response.new_state
        );

        let (next, _) = run(
            &timeline,
            response.new_state.clone(),
            &Cut {
                viewer_at: everything,
                shared_at: everything,
                private_at: everything,
            },
            100,
        );
        let State::Exact(state) = response.new_state else {
            panic!("unexpected state {:?}", response.new_state);
        };
        assert_eq!(
            timeline.missing(state, &next.new_state, &next),
            Vec::<u64>::new(),
            "since {since:?}: the next call lost the rows above the cut"
        );
        assert_eq!(next.new_state, State::Exact(104));
    }
}

#[test]
fn intermediate_pages_replay_the_same_rows() {
    let timeline = race();
    let before_101 = timeline.position(100);
    let everything = timeline.0.len();
    let first = Cut {
        viewer_at: before_101,
        shared_at: before_101,
        private_at: everything,
    };

    for since in [State::Exact(95), State::Initial] {
        let (page, merged) = run(&timeline, since.clone(), &first, 2);
        assert!(page.has_more_changes, "{since:?}");
        let State::Intermediate(intermediate) = &page.new_state else {
            panic!("{since:?}: unexpected state {:?}", page.new_state);
        };
        assert_eq!(intermediate.to_id, 100, "{since:?}");

        let mut state = page.new_state.clone();
        let mut sent = page.updated.clone();
        loop {
            let (next, replayed) = run(
                &timeline,
                state.clone(),
                &Cut {
                    viewer_at: everything,
                    shared_at: everything,
                    private_at: everything,
                },
                2,
            );
            assert_eq!(
                replayed, merged,
                "{since:?}: a later page saw a different list"
            );
            sent.extend(next.updated.iter().copied());
            state = next.new_state.clone();
            if !next.has_more_changes {
                break;
            }
        }
        assert_eq!(state, State::Exact(100), "{since:?}");
        let expected = merged
            .iter()
            .filter_map(|change| change.change().item_id().map(Id::from))
            .collect::<Vec<_>>();
        assert_eq!(sent, expected, "{since:?}");
    }
}

#[test]
fn shared_pages_match_shared_viewer_pages() {
    let list = [
        Change::InsertItem(1),
        Change::UpdateItem(2),
        Change::UpdateItemMetadata(3),
        Change::DeleteItem(4),
        Change::InsertContainer(5),
        Change::UpdateContainer(6),
        Change::UpdateContainerPartial(7, PartialChange::PROPERTIES),
        Change::UpdateContainerPartial(8, PartialChange::METADATA),
        Change::UpdateContainerPartial(9, PartialChange::PROPERTIES.union(PartialChange::METADATA)),
        Change::DeleteContainer(10),
    ];
    let mut selected = Vec::with_capacity(list.len());
    for mask in 0u32..(1 << list.len()) {
        selected.clear();
        selected.extend(
            list.iter()
                .enumerate()
                .filter(|(position, _)| mask & (1 << position) != 0)
                .map(|(_, change)| *change),
        );
        for metadata in [
            MetadataChanges::Unsupported,
            MetadataChanges::Ignored,
            MetadataChanges::Reported,
        ] {
            for partial in [PartialProperties::Counts, PartialProperties::Unknown] {
                for (items_sent, max_changes) in [(0, 1), (0, 2), (0, 64), (1, 2), (2, 64)] {
                    let mut shared = response();
                    let shared_page = fill_page(
                        selected.iter().copied(),
                        items_sent,
                        max_changes,
                        metadata,
                        partial,
                        &mut shared,
                    );
                    let mut viewer = response();
                    let viewer_page = fill_page(
                        selected.iter().copied().map(ViewerChange::Shared),
                        items_sent,
                        max_changes,
                        metadata,
                        partial,
                        &mut viewer,
                    );
                    let case = (mask, metadata, partial, items_sent, max_changes);
                    assert_eq!(shared_page, viewer_page, "{case:?}");
                    assert_eq!(shared.created, viewer.created, "{case:?}");
                    assert_eq!(shared.updated, viewer.updated, "{case:?}");
                    assert_eq!(shared.destroyed, viewer.destroyed, "{case:?}");
                }
            }
        }
    }
}
