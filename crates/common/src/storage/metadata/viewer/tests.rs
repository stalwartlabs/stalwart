/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CACHE_INDEX_SIZE, CACHE_SLOT_SIZE, MetadataViewerCache, PrivateMetadataChange, ViewerStates,
};
use std::sync::Arc;
use store::write::metadata::ViewerState;
use types::collection::{Collection, SyncCollection};
use utils::cache::{Cache, CacheItemWeight};

const MEASURED_VIEWERS: u32 = 4096;
const VIEWER: u32 = 9;

#[test]
fn loads_mark_stale_only_owners_with_a_private_change() {
    let state = |change_id, containers| ViewerState {
        change_id,
        containers,
    };
    let states = ViewerStates::new([
        (1, u8::from(Collection::Email), state(5, 0)),
        (1, u8::from(Collection::Mailbox), state(0, 1)),
        (2, u8::from(Collection::CalendarEvent), state(7, 2)),
        (3, u8::from(Collection::FileNode), state(0, 0)),
    ]);
    assert_eq!(
        states.logged_owners().collect::<Vec<_>>(),
        [(1, SyncCollection::Email), (2, SyncCollection::Calendar)]
    );
    assert_eq!(ViewerStates::default().logged_owners().count(), 0);
}

#[test]
fn a_load_overtaken_between_check_and_insert_is_discarded() {
    let cache = MetadataViewerCache::new(1 << 20);
    let stale = Arc::new(ViewerStates::default());
    let commit = PrivateMetadataChange {
        owner_id: 1,
        viewer_id: VIEWER,
        collection: Collection::Email,
        is_logged: true,
        containers: 1,
    };

    let epoch = cache.epoch(VIEWER);
    cache.apply(&commit, Some(3));
    cache.states.insert(VIEWER, stale.clone());
    cache.discard_if_stale(VIEWER, epoch);
    assert!(
        cache.get(VIEWER).is_none(),
        "a commit that found no entry must not leave the earlier load cached"
    );

    let epoch = cache.epoch(VIEWER);
    cache.invalidate(VIEWER);
    cache.states.insert(VIEWER, stale.clone());
    cache.discard_if_stale(VIEWER, epoch);
    assert!(cache.get(VIEWER).is_none());

    let epoch = cache.epoch(VIEWER);
    cache.states.insert(VIEWER, stale);
    cache.discard_if_stale(VIEWER, epoch);
    assert!(cache.get(VIEWER).is_some());
}

#[test]
fn only_changes_to_the_same_viewer_or_a_clear_discard_a_load() {
    let cache = MetadataViewerCache::new(1 << 20);
    let other = VIEWER + 1;
    let commit = PrivateMetadataChange {
        owner_id: 1,
        viewer_id: other,
        collection: Collection::Email,
        is_logged: true,
        containers: 1,
    };

    let epoch = cache.epoch(VIEWER);
    cache.apply(&commit, Some(3));
    cache.invalidate(other);
    cache.insert(VIEWER, Arc::new(ViewerStates::default()), epoch);
    assert!(
        cache.get(VIEWER).is_some(),
        "a commit for another viewer must not discard this viewer's load"
    );

    for viewer_id in [VIEWER, other] {
        let epoch = cache.epoch(viewer_id);
        cache.clear();
        cache.insert(viewer_id, Arc::new(ViewerStates::default()), epoch);
        assert!(cache.get(viewer_id).is_none());
    }
}

fn viewer(entries: u32) -> ViewerStates {
    ViewerStates::new((0..entries).map(|owner_id| (owner_id, 1, ViewerState::default())))
}

fn weight(states: &ViewerStates) -> u64 {
    0u32.weight() + states.weight()
}

#[test]
fn viewer_weight_counts_the_slot_arc_and_entries() {
    assert_eq!(weight(&viewer(0)), 72);
    assert_eq!(weight(&viewer(1)), 96);
    assert_eq!(weight(&viewer(2)), 120);
    assert_eq!(weight(&viewer(10)), 312);
}

#[test]
fn cache_slots_match_the_weighted_slot_size() {
    let cache = Cache::<u32, Arc<ViewerStates>>::new_single_shard(u64::from(u32::MAX), 72);
    for viewer_id in 0..MEASURED_VIEWERS {
        cache.insert(viewer_id, Arc::new(ViewerStates::default()));
    }
    let viewers = MEASURED_VIEWERS as usize;
    let memory = cache.inner().memory_used();
    assert_eq!(memory.entries, viewers * CACHE_SLOT_SIZE);
    assert!(
        memory.map >= viewers * CACHE_INDEX_SIZE / 2
            && memory.map <= viewers * CACHE_INDEX_SIZE * 2,
        "index overhead {} for {viewers} viewers",
        memory.map
    );
}
