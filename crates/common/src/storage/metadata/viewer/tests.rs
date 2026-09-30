/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CACHE_INDEX_SIZE, CACHE_SLOT_SIZE, ViewerStates};
use std::sync::Arc;
use store::write::metadata::ViewerState;
use utils::cache::{Cache, CacheItemWeight};

const MEASURED_VIEWERS: u32 = 4096;

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
