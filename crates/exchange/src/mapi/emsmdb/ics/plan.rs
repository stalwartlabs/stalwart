/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::mapi::ids::{ChangeNumber, ChangeSpace};
use common::cache::exchange::foreign_replica_id;
use exchange_proto::{
    ics::{GlobSet, IcsState, IdSet, ReplKey, fx::ProgressInformation},
    ids::{Globcnt, ReplGuid, ReplId},
};
use std::cmp::Reverse;
use store::roaring::RoaringBitmap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemVersion {
    Known(ChangeNumber),
    Unchanged,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Normal,
    Associated,
    NormalFai,
}

impl ItemKind {
    pub fn associated(self) -> bool {
        self == ItemKind::Associated
    }

    pub fn fai_row(self) -> bool {
        self != ItemKind::Normal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeItem {
    pub id: Globcnt,
    pub version: ItemVersion,
    pub kind: ItemKind,
    pub size: u32,
    pub order: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanEntry {
    pub id: Globcnt,
    cn: Globcnt,
    pub size: u32,
    flags: u8,
}

const _: () = assert!(size_of::<PlanEntry>() <= 24);

const ENTRY_ASSOCIATED: u8 = 1;
const ENTRY_GIVEN: u8 = 2;
const ENTRY_FAI_ROW: u8 = 4;
const NO_CN: Globcnt = Globcnt::from_wire([0; 6]);

impl PlanEntry {
    pub fn new(
        id: Globcnt,
        cn: Option<ChangeNumber>,
        kind: ItemKind,
        in_given: bool,
        size: u32,
    ) -> Self {
        let mut flags = 0;
        if kind.associated() {
            flags |= ENTRY_ASSOCIATED;
        }
        if kind.fai_row() {
            flags |= ENTRY_FAI_ROW;
        }
        if in_given {
            flags |= ENTRY_GIVEN;
        }
        PlanEntry {
            id,
            cn: cn.map_or(NO_CN, ChangeNumber::globcnt),
            size,
            flags,
        }
    }

    pub fn cn(&self) -> Option<ChangeNumber> {
        ChangeNumber::from_globcnt(self.cn)
    }

    pub fn associated(&self) -> bool {
        self.flags & ENTRY_ASSOCIATED != 0
    }

    pub fn fai_row(&self) -> bool {
        self.flags & ENTRY_FAI_ROW != 0
    }

    pub fn in_given(&self) -> bool {
        self.flags & ENTRY_GIVEN != 0
    }

    pub fn echoes(&self, uploaded: &IcsState, guid: ReplGuid, cn: ChangeNumber) -> bool {
        self.in_given()
            && uploaded_seen(uploaded, self.fai_row()).contains(ReplKey::Guid(guid), cn.globcnt())
    }
}

fn uploaded_seen(uploaded: &IcsState, fai_row: bool) -> &IdSet {
    if fai_row {
        &uploaded.seen_fai
    } else {
        &uploaded.seen
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanOrder {
    Input,
    ChangeNumber,
    NewestFirst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceHead {
    pub space: ChangeSpace,
    pub head: u64,
}

pub struct PlanInput<'x> {
    pub guid: ReplGuid,
    pub uploaded: &'x IcsState,
    pub heads: &'x [SpaceHead],
    pub fai_heads: &'x [SpaceHead],
    pub outside: &'x GlobSet,
    pub order: PlanOrder,
    pub replicas: &'x [[u8; 16]],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreported {
    OutOfScope,
    Deletions,
}

#[derive(Debug, Default)]
pub struct DownloadPlan {
    pub changes: Vec<PlanEntry>,
    pub deleted: IdSet,
    pub no_longer_in_scope: IdSet,
    pub foreign_given: IdSet,
    pub next: IcsState,
}

impl DownloadPlan {
    fn seen_mut(&mut self, entry: &PlanEntry) -> &mut IdSet {
        if entry.fai_row() {
            &mut self.next.seen_fai
        } else {
            &mut self.next.seen
        }
    }

    pub fn keep_unreported(&mut self, guid: ReplGuid, unreported: Unreported) {
        let local = ReplKey::Id(ReplId::LOCAL);
        let key = ReplKey::Guid(guid);
        if let Some(set) = self.no_longer_in_scope.get(local) {
            self.next.given.get_mut(key).union_with(set);
        }
        if unreported == Unreported::Deletions {
            if let Some(set) = self.deleted.get(local) {
                self.next.given.get_mut(key).union_with(set);
            }
            self.next.given.union_with(&self.foreign_given);
        }
    }

    pub fn record_sent(&mut self, entry: &PlanEntry, cn: ChangeNumber, guid: ReplGuid) {
        self.seen_mut(entry)
            .get_mut(ReplKey::Guid(guid))
            .insert(cn.globcnt());
    }

    pub fn skip(&mut self, entry: &PlanEntry, guid: ReplGuid) {
        let key = ReplKey::Guid(guid);
        match (entry.in_given(), entry.cn()) {
            (true, Some(cn)) => self.seen_mut(entry).get_mut(key).remove(cn.globcnt()),
            (true, None) => {
                self.next.given.get_mut(key).remove(entry.id);
                self.deleted
                    .get_mut(ReplKey::Id(ReplId::LOCAL))
                    .insert(entry.id);
            }
            (false, _) => self.next.given.get_mut(key).remove(entry.id),
        }
    }

    pub fn progress(&self) -> ProgressInformation {
        let mut progress = ProgressInformation {
            fai_count: 0,
            fai_size: 0,
            normal_count: 0,
            normal_size: 0,
        };
        for entry in &self.changes {
            let size = u64::from(entry.size);
            if entry.associated() {
                progress.fai_count = progress.fai_count.saturating_add(1);
                progress.fai_size = progress.fai_size.saturating_add(size);
            } else {
                progress.normal_count = progress.normal_count.saturating_add(1);
                progress.normal_size = progress.normal_size.saturating_add(size);
            }
        }
        progress
    }

    pub fn footprint(&self) -> u64 {
        let entries = self
            .changes
            .capacity()
            .saturating_mul(size_of::<PlanEntry>());
        let ranges = self
            .deleted
            .total_ranges()
            .saturating_add(self.no_longer_in_scope.total_ranges())
            .saturating_add(self.foreign_given.total_ranges())
            .saturating_add(self.next.given.total_ranges())
            .saturating_add(self.next.seen.total_ranges())
            .saturating_add(self.next.seen_fai.total_ranges())
            .saturating_add(self.next.read.total_ranges())
            .saturating_mul(2 * size_of::<u64>());
        u64::try_from(entries.saturating_add(ranges)).unwrap_or(u64::MAX)
    }
}

pub fn is_candidate(uploaded: &IcsState, guid: ReplGuid, item: &ScopeItem) -> bool {
    let key = ReplKey::Guid(guid);
    let in_given = uploaded
        .given
        .get(key)
        .is_some_and(|given| given.contains(item.id));
    let seen = uploaded_seen(uploaded, item.kind.fai_row());
    match item.version {
        ItemVersion::Known(cn) => !(in_given && seen.contains(key, cn.globcnt())),
        ItemVersion::Unchanged => !in_given,
        ItemVersion::Unknown => true,
    }
}

pub fn plan(input: &PlanInput<'_>, mut items: Vec<ScopeItem>) -> DownloadPlan {
    let key = ReplKey::Guid(input.guid);
    let uploaded = input.uploaded;
    let given = uploaded.given.get(key);

    items.sort_unstable_by_key(|item| item.id);
    items.dedup_by_key(|item| item.id);
    let mut existence = GlobSet::new();
    for item in &items {
        existence.push_ascending(item.id, item.id);
    }
    items.retain(|item| is_candidate(uploaded, input.guid, item));
    match input.order {
        PlanOrder::Input => {
            items.sort_unstable_by_key(|item| (Reverse(item.kind.associated()), item.order))
        }
        PlanOrder::ChangeNumber => items.sort_unstable_by_key(|item| {
            (
                Reverse(item.kind.associated()),
                match item.version {
                    ItemVersion::Known(cn) => cn.globcnt().get(),
                    ItemVersion::Unchanged | ItemVersion::Unknown => u64::MAX,
                },
            )
        }),
        PlanOrder::NewestFirst => items
            .sort_unstable_by_key(|item| (Reverse(item.kind.associated()), Reverse(item.order))),
    }
    let mut changes: Vec<PlanEntry> = items
        .into_iter()
        .map(|item| {
            PlanEntry::new(
                item.id,
                match item.version {
                    ItemVersion::Known(cn) => Some(cn),
                    ItemVersion::Unchanged | ItemVersion::Unknown => None,
                },
                item.kind,
                given.is_some_and(|given| given.contains(item.id)),
                item.size,
            )
        })
        .collect();
    changes.shrink_to_fit();

    let mut deleted = IdSet::new();
    let mut no_longer_in_scope = IdSet::new();
    let mut foreign_given = IdSet::new();
    if let Some(given) = given {
        let mut gone = given.clone();
        gone.difference_with(&existence);
        if input.outside.intersects(&gone) {
            let mut filtered = gone.clone();
            filtered.difference_with(input.outside);
            let mut outside = gone;
            outside.difference_with(&filtered);
            *no_longer_in_scope.get_mut(ReplKey::Id(ReplId::LOCAL)) = outside;
            gone = filtered;
        }
        if !gone.is_empty() {
            *deleted.get_mut(ReplKey::Id(ReplId::LOCAL)) = gone;
        }
    }
    for (replica, set) in uploaded.given.replicas() {
        if let ReplKey::Guid(foreign) = replica
            && foreign != input.guid
            && let Some(replid) = foreign_replica_id(input.replicas, &foreign.0.0)
        {
            deleted.get_mut(ReplKey::Id(ReplId(replid))).union_with(set);
            foreign_given.get_mut(replica).union_with(set);
        }
    }

    let mut next = IcsState {
        given: IdSet::new(),
        seen: uploaded.seen.clone(),
        seen_fai: uploaded.seen_fai.clone(),
        read: uploaded.read.clone(),
    };
    if !existence.is_empty() {
        *next.given.get_mut(key) = existence;
    }
    collapse(&mut next.seen, key, input.heads);
    collapse(&mut next.seen_fai, key, input.fai_heads);

    DownloadPlan {
        changes,
        deleted,
        no_longer_in_scope,
        foreign_given,
        next,
    }
}

pub(super) fn collapse(set: &mut IdSet, key: ReplKey, heads: &[SpaceHead]) {
    for head in heads {
        if let Some(last) = head.space.cn(head.head) {
            set.get_mut(key)
                .insert_range(head.space.first(), last.globcnt());
        }
    }
}

pub fn seen_run_end(seen: &IdSet, guid: ReplGuid, space: ChangeSpace) -> u64 {
    seen.get(ReplKey::Guid(guid))
        .and_then(|set| set.run_end(space.first()))
        .and_then(|end| space.counter_of(end))
        .unwrap_or(0)
}

const MAX_SEEN_SEGMENTS: usize = 33;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CnSegment {
    Unseen { from: u64, to: u64 },
    Seen { from: u64, to: u64 },
}

pub fn seen_segments(
    seen: &IdSet,
    guid: ReplGuid,
    space: ChangeSpace,
    (since, head): (u64, u64),
) -> Option<Vec<CnSegment>> {
    let set = seen.get(ReplKey::Guid(guid))?;
    let first = space.first();
    let counter = |globcnt: Globcnt| {
        if globcnt < first {
            0
        } else {
            space.counter_of(globcnt).unwrap_or(u64::MAX)
        }
    };
    let mut segments = Vec::new();
    let mut cursor = since.saturating_add(1);
    for (lo, hi) in set.ranges() {
        let (lo, hi) = (counter(lo).max(cursor), counter(hi).min(head));
        if lo > head {
            break;
        }
        if hi < lo {
            continue;
        }
        if lo > cursor {
            segments.push(CnSegment::Unseen {
                from: cursor,
                to: lo - 1,
            });
        }
        segments.push(CnSegment::Seen { from: lo, to: hi });
        if segments.len() >= MAX_SEEN_SEGMENTS {
            return None;
        }
        cursor = hi.saturating_add(1);
    }
    if segments.is_empty() {
        return None;
    }
    if cursor <= head {
        segments.push(CnSegment::Unseen {
            from: cursor,
            to: head,
        });
    }
    Some(segments)
}

impl CnSegment {
    pub fn range(self) -> (u64, u64) {
        match self {
            CnSegment::Unseen { from, to } | CnSegment::Seen { from, to } => (from, to),
        }
    }
}

pub struct SegmentWalk {
    unclassified: RoaringBitmap,
    pending: RoaringBitmap,
}

impl SegmentWalk {
    pub fn new(changed: RoaringBitmap) -> Self {
        SegmentWalk {
            unclassified: changed,
            pending: RoaringBitmap::new(),
        }
    }

    pub fn is_done(&self) -> bool {
        self.unclassified.is_empty()
    }

    pub fn attribute(&mut self, segment: CnSegment, mut items: RoaringBitmap) {
        items &= &self.unclassified;
        self.unclassified -= &items;
        if let CnSegment::Unseen { .. } = segment {
            self.pending |= items;
        }
    }

    pub fn pending(self) -> RoaringBitmap {
        self.pending
    }

    pub fn truncated(mut self) -> RoaringBitmap {
        self.pending |= self.unclassified;
        self.pending
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/ics/plan/tests.rs"]
mod tests;
