/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    U16_LEN, U64_LEN,
    write::{AssignedIds, PendingId},
};
use ahash::{AHashSet, RandomState};
use indexmap::IndexSet;
use types::collection::{SyncCollection, VanishedCollection};
use utils::{codec::leb128::Leb128Vec, map::vec_map::VecMap};

pub const CONTAINER_INSERTS: usize = 0;
pub const CONTAINER_UPDATES: usize = 1;
pub const CONTAINER_PROPERTY_CHANGES: usize = 2;
pub const CONTAINER_DELETES: usize = 3;
pub const ITEM_INSERTS: usize = 4;
pub const ITEM_UPDATES: usize = 5;
pub const ITEM_DELETES: usize = 6;
pub const CHANGE_LISTS: usize = 7;

const _: () = assert!(CHANGE_LISTS == ITEM_DELETES + 1);
const _: () = assert!(CHANGE_LISTS <= u8::BITS as usize);

const CHANGE_SET_THRESHOLD: usize = 256;
const CHANGE_SET_SCAN_LIMIT: usize = 32;

const CONTAINER_BYTES_HINT: usize = 2;
const ITEM_BYTES_HINT: usize = 2;
const PREFIXED_ITEM_BYTES_HINT: usize = 3;
const VANISHED_ID_BYTES_HINT: usize = 2;

#[derive(Debug)]
pub enum ChangeSet<T> {
    Small(Vec<T>),
    Large(AHashSet<T>),
}

impl<T: std::hash::Hash + Eq> PartialEq for ChangeSet<T> {
    fn eq(&self, other: &Self) -> bool {
        self.len_inner() == other.len_inner() && self.iter().all(|item| other.contains_inner(item))
    }
}

impl<T: std::hash::Hash + Eq> Eq for ChangeSet<T> {}

impl<T: std::hash::Hash + Eq> std::hash::Hash for ChangeSet<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut fold = 0u64;
        for item in self.iter() {
            let mut hasher = ahash::AHasher::default();
            item.hash(&mut hasher);
            fold ^= std::hash::Hasher::finish(&hasher);
        }
        state.write_u64(fold);
        state.write_usize(self.len_inner());
    }
}

impl<T> ChangeSet<T> {
    #[inline(always)]
    fn len_inner(&self) -> usize {
        match self {
            ChangeSet::Small(items) => items.len(),
            ChangeSet::Large(items) => items.len(),
        }
    }
}

impl<T: std::hash::Hash + Eq> ChangeSet<T> {
    #[inline(always)]
    fn contains_inner(&self, value: &T) -> bool {
        match self {
            ChangeSet::Small(items) => items.contains(value),
            ChangeSet::Large(items) => items.contains(value),
        }
    }
}

pub const PENDING_ID_MARKER: u64 = (u32::MAX as u64) << 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PendingChange {
    pub prefix: Option<PendingId>,
    pub id: PendingId,
}

#[inline(always)]
pub const fn is_pending_id(id: u64) -> bool {
    id & PENDING_ID_MARKER == PENDING_ID_MARKER
}

impl<T> Default for ChangeSet<T> {
    fn default() -> Self {
        ChangeSet::Small(Vec::new())
    }
}

pub enum ChangeSetIter<'x, T> {
    Small(std::slice::Iter<'x, T>),
    Large(std::collections::hash_set::Iter<'x, T>),
}

impl<'x, T> Iterator for ChangeSetIter<'x, T> {
    type Item = &'x T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ChangeSetIter::Small(items) => items.next(),
            ChangeSetIter::Large(items) => items.next(),
        }
    }
}

impl<T> ChangeSet<T> {
    pub fn iter(&self) -> ChangeSetIter<'_, T> {
        match self {
            ChangeSet::Small(items) => ChangeSetIter::Small(items.iter()),
            ChangeSet::Large(items) => ChangeSetIter::Large(items.iter()),
        }
    }
}

impl<'x, T> IntoIterator for &'x ChangeSet<T> {
    type Item = &'x T;
    type IntoIter = ChangeSetIter<'x, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: Copy + Eq + std::hash::Hash + Into<u64>> ChangeSet<T> {
    pub fn insert(&mut self, value: T) -> bool {
        match self {
            ChangeSet::Small(items) => {
                if items.contains(&value) {
                    return false;
                }
                items.push(value);
                if items.len() > CHANGE_SET_THRESHOLD {
                    *self = ChangeSet::Large(items.iter().copied().collect());
                }
                true
            }
            ChangeSet::Large(items) => items.insert(value),
        }
    }

    pub fn remove(&mut self, value: &T) -> bool {
        if let ChangeSet::Small(items) = self
            && items.len() > CHANGE_SET_SCAN_LIMIT
        {
            *self = ChangeSet::Large(items.iter().copied().collect());
        }

        match self {
            ChangeSet::Small(items) => {
                if let Some(pos) = items.iter().position(|item| item == value) {
                    items.swap_remove(pos);
                    true
                } else {
                    false
                }
            }
            ChangeSet::Large(items) => items.remove(value),
        }
    }

    pub fn contains(&self, value: &T) -> bool {
        match self {
            ChangeSet::Small(items) => items.contains(value),
            ChangeSet::Large(items) => items.contains(value),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            ChangeSet::Small(items) => items.len(),
            ChangeSet::Large(items) => items.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            ChangeSet::Small(items) => items.is_empty(),
            ChangeSet::Large(items) => items.is_empty(),
        }
    }

    fn collect_unsorted(&self, out: &mut Vec<u64>) {
        out.clear();
        match self {
            ChangeSet::Small(items) => out.extend(items.iter().map(|item| (*item).into())),
            ChangeSet::Large(items) => out.extend(items.iter().map(|item| (*item).into())),
        }
    }

    fn collect_sorted(&self, out: &mut Vec<u64>) {
        self.collect_unsorted(out);
        out.sort_unstable();
    }
}

#[inline(always)]
pub fn zigzag_encode(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

#[inline(always)]
pub fn zigzag_decode(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

#[derive(Default, Debug)]
pub(crate) struct ChangeLogBuilder {
    pub changes: VecMap<SyncCollection, Changes>,
    pub vanished: VecMap<VanishedCollection, VanishedItems>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum VanishedItem {
    Name(String),
    Id(u64),
}

#[derive(Default, Debug)]
pub(crate) struct VanishedItems(Vec<VanishedItem>);

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Changes {
    pub item_inserts: ChangeSet<u64>,
    pub item_updates: ChangeSet<u64>,
    pub item_deletes: ChangeSet<u64>,

    pub container_inserts: ChangeSet<u64>,
    pub container_updates: ChangeSet<u64>,
    pub container_deletes: ChangeSet<u64>,
    pub container_property_changes: ChangeSet<u64>,

    pending: IndexSet<PendingChange, RandomState>,
}

impl std::hash::Hash for Changes {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.item_inserts.hash(state);
        self.item_updates.hash(state);
        self.item_deletes.hash(state);
        self.container_inserts.hash(state);
        self.container_updates.hash(state);
        self.container_deletes.hash(state);
        self.container_property_changes.hash(state);
        state.write_usize(self.pending.len());
    }
}

impl Changes {
    fn build_id(&mut self, prefix: Option<PendingId>, document_id: PendingId) -> u64 {
        match (prefix, document_id) {
            (None, PendingId::Assigned(document_id)) => document_id as u64,
            (Some(PendingId::Assigned(prefix)), PendingId::Assigned(document_id)) => {
                debug_assert_ne!(prefix, u32::MAX, "prefix collides with the pending marker");
                ((prefix as u64) << 32) | document_id as u64
            }
            _ => {
                let change = PendingChange {
                    prefix,
                    id: document_id,
                };
                PENDING_ID_MARKER | self.pending.insert_full(change).0 as u64
            }
        }
    }

    fn resolve_id(&self, id: u64, ids: &AssignedIds) -> u64 {
        if !is_pending_id(id) {
            return id;
        }

        let Some(change) = self
            .pending
            .get_index((id & u32::MAX as u64) as usize)
            .copied()
        else {
            debug_assert!(false, "pending change is out of range");
            return id;
        };
        let document_id = change.id.resolve(ids) as u64;

        match change.prefix {
            Some(prefix) => ((prefix.resolve(ids) as u64) << 32) | document_id,
            None => document_id,
        }
    }

    #[inline(always)]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
}

impl ChangeLogBuilder {
    pub fn log_container_insert(&mut self, collection: SyncCollection, document_id: PendingId) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(None, document_id);
        if changes.container_deletes.remove(&id) {
            changes.container_updates.insert(id);
        } else {
            changes.container_inserts.insert(id);
        }
    }

    pub fn log_item_insert(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
        document_id: PendingId,
    ) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(prefix, document_id);
        if changes.item_deletes.remove(&id) {
            changes.item_updates.insert(id);
        } else {
            changes.item_inserts.insert(id);
        }
    }

    pub fn log_container_update(&mut self, collection: SyncCollection, document_id: PendingId) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(None, document_id);
        changes.container_updates.insert(id);
    }

    pub fn log_container_property_update(
        &mut self,
        collection: SyncCollection,
        document_id: PendingId,
    ) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(None, document_id);
        changes.container_property_changes.insert(id);
    }

    pub fn log_item_update(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
        document_id: PendingId,
    ) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(prefix, document_id);
        changes.item_updates.insert(id);
    }

    pub fn log_container_delete(&mut self, collection: SyncCollection, document_id: PendingId) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(None, document_id);
        changes.container_updates.remove(&id);
        changes.container_property_changes.remove(&id);
        changes.container_deletes.insert(id);
    }

    pub fn log_item_delete(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
        document_id: PendingId,
    ) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(prefix, document_id);
        changes.item_updates.remove(&id);
        changes.item_deletes.insert(id);
    }

    pub fn log_vanished_item(
        &mut self,
        collection: VanishedCollection,
        item: impl Into<VanishedItem>,
    ) {
        self.vanished
            .get_mut_or_insert(collection)
            .0
            .push(item.into());
    }
}

impl Changes {
    pub fn has_container_changes(&self) -> bool {
        !self.container_inserts.is_empty()
            || !self.container_updates.is_empty()
            || !self.container_property_changes.is_empty()
            || !self.container_deletes.is_empty()
    }

    pub fn has_item_changes(&self) -> bool {
        !self.item_inserts.is_empty()
            || !self.item_updates.is_empty()
            || !self.item_deletes.is_empty()
    }
}

impl Changes {
    pub fn serialize(&self, is_prefixed: bool, scratch: &mut Vec<u64>) -> Vec<u8> {
        debug_assert!(!self.has_pending());
        let mut buf = Vec::new();
        self.serialize_into(is_prefixed, None, scratch, &mut buf);
        buf
    }

    pub fn serialize_into(
        &self,
        is_prefixed: bool,
        ids: Option<&AssignedIds>,
        scratch: &mut Vec<u64>,
        buf: &mut Vec<u8>,
    ) {
        let container_lists = [
            (CONTAINER_INSERTS, &self.container_inserts),
            (CONTAINER_UPDATES, &self.container_updates),
            (CONTAINER_PROPERTY_CHANGES, &self.container_property_changes),
            (CONTAINER_DELETES, &self.container_deletes),
        ];
        let item_lists = [
            (ITEM_INSERTS, &self.item_inserts),
            (ITEM_UPDATES, &self.item_updates),
            (ITEM_DELETES, &self.item_deletes),
        ];

        let mut presence = 0u8;
        for (slot, list) in container_lists.iter() {
            if !list.is_empty() {
                presence |= 1 << slot;
            }
        }
        for (slot, list) in item_lists.iter() {
            if !list.is_empty() {
                presence |= 1 << slot;
            }
        }

        let containers = self.container_inserts.len()
            + self.container_updates.len()
            + self.container_property_changes.len()
            + self.container_deletes.len();
        let items = self.item_inserts.len() + self.item_updates.len() + self.item_deletes.len();

        buf.clear();
        buf.reserve(
            1 + CHANGE_LISTS
                + (containers * CONTAINER_BYTES_HINT)
                + (items
                    * if is_prefixed {
                        PREFIXED_ITEM_BYTES_HINT
                    } else {
                        ITEM_BYTES_HINT
                    }),
        );
        buf.push(presence);

        for (slot, list) in container_lists.iter() {
            if presence & (1 << slot) != 0 {
                buf.push_leb128(list.len());
            }
        }
        for (slot, list) in item_lists.iter() {
            if presence & (1 << slot) != 0 {
                buf.push_leb128(list.len());
            }
        }

        for (slot, list) in container_lists.iter() {
            if presence & (1 << slot) == 0 {
                continue;
            }
            self.collect(list, scratch, ids);

            let mut prev = 0u64;
            for id in scratch.iter() {
                buf.push_leb128(*id - prev);
                prev = *id;
            }
        }

        for (slot, list) in item_lists.iter() {
            if presence & (1 << slot) == 0 {
                continue;
            }
            self.collect(list, scratch, ids);

            if is_prefixed {
                let mut prev_prefix = 0i64;
                let mut prev_document_id = 0i64;
                for id in scratch.iter() {
                    let prefix = (*id >> 32) as i64;
                    let document_id = (*id & u32::MAX as u64) as i64;
                    buf.push_leb128((prefix - prev_prefix) as u64);
                    buf.push_leb128(zigzag_encode(document_id - prev_document_id));
                    prev_prefix = prefix;
                    prev_document_id = document_id;
                }
            } else {
                let mut prev = 0u64;
                for id in scratch.iter() {
                    buf.push_leb128(*id - prev);
                    prev = *id;
                }
            }
        }
    }

    fn collect(&self, list: &ChangeSet<u64>, scratch: &mut Vec<u64>, ids: Option<&AssignedIds>) {
        if !self.has_pending() {
            list.collect_sorted(scratch);
            return;
        }

        let ids = ids.expect("pending changes require assigned ids");
        list.collect_unsorted(scratch);
        for id in scratch.iter_mut() {
            *id = self.resolve_id(*id, ids);
        }
        scratch.sort_unstable();
    }
}

impl From<String> for VanishedItem {
    fn from(value: String) -> Self {
        VanishedItem::Name(value)
    }
}

impl From<(u32, u32)> for VanishedItem {
    fn from(value: (u32, u32)) -> Self {
        VanishedItem::Id((value.0 as u64) << 32 | value.1 as u64)
    }
}

impl VanishedItem {
    pub fn serialized_size(&self) -> usize {
        match self {
            VanishedItem::Name(name) => name.len() + U16_LEN,
            VanishedItem::Id(_) => U16_LEN,
        }
    }
}

fn shared_prefix_len(prev: &str, name: &str) -> usize {
    let prev = prev.as_bytes();
    let bytes = name.as_bytes();
    let max_len = prev.len().min(bytes.len());
    let mut len = 0;

    while len + U64_LEN <= max_len {
        let a = u64::from_le_bytes(prev[len..len + U64_LEN].try_into().unwrap());
        let b = u64::from_le_bytes(bytes[len..len + U64_LEN].try_into().unwrap());
        if a != b {
            len += (a ^ b).trailing_zeros() as usize / 8;
            break;
        }
        len += U64_LEN;
    }
    while len < max_len && prev[len] == bytes[len] {
        len += 1;
    }
    while len > 0 && !name.is_char_boundary(len) {
        len -= 1;
    }

    len
}

impl VanishedItems {
    pub fn serialize(&self, is_named: bool, scratch: &mut Vec<u64>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(if is_named {
            self.0.iter().map(|item| item.serialized_size()).sum()
        } else {
            self.0.len() * VANISHED_ID_BYTES_HINT + U64_LEN
        });

        if is_named {
            let mut prev: Option<&str> = None;

            for item in &self.0 {
                match item {
                    VanishedItem::Name(name) => {
                        if let Some(prev) = prev {
                            let shared = shared_prefix_len(prev, name);
                            buf.push_leb128(shared);
                            buf.push_leb128(name.len() - shared);
                            buf.extend_from_slice(&name.as_bytes()[shared..]);
                        } else {
                            buf.push_leb128(name.len());
                            buf.extend_from_slice(name.as_bytes());
                        }
                        prev = Some(name);
                    }
                    VanishedItem::Id(_) => {
                        debug_assert!(false, "id logged for a name-based vanished collection");
                    }
                }
            }

            return buf;
        }

        scratch.clear();
        scratch.extend(self.0.iter().filter_map(|item| match item {
            VanishedItem::Id(id) => Some(*id),
            VanishedItem::Name(_) => {
                debug_assert!(false, "name logged for an id-based vanished collection");
                None
            }
        }));
        scratch.sort_unstable();
        scratch.dedup();

        let mut pos = 0;
        let mut prev_group = 0u64;
        while pos < scratch.len() {
            let group = scratch[pos] >> 32;
            let mut end = pos;
            while end < scratch.len() && scratch[end] >> 32 == group {
                end += 1;
            }

            buf.push_leb128(group - prev_group);
            buf.push_leb128(end - pos);

            let mut prev_id = 0u64;
            for id in &scratch[pos..end] {
                let id = *id & u32::MAX as u64;
                buf.push_leb128(id - prev_id);
                prev_id = id;
            }

            prev_group = group;
            pos = end;
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::log::Change;

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0 >> 16
        }
    }

    fn roundtrip(changes: &Changes, is_prefixed: bool) {
        let mut scratch = Vec::new();
        let bytes = changes.serialize(is_prefixed, &mut scratch);
        let mut decoded = crate::query::log::Changes::default();
        let (has_container, has_item) = decoded
            .deserialize(&bytes, is_prefixed)
            .expect("failed to decode");

        assert_eq!(has_container, changes.has_container_changes());
        assert_eq!(has_item, changes.has_item_changes());
        decoded.finalize();

        let mut expected = Vec::new();
        for id in &changes.container_inserts {
            if !changes.container_deletes.contains(id) {
                expected.push(Change::InsertContainer(*id));
            }
        }
        for id in &changes.container_updates {
            if !changes.container_inserts.contains(id) && !changes.container_deletes.contains(id) {
                expected.push(Change::UpdateContainer(*id));
            }
        }
        for id in &changes.container_property_changes {
            if !changes.container_inserts.contains(id)
                && !changes.container_updates.contains(id)
                && !changes.container_deletes.contains(id)
            {
                expected.push(Change::UpdateContainerProperty(*id));
            }
        }
        for id in &changes.container_deletes {
            if !changes.container_inserts.contains(id) {
                expected.push(Change::DeleteContainer(*id));
            }
        }
        for id in &changes.item_inserts {
            if !changes.item_deletes.contains(id) {
                expected.push(Change::InsertItem(*id));
            }
        }
        for id in &changes.item_updates {
            if !changes.item_inserts.contains(id) && !changes.item_deletes.contains(id) {
                expected.push(Change::UpdateItem(*id));
            }
        }
        for id in &changes.item_deletes {
            if !changes.item_inserts.contains(id) {
                expected.push(Change::DeleteItem(*id));
            }
        }

        let mut got = decoded.changes.clone();
        expected.sort_by_key(|c| format!("{c:?}"));
        got.sort_by_key(|c| format!("{c:?}"));
        assert_eq!(expected, got, "roundtrip mismatch, prefixed={is_prefixed}");
    }

    #[test]
    fn changelog_roundtrip_boundaries() {
        let ids = [
            0u64,
            1,
            u32::MAX as u64,
            1u64 << 32,
            (1u64 << 32) | 5,
            (5u64 << 32) | 1,
            ((u32::MAX as u64) << 32) | u32::MAX as u64,
            ((u32::MAX as u64) << 32),
            (10u64 << 32) | 500,
            (11u64 << 32) | 20,
        ];

        for window in 0..=ids.len() {
            for is_prefixed in [true, false] {
                let mut changes = Changes::default();
                for id in &ids[..window] {
                    changes.item_inserts.insert(*id);
                }
                roundtrip(&changes, is_prefixed);

                let mut changes = Changes::default();
                for id in &ids[..window] {
                    changes.item_updates.insert(*id);
                    changes.item_deletes.insert(id.wrapping_add(1));
                }
                roundtrip(&changes, is_prefixed);
            }
        }
    }

    #[test]
    fn changelog_roundtrip_empty_and_single_lists() {
        roundtrip(&Changes::default(), true);
        roundtrip(&Changes::default(), false);

        for slot in 0..CHANGE_LISTS {
            let mut changes = Changes::default();
            match slot {
                0 => {
                    changes.container_inserts.insert(7);
                }
                1 => {
                    changes.container_updates.insert(7);
                }
                2 => {
                    changes.container_property_changes.insert(7);
                }
                3 => {
                    changes.container_deletes.insert(7);
                }
                4 => {
                    changes.item_inserts.insert((3u64 << 32) | 9);
                }
                5 => {
                    changes.item_updates.insert((3u64 << 32) | 9);
                }
                _ => {
                    changes.item_deletes.insert((3u64 << 32) | 9);
                }
            }
            roundtrip(&changes, true);
        }
    }

    #[test]
    fn changelog_roundtrip_random() {
        let mut lcg = Lcg(0x5eed);

        for _ in 0..400 {
            let mut changes = Changes::default();
            let n = (lcg.next() % 40) as usize;

            for _ in 0..n {
                let document_id = lcg.next() % 500_000;
                let thread_id = if lcg.next() % 10 < 7 {
                    document_id
                } else {
                    document_id.saturating_sub(lcg.next() % 5_000)
                };
                let id = (thread_id << 32) | document_id;

                match lcg.next() % 3 {
                    0 => {
                        changes.item_inserts.insert(id);
                    }
                    1 => {
                        changes.item_updates.insert(id);
                    }
                    _ => {
                        changes.item_deletes.insert(id);
                    }
                }

                match lcg.next() % 4 {
                    0 => {
                        changes.container_inserts.insert(lcg.next() % 1000);
                    }
                    1 => {
                        changes.container_updates.insert(lcg.next() % 1000);
                    }
                    2 => {
                        changes.container_property_changes.insert(lcg.next() % 1000);
                    }
                    _ => {
                        changes.container_deletes.insert(lcg.next() % 1000);
                    }
                }
            }

            roundtrip(&changes, true);
        }
    }

    #[test]
    fn change_set_matches_hash_set() {
        let mut lcg = Lcg(0xc0ffee);

        for rounds in [1usize, 8, 63, 64, 65, 200, 1000] {
            let mut subject = ChangeSet::<u64>::default();
            let mut reference = AHashSet::new();

            for _ in 0..rounds {
                let value = lcg.next() % 300;
                assert_eq!(
                    subject.insert(value),
                    reference.insert(value),
                    "insert disagreed at n={rounds}"
                );

                let victim = lcg.next() % 300;
                assert_eq!(
                    subject.remove(&victim),
                    reference.remove(&victim),
                    "remove disagreed at n={rounds}"
                );

                assert_eq!(subject.len(), reference.len());
                assert_eq!(subject.is_empty(), reference.is_empty());
                assert_eq!(subject.contains(&value), reference.contains(&value));
            }

            let mut got = Vec::new();
            subject.collect_sorted(&mut got);
            let mut want: Vec<u64> = reference.iter().copied().collect();
            want.sort_unstable();
            assert_eq!(want, got, "contents diverged at n={rounds}");

            assert!(
                subject.len() <= CHANGE_SET_THRESHOLD || matches!(subject, ChangeSet::Large(_)),
                "a set larger than the threshold must not stay linear (n={rounds})"
            );
        }
    }

    #[test]
    fn changelog_roundtrip_across_threshold() {
        for n in [
            CHANGE_SET_THRESHOLD - 1,
            CHANGE_SET_THRESHOLD,
            CHANGE_SET_THRESHOLD + 1,
            CHANGE_SET_THRESHOLD * 4,
        ] {
            let mut changes = Changes::default();
            for idx in 0..n as u64 {
                let document_id = 400_000 + idx;
                let thread_id = if idx % 3 == 0 {
                    document_id
                } else {
                    document_id - (idx % 977)
                };
                changes.item_inserts.insert((thread_id << 32) | document_id);
                changes.container_property_changes.insert(idx % 50);
            }
            roundtrip(&changes, true);

            let mut changes = Changes::default();
            for idx in 0..n as u64 {
                changes.item_deletes.insert((idx << 32) | (n as u64 - idx));
                changes.container_deletes.insert(idx);
            }
            roundtrip(&changes, true);
        }
    }

    #[test]
    fn changelog_roundtrip_unprefixed() {
        let mut lcg = Lcg(0xd1ce);

        for _ in 0..200 {
            let mut changes = Changes::default();
            for _ in 0..(lcg.next() % 30) {
                changes.item_inserts.insert(lcg.next() % 100_000);
                changes.container_deletes.insert(lcg.next() % 5_000);
            }
            roundtrip(&changes, false);
        }
    }

    fn vanished_ids_roundtrip(ids: &[u64]) {
        let mut scratch = Vec::new();
        let items = VanishedItems(ids.iter().map(|id| VanishedItem::Id(*id)).collect());
        let bytes = items.serialize(false, &mut scratch);

        let mut decoded = Vec::new();
        <(u32, u32) as crate::query::log::DeserializeVanished>::deserialize_vanished(
            &bytes,
            &mut decoded,
        )
        .expect("failed to decode vanished ids");

        let mut want: Vec<(u32, u32)> = ids
            .iter()
            .map(|id| ((*id >> 32) as u32, (*id & u32::MAX as u64) as u32))
            .collect();
        want.sort_unstable();
        want.dedup();

        let mut got = decoded.clone();
        got.sort_unstable();
        assert_eq!(want, got, "vanished id roundtrip failed");

        for mailbox_id in want.iter().map(|(m, _)| *m).chain([0, 1, 7, u32::MAX]) {
            let mut uids = Vec::new();
            crate::query::log::decode_vanished_uids(&bytes, mailbox_id, &mut uids)
                .expect("failed to skip-decode");
            uids.sort_unstable();

            let mut expected: Vec<u32> = want
                .iter()
                .filter(|(m, _)| *m == mailbox_id)
                .map(|(_, u)| *u)
                .collect();
            expected.sort_unstable();
            assert_eq!(
                expected, uids,
                "skip-decode disagreed for mailbox {mailbox_id}"
            );
        }
    }

    #[test]
    fn vanished_ids_boundaries() {
        let mut lcg = Lcg(0xbeef);

        for ids in [
            vec![],
            vec![0u64],
            vec![u64::MAX],
            vec![(u32::MAX as u64) << 32],
            vec![u32::MAX as u64],
            vec![((7u64) << 32) | 1, (7u64 << 32) | 2, (7u64 << 32) | 3],
            vec![(1u64 << 32) | 500, (2u64 << 32) | 20],
            vec![(9u64 << 32) | 5, (9u64 << 32) | 5],
            vec![(3u64 << 32) | 9, (1u64 << 32) | 4, (2u64 << 32) | 77],
        ] {
            vanished_ids_roundtrip(&ids);
        }

        for _ in 0..200 {
            let n = (lcg.next() % 60) as usize;
            let ids: Vec<u64> = (0..n)
                .map(|_| {
                    let mailbox = lcg.next() % 8;
                    let uid = lcg.next() % 5_000;
                    (mailbox << 32) | uid
                })
                .collect();
            vanished_ids_roundtrip(&ids);
        }
    }

    #[test]
    fn vanished_names_roundtrip() {
        let mut scratch = Vec::new();

        for names in [
            vec![],
            vec![String::new()],
            vec!["/dav/cal/john.doe/personal/aB3xK9qLm7".to_string()],
            vec![
                "/dav/cal/john.doe/personal/aB3xK9qLm7".to_string(),
                "/dav/cal/john.doe/personal/".to_string(),
                "x".repeat(200),
                "unicode-\u{1F600}-name".to_string(),
            ],
            vec![
                "/dav/cal/john.doe/personal/aB3xK9qLm7.ics".to_string(),
                "/dav/cal/john.doe/personal/aB3xK9qLm8.ics".to_string(),
                "/dav/cal/john.doe/personal/zZ9yT2wVn4.ics".to_string(),
                "/dav/cal/john.doe/work/aB3xK9qLm7.ics".to_string(),
            ],
            vec![String::new(), String::new(), String::new()],
            vec![
                "/dav/cal/jos\u{e9}/caf\u{e9}".to_string(),
                "/dav/cal/jos\u{e9}/caf\u{e8}".to_string(),
                "/dav/cal/jos\u{e9}/caf\u{e9}\u{1F600}".to_string(),
                "/dav/cal/jos\u{e9}/caf\u{e9}\u{1F601}".to_string(),
            ],
            (0..300)
                .map(|i| format!("/dav/file/john.doe/Documents/Projects/{i}/report.pdf"))
                .collect(),
        ] {
            let items = VanishedItems(
                names
                    .iter()
                    .map(|name| VanishedItem::Name(name.clone()))
                    .collect(),
            );
            let bytes = items.serialize(true, &mut scratch);

            let mut decoded = Vec::new();
            <String as crate::query::log::DeserializeVanished>::deserialize_vanished(
                &bytes,
                &mut decoded,
            )
            .expect("failed to decode vanished names");

            assert_eq!(names, decoded, "vanished name roundtrip failed");
        }
    }

    #[test]
    fn vanished_names_survive_embedded_nul() {
        let mut scratch = Vec::new();
        let names = vec![
            "before\u{0}after".to_string(),
            "/dav/file/john.doe/a\u{0}b".to_string(),
        ];
        let items = VanishedItems(
            names
                .iter()
                .map(|name| VanishedItem::Name(name.clone()))
                .collect(),
        );

        let mut decoded = Vec::new();
        <String as crate::query::log::DeserializeVanished>::deserialize_vanished(
            &items.serialize(true, &mut scratch),
            &mut decoded,
        )
        .expect("failed to decode names containing NUL");

        assert_eq!(names, decoded, "a NUL byte must not split a path");
    }

    #[test]
    fn vanished_names_do_not_share_across_log_entries() {
        let mut scratch = Vec::new();
        let entries = [
            vec![
                "/dav/cal/john.doe/personal/aB3xK9qLm7.ics".to_string(),
                "/dav/cal/john.doe/personal/aB3xK9qLm8.ics".to_string(),
            ],
            vec!["/x".to_string(), "/y".to_string()],
            vec!["/dav/card/john.doe/contacts/zZ9.vcf".to_string()],
        ];

        let mut decoded = Vec::new();
        for names in &entries {
            let items = VanishedItems(
                names
                    .iter()
                    .map(|name| VanishedItem::Name(name.clone()))
                    .collect(),
            );
            <String as crate::query::log::DeserializeVanished>::deserialize_vanished(
                &items.serialize(true, &mut scratch),
                &mut decoded,
            )
            .expect("failed to decode vanished names");
        }

        assert_eq!(
            entries.concat(),
            decoded,
            "prefixes must not carry over between log entries"
        );
    }

    #[test]
    fn vanished_names_reject_corrupt_prefix() {
        for bytes in [
            vec![0x02, b'/', b'a', 0x09, 0x00],
            vec![0x02, b'/', b'a', 0x02, 0x05],
            vec![0x05],
            vec![0x02, b'/'],
        ] {
            let mut decoded = Vec::new();
            assert!(
                <String as crate::query::log::DeserializeVanished>::deserialize_vanished(
                    &bytes,
                    &mut decoded,
                )
                .is_none(),
                "corrupt payload {bytes:?} decoded as {decoded:?}"
            );
        }
    }

    fn accumulate(rows: &[Changes], is_prefixed: bool) -> Vec<Change> {
        let mut scratch = Vec::new();
        let mut decoded = crate::query::log::Changes::default();
        for row in rows {
            decoded
                .deserialize(&row.serialize(is_prefixed, &mut scratch), is_prefixed)
                .expect("failed to decode");
        }
        decoded.finalize();
        decoded.changes
    }

    fn container_row(slot: usize, id: u64) -> Changes {
        let mut changes = Changes::default();
        match slot {
            CONTAINER_INSERTS => changes.container_inserts.insert(id),
            CONTAINER_UPDATES => changes.container_updates.insert(id),
            CONTAINER_PROPERTY_CHANGES => changes.container_property_changes.insert(id),
            _ => changes.container_deletes.insert(id),
        };
        changes
    }

    fn item_row(slot: usize, id: u64) -> Changes {
        let mut changes = Changes::default();
        match slot {
            ITEM_INSERTS => changes.item_inserts.insert(id),
            ITEM_UPDATES => changes.item_updates.insert(id),
            _ => changes.item_deletes.insert(id),
        };
        changes
    }

    #[test]
    fn changelog_precedence_across_rows() {
        let id = 7u64;

        let cases: [(usize, usize, Option<Change>); 12] = [
            (
                CONTAINER_INSERTS,
                CONTAINER_UPDATES,
                Some(Change::InsertContainer(7)),
            ),
            (
                CONTAINER_INSERTS,
                CONTAINER_PROPERTY_CHANGES,
                Some(Change::InsertContainer(7)),
            ),
            (CONTAINER_INSERTS, CONTAINER_DELETES, None),
            (
                CONTAINER_UPDATES,
                CONTAINER_PROPERTY_CHANGES,
                Some(Change::UpdateContainer(7)),
            ),
            (
                CONTAINER_UPDATES,
                CONTAINER_DELETES,
                Some(Change::DeleteContainer(7)),
            ),
            (
                CONTAINER_PROPERTY_CHANGES,
                CONTAINER_UPDATES,
                Some(Change::UpdateContainer(7)),
            ),
            (
                CONTAINER_PROPERTY_CHANGES,
                CONTAINER_DELETES,
                Some(Change::DeleteContainer(7)),
            ),
            (
                CONTAINER_DELETES,
                CONTAINER_UPDATES,
                Some(Change::DeleteContainer(7)),
            ),
            (
                CONTAINER_DELETES,
                CONTAINER_PROPERTY_CHANGES,
                Some(Change::DeleteContainer(7)),
            ),
            (
                CONTAINER_INSERTS,
                CONTAINER_INSERTS,
                Some(Change::InsertContainer(7)),
            ),
            (
                CONTAINER_UPDATES,
                CONTAINER_UPDATES,
                Some(Change::UpdateContainer(7)),
            ),
            (
                CONTAINER_DELETES,
                CONTAINER_DELETES,
                Some(Change::DeleteContainer(7)),
            ),
        ];

        for (first, second, expected) in cases {
            let got = accumulate(
                &[container_row(first, id), container_row(second, id)],
                false,
            );
            let want: Vec<Change> = expected.into_iter().collect();
            assert_eq!(want, got, "container precedence {first} then {second}");
        }

        let id = (3u64 << 32) | 9;

        let cases: [(usize, usize, Option<Change>); 8] = [
            (ITEM_INSERTS, ITEM_UPDATES, Some(Change::InsertItem(id))),
            (ITEM_INSERTS, ITEM_DELETES, None),
            (ITEM_UPDATES, ITEM_DELETES, Some(Change::DeleteItem(id))),
            (ITEM_DELETES, ITEM_UPDATES, Some(Change::DeleteItem(id))),
            (ITEM_UPDATES, ITEM_UPDATES, Some(Change::UpdateItem(id))),
            (ITEM_DELETES, ITEM_DELETES, Some(Change::DeleteItem(id))),
            (ITEM_INSERTS, ITEM_INSERTS, Some(Change::InsertItem(id))),
            (ITEM_UPDATES, ITEM_INSERTS, Some(Change::InsertItem(id))),
        ];

        for (first, second, expected) in cases {
            let got = accumulate(&[item_row(first, id), item_row(second, id)], true);
            let want: Vec<Change> = expected.into_iter().collect();
            assert_eq!(want, got, "item precedence {first} then {second}");
        }
    }

    #[test]
    fn changelog_delete_survives_later_property_change() {
        let got = accumulate(
            &[
                container_row(CONTAINER_DELETES, 4),
                container_row(CONTAINER_PROPERTY_CHANGES, 4),
                container_row(CONTAINER_PROPERTY_CHANGES, 4),
            ],
            false,
        );

        assert_eq!(
            vec![Change::DeleteContainer(4)],
            got,
            "a destroyed container must not be downgraded to a property change"
        );
    }

    #[test]
    fn changelog_never_serializes_to_an_empty_value() {
        let mut scratch = Vec::new();

        for is_prefixed in [true, false] {
            assert!(
                !Changes::default()
                    .serialize(is_prefixed, &mut scratch)
                    .is_empty(),
                "an empty changelog row must not collide with the truncation marker"
            );

            for slot in 0..CHANGE_LISTS {
                let mut changes = Changes::default();
                match slot {
                    CONTAINER_INSERTS => changes.container_inserts.insert(0),
                    CONTAINER_UPDATES => changes.container_updates.insert(0),
                    CONTAINER_PROPERTY_CHANGES => changes.container_property_changes.insert(0),
                    CONTAINER_DELETES => changes.container_deletes.insert(0),
                    ITEM_INSERTS => changes.item_inserts.insert(0),
                    ITEM_UPDATES => changes.item_updates.insert(0),
                    _ => changes.item_deletes.insert(0),
                };
                assert!(
                    !changes.serialize(is_prefixed, &mut scratch).is_empty(),
                    "a row holding only id 0 must not serialize to an empty value"
                );
            }
        }
    }

    #[test]
    fn vanished_names_split_multibyte_characters() {
        let mut scratch = Vec::new();

        for names in [
            vec![
                "/dav/cal/u/Caf\u{e9}/x".to_string(),
                "/dav/cal/u/Caf\u{e8}/y".to_string(),
            ],
            vec!["a\u{e9}x".to_string(), "a\u{eb}y".to_string()],
            vec![
                "\u{65e5}\u{672c}".to_string(),
                "\u{65e5}\u{4e2d}".to_string(),
            ],
            vec!["\u{1F600}a".to_string(), "\u{1F601}b".to_string()],
            vec!["prefix".to_string(), "prefix\u{e9}".to_string()],
            vec!["prefix\u{e9}".to_string(), "prefix".to_string()],
            vec!["\u{e9}".to_string(), "\u{e9}".to_string()],
            vec!["".to_string(), "\u{e9}".to_string()],
            vec![
                "/dav/file/u/\u{4e2d}\u{6587}/a".to_string(),
                "/dav/file/u/\u{4e2d}\u{56fd}/b".to_string(),
                "/dav/file/u/\u{4e2d}\u{6587}/c".to_string(),
            ],
        ] {
            let items = VanishedItems(
                names
                    .iter()
                    .map(|n| VanishedItem::Name(n.clone()))
                    .collect(),
            );
            let bytes = items.serialize(true, &mut scratch);

            let mut decoded = Vec::new();
            <String as crate::query::log::DeserializeVanished>::deserialize_vanished(
                &bytes,
                &mut decoded,
            )
            .unwrap_or_else(|| panic!("failed to decode {names:?}"));

            assert_eq!(names, decoded, "multibyte roundtrip failed");
        }
    }
}
