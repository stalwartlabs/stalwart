/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::key::KeySerializer;
use crate::{SerializeInfallible, U64_LEN};
use ahash::AHashSet;
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

#[derive(Debug)]
pub enum ChangeSet<T> {
    Small(Vec<T>),
    Large(AHashSet<T>),
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

    fn collect_sorted(&self, out: &mut Vec<u64>) {
        out.clear();
        match self {
            ChangeSet::Small(items) => out.extend(items.iter().map(|item| (*item).into())),
            ChangeSet::Large(items) => out.extend(items.iter().map(|item| (*item).into())),
        }
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
    IdPair(u32, u32),
}

#[derive(Default, Debug)]
pub(crate) struct VanishedItems(Vec<VanishedItem>);

#[derive(Default, Debug)]
pub struct Changes {
    pub item_inserts: ChangeSet<u64>,
    pub item_updates: ChangeSet<u64>,
    pub item_deletes: ChangeSet<u64>,

    pub container_inserts: ChangeSet<u32>,
    pub container_updates: ChangeSet<u32>,
    pub container_deletes: ChangeSet<u32>,
    pub container_property_changes: ChangeSet<u32>,
}

impl ChangeLogBuilder {
    pub fn log_container_insert(&mut self, collection: SyncCollection, document_id: u32) {
        let changes = self.changes.get_mut_or_insert(collection);
        if changes.container_deletes.remove(&document_id) {
            changes.container_updates.insert(document_id);
        } else {
            changes.container_inserts.insert(document_id);
        }
    }

    pub fn log_item_insert(
        &mut self,
        collection: SyncCollection,
        prefix: Option<u32>,
        document_id: u32,
    ) {
        let id = build_id(prefix, document_id);
        let changes = self.changes.get_mut_or_insert(collection);
        if changes.item_deletes.remove(&id) {
            changes.item_updates.insert(id);
        } else {
            changes.item_inserts.insert(id);
        }
    }

    pub fn log_container_update(&mut self, collection: SyncCollection, document_id: u32) {
        self.changes
            .get_mut_or_insert(collection)
            .container_updates
            .insert(document_id);
    }

    pub fn log_container_property_update(&mut self, collection: SyncCollection, document_id: u32) {
        self.changes
            .get_mut_or_insert(collection)
            .container_property_changes
            .insert(document_id);
    }

    pub fn log_item_update(
        &mut self,
        collection: SyncCollection,
        prefix: Option<u32>,
        document_id: u32,
    ) {
        self.changes
            .get_mut_or_insert(collection)
            .item_updates
            .insert(build_id(prefix, document_id));
    }

    pub fn log_container_delete(&mut self, collection: SyncCollection, document_id: u32) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = document_id;
        changes.container_updates.remove(&id);
        changes.container_property_changes.remove(&id);
        changes.container_deletes.insert(id);
    }

    pub fn log_item_delete(
        &mut self,
        collection: SyncCollection,
        prefix: Option<u32>,
        document_id: u32,
    ) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = build_id(prefix, document_id);
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

#[inline(always)]
fn build_id(prefix: Option<u32>, document_id: u32) -> u64 {
    if let Some(prefix) = prefix {
        ((prefix as u64) << 32) | document_id as u64
    } else {
        document_id as u64
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

        let mut buf = Vec::with_capacity(
            1 + (self.item_inserts.len()
                + self.item_updates.len()
                + self.item_deletes.len()
                + self.container_inserts.len()
                + self.container_updates.len()
                + self.container_property_changes.len()
                + self.container_deletes.len()
                + 4)
                * std::mem::size_of::<usize>(),
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
            list.collect_sorted(scratch);

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
            list.collect_sorted(scratch);

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

        buf
    }
}

impl From<String> for VanishedItem {
    fn from(value: String) -> Self {
        VanishedItem::Name(value)
    }
}

impl From<u64> for VanishedItem {
    fn from(value: u64) -> Self {
        VanishedItem::Id(value)
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
            VanishedItem::Name(name) => name.len() + 1,
            VanishedItem::Id(_) | VanishedItem::IdPair(..) => U64_LEN,
        }
    }
}

impl SerializeInfallible for VanishedItems {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = KeySerializer::new(64);

        for item in &self.0 {
            buf = match item {
                VanishedItem::Name(name) => buf.write(name.as_bytes()).write(0u8),
                VanishedItem::Id(id) => buf.write(id.to_be_bytes().as_slice()),
                VanishedItem::IdPair(a, b) => buf
                    .write(a.to_be_bytes().as_slice())
                    .write(b.to_be_bytes().as_slice()),
            };
        }

        buf.finalize()
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
                expected.push(Change::InsertContainer(*id as u64));
            }
        }
        for id in &changes.container_updates {
            if !changes.container_inserts.contains(id) && !changes.container_deletes.contains(id) {
                expected.push(Change::UpdateContainer(*id as u64));
            }
        }
        for id in &changes.container_property_changes {
            if !changes.container_inserts.contains(id)
                && !changes.container_updates.contains(id)
                && !changes.container_deletes.contains(id)
            {
                expected.push(Change::UpdateContainerProperty(*id as u64));
            }
        }
        for id in &changes.container_deletes {
            if !changes.container_inserts.contains(id) {
                expected.push(Change::DeleteContainer(*id as u64));
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
                        changes.container_inserts.insert((lcg.next() % 1000) as u32);
                    }
                    1 => {
                        changes.container_updates.insert((lcg.next() % 1000) as u32);
                    }
                    2 => {
                        changes
                            .container_property_changes
                            .insert((lcg.next() % 1000) as u32);
                    }
                    _ => {
                        changes.container_deletes.insert((lcg.next() % 1000) as u32);
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
                changes.container_property_changes.insert((idx % 50) as u32);
            }
            roundtrip(&changes, true);

            let mut changes = Changes::default();
            for idx in 0..n as u64 {
                changes.item_deletes.insert((idx << 32) | (n as u64 - idx));
                changes.container_deletes.insert(idx as u32);
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
                changes
                    .container_deletes
                    .insert((lcg.next() % 5_000) as u32);
            }
            roundtrip(&changes, false);
        }
    }
}
