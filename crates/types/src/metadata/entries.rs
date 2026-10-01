/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::builder::EntryKey;
use std::{
    borrow::Cow,
    collections::{BTreeMap, btree_map},
    mem,
};

const TREE_THRESHOLD: usize = 256;

type Value<'x> = Cow<'x, [u8]>;

#[derive(Debug, Clone)]
pub(super) struct Entry<'x> {
    pub(super) key: EntryKey<'x>,
    pub(super) value: Value<'x>,
}

#[derive(Debug, Clone)]
pub(super) enum Entries<'x> {
    List(Vec<Entry<'x>>),
    Tree(BTreeMap<EntryKey<'x>, Value<'x>>),
}

impl Default for Entries<'_> {
    fn default() -> Self {
        Entries::List(Vec::new())
    }
}

impl<'x> Entries<'x> {
    pub(super) fn from_list(mut list: Vec<Entry<'x>>) -> Self {
        if !list.is_sorted_by(|a, b| a.key < b.key) {
            list.sort_unstable_by(|a, b| a.key.cmp(&b.key));
            list.dedup_by(|a, b| a.key == b.key);
        }
        if list.len() > TREE_THRESHOLD {
            Entries::Tree(into_tree(list))
        } else {
            Entries::List(list)
        }
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Entries::List(list) => list.len(),
            Entries::Tree(tree) => tree.len(),
        }
    }

    pub(super) fn get(&self, key: &EntryKey<'_>) -> Option<&[u8]> {
        match self {
            Entries::List(list) => list
                .binary_search_by(|entry| entry.key.cmp(key))
                .ok()
                .and_then(|position| list.get(position))
                .map(|entry| entry.value.as_ref()),
            Entries::Tree(tree) => tree.get(&key.clone().into_owned()).map(AsRef::as_ref),
        }
    }

    pub(super) fn upsert(&mut self, key: EntryKey<'x>, value: Value<'x>) -> bool {
        match self {
            Entries::List(list) => match list.binary_search_by(|entry| entry.key.cmp(&key)) {
                Ok(position) => list
                    .get_mut(position)
                    .is_some_and(|entry| replace(&mut entry.value, value)),
                Err(position) => {
                    list.insert(position, Entry { key, value });
                    if list.len() > TREE_THRESHOLD {
                        *self = Entries::Tree(into_tree(mem::take(list)));
                    }
                    true
                }
            },
            Entries::Tree(tree) => match tree.entry(key) {
                btree_map::Entry::Occupied(mut entry) => replace(entry.get_mut(), value),
                btree_map::Entry::Vacant(entry) => {
                    entry.insert(value);
                    true
                }
            },
        }
    }

    pub(super) fn remove(&mut self, key: &EntryKey<'_>) -> bool {
        match self {
            Entries::List(list) => match list.binary_search_by(|entry| entry.key.cmp(key)) {
                Ok(position) => {
                    list.remove(position);
                    true
                }
                Err(_) => false,
            },
            Entries::Tree(tree) => tree.remove(&key.clone().into_owned()).is_some(),
        }
    }

    pub(super) fn retain(&mut self, mut keep: impl FnMut(&EntryKey<'x>) -> bool) {
        match self {
            Entries::List(list) => list.retain(|entry| keep(&entry.key)),
            Entries::Tree(tree) => tree.retain(|key, _| keep(key)),
        }
    }

    pub(super) fn into_owned(self) -> Entries<'static> {
        match self {
            Entries::List(list) => Entries::List(
                list.into_iter()
                    .map(|entry| Entry {
                        key: entry.key.into_owned(),
                        value: Cow::Owned(entry.value.into_owned()),
                    })
                    .collect(),
            ),
            Entries::Tree(tree) => Entries::Tree(
                tree.into_iter()
                    .map(|(key, value)| (key.into_owned(), Cow::Owned(value.into_owned())))
                    .collect(),
            ),
        }
    }
}

#[cold]
#[inline(never)]
fn into_tree<'x>(list: Vec<Entry<'x>>) -> BTreeMap<EntryKey<'x>, Value<'x>> {
    list.into_iter()
        .map(|entry| (entry.key, entry.value))
        .collect()
}

fn replace<'x>(current: &mut Value<'x>, value: Value<'x>) -> bool {
    if *current != value {
        *current = value;
        true
    } else {
        false
    }
}
