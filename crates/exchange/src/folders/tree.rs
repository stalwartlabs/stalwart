/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ContainerClass, FolderNode, SpecialFolder};
use crate::store::{FolderKind, FolderRef};
use ahash::AHashMap;
use std::{collections::hash_map::Entry, sync::Arc};
use store::xxhash_rust::xxh3::{xxh3_64, xxh3_64_with_seed};

const STORED_SET_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScopeKinds(u8);

impl ScopeKinds {
    const ITEMS: ScopeKinds = ScopeKinds(
        Self::bit(FolderKind::Mailbox)
            | Self::bit(FolderKind::Calendar)
            | Self::bit(FolderKind::AddressBook),
    );

    const fn bit(kind: FolderKind) -> u8 {
        1 << kind as u8
    }

    pub const fn contains(self, kind: FolderKind) -> bool {
        self.0 & Self::bit(kind) != 0
    }

    const fn covers_items(self) -> bool {
        self.0 & Self::ITEMS.0 == Self::ITEMS.0
    }

    fn insert(&mut self, node: FolderNode) {
        if let FolderNode::Stored(FolderRef { kind, .. }) = node {
            self.0 |= Self::bit(kind) & Self::ITEMS.0;
        }
    }

    fn union(&mut self, other: ScopeKinds) {
        self.0 |= other.0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderEntry {
    pub node: FolderNode,
    pub parent: Option<FolderNode>,
    pub name: Arc<str>,
    pub class: ContainerClass,
    pub special: Option<SpecialFolder>,
    pub ipm: bool,
    pub search: bool,
    pub scope: ScopeKinds,
    pub change_id: u64,
    subtree_end: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct HierarchyVersion {
    pub mail: u64,
    pub calendar: u64,
    pub address_book: u64,
    pub virtual_change: u64,
    pub virtual_horizon: u64,
    pub virtual_count: u32,
    pub default_calendar: Option<u32>,
    pub default_address_book: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct FolderTree {
    entries: Vec<FolderEntry>,
    index: AHashMap<FolderNode, u32>,
    specials: Vec<(SpecialFolder, u32)>,
    virtual_deletions: Vec<(u32, u64)>,
    virtual_modified: Vec<(u32, u64)>,
    version: HierarchyVersion,
}

impl FolderTree {
    pub fn iter(&self) -> impl Iterator<Item = &FolderEntry> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, node: FolderNode) -> Option<&FolderEntry> {
        self.index
            .get(&node)
            .and_then(|&pos| self.entries.get(pos as usize))
    }

    pub fn position(&self, node: FolderNode) -> Option<usize> {
        self.index.get(&node).map(|&pos| pos as usize)
    }

    pub fn special(&self, folder: SpecialFolder) -> Option<&FolderEntry> {
        self.specials
            .iter()
            .find(|(special, _)| *special == folder)
            .and_then(|&(_, pos)| self.entries.get(pos as usize))
    }

    pub fn children(&self, node: FolderNode) -> impl Iterator<Item = &FolderEntry> {
        let (mut next, end) = self
            .index
            .get(&node)
            .and_then(|&pos| {
                self.entries
                    .get(pos as usize)
                    .map(|entry| (pos + 1, entry.subtree_end))
            })
            .unwrap_or_default();
        std::iter::from_fn(move || {
            let entry = (next < end)
                .then(|| self.entries.get(next as usize))
                .flatten()?;
            next = entry.subtree_end;
            Some(entry)
        })
    }

    pub fn descendants(&self, node: FolderNode) -> impl Iterator<Item = &FolderEntry> + Clone {
        self.index
            .get(&node)
            .and_then(|&pos| {
                let entry = self.entries.get(pos as usize)?;
                self.entries
                    .get(pos as usize + 1..entry.subtree_end as usize)
            })
            .unwrap_or_default()
            .iter()
    }

    pub fn in_subtree(&self, root: FolderNode, node: FolderNode) -> bool {
        root == node
            || match (self.index.get(&root), self.index.get(&node)) {
                (Some(&root), Some(&node)) => self
                    .entries
                    .get(root as usize)
                    .is_some_and(|entry| root < node && node < entry.subtree_end),
                _ => false,
            }
    }

    fn scope_kinds(&self, scope: FolderNode) -> ScopeKinds {
        if matches!(scope, FolderNode::Special(_)) {
            return ScopeKinds::ITEMS;
        }
        let mut kinds = ScopeKinds::default();
        kinds.insert(scope);
        for entry in self.descendants(scope) {
            if kinds.covers_items() {
                break;
            }
            kinds.insert(entry.node);
        }
        kinds
    }

    pub fn version(&self) -> HierarchyVersion {
        self.version
    }

    pub fn virtual_deletions(&self) -> &[(u32, u64)] {
        &self.virtual_deletions
    }

    pub fn modified(&self, node: FolderNode) -> Option<u64> {
        let FolderNode::Stored(FolderRef {
            kind: FolderKind::Virtual,
            id,
        }) = node
        else {
            return None;
        };
        self.virtual_modified
            .iter()
            .find_map(|(folder, modified)| (*folder == id).then_some(*modified))
    }

    pub fn stored_hash(&self, account_id: u32) -> u32 {
        let sum = self
            .entries
            .iter()
            .filter_map(|entry| match entry.node {
                FolderNode::Stored(FolderRef { kind, id }) => {
                    let [a, b, c, d] = id.to_le_bytes();
                    Some(xxh3_64(&[kind as u8, a, b, c, d]))
                }
                FolderNode::Special(_) => None,
            })
            .fold(STORED_SET_SEED, u64::wrapping_add);
        seal_hash(sum, account_id)
    }

    pub fn account_hash(account_id: u32) -> u32 {
        seal_hash(0, account_id)
    }

    pub fn subset(&self, keep: impl IntoIterator<Item = bool>) -> FolderTree {
        let mut kept_before = Vec::with_capacity(self.entries.len() + 1);
        let mut kept = 0u32;
        for keep in keep.into_iter().take(self.entries.len()) {
            kept_before.push(kept);
            kept += u32::from(keep);
        }
        kept_before.resize(self.entries.len() + 1, kept);
        let new_position = |position: usize| match kept_before.get(position..position + 2) {
            Some(&[before, after]) if after > before => Some(before),
            _ => None,
        };
        let len = kept as usize;
        let mut tree = FolderTree {
            entries: Vec::with_capacity(len),
            index: AHashMap::with_capacity(len),
            specials: self
                .specials
                .iter()
                .filter_map(|&(special, position)| {
                    new_position(position as usize).map(|position| (special, position))
                })
                .collect(),
            virtual_deletions: Vec::new(),
            virtual_modified: self.virtual_modified.clone(),
            version: self.version,
        };
        for (position, entry) in self.entries.iter().enumerate() {
            let Some(new) = new_position(position) else {
                continue;
            };
            tree.index.insert(entry.node, new);
            tree.entries.push(FolderEntry {
                subtree_end: kept_before
                    .get(entry.subtree_end as usize)
                    .copied()
                    .unwrap_or(kept),
                ..entry.clone()
            });
        }
        tree
    }
}

pub(crate) struct PendingFolder {
    pub node: FolderNode,
    pub parent: Option<FolderNode>,
    pub name: Arc<str>,
    pub class: ContainerClass,
    pub special: Option<SpecialFolder>,
    pub change_id: u64,
    pub search: bool,
}

#[derive(Default)]
pub(crate) struct TreeBuilder {
    pending: Vec<PendingFolder>,
    specials: u32,
    virtual_deletions: Vec<(u32, u64)>,
    virtual_modified: Vec<(u32, u64)>,
    search_scopes: Vec<(FolderNode, FolderNode)>,
}

const _: () = assert!(SpecialFolder::ALL.len() <= u32::BITS as usize);

impl TreeBuilder {
    pub fn with_capacity(capacity: usize) -> Self {
        TreeBuilder {
            pending: Vec::with_capacity(capacity),
            specials: 0,
            virtual_deletions: Vec::new(),
            virtual_modified: Vec::new(),
            search_scopes: Vec::new(),
        }
    }

    pub fn push(&mut self, folder: PendingFolder) {
        if let Some(special) = folder.special {
            self.specials |= special.bit();
        }
        self.pending.push(folder);
    }

    pub fn push_special(&mut self, folder: SpecialFolder, parent: SpecialFolder, change_id: u64) {
        self.push_special_under(folder, FolderNode::Special(parent), change_id);
    }

    fn push_special_under(&mut self, folder: SpecialFolder, parent: FolderNode, change_id: u64) {
        self.push(PendingFolder {
            node: FolderNode::Special(folder),
            parent: Some(parent),
            name: super::special_name(folder),
            class: folder.class(),
            special: Some(folder),
            change_id,
            search: false,
        });
    }

    pub fn adopt_or_push_special(
        &mut self,
        folder: SpecialFolder,
        parent: FolderNode,
        change_id: u64,
    ) -> FolderNode {
        let name = folder.display_name();
        let adopted = self
            .pending
            .iter_mut()
            .filter(|pending| {
                pending.special.is_none()
                    && pending.parent == Some(parent)
                    && pending.name.eq_ignore_ascii_case(name)
            })
            .filter_map(|pending| match pending.node {
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Mailbox,
                    id,
                }) => Some((id, pending)),
                FolderNode::Stored(_) | FolderNode::Special(_) => None,
            })
            .min_by_key(|(id, _)| *id);
        match adopted {
            Some((_, pending)) => {
                pending.special = Some(folder);
                pending.class = folder.class();
                self.specials |= folder.bit();
                pending.node
            }
            None => {
                self.push_special_under(folder, parent, change_id);
                FolderNode::Special(folder)
            }
        }
    }

    pub fn push_virtual_deletion(&mut self, id: u32, change: u64) {
        self.virtual_deletions.push((id, change));
    }

    pub fn push_virtual_modified(&mut self, id: u32, modified: u64) {
        self.virtual_modified.push((id, modified));
    }

    pub fn push_search_scope(&mut self, search: FolderNode, scope: FolderNode) {
        self.search_scopes.push((search, scope));
    }

    pub fn has_special(&self, folder: SpecialFolder) -> bool {
        self.specials & folder.bit() != 0
    }

    pub fn build(self, version: HierarchyVersion) -> FolderTree {
        let mut slots = self.pending.into_iter().map(Some).collect::<Vec<_>>();
        let mut positions = AHashMap::with_capacity(slots.len());
        let mut roots = Vec::with_capacity(1);
        for (pos, pending) in slots.iter().enumerate() {
            let Some(pending) = pending else { continue };
            if let Entry::Vacant(slot) = positions.entry(pending.node) {
                slot.insert(pos);
                if pending.parent.is_none() {
                    roots.push(pos);
                }
            }
        }
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); slots.len()];
        for (pos, pending) in slots.iter().enumerate() {
            let Some(pending) = pending else { continue };
            if positions.get(&pending.node) != Some(&pos) {
                continue;
            }
            if let Some(parent) = pending.parent.and_then(|parent| positions.get(&parent)) {
                children[*parent].push(pos);
            }
        }

        let mut tree = FolderTree {
            entries: Vec::with_capacity(slots.len()),
            index: AHashMap::with_capacity(slots.len()),
            specials: Vec::new(),
            virtual_deletions: self.virtual_deletions,
            virtual_modified: self.virtual_modified,
            version,
        };
        let mut stack: Vec<(usize, bool)> =
            roots.into_iter().rev().map(|pos| (pos, false)).collect();
        let mut open: Vec<usize> = Vec::new();
        while let Some((pos, ipm)) = stack.pop() {
            let Some(pending) = slots.get_mut(pos).and_then(Option::take) else {
                continue;
            };
            let entry_pos = tree.entries.len();
            let Ok(entry_index) = u32::try_from(entry_pos) else {
                break;
            };
            while let Some(&top) = open.last() {
                if is_ancestor(&tree.entries, top, &pending) {
                    break;
                }
                close(&mut tree.entries, top, entry_index);
                open.pop();
            }
            let ipm = ipm || pending.special == Some(SpecialFolder::IpmSubtree);
            let in_ipm = ipm && pending.special != Some(SpecialFolder::IpmSubtree);
            tree.index.insert(pending.node, entry_index);
            if let Some(special) = pending.special {
                tree.specials.push((special, entry_index));
            }
            tree.entries.push(FolderEntry {
                node: pending.node,
                parent: pending.parent,
                name: pending.name,
                class: pending.class,
                special: pending.special,
                ipm: in_ipm,
                search: pending.search,
                scope: ScopeKinds::default(),
                change_id: pending.change_id,
                subtree_end: entry_index.saturating_add(1),
            });
            open.push(entry_pos);
            if let Some(kids) = children.get_mut(pos) {
                stack.extend(std::mem::take(kids).into_iter().rev().map(|kid| (kid, ipm)));
            }
        }
        let end = u32::try_from(tree.entries.len()).unwrap_or(u32::MAX);
        for top in open.into_iter().rev() {
            close(&mut tree.entries, top, end);
        }
        for (search, scope) in self.search_scopes {
            let kinds = tree.scope_kinds(scope);
            if let Some(entry) = tree
                .position(search)
                .and_then(|pos| tree.entries.get_mut(pos))
            {
                entry.scope.union(kinds);
            }
        }
        tree
    }
}

fn is_ancestor(entries: &[FolderEntry], candidate: usize, pending: &PendingFolder) -> bool {
    entries
        .get(candidate)
        .is_some_and(|entry| Some(entry.node) == pending.parent)
}

fn close(entries: &mut [FolderEntry], pos: usize, end: u32) {
    if let Some(entry) = entries.get_mut(pos) {
        entry.subtree_end = end;
    }
}

fn seal_hash(sum: u64, account_id: u32) -> u32 {
    let hash = xxh3_64_with_seed(&sum.to_le_bytes(), u64::from(account_id));
    u32::try_from(hash >> u32::BITS).unwrap_or_default()
}
