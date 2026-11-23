/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::state::ClientView;
use std::cmp::Reverse;
use store::roaring::RoaringBitmap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemEntry {
    pub document_id: u32,
    pub change_id: u64,
    pub received_at: u64,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Watermark {
    pub change_id: u64,
    pub page: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerItem {
    Delete(u32),
    SoftDelete(u32),
    Change(u32),
    Add(u32),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ServerChanges {
    pub items: Vec<ServerItem>,
    pub more_available: bool,
    pub bytes: usize,
}

#[derive(Debug, Default)]
pub struct OwnChanges {
    pub documents: RoaringBitmap,
    pub change_id: Option<u64>,
}

pub struct ChangeScope<'x> {
    pub current: &'x [ItemEntry],
    pub cutoff: Option<u64>,
    pub snapshot: u64,
    pub window: usize,
    pub bytes: usize,
    pub own: Option<&'x OwnChanges>,
}

impl OwnChanges {
    fn covers(&self, entry: &ItemEntry) -> bool {
        self.change_id
            .is_some_and(|change_id| entry.change_id <= change_id)
            && self.documents.contains(entry.document_id)
    }
}

impl ServerItem {
    pub fn added(&self) -> Option<u32> {
        match self {
            ServerItem::Add(document_id) => Some(*document_id),
            _ => None,
        }
    }

    pub fn with_data(&self) -> Option<u32> {
        match self {
            ServerItem::Add(document_id) | ServerItem::Change(document_id) => Some(*document_id),
            ServerItem::Delete(_) | ServerItem::SoftDelete(_) => None,
        }
    }
}

impl Watermark {
    fn covers(&self, change_id: u64, document_id: u32) -> bool {
        match self.page {
            Some(page) => (change_id, document_id) <= (self.change_id, page),
            None => change_id <= self.change_id,
        }
    }
}

impl ChangeScope<'_> {
    fn is_own(&self, entry: &ItemEntry) -> bool {
        self.own.is_some_and(|own| own.covers(entry))
    }

    fn is_changed(&self, view: &ClientView, watermark: &Watermark, entry: &ItemEntry) -> bool {
        view.pending.contains(entry.document_id)
            || (!self.is_own(entry) && !watermark.covers(entry.change_id, entry.document_id))
    }

    pub fn defer(&self, view: &mut ClientView, watermark: &mut Watermark) {
        for entry in self.current {
            if view.held.contains(entry.document_id) && self.is_changed(view, watermark, entry) {
                view.pending.insert(entry.document_id);
            }
        }
        *watermark = Watermark {
            change_id: self.snapshot.max(watermark.change_id),
            page: None,
        };
    }

    fn is_in_scope(&self, entry: &ItemEntry) -> bool {
        self.cutoff.is_none_or(|cutoff| entry.received_at >= cutoff)
    }

    fn partition(&self) -> (RoaringBitmap, RoaringBitmap) {
        let mut in_scope = RoaringBitmap::new();
        let mut out_of_scope = RoaringBitmap::new();
        for entry in self.current {
            if self.is_in_scope(entry) {
                in_scope.insert(entry.document_id);
            } else {
                out_of_scope.insert(entry.document_id);
            }
        }
        (in_scope, out_of_scope)
    }

    pub fn count(&self, view: &ClientView, watermark: Watermark) -> u64 {
        let mut in_scope_held = 0u64;
        let mut pending = 0u64;
        for entry in self.current.iter().filter(|entry| self.is_in_scope(entry)) {
            if view.held.contains(entry.document_id) {
                in_scope_held += 1;
                if self.is_changed(view, &watermark, entry) {
                    pending += 1;
                }
            } else {
                pending += 1;
            }
        }
        view.held.len().saturating_sub(in_scope_held) + pending
    }

    pub fn collect(&self, view: &mut ClientView, watermark: &mut Watermark) -> ServerChanges {
        let (in_scope, out_of_scope) = self.partition();

        let mut changes = ServerChanges::default();
        let mut budget = self.window;

        let gone = &(&view.held - &in_scope) - &out_of_scope;
        let soft = &view.held & &out_of_scope;
        for (document_id, item) in gone
            .iter()
            .map(|id| (id, ServerItem::Delete(id)))
            .chain(soft.iter().map(|id| (id, ServerItem::SoftDelete(id))))
        {
            if budget == 0 {
                changes.more_available = true;
                return changes;
            }
            budget -= 1;
            view.held.remove(document_id);
            view.pending.remove(document_id);
            view.removed.insert(document_id);
            changes.items.push(item);
        }

        let mut changed = self
            .current
            .iter()
            .filter(|entry| {
                view.held.contains(entry.document_id) && self.is_changed(view, watermark, entry)
            })
            .map(|entry| (entry.change_id, entry.document_id))
            .collect::<Vec<_>>();
        let more_changed = take_first(&mut changed, budget);
        budget -= changed.len();
        changes.items.reserve(changed.len());
        for &(_, document_id) in &changed {
            if view.pending.remove(document_id) {
                view.changed.insert(document_id);
            }
            changes.items.push(ServerItem::Change(document_id));
        }
        if more_changed {
            changes.more_available = true;
            if let Some(&(change_id, document_id)) = changed.last()
                && !watermark.covers(change_id, document_id)
            {
                *watermark = Watermark {
                    change_id,
                    page: Some(document_id),
                };
            }
            return changes;
        }
        *watermark = Watermark {
            change_id: self.snapshot.max(watermark.change_id),
            page: None,
        };

        let mut added = self
            .current
            .iter()
            .filter(|entry| {
                in_scope.contains(entry.document_id) && !view.held.contains(entry.document_id)
            })
            .map(|entry| Reverse((entry.received_at, entry.document_id, entry.size)))
            .collect::<Vec<_>>();
        changes.more_available = take_first(&mut added, budget);
        let mut bytes = self.bytes;
        for Reverse((_, document_id, size)) in added {
            if bytes == 0 {
                changes.more_available = true;
                break;
            }
            bytes = bytes.saturating_sub(size as usize);
            view.held.insert(document_id);
            view.added.insert(document_id);
            changes.items.push(ServerItem::Add(document_id));
        }
        changes.bytes = self.bytes - bytes;
        changes
    }
}

fn take_first<T: Ord>(items: &mut Vec<T>, count: usize) -> bool {
    let more = items.len() > count;
    if more {
        match count.checked_sub(1) {
            Some(last) => {
                items.select_nth_unstable(last);
                items.truncate(count);
            }
            None => items.clear(),
        }
    }
    items.sort_unstable();
    more
}
