/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CounterDelta, KeywordBits, SelectedMailbox, SessionData};
use common::{MessageStoreCache, MessagesCache, NO_ID, network::SessionStream};

pub use common::MailboxRow as Row;
use imap_proto::protocol::{Sequence, expunge, select::Exists};
use std::{borrow::Cow, mem, sync::Arc};
use store::{query::log::Query, roaring::RoaringBitmap};
use trc::AddContext;
use types::collection::SyncCollection;

const CHANGED_SCAN_RATIO: usize = 5;
const CHANGED_FALLBACK_RATIO: usize = 8;
const MAX_SCAN_SEQUENCE_ITEMS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    pub seqnum: u32,
    pub uid: u32,
    pub id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemChanges<'x> {
    Rebuild,
    Items(&'x [u32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    Unchanged,
    Incremental,
    Rebuilt,
}

impl SyncOutcome {
    pub fn is_changed(self) -> bool {
        !matches!(self, SyncOutcome::Unchanged)
    }
}

pub struct MailboxView {
    mailbox_id: u32,
    rows: Arc<Vec<Row>>,
    tombstones: Vec<u32>,
    pending: Vec<Row>,
    appended: u32,
    uid_max: u32,
    snapshot: Arc<MessagesCache>,
    sorted: bool,
    mask: Option<RoaringBitmap>,
}

impl Resolved {
    #[inline(always)]
    pub fn imap_id(&self, is_uid: bool) -> u32 {
        if is_uid { self.uid } else { self.seqnum }
    }

    #[inline(always)]
    pub fn row(&self) -> Row {
        Row {
            uid: self.uid,
            id: self.id,
        }
    }
}

impl MailboxView {
    pub fn build(cache: &MessageStoreCache, mailbox_id: u32) -> Self {
        let rows = cache
            .refresh
            .mailbox_rows
            .get_or_build(&cache.emails, mailbox_id, || {
                let mut rows = Self::collect_rows(cache, mailbox_id);
                rows.sort_unstable_by_key(|row| row.uid);
                rows
            });

        MailboxView {
            mailbox_id,
            uid_max: rows.last().map_or(0, |row| row.uid),
            rows,
            tombstones: Vec::new(),
            pending: Vec::new(),
            appended: 0,
            snapshot: cache.emails.clone(),
            sorted: true,
            mask: None,
        }
    }

    fn collect_rows(cache: &MessageStoreCache, mailbox_id: u32) -> Vec<Row> {
        cache
            .emails
            .iter()
            .filter_map(|message| {
                message.uid_in(mailbox_id).map(|uid| Row {
                    uid,
                    id: message.document_id(),
                })
            })
            .collect()
    }

    #[inline(always)]
    pub fn change_id(&self) -> u64 {
        self.snapshot.change_id
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    #[inline(always)]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    #[inline(always)]
    pub fn uid_max(&self) -> u32 {
        self.uid_max
    }

    pub fn announce_appended(&mut self, buf: &mut Vec<u8>) {
        self.publish_pending();
        if self.appended > 0 {
            self.appended = 0;
            Exists {
                total_messages: self.rows.len(),
            }
            .serialize(buf);
        }
    }

    fn publish_pending(&mut self) {
        if !self.pending.is_empty() {
            let mut rows = mem::take(&mut self.pending);
            rows.sort_unstable_by_key(|row| row.uid);
            self.insert_rows(rows);
        }
    }

    pub fn has_pending_changes(&self) -> bool {
        !self.tombstones.is_empty() || self.appended > 0 || !self.sorted
    }

    pub fn live_rows_by_uid(&self) -> Vec<Row> {
        let mut rows = self
            .rows
            .iter()
            .copied()
            .filter(Row::is_live)
            .collect::<Vec<_>>();
        if !self.sorted {
            rows.sort_unstable_by_key(|row| row.uid);
        }
        rows
    }

    fn position_of_uid(&self, uid: u32) -> Option<usize> {
        if self.sorted {
            self.rows.binary_search_by_key(&uid, |row| row.uid).ok()
        } else {
            self.rows.iter().position(|row| row.uid == uid)
        }
    }

    fn for_uid_range(&self, lo: u32, hi: u32, mut f: impl FnMut(usize, &Row)) {
        if lo > hi {
            return;
        }
        if self.sorted {
            let from = self.rows.partition_point(|row| row.uid < lo);
            let to = self.rows.partition_point(|row| row.uid <= hi);
            if let Some(slice) = self.rows.get(from..to) {
                for (offset, row) in slice.iter().enumerate() {
                    f(from + offset, row);
                }
            }
        } else {
            for (position, row) in self.rows.iter().enumerate() {
                if (lo..=hi).contains(&row.uid) {
                    f(position, row);
                }
            }
        }
    }

    #[inline(always)]
    fn resolved_at(position: usize, row: &Row) -> Option<Resolved> {
        row.is_live().then_some(Resolved {
            seqnum: position as u32 + 1,
            uid: row.uid,
            id: row.id,
        })
    }

    pub fn uid_to_seqnum(&self, uid: u32) -> Option<u32> {
        self.position_of_uid(uid)
            .map(|position| position as u32 + 1)
    }

    pub fn seqnum_to_uid(&self, seqnum: u32) -> Option<u32> {
        seqnum
            .checked_sub(1)
            .and_then(|position| self.rows.get(position as usize))
            .map(|row| row.uid)
    }

    pub fn resolve(
        &self,
        sequence: &Sequence,
        is_uid: bool,
        saved: Option<&[Row]>,
    ) -> Vec<Resolved> {
        let mut out = Vec::new();
        let sequence = self.merge_ranges(sequence, is_uid);
        self.resolve_into(&sequence, is_uid, saved, &mut out);
        if matches!(*sequence, Sequence::List { .. }) {
            out.sort_unstable_by_key(|resolved| resolved.seqnum);
            out.dedup_by_key(|resolved| resolved.seqnum);
        }
        out
    }

    fn merge_ranges<'s>(&self, sequence: &'s Sequence, is_uid: bool) -> Cow<'s, Sequence> {
        let Sequence::List { items } = sequence else {
            return Cow::Borrowed(sequence);
        };
        let max = if is_uid {
            self.uid_max()
        } else {
            self.rows.len() as u32
        };
        let mut ranges = Vec::with_capacity(items.len());
        let mut has_saved_search = false;
        for item in items {
            match item {
                Sequence::Number { value } => ranges.push((*value, *value)),
                Sequence::Range { start, end } => {
                    let (start, end) = (start.unwrap_or(max), end.unwrap_or(max));
                    ranges.push((start.min(end), start.max(end)));
                }
                Sequence::SavedSearch => has_saved_search = true,
                Sequence::List { .. } => return Cow::Borrowed(sequence),
            }
        }
        ranges.sort_unstable();

        let mut merged = Vec::with_capacity(ranges.len() + usize::from(has_saved_search));
        let mut ranges = ranges.into_iter();
        if let Some((mut lo, mut hi)) = ranges.next() {
            for (next_lo, next_hi) in ranges {
                if next_lo <= hi.saturating_add(1) {
                    hi = hi.max(next_hi);
                } else {
                    merged.push(Sequence::range(Some(lo), Some(hi)));
                    (lo, hi) = (next_lo, next_hi);
                }
            }
            merged.push(Sequence::range(Some(lo), Some(hi)));
        }
        if has_saved_search {
            merged.push(Sequence::SavedSearch);
        }
        Cow::Owned(Sequence::List { items: merged })
    }

    pub fn resolve_uid(&self, uid: u32) -> Option<Resolved> {
        self.position_of_uid(uid)
            .and_then(|position| self.rows.get(position).map(|row| (position, row)))
            .and_then(|(position, row)| Self::resolved_at(position, row))
    }

    pub fn changed_since_scan(
        &self,
        emails: &MessagesCache,
        changed_since: u64,
        sequence: &Sequence,
        is_uid: bool,
    ) -> Option<Vec<Resolved>> {
        let mut items = MAX_SCAN_SEQUENCE_ITEMS;
        if !self.sorted || !Self::is_scannable(sequence, &mut items) {
            return None;
        }
        let covered = self.covered_by(sequence, is_uid);
        if covered.saturating_mul(CHANGED_SCAN_RATIO) < emails.len() {
            return None;
        }
        self.resolve_changed(
            emails,
            changed_since,
            sequence,
            is_uid,
            covered / CHANGED_FALLBACK_RATIO,
        )
    }

    fn is_scannable(sequence: &Sequence, items: &mut usize) -> bool {
        match sequence {
            Sequence::Number { .. } | Sequence::Range { .. } => {
                let available = *items > 0;
                *items = items.saturating_sub(1);
                available
            }
            Sequence::List { items: list } => list
                .iter()
                .all(|sequence| Self::is_scannable(sequence, items)),
            Sequence::SavedSearch => false,
        }
    }

    fn covered_by(&self, sequence: &Sequence, is_uid: bool) -> usize {
        match sequence {
            Sequence::Number { .. } => 1,
            Sequence::Range { start, end } => {
                let max = if is_uid {
                    self.uid_max()
                } else {
                    self.rows.len() as u32
                };
                let (start, end) = (start.unwrap_or(max), end.unwrap_or(max));
                let (lo, hi) = (start.min(end), start.max(end));
                if is_uid {
                    self.rows
                        .partition_point(|row| row.uid <= hi)
                        .saturating_sub(self.rows.partition_point(|row| row.uid < lo))
                } else {
                    (hi.min(max) as usize + 1).saturating_sub(lo.max(1) as usize)
                }
            }
            Sequence::List { items } => {
                items.iter().map(|item| self.covered_by(item, is_uid)).sum()
            }
            Sequence::SavedSearch => self.rows.len(),
        }
    }

    fn resolve_changed(
        &self,
        emails: &MessagesCache,
        changed_since: u64,
        sequence: &Sequence,
        is_uid: bool,
        budget: usize,
    ) -> Option<Vec<Resolved>> {
        let mut candidates = Vec::new();
        for message in emails
            .iter()
            .rev()
            .filter(|message| message.change_id() >= changed_since)
        {
            if let Some(uid) = message.uid_in(self.mailbox_id) {
                if candidates.len() == budget {
                    return None;
                }
                candidates.push(Resolved {
                    seqnum: 0,
                    uid,
                    id: message.document_id(),
                });
            }
        }

        let max = if is_uid {
            self.uid_max()
        } else {
            self.rows.len() as u32
        };
        candidates.retain_mut(|candidate| match self.resolve_uid(candidate.uid) {
            Some(resolved)
                if resolved.id == candidate.id
                    && sequence.contains(resolved.imap_id(is_uid), max) =>
            {
                *candidate = resolved;
                true
            }
            _ => false,
        });
        Some(candidates)
    }

    fn resolve_into(
        &self,
        sequence: &Sequence,
        is_uid: bool,
        saved: Option<&[Row]>,
        out: &mut Vec<Resolved>,
    ) {
        match sequence {
            Sequence::Number { value } => {
                let position = if is_uid {
                    self.position_of_uid(*value)
                } else {
                    value.checked_sub(1).map(|position| position as usize)
                };
                if let Some(resolved) = position
                    .and_then(|position| self.rows.get(position).map(|row| (position, row)))
                    .and_then(|(position, row)| Self::resolved_at(position, row))
                {
                    out.push(resolved);
                }
            }
            Sequence::Range { start, end } => {
                let max = if is_uid {
                    self.uid_max()
                } else {
                    self.rows.len() as u32
                };
                let (start, end) = (start.unwrap_or(max), end.unwrap_or(max));
                let (lo, hi) = (start.min(end), start.max(end));
                if is_uid {
                    self.for_uid_range(lo, hi, |position, row| {
                        if let Some(resolved) = Self::resolved_at(position, row) {
                            out.push(resolved);
                        }
                    });
                } else {
                    let from = lo.max(1) as usize - 1;
                    let to = (hi as usize).min(self.rows.len());
                    if let Some(slice) = self.rows.get(from..to) {
                        out.reserve(slice.len());
                        out.extend(
                            slice
                                .iter()
                                .enumerate()
                                .filter_map(|(offset, row)| Self::resolved_at(from + offset, row)),
                        );
                    }
                }
            }
            Sequence::List { items } => {
                for item in items {
                    self.resolve_into(item, is_uid, saved, out);
                }
            }
            Sequence::SavedSearch => {
                if let Some(saved) = saved {
                    out.reserve(saved.len());
                    for row in saved {
                        if let Some(resolved) = self
                            .position_of_uid(row.uid)
                            .and_then(|position| self.rows.get(position).map(|row| (position, row)))
                            .and_then(|(position, row)| Self::resolved_at(position, row))
                        {
                            out.push(resolved);
                        }
                    }
                }
            }
        }
    }

    pub fn missing_in(
        &self,
        sequence: &Sequence,
        is_uid: bool,
        saved: Option<&[Row]>,
        out: &mut Vec<(u32, u32)>,
    ) -> bool {
        let mut expunged = false;
        match sequence {
            Sequence::Number { value } => {
                let row = if is_uid {
                    self.position_of_uid(*value)
                        .and_then(|position| self.rows.get(position))
                } else {
                    value
                        .checked_sub(1)
                        .and_then(|position| self.rows.get(position as usize))
                };
                match row {
                    Some(row) if row.is_live() => {}
                    Some(_) => {
                        expunged = true;
                        out.push((*value, *value));
                    }
                    None => out.push((*value, *value)),
                }
            }
            Sequence::Range { start, end } => {
                let max = if is_uid {
                    self.uid_max()
                } else {
                    self.rows.len() as u32
                };
                let (start, end) = (start.unwrap_or(max), end.unwrap_or(max));
                let (lo, hi) = (start.min(end), start.max(end));
                if is_uid {
                    let mut next_expected = lo;
                    self.for_uid_range(lo, hi, |_, row| {
                        if self.sorted && row.uid > next_expected {
                            out.push((next_expected, row.uid - 1));
                        }
                        if !row.is_live() {
                            expunged = true;
                            out.push((row.uid, row.uid));
                        }
                        next_expected = row.uid.saturating_add(1);
                    });
                    if self.sorted && next_expected <= hi {
                        out.push((next_expected, hi));
                    }
                } else {
                    let lo = lo.max(1);
                    let len = self.rows.len() as u32;
                    for &position in &self.tombstones {
                        let seqnum = position + 1;
                        if (lo..=hi).contains(&seqnum) {
                            expunged = true;
                            out.push((seqnum, seqnum));
                        }
                    }
                    if hi > len && lo <= hi {
                        out.push((lo.max(len + 1), hi));
                    }
                }
            }
            Sequence::List { items } => {
                for item in items {
                    expunged |= self.missing_in(item, is_uid, saved, out);
                }
            }
            Sequence::SavedSearch => {
                if let Some(saved) = saved {
                    for row in saved {
                        match self.position_of_uid(row.uid) {
                            Some(position) if self.rows.get(position).is_some_and(Row::is_live) => {
                            }
                            Some(position) => {
                                expunged = true;
                                out.push(if is_uid {
                                    (row.uid, row.uid)
                                } else {
                                    (position as u32 + 1, position as u32 + 1)
                                });
                            }
                            None if is_uid => out.push((row.uid, row.uid)),
                            None => {}
                        }
                    }
                }
            }
        }
        expunged
    }

    pub fn map_result(&self, document_id: u32) -> Option<Resolved> {
        self.snapshot
            .by_id(document_id)
            .and_then(|message| message.uid_in(self.mailbox_id))
            .and_then(|uid| self.position_of_uid(uid))
            .and_then(|position| {
                self.rows
                    .get(position)
                    .and_then(|row| Self::resolved_at(position, row))
            })
    }

    pub fn map_result_set(&self, set: &RoaringBitmap, mut f: impl FnMut(Resolved)) {
        for (position, row) in self.rows.iter().enumerate() {
            if row.is_live() && set.contains(row.id) {
                f(Resolved {
                    seqnum: position as u32 + 1,
                    uid: row.uid,
                    id: row.id,
                });
            }
        }
    }

    pub fn uids_in_range(&self, min: Option<u32>, max: Option<u32>) -> RoaringBitmap {
        let mut set = RoaringBitmap::new();
        self.for_uid_range(min.unwrap_or(1), max.unwrap_or(u32::MAX), |_, row| {
            if row.is_live() {
                set.insert(row.id);
            }
        });
        set
    }

    pub fn document_ids(&mut self) -> RoaringBitmap {
        self.mask
            .get_or_insert_with(|| {
                RoaringBitmap::from_iter(
                    self.rows
                        .iter()
                        .filter(|row| row.is_live())
                        .map(|row| row.id),
                )
            })
            .clone()
    }

    pub fn append_local(&mut self, rows: impl IntoIterator<Item = Row>) {
        let mut rows = rows.into_iter().collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| row.uid);
        self.insert_rows(rows);
    }

    fn insert_rows(&mut self, rows: Vec<Row>) -> bool {
        if rows.is_empty() {
            return false;
        }
        if Arc::get_mut(&mut self.rows).is_none() {
            let mut owned = Vec::with_capacity(self.rows.len() + rows.len());
            owned.extend_from_slice(&self.rows);
            self.rows = Arc::new(owned);
        }

        let mut out_of_order = false;
        for row in rows {
            if row.uid > self.uid_max {
                self.push_row(row);
            } else if self.position_of_uid(row.uid).is_none() {
                self.push_row(row);
                self.sorted = false;
                out_of_order = true;
            }
        }
        if out_of_order {
            trc::event!(
                Imap(trc::ImapEvent::Error),
                MailboxId = self.mailbox_id,
                Details = "A message with a UID below the mailbox maximum was added.",
            );
        }
        out_of_order
    }

    fn push_row(&mut self, row: Row) {
        if let Some(mask) = &mut self.mask {
            mask.insert(row.id);
        }
        self.uid_max = self.uid_max.max(row.uid);
        Arc::make_mut(&mut self.rows).push(row);
        self.appended += 1;
    }

    fn tombstone(&mut self, position: usize) {
        if self.rows.get(position).is_some_and(Row::is_live)
            && let Some(row) = Arc::make_mut(&mut self.rows).get_mut(position)
        {
            if let Some(mask) = &mut self.mask {
                mask.remove(row.id);
            }
            row.id = NO_ID;
            self.tombstones.push(position as u32);
        }
    }

    pub fn sync(
        &mut self,
        cache: &MessageStoreCache,
        changes: ItemChanges<'_>,
        mut changed: Option<&mut Vec<u32>>,
        mut deltas: Option<&mut Vec<CounterDelta>>,
    ) -> SyncOutcome {
        if cache.emails.change_id <= self.snapshot.change_id {
            return SyncOutcome::Unchanged;
        }

        let outcome = match changes {
            ItemChanges::Rebuild => {
                self.rebuild(cache);
                SyncOutcome::Rebuilt
            }
            ItemChanges::Items(document_ids) => {
                let bits = KeywordBits::new();
                let mut withdrawn = Vec::new();
                for &document_id in document_ids {
                    let before_message = self.snapshot.by_id(document_id);
                    let after_message = cache.emails.by_id(document_id);
                    if let Some(deltas) = deltas.as_deref_mut() {
                        if let Some(message) = before_message {
                            CounterDelta::push_for(message, bits, false, deltas);
                        }
                        if let Some(message) = after_message {
                            CounterDelta::push_for(message, bits, true, deltas);
                        }
                    }
                    let before = before_message.and_then(|message| message.uid_in(self.mailbox_id));
                    let after = after_message.and_then(|message| message.uid_in(self.mailbox_id));

                    if let Some(uid) = before
                        && after != before
                    {
                        match self.position_of_uid(uid) {
                            Some(position) => self.tombstone(position),
                            None if !self.pending.is_empty() => withdrawn.push(uid),
                            None => {}
                        }
                    }
                    if let Some(uid) = after {
                        if after != before {
                            self.pending.push(Row {
                                uid,
                                id: document_id,
                            });
                        } else if let Some(changed) = changed.as_deref_mut() {
                            changed.push(uid);
                        }
                    }
                }
                if !withdrawn.is_empty() {
                    withdrawn.sort_unstable();
                    self.pending
                        .retain(|row| withdrawn.binary_search(&row.uid).is_err());
                }
                SyncOutcome::Incremental
            }
        };

        self.snapshot = cache.emails.clone();
        outcome
    }

    fn rebuild(&mut self, cache: &MessageStoreCache) {
        let mut fresh = Self::collect_rows(cache, self.mailbox_id);
        fresh.sort_unstable_by_key(|row| row.uid);

        let (removed, added) = if self.sorted {
            Self::diff_sorted(&self.rows, 0..self.rows.len(), &fresh)
        } else {
            let mut order = (0..self.rows.len()).collect::<Vec<_>>();
            order
                .sort_unstable_by_key(|&position| self.rows.get(position).map_or(0, |row| row.uid));
            Self::diff_sorted(&self.rows, order.into_iter(), &fresh)
        };

        for position in removed {
            self.tombstone(position);
        }
        self.pending = added;
    }

    fn diff_sorted(
        rows: &[Row],
        positions: impl Iterator<Item = usize>,
        fresh: &[Row],
    ) -> (Vec<usize>, Vec<Row>) {
        let mut removed = Vec::new();
        let mut added = Vec::new();
        let mut fresh_iter = fresh.iter().peekable();
        for position in positions {
            let Some(old) = rows.get(position) else {
                continue;
            };
            loop {
                match fresh_iter.peek() {
                    Some(new) if new.uid < old.uid => {
                        added.push(**new);
                        fresh_iter.next();
                    }
                    Some(new) if new.uid == old.uid => {
                        fresh_iter.next();
                        break;
                    }
                    _ => {
                        removed.push(position);
                        break;
                    }
                }
            }
        }
        added.extend(fresh_iter.copied());
        (removed, added)
    }

    pub fn flush(&mut self, use_vanished: bool, buf: &mut Vec<u8>) {
        self.publish_pending();
        if !self.tombstones.is_empty() {
            self.tombstones.sort_unstable();
            self.tombstones.dedup();
            let ids = if use_vanished {
                let mut uids = self
                    .tombstones
                    .iter()
                    .filter_map(|&position| self.rows.get(position as usize))
                    .map(|row| row.uid)
                    .collect::<Vec<_>>();
                if !self.sorted {
                    uids.sort_unstable();
                }
                uids
            } else {
                self.tombstones
                    .iter()
                    .map(|position| position + 1)
                    .collect::<Vec<_>>()
            };
            expunge::Response { use_vanished, ids }.serialize_to(buf);
            Arc::make_mut(&mut self.rows).retain(Row::is_live);
            self.tombstones.clear();
            self.appended = 0;
            Exists {
                total_messages: self.rows.len(),
            }
            .serialize(buf);
        } else if self.appended > 0 {
            self.appended = 0;
            Exists {
                total_messages: self.rows.len(),
            }
            .serialize(buf);
        }
    }
}

impl SelectedMailbox {
    pub async fn resolve(&self, sequence: &Sequence, is_uid: bool) -> trc::Result<Vec<Resolved>> {
        let saved = if sequence.is_saved_search() {
            Some(self.get_saved_search().await.ok_or_else(|| {
                trc::ImapEvent::Error
                    .into_err()
                    .details("No saved search found.")
            })?)
        } else {
            None
        };
        Ok(self
            .view
            .lock()
            .resolve(sequence, is_uid, saved.as_deref().map(Vec::as_slice)))
    }

    pub async fn missing_in(&self, sequence: &Sequence, is_uid: bool) -> (Vec<(u32, u32)>, bool) {
        let saved = if sequence.is_saved_search() {
            self.get_saved_search().await
        } else {
            None
        };
        let mut out = Vec::new();
        let view = self.view.lock();
        let sequence = view.merge_ranges(sequence, is_uid);
        let expunged = view.missing_in(
            &sequence,
            is_uid,
            saved.as_deref().map(Vec::as_slice),
            &mut out,
        );
        (out, expunged)
    }

    pub fn change_id(&self) -> u64 {
        self.view.lock().change_id()
    }

    pub fn announce_appended(&self, buf: &mut Vec<u8>) {
        self.view.lock().announce_appended(buf);
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn sync_view(
        &self,
        mailbox: &SelectedMailbox,
        cache: &MessageStoreCache,
        changed: Option<&mut Vec<u32>>,
    ) -> trc::Result<u64> {
        let since = mailbox.change_id();
        if cache.emails.change_id <= since {
            return Ok(since);
        }

        let document_ids = match cache.refresh.changed_items(since, cache.emails.change_id) {
            Some(document_ids) => Some(document_ids),
            None => {
                let changes = self
                    .server
                    .store()
                    .changes(
                        mailbox.id.account_id,
                        SyncCollection::Email.into(),
                        Query::Since(since),
                    )
                    .await
                    .caused_by(trc::location!())?;
                (!changes.needs_full_rebuild(since)).then(|| {
                    let mut document_ids = changes
                        .changes
                        .iter()
                        .filter(|change| !change.is_metadata_only())
                        .filter_map(|change| change.item_id())
                        .map(|item_id| (item_id & u32::MAX as u64) as u32)
                        .collect::<Vec<_>>();
                    document_ids.sort_unstable();
                    document_ids.dedup();
                    Cow::Owned(document_ids)
                })
            }
        };
        let changes = match &document_ids {
            Some(document_ids) => ItemChanges::Items(document_ids),
            None => ItemChanges::Rebuild,
        };

        let mut deltas = Vec::new();
        let track_counters = self.has_counters_at(mailbox.id.account_id, since);
        let (outcome, change_id) = {
            let mut view = mailbox.view.lock();
            let outcome = view.sync(
                cache,
                changes,
                changed,
                track_counters.then_some(&mut deltas),
            );
            (outcome, view.change_id())
        };
        if outcome.is_changed() && track_counters {
            self.apply_counter_deltas(
                mailbox.id.account_id,
                since,
                change_id,
                &deltas,
                matches!(outcome, SyncOutcome::Rebuilt),
            );
        }
        Ok(change_id)
    }

    pub async fn flush_view(
        &self,
        mailbox: &SelectedMailbox,
        use_vanished: bool,
    ) -> trc::Result<()> {
        let mut buf = Vec::new();
        mailbox.view.lock().flush(use_vanished, &mut buf);
        if !buf.is_empty() {
            self.write_bytes(buf).await
        } else {
            Ok(())
        }
    }

    pub async fn write_mailbox_changes(
        &self,
        mailbox: &SelectedMailbox,
        cache: &MessageStoreCache,
        use_vanished: bool,
    ) -> trc::Result<u64> {
        let change_id = self.sync_view(mailbox, cache, None).await?;
        self.flush_view(mailbox, use_vanished).await?;
        Ok(change_id)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/imap/src/core/view/tests.rs"]
pub(crate) mod tests;
