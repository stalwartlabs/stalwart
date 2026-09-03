/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CounterDelta, KeywordBits, SelectedMailbox, SessionData};
use common::{MessageStoreCache, MessagesCache, NO_ID, network::SessionStream};
use imap_proto::protocol::{Sequence, expunge, select::Exists};
use std::sync::Arc;
use store::{
    query::log::{Changes, Query},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::collection::SyncCollection;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Row {
    pub uid: u32,
    pub id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    pub seqnum: u32,
    pub uid: u32,
    pub id: u32,
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
    rows: Vec<Row>,
    tombstones: Vec<u32>,
    appended: u32,
    uid_max: u32,
    snapshot: Arc<MessagesCache>,
    sorted: bool,
    mask: Option<RoaringBitmap>,
}

impl Row {
    #[inline(always)]
    pub fn is_live(&self) -> bool {
        self.id != NO_ID
    }
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
        let mut rows = Self::collect_rows(cache, mailbox_id);
        rows.sort_unstable_by_key(|row| row.uid);

        MailboxView {
            mailbox_id,
            uid_max: rows.last().map_or(0, |row| row.uid),
            rows,
            tombstones: Vec::new(),
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
        self.resolve_into(sequence, is_uid, saved, &mut out);
        if matches!(sequence, Sequence::List { .. }) {
            out.sort_unstable_by_key(|resolved| resolved.seqnum);
            out.dedup_by_key(|resolved| resolved.seqnum);
        }
        out
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
        let mut out_of_order = false;
        for row in rows {
            if row.uid > self.uid_max {
                self.push_row(row);
            } else if self.position_of_uid(row.uid).is_none() {
                self.push_row(row);
                out_of_order = true;
            }
        }
        if out_of_order {
            trc::event!(
                Imap(trc::ImapEvent::Error),
                MailboxId = self.mailbox_id,
                Details = "A message with a UID below the mailbox maximum was added.",
            );
            self.sorted = false;
        }
        out_of_order
    }

    fn push_row(&mut self, row: Row) {
        if let Some(mask) = &mut self.mask {
            mask.insert(row.id);
        }
        self.uid_max = self.uid_max.max(row.uid);
        self.rows.push(row);
        self.appended += 1;
    }

    fn tombstone(&mut self, position: usize) {
        if let Some(row) = self.rows.get_mut(position)
            && row.is_live()
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
        changes: &Changes,
        mut changed: Option<&mut Vec<u32>>,
        mut deltas: Option<&mut Vec<CounterDelta>>,
    ) -> SyncOutcome {
        let since = self.snapshot.change_id;
        if cache.emails.change_id <= since {
            return SyncOutcome::Unchanged;
        }

        let outcome = if changes.needs_full_rebuild(since) {
            self.rebuild(cache);
            SyncOutcome::Rebuilt
        } else {
            let bits = KeywordBits::new();
            let mut inserted = Vec::new();
            for item_id in changes.changes.iter().filter_map(|change| change.item_id()) {
                let document_id = (item_id & u32::MAX as u64) as u32;
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
                    && let Some(position) = self.position_of_uid(uid)
                {
                    self.tombstone(position);
                }
                if let Some(uid) = after {
                    if after != before {
                        inserted.push(Row {
                            uid,
                            id: document_id,
                        });
                    }
                    if let Some(changed) = changed.as_deref_mut() {
                        changed.push(uid);
                    }
                }
            }

            if !inserted.is_empty() {
                inserted.sort_unstable_by_key(|row| row.uid);
                self.insert_rows(inserted);
            }
            SyncOutcome::Incremental
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
        self.insert_rows(added);
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
            self.rows.retain(Row::is_live);
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
        let expunged = self.view.lock().missing_in(
            sequence,
            is_uid,
            saved.as_deref().map(Vec::as_slice),
            &mut out,
        );
        (out, expunged)
    }

    pub fn change_id(&self) -> u64 {
        self.view.lock().change_id()
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

        let mut deltas = Vec::new();
        let track_counters = self.has_counters_at(mailbox.id.account_id, since);
        let (outcome, change_id) = {
            let mut view = mailbox.view.lock();
            let outcome = view.sync(
                cache,
                &changes,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::MailboxCounters;
    use common::{MailboxCache, MailboxesCache, MessageCache, MessageUid, UpdateLock};
    use store::query::log::Change;
    use types::special_use::SpecialUse;

    const MAILBOX: u32 = 3;
    const OTHER: u32 = 2;

    fn message(document_id: u32, uid: u32, received_at: u64) -> MessageCache {
        MessageCache::new(
            document_id,
            [MessageUid {
                mailbox_id: MAILBOX,
                uid,
            }]
            .into_iter()
            .collect(),
            0,
            document_id,
            1,
            100,
            received_at,
            0,
        )
    }

    fn cache(change_id: u64, mut items: Vec<MessageCache>) -> MessageStoreCache {
        items.sort_unstable_by_key(MessageCache::sort_rank);
        let mailbox = MailboxCache {
            document_id: MAILBOX,
            name: "Test".into(),
            path: "Test".into(),
            role: SpecialUse::None,
            parent_id: u32::MAX,
            sort_order: 0,
            subscribers: Default::default(),
            uid_validity: 1,
            acls: Default::default(),
        };
        MessageStoreCache {
            emails: Arc::new(MessagesCache::new(change_id, items, Vec::new())),
            mailboxes: Arc::new(MailboxesCache {
                change_id,
                index: [(MAILBOX, 0u32)].into_iter().collect(),
                items: vec![mailbox].into_boxed_slice(),
                size: 0,
            }),
            update_lock: Arc::new(UpdateLock::new()),
            last_change_id: change_id,
            size: 0,
        }
    }

    fn changes(to_change_id: u64, items: Vec<Change>) -> Changes {
        let mut changes = Changes::default();
        changes.changes = items;
        changes.to_change_id = to_change_id;
        changes
    }

    fn seqnums(resolved: &[Resolved]) -> Vec<u32> {
        resolved.iter().map(|r| r.seqnum).collect()
    }

    fn uids(resolved: &[Resolved]) -> Vec<u32> {
        resolved.iter().map(|r| r.uid).collect()
    }

    fn initial() -> (MessageStoreCache, MailboxView) {
        let cache = cache(
            10,
            vec![
                message(100, 5, 50),
                message(101, 1, 10),
                message(102, 3, 30),
                message(103, 2, 60),
                message(104, 4, 40),
            ],
        );
        let view = MailboxView::build(&cache, MAILBOX);
        (cache, view)
    }

    #[test]
    fn build_orders_rows_by_uid() {
        let (_, view) = initial();
        assert_eq!(
            view.rows()
                .iter()
                .map(|r| (r.uid, r.id))
                .collect::<Vec<_>>(),
            vec![(1, 101), (2, 103), (3, 102), (4, 104), (5, 100)]
        );
        assert_eq!(view.uid_max(), 5);
        assert_eq!(view.change_id(), 10);
    }

    #[test]
    fn resolve_sequence_forms() {
        let (_, view) = initial();
        let all = Sequence::Range {
            start: Some(1),
            end: None,
        };
        assert_eq!(
            seqnums(&view.resolve(&all, false, None)),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(uids(&view.resolve(&all, true, None)), vec![1, 2, 3, 4, 5]);

        let star = Sequence::Range {
            start: None,
            end: None,
        };
        assert_eq!(seqnums(&view.resolve(&star, false, None)), vec![5]);
        assert_eq!(uids(&view.resolve(&star, true, None)), vec![5]);

        let reversed = Sequence::Range {
            start: Some(4),
            end: Some(2),
        };
        assert_eq!(
            seqnums(&view.resolve(&reversed, false, None)),
            vec![2, 3, 4]
        );

        let beyond = Sequence::Range {
            start: Some(100),
            end: None,
        };
        assert_eq!(uids(&view.resolve(&beyond, true, None)), vec![5]);
        assert_eq!(seqnums(&view.resolve(&beyond, false, None)), vec![5]);

        let list = Sequence::List {
            items: vec![
                Sequence::Number { value: 4 },
                Sequence::Range {
                    start: Some(1),
                    end: Some(2),
                },
                Sequence::Number { value: 2 },
            ],
        };
        assert_eq!(seqnums(&view.resolve(&list, false, None)), vec![1, 2, 4]);

        assert!(
            view.resolve(&Sequence::Number { value: 0 }, false, None)
                .is_empty()
        );
        assert!(
            view.resolve(&Sequence::Number { value: 9 }, true, None)
                .is_empty()
        );

        let saved = [Row { uid: 3, id: 0 }, Row { uid: 9, id: 0 }];
        let resolved = view.resolve(&Sequence::SavedSearch, true, Some(&saved));
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, 102);
        assert_eq!(resolved[0].seqnum, 3);
    }

    #[test]
    fn sync_appends_tombstones_and_reports_flag_changes() {
        let (_, mut view) = initial();
        let next = cache(
            20,
            vec![
                message(100, 5, 50),
                message(101, 1, 10),
                message(103, 2, 60),
                message(104, 4, 40),
                message(105, 6, 70),
            ],
        );
        let mut changed = Vec::new();
        assert!(
            view.sync(
                &next,
                &changes(
                    20,
                    vec![
                        Change::DeleteItem(102),
                        Change::InsertItem(105),
                        Change::UpdateItem(104),
                    ]
                ),
                Some(&mut changed),
                None
            )
            .is_changed()
        );
        changed.sort_unstable();
        assert_eq!(changed, vec![4, 6]);
        assert_eq!(view.len(), 6);
        assert_eq!(view.change_id(), 20);

        let all = Sequence::Range {
            start: Some(1),
            end: None,
        };
        let resolved = view.resolve(&all, false, None);
        assert_eq!(seqnums(&resolved), vec![1, 2, 4, 5, 6]);
        assert_eq!(uids(&resolved), vec![1, 2, 4, 5, 6]);
        assert!(
            view.resolve(&Sequence::Number { value: 3 }, false, None)
                .is_empty()
        );
        assert_eq!(view.uid_to_seqnum(6), Some(6));

        let mut missing = Vec::new();
        view.missing_in(&all, false, None, &mut missing);
        assert_eq!(missing, vec![(3, 3)]);

        assert!(
            !view
                .sync(&next, &changes(20, vec![]), None, None)
                .is_changed()
        );

        let mut buf = Vec::new();
        view.flush(false, &mut buf);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "* 3 EXPUNGE\r\n* 5 EXISTS\r\n"
        );
        assert_eq!(view.len(), 5);
        assert_eq!(
            seqnums(&view.resolve(&all, false, None)),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(uids(&view.resolve(&all, false, None)), vec![1, 2, 4, 5, 6]);
        assert!(!view.has_pending_changes());
    }

    #[test]
    fn replayed_changes_are_idempotent() {
        let (_, mut view) = initial();
        let next = cache(
            20,
            vec![
                message(100, 5, 50),
                message(101, 1, 10),
                message(103, 2, 60),
                message(104, 4, 40),
                message(105, 6, 70),
            ],
        );
        let log = changes(20, vec![Change::DeleteItem(102), Change::InsertItem(105)]);
        assert!(view.sync(&next, &log, None, None).is_changed());
        let later = cache(
            21,
            vec![
                message(100, 5, 50),
                message(101, 1, 10),
                message(103, 2, 60),
                message(104, 4, 40),
                message(105, 6, 70),
            ],
        );
        let log = changes(
            21,
            vec![
                Change::DeleteItem(102),
                Change::InsertItem(105),
                Change::UpdateItem(100),
            ],
        );
        assert!(view.sync(&later, &log, None, None).is_changed());
        assert_eq!(view.len(), 6);
        assert_eq!(view.tombstones, vec![2]);

        let mut buf = Vec::new();
        view.flush(true, &mut buf);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "* VANISHED 3\r\n* 5 EXISTS\r\n"
        );
    }

    #[test]
    fn truncated_log_rebuilds_by_merging() {
        let (_, mut view) = initial();
        let next = cache(
            30,
            vec![
                message(101, 1, 10),
                message(104, 4, 40),
                message(106, 7, 70),
                message(107, 8, 80),
            ],
        );
        let mut log = changes(30, vec![]);
        log.is_truncated = true;
        assert!(view.sync(&next, &log, None, None).is_changed());
        assert_eq!(view.len(), 7);
        assert_eq!(view.tombstones.len(), 3);

        let all = Sequence::Range {
            start: Some(1),
            end: None,
        };
        let resolved = view.resolve(&all, true, None);
        assert_eq!(uids(&resolved), vec![1, 4, 7, 8]);
        assert_eq!(seqnums(&resolved), vec![1, 4, 6, 7]);

        let mut buf = Vec::new();
        view.flush(false, &mut buf);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "* 2 EXPUNGE\r\n* 2 EXPUNGE\r\n* 3 EXPUNGE\r\n* 4 EXISTS\r\n"
        );
    }

    #[test]
    fn missing_ranges_cover_uid_gaps() {
        let (_, view) = initial();
        let mut missing = Vec::new();
        view.missing_in(
            &Sequence::Range {
                start: Some(3),
                end: Some(9),
            },
            true,
            None,
            &mut missing,
        );
        assert_eq!(missing, vec![(6, 9)]);

        missing.clear();
        view.missing_in(
            &Sequence::Range {
                start: Some(1),
                end: Some(8),
            },
            false,
            None,
            &mut missing,
        );
        assert_eq!(missing, vec![(6, 8)]);

        missing.clear();
        view.missing_in(&Sequence::Number { value: 7 }, true, None, &mut missing);
        assert_eq!(missing, vec![(7, 7)]);
    }

    #[test]
    fn local_appends_report_exists() {
        let (_, mut view) = initial();
        view.append_local([Row { uid: 6, id: 105 }, Row { uid: 7, id: 106 }]);
        assert_eq!(view.len(), 7);
        assert_eq!(view.uid_to_seqnum(7), Some(7));
        let mut buf = Vec::new();
        view.flush(false, &mut buf);
        assert_eq!(String::from_utf8(buf).unwrap(), "* 7 EXISTS\r\n");
    }

    #[test]
    fn out_of_order_uid_keeps_sequence_numbers() {
        let (_, mut view) = initial();
        let next = cache(
            20,
            vec![
                message(100, 5, 50),
                message(101, 1, 10),
                message(102, 3, 30),
                message(103, 2, 60),
                message(104, 4, 40),
                message(105, 6, 70),
                message(106, 0, 5),
            ],
        );
        assert!(
            view.sync(
                &next,
                &changes(20, vec![Change::InsertItem(105), Change::InsertItem(106)]),
                None,
                None
            )
            .is_changed()
        );
        assert!(!view.sorted);
        assert_eq!(view.uid_max(), 6);
        assert_eq!(view.uid_to_seqnum(0), Some(6));
        assert_eq!(view.uid_to_seqnum(6), Some(7));
        let resolved = view.resolve(
            &Sequence::Range {
                start: Some(0),
                end: Some(1),
            },
            true,
            None,
        );
        assert_eq!(seqnums(&resolved), vec![1, 6]);
        let star = view.resolve(
            &Sequence::Range {
                start: Some(6),
                end: None,
            },
            true,
            None,
        );
        assert_eq!(uids(&star), vec![6]);
    }

    #[test]
    fn descending_inserts_in_one_change_stay_sorted() {
        let (_, mut view) = initial();
        let next = cache(
            20,
            vec![
                message(100, 5, 50),
                message(101, 1, 10),
                message(102, 3, 30),
                message(103, 2, 60),
                message(104, 4, 40),
                message(105, 7, 70),
                message(106, 6, 80),
            ],
        );
        assert!(
            view.sync(
                &next,
                &changes(20, vec![Change::InsertItem(105), Change::InsertItem(106)]),
                None,
                None
            )
            .is_changed()
        );
        assert!(view.sorted);
        assert_eq!(view.uid_to_seqnum(6), Some(6));
        assert_eq!(view.uid_to_seqnum(7), Some(7));
    }

    #[test]
    fn move_out_and_back_gets_a_new_row() {
        let (_, mut view) = initial();
        let next = cache(
            20,
            vec![
                message(100, 5, 50),
                message(101, 1, 10),
                message(102, 8, 30),
                message(103, 2, 60),
                message(104, 4, 40),
            ],
        );
        let mut changed = Vec::new();
        assert!(
            view.sync(
                &next,
                &changes(20, vec![Change::InsertItem(102)]),
                Some(&mut changed),
                None
            )
            .is_changed()
        );
        assert_eq!(changed, vec![8]);
        assert!(
            view.resolve(&Sequence::Number { value: 3 }, true, None)
                .is_empty()
        );
        let resolved = view.resolve(&Sequence::Number { value: 8 }, true, None);
        assert_eq!(resolved.len(), 1);
        assert_eq!((resolved[0].seqnum, resolved[0].id), (6, 102));
        assert_eq!(view.map_result(102).map(|r| r.uid), Some(8));

        let mut buf = Vec::new();
        view.flush(false, &mut buf);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "* 3 EXPUNGE\r\n* 5 EXISTS\r\n"
        );
    }

    #[test]
    fn map_results_use_the_snapshot() {
        let (_, mut view) = initial();
        let resolved = view.map_result(102).expect("present");
        assert_eq!((resolved.seqnum, resolved.uid), (3, 3));
        assert!(view.map_result(999).is_none());

        let set = RoaringBitmap::from_iter([100, 101]);
        let mut found = Vec::new();
        view.map_result_set(&set, |resolved| found.push(resolved.uid));
        assert_eq!(found, vec![1, 5]);

        assert_eq!(view.uids_in_range(Some(2), Some(4)).len(), 3);
        assert_eq!(view.document_ids().len(), 5);
    }

    #[test]
    fn incremental_counters_match_a_full_pass() {
        let (before, mut view) = initial();
        let mut counters = MailboxCounters::compute(&before);
        assert_eq!(counters.get(MAILBOX).total, 5);
        assert_eq!(counters.get(MAILBOX).unseen, 5);

        let moved = MessageCache::new(
            103,
            [MessageUid {
                mailbox_id: OTHER,
                uid: 1,
            }]
            .into_iter()
            .collect(),
            0,
            103,
            1,
            100,
            60,
            0,
        );
        let seen = MessageCache::new(
            104,
            [MessageUid {
                mailbox_id: MAILBOX,
                uid: 4,
            }]
            .into_iter()
            .collect(),
            1,
            104,
            1,
            100,
            40,
            0,
        );
        let after = cache(
            20,
            vec![
                message(100, 5, 50),
                message(101, 1, 10),
                moved,
                seen,
                message(105, 6, 70),
            ],
        );
        let log = changes(
            20,
            vec![
                Change::DeleteItem(102),
                Change::UpdateItem(103),
                Change::UpdateItem(104),
                Change::InsertItem(105),
            ],
        );
        let mut deltas = Vec::new();
        assert_eq!(
            view.sync(&after, &log, None, Some(&mut deltas)),
            SyncOutcome::Incremental
        );
        counters.apply_deltas(&deltas, after.emails.change_id);

        let expected = MailboxCounters::compute(&after);
        assert_eq!(counters.change_id, expected.change_id);
        assert_eq!(counters.get(MAILBOX), expected.get(MAILBOX));
        assert_eq!(counters.get(OTHER), expected.get(OTHER));
        assert_eq!(counters.get(MAILBOX).total, 4);
        assert_eq!(counters.get(MAILBOX).unseen, 3);
        assert_eq!(counters.get(OTHER).total, 1);
    }
}
