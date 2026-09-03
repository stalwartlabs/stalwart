/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    CACHE_CHUNK, ColBlock, CustomKeywords, MAX_RECEIVED_AT, MessageCache, MessageUid, MessagesCache,
};
use compact_str::CompactString;
use std::sync::Arc;
use tinyvec::TinyVec;

impl MessageCache {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document_id: u32,
        mailboxes: TinyVec<[MessageUid; 2]>,
        keywords: u32,
        thread_id: u32,
        change_id: u64,
        size: u32,
        received_at: u64,
        sent_at: i32,
    ) -> Self {
        Self {
            document_id,
            mailboxes,
            keywords,
            thread_id,
            change_id,
            size,
            received_at,
            sent_at,
        }
    }

    #[inline(always)]
    pub fn document_id(&self) -> u32 {
        self.document_id
    }

    #[inline(always)]
    pub fn mailboxes(&self) -> &[MessageUid] {
        &self.mailboxes
    }

    #[inline(always)]
    pub fn keywords(&self) -> u32 {
        self.keywords
    }

    #[inline(always)]
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    #[inline(always)]
    pub fn change_id(&self) -> u64 {
        self.change_id
    }

    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.size
    }

    #[inline(always)]
    pub fn received_at(&self) -> u64 {
        self.received_at
    }

    #[inline(always)]
    pub fn received_at_secs(&self) -> u32 {
        debug_assert!(
            self.received_at <= MAX_RECEIVED_AT,
            "received_at {} exceeds the representable range and should have been clamped by the caller",
            self.received_at
        );
        self.received_at.min(MAX_RECEIVED_AT) as u32
    }

    #[inline(always)]
    pub fn sent_at(&self) -> i32 {
        self.sent_at
    }

    #[inline(always)]
    pub fn sort_rank(&self) -> (u64, u32) {
        (self.received_at, self.document_id)
    }

    #[inline(always)]
    pub fn has_mailbox_id(&self, mailbox_id: u32) -> bool {
        self.mailboxes
            .iter()
            .any(|uid| uid.mailbox_id == mailbox_id)
    }

    #[inline(always)]
    pub fn uid_in(&self, mailbox_id: u32) -> Option<u32> {
        self.mailboxes
            .iter()
            .find(|uid| uid.mailbox_id == mailbox_id)
            .map(|uid| uid.uid)
    }
}

impl ColBlock {
    fn from_records(items: &[MessageCache]) -> Self {
        let mut mb_offsets = Vec::with_capacity(items.len() + 1);
        let mut mb_arena = Vec::with_capacity(items.len());
        let mut offset = 0u32;
        for item in items {
            mb_offsets.push(offset);
            mb_arena.extend_from_slice(&item.mailboxes);
            offset += item.mailboxes.len() as u32;
        }
        mb_offsets.push(offset);

        ColBlock {
            document_ids: items.iter().map(|item| item.document_id).collect(),
            change_ids: items.iter().map(|item| item.change_id).collect(),
            received_at: items.iter().map(|item| item.received_at_secs()).collect(),
            sent_at: items.iter().map(|item| item.sent_at).collect(),
            sizes: items.iter().map(|item| item.size).collect(),
            keywords: items.iter().map(|item| item.keywords).collect(),
            thread_ids: items.iter().map(|item| item.thread_id).collect(),
            mb_offsets: mb_offsets.into(),
            mb_arena: mb_arena.into(),
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.document_ids.len()
    }

    #[inline(always)]
    fn mailboxes(&self, slot: u32) -> &[MessageUid] {
        let from = self.mb_offsets[slot as usize] as usize;
        let to = self.mb_offsets[slot as usize + 1] as usize;
        &self.mb_arena[from..to]
    }

    #[inline(always)]
    fn rank(&self, slot: usize) -> (u64, u32) {
        (self.received_at[slot] as u64, self.document_ids[slot])
    }

    fn patch_slots(&mut self, slots: &[(u32, u32, &MessageCache)]) {
        Self::patch_column(&mut self.change_ids, slots, |record| record.change_id);
        Self::patch_column(&mut self.keywords, slots, |record| record.keywords);
        Self::patch_column(&mut self.thread_ids, slots, |record| record.thread_id);
        Self::patch_column(&mut self.sizes, slots, |record| record.size);
        self.patch_mailboxes(slots);
    }

    fn patch_column<T: Copy + PartialEq>(
        column: &mut Arc<[T]>,
        slots: &[(u32, u32, &MessageCache)],
        pick: impl Fn(&MessageCache) -> T,
    ) {
        if slots
            .iter()
            .all(|(_, slot, record)| column[*slot as usize] == pick(record))
        {
            return;
        }
        let mut patched = column.to_vec();
        for (_, slot, record) in slots {
            patched[*slot as usize] = pick(record);
        }
        *column = patched.into();
    }

    fn patch_mailboxes(&mut self, slots: &[(u32, u32, &MessageCache)]) {
        if slots
            .iter()
            .all(|(_, slot, record)| self.mailboxes(*slot) == record.mailboxes.as_slice())
        {
            return;
        }
        let mut mb_offsets = Vec::with_capacity(self.len() + 1);
        let mut mb_arena = Vec::with_capacity(self.mb_arena.len());
        let mut offset = 0u32;
        let mut updated = slots.iter().peekable();
        for slot in 0..self.len() as u32 {
            mb_offsets.push(offset);
            let mailboxes = match updated.next_if(|(_, at, _)| *at == slot) {
                Some((_, _, record)) => record.mailboxes.as_slice(),
                None => self.mailboxes(slot),
            };
            mb_arena.extend_from_slice(mailboxes);
            offset += mailboxes.len() as u32;
        }
        mb_offsets.push(offset);
        self.mb_offsets = mb_offsets.into();
        self.mb_arena = mb_arena.into();
    }

    fn weight(&self) -> u64 {
        ((self.document_ids.len()
            * (std::mem::size_of::<u32>() * 5
                + std::mem::size_of::<i32>()
                + std::mem::size_of::<u64>()))
            + (self.mb_offsets.len() * std::mem::size_of::<u32>())
            + (self.mb_arena.len() * std::mem::size_of::<MessageUid>())
            + std::mem::size_of::<ColBlock>()) as u64
    }
}

struct ColBuilder {
    document_ids: Vec<u32>,
    change_ids: Vec<u64>,
    received_at: Vec<u32>,
    sent_at: Vec<i32>,
    sizes: Vec<u32>,
    keywords: Vec<u32>,
    thread_ids: Vec<u32>,
    mb_offsets: Vec<u32>,
    mb_arena: Vec<MessageUid>,
}

impl ColBuilder {
    fn with_capacity(rows: usize, arena: usize) -> Self {
        ColBuilder {
            document_ids: Vec::with_capacity(rows),
            change_ids: Vec::with_capacity(rows),
            received_at: Vec::with_capacity(rows),
            sent_at: Vec::with_capacity(rows),
            sizes: Vec::with_capacity(rows),
            keywords: Vec::with_capacity(rows),
            thread_ids: Vec::with_capacity(rows),
            mb_offsets: Vec::with_capacity(rows + 1),
            mb_arena: Vec::with_capacity(arena),
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.document_ids.len()
    }

    #[inline(always)]
    fn push_record(&mut self, record: &MessageCache) {
        self.document_ids.push(record.document_id);
        self.change_ids.push(record.change_id);
        self.received_at.push(record.received_at_secs());
        self.sent_at.push(record.sent_at);
        self.sizes.push(record.size);
        self.keywords.push(record.keywords);
        self.thread_ids.push(record.thread_id);
        self.mb_offsets.push(self.mb_arena.len() as u32);
        self.mb_arena.extend_from_slice(&record.mailboxes);
    }

    fn copy_run(&mut self, old: &ColBlock, from: usize, to: usize) {
        if from >= to {
            return;
        }
        self.document_ids
            .extend_from_slice(&old.document_ids[from..to]);
        self.change_ids.extend_from_slice(&old.change_ids[from..to]);
        self.received_at
            .extend_from_slice(&old.received_at[from..to]);
        self.sent_at.extend_from_slice(&old.sent_at[from..to]);
        self.sizes.extend_from_slice(&old.sizes[from..to]);
        self.keywords.extend_from_slice(&old.keywords[from..to]);
        self.thread_ids.extend_from_slice(&old.thread_ids[from..to]);

        let base = old.mb_offsets[from];
        let shift = self.mb_arena.len() as u32;
        self.mb_offsets
            .extend(old.mb_offsets[from..to].iter().map(|o| o - base + shift));
        self.mb_arena.extend_from_slice(
            &old.mb_arena[old.mb_offsets[from] as usize..old.mb_offsets[to] as usize],
        );
    }

    fn finish_into(mut self, out: &mut Vec<ColBlock>) {
        let rows = self.len();
        if rows == 0 {
            return;
        }
        self.mb_offsets.push(self.mb_arena.len() as u32);

        if rows <= CACHE_CHUNK * 2 {
            out.push(ColBlock {
                document_ids: self.document_ids.into(),
                change_ids: self.change_ids.into(),
                received_at: self.received_at.into(),
                sent_at: self.sent_at.into(),
                sizes: self.sizes.into(),
                keywords: self.keywords.into(),
                thread_ids: self.thread_ids.into(),
                mb_offsets: self.mb_offsets.into(),
                mb_arena: self.mb_arena.into(),
            });
            return;
        }

        let mut from = 0usize;
        while from < rows {
            let to = (from + CACHE_CHUNK).min(rows);
            let base = self.mb_offsets[from];
            let arena_from = base as usize;
            let arena_to = self.mb_offsets[to] as usize;
            let mut mb_offsets = self.mb_offsets[from..to]
                .iter()
                .map(|offset| offset - base)
                .collect::<Vec<_>>();
            mb_offsets.push((arena_to - arena_from) as u32);

            out.push(ColBlock {
                document_ids: self.document_ids[from..to].into(),
                change_ids: self.change_ids[from..to].into(),
                received_at: self.received_at[from..to].into(),
                sent_at: self.sent_at[from..to].into(),
                sizes: self.sizes[from..to].into(),
                keywords: self.keywords[from..to].into(),
                thread_ids: self.thread_ids[from..to].into(),
                mb_offsets: mb_offsets.into(),
                mb_arena: self.mb_arena[arena_from..arena_to].into(),
            });
            from = to;
        }
    }
}

const SHIFT_BUCKET: usize = 1024;

struct PositionShift {
    steps: Vec<(u32, i32)>,
    bucket_first: Vec<u32>,
    bucket_delta: Vec<i32>,
    first_key: u32,
}

impl PositionShift {
    fn build(
        insert_positions: impl Iterator<Item = u32>,
        delete_positions: impl Iterator<Item = u32>,
        old_len: usize,
    ) -> Self {
        let mut steps: Vec<(u32, i32)> = Vec::new();
        let mut inserted = insert_positions.peekable();
        let mut deleted = delete_positions.map(|position| position + 1).peekable();
        let mut total = 0i32;
        loop {
            let (key, delta) = match (inserted.peek(), deleted.peek()) {
                (Some(insert), Some(delete)) if insert > delete => (deleted.next().unwrap(), -1i32),
                (Some(_), _) => (inserted.next().unwrap(), 1i32),
                (None, Some(_)) => (deleted.next().unwrap(), -1i32),
                (None, None) => break,
            };

            total += delta;
            if let Some(last) = steps.last_mut()
                && last.0 == key
            {
                last.1 = total;
            } else {
                steps.push((key, total));
            }
        }

        let buckets = old_len / SHIFT_BUCKET + 2;
        let mut bucket_first = Vec::with_capacity(buckets);
        let mut bucket_delta = Vec::with_capacity(buckets);
        let mut cursor = steps.iter().enumerate().peekable();
        let mut carried = 0i32;
        for bucket in 0..buckets {
            let start = (bucket * SHIFT_BUCKET) as u32;
            while let Some((_, (_, delta))) = cursor.next_if(|(_, (key, _))| *key < start) {
                carried = *delta;
            }
            bucket_first.push(cursor.peek().map_or(steps.len(), |(at, _)| *at) as u32);
            bucket_delta.push(carried);
        }

        PositionShift {
            first_key: steps.first().map_or(u32::MAX, |(key, _)| *key),
            steps,
            bucket_first,
            bucket_delta,
        }
    }

    #[inline(always)]
    fn at(&self, position: u32) -> i32 {
        if position < self.first_key {
            return 0;
        }
        let bucket = (position as usize / SHIFT_BUCKET).min(self.bucket_first.len() - 1);
        let from = self.bucket_first[bucket] as usize;

        self.steps[from..]
            .iter()
            .take_while(|(key, _)| *key <= position)
            .last()
            .map_or(self.bucket_delta[bucket], |(_, delta)| *delta)
    }
}

impl MessagesCache {
    pub fn new(change_id: u64, items: Vec<MessageCache>, keywords: Vec<CustomKeywords>) -> Self {
        debug_assert!(
            items.is_sorted_by_key(|item| item.sort_rank()),
            "items must be ordered by (received_at, document_id)"
        );
        debug_assert!(
            keywords.is_sorted_by_key(|entry| entry.document_id),
            "custom keywords must be ordered by document_id"
        );

        Self::from_records(change_id, &items, keywords.into())
    }

    fn from_records(
        change_id: u64,
        items: &[MessageCache],
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        let blocks = items
            .chunks(CACHE_CHUNK)
            .map(ColBlock::from_records)
            .collect::<Vec<_>>();
        let (starts, len) = Self::starts_of(&blocks);

        Self::assemble(change_id, blocks, starts, len, keywords)
    }

    fn starts_of(blocks: &[ColBlock]) -> (Vec<u32>, usize) {
        let mut starts = Vec::with_capacity(blocks.len());
        let mut start = 0u32;
        for block in blocks {
            starts.push(start);
            start += block.len() as u32;
        }
        (starts, start as usize)
    }

    fn assemble(
        change_id: u64,
        blocks: Vec<ColBlock>,
        starts: Vec<u32>,
        len: usize,
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        let mut index = Vec::with_capacity(len);
        for (block_idx, block) in blocks.iter().enumerate() {
            let start = starts[block_idx];
            for (slot, document_id) in block.document_ids.iter().enumerate() {
                index.push((*document_id, start + slot as u32));
            }
        }
        index.sort_unstable_by_key(|(document_id, _)| *document_id);

        Self::from_parts(change_id, blocks, starts, index.into(), keywords, len)
    }

    pub(crate) fn from_parts(
        change_id: u64,
        blocks: Vec<ColBlock>,
        starts: Vec<u32>,
        index: Arc<[(u32, u32)]>,
        keywords: Arc<[CustomKeywords]>,
        len: usize,
    ) -> Self {
        let size = keywords
            .iter()
            .map(|entry| {
                std::mem::size_of::<CustomKeywords>()
                    + (entry.names.len() * std::mem::size_of::<String>())
            })
            .sum::<usize>() as u64
            + blocks.iter().map(ColBlock::weight).sum::<u64>()
            + (index.len() * std::mem::size_of::<(u32, u32)>()) as u64;

        MessagesCache {
            change_id,
            blocks,
            starts,
            index,
            keywords,
            len,
            size,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn keywords(&self) -> &[CustomKeywords] {
        &self.keywords
    }

    #[inline(always)]
    pub fn shared_keywords(&self) -> Arc<[CustomKeywords]> {
        self.keywords.clone()
    }

    #[inline(always)]
    fn locate(&self, position: u32) -> Option<(u32, u32)> {
        if (position as usize) >= self.len {
            return None;
        }
        let block = match self.starts.binary_search(&position) {
            Ok(block) => block,
            Err(next) => next - 1,
        };
        Some((block as u32, position - self.starts[block]))
    }

    #[inline(always)]
    pub fn position(&self, document_id: u32) -> Option<u32> {
        self.index
            .binary_search_by_key(&document_id, |(id, _)| *id)
            .ok()
            .map(|idx| self.index[idx].1)
    }

    #[inline(always)]
    pub fn contains(&self, document_id: u32) -> bool {
        self.index
            .binary_search_by_key(&document_id, |(id, _)| *id)
            .is_ok()
    }

    #[inline(always)]
    pub fn document_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.index.iter().map(|(document_id, _)| *document_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = MessageRef<'_>> + '_ {
        self.blocks
            .iter()
            .enumerate()
            .flat_map(move |(block, col)| {
                (0..col.len() as u32).map(move |slot| MessageRef {
                    cache: self,
                    block: block as u32,
                    slot,
                })
            })
    }

    #[inline(always)]
    pub fn at(&self, position: u32) -> Option<MessageRef<'_>> {
        self.locate(position).map(|(block, slot)| MessageRef {
            cache: self,
            block,
            slot,
        })
    }

    #[inline(always)]
    pub fn by_id(&self, document_id: u32) -> Option<MessageRef<'_>> {
        self.position(document_id).and_then(|p| self.at(p))
    }

    pub fn patch(
        &self,
        change_id: u64,
        updates: &[(u32, MessageCache)],
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        let mut blocks = self.blocks.clone();
        let mut touched = updates
            .iter()
            .filter_map(|(position, record)| {
                let (block, slot) = self.locate(*position)?;
                debug_assert_eq!(
                    self.blocks[block as usize].document_ids[slot as usize], record.document_id,
                    "a patch must not move a message to a different position"
                );
                Some((block, slot, record))
            })
            .collect::<Vec<_>>();
        touched.sort_unstable_by_key(|(block, slot, _)| (*block, *slot));

        for slots in touched.chunk_by(|(left, _, _), (right, _, _)| left == right) {
            blocks[slots[0].0 as usize].patch_slots(slots);
        }

        Self::from_parts(
            change_id,
            blocks,
            self.starts.clone(),
            self.index.clone(),
            keywords,
            self.len,
        )
    }

    fn locate_insert(&self, rank: (u64, u32)) -> (u32, u32) {
        let block = self
            .blocks
            .partition_point(|block| block.rank(block.len() - 1) < rank);
        match self.blocks.get(block) {
            Some(col) => {
                let (mut low, mut high) = (0usize, col.len());
                while low < high {
                    let mid = low + (high - low) / 2;
                    if col.rank(mid) < rank {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
                (block as u32, low as u32)
            }
            None => {
                let last = self.blocks.len() - 1;
                (last as u32, self.blocks[last].len() as u32)
            }
        }
    }

    pub fn splice(
        &self,
        change_id: u64,
        deletes: &[u32],
        updates: &[(u32, MessageCache)],
        inserts: &[MessageCache],
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        debug_assert!(
            inserts.is_sorted_by_key(|item| item.sort_rank()),
            "inserts must be ordered by (received_at, document_id)"
        );
        debug_assert!(
            deletes.is_sorted(),
            "deletes must be ordered by document id"
        );

        if self.blocks.is_empty() {
            return Self::from_records(change_id, inserts, keywords);
        }

        let mut deletions = deletes
            .iter()
            .filter_map(|document_id| {
                self.position(*document_id)
                    .and_then(|position| self.locate(position))
            })
            .collect::<Vec<_>>();
        deletions.sort_unstable();

        let mut edits = updates
            .iter()
            .filter_map(|(position, record)| {
                let (block, slot) = self.locate(*position)?;
                debug_assert_eq!(
                    self.blocks[block as usize].rank(slot as usize),
                    (record.received_at_secs() as u64, record.document_id),
                    "an update must not move a message to a different position"
                );
                Some((block, slot, record))
            })
            .collect::<Vec<_>>();
        edits.sort_unstable_by_key(|(block, slot, _)| (*block, *slot));

        let insertions = inserts
            .iter()
            .map(|record| {
                let (block, slot) =
                    self.locate_insert((record.received_at_secs() as u64, record.document_id));
                (block, slot, record)
            })
            .collect::<Vec<_>>();

        let extra_arena = inserts
            .iter()
            .map(|record| record.mailboxes.len())
            .sum::<usize>();
        let mut blocks: Vec<ColBlock> = Vec::with_capacity(self.blocks.len() + 1);
        let mut inserted_index: Vec<(u32, u32)> = Vec::with_capacity(inserts.len());
        let mut out_position = 0u32;
        let mut pending_deletes = deletions.iter().peekable();
        let mut pending_edits = edits.iter().peekable();
        let mut pending_inserts = insertions.iter().peekable();

        for (block_idx, old) in self.blocks.iter().enumerate() {
            let block_idx = block_idx as u32;
            let is_touched = pending_deletes
                .peek()
                .is_some_and(|(block, _)| *block == block_idx)
                || pending_edits
                    .peek()
                    .is_some_and(|(block, _, _)| *block == block_idx)
                || pending_inserts
                    .peek()
                    .is_some_and(|(block, _, _)| *block == block_idx);
            if !is_touched {
                out_position += old.len() as u32;
                blocks.push(old.clone());
                continue;
            }

            let mut builder = ColBuilder::with_capacity(
                old.len() + inserts.len(),
                old.mb_arena.len() + extra_arena,
            );
            let block_start = out_position;
            let mut run = 0usize;

            for slot in 0..=old.len() {
                let is_delete = pending_deletes
                    .peek()
                    .is_some_and(|(block, at)| *block == block_idx && *at as usize == slot);
                let is_edit = pending_edits
                    .peek()
                    .is_some_and(|(block, at, _)| *block == block_idx && *at as usize == slot);
                let is_insert = pending_inserts
                    .peek()
                    .is_some_and(|(block, at, _)| *block == block_idx && *at as usize == slot);
                if !is_delete && !is_edit && !is_insert && slot < old.len() {
                    continue;
                }

                builder.copy_run(old, run, slot);
                run = slot;

                while let Some((_, _, record)) = pending_inserts
                    .next_if(|(block, at, _)| *block == block_idx && *at as usize == slot)
                {
                    inserted_index.push((record.document_id, block_start + builder.len() as u32));
                    builder.push_record(record);
                }

                if slot == old.len() {
                    break;
                }
                if is_delete {
                    pending_deletes.next();
                    run = slot + 1;
                } else if let Some((_, _, record)) = pending_edits
                    .next_if(|(block, at, _)| *block == block_idx && *at as usize == slot)
                {
                    builder.push_record(record);
                    run = slot + 1;
                }
            }

            out_position += builder.len() as u32;
            builder.finish_into(&mut blocks);
        }

        let (starts, len) = Self::starts_of(&blocks);

        let shift = PositionShift::build(
            insertions
                .iter()
                .map(|(block, slot, _)| self.starts[*block as usize] + slot),
            deletions
                .iter()
                .map(|(block, slot)| self.starts[*block as usize] + slot),
            self.len,
        );
        inserted_index.sort_unstable_by_key(|(document_id, _)| *document_id);

        let mut index = Vec::with_capacity(len);
        let mut added = inserted_index.iter().peekable();
        let mut removed = deletes.iter().peekable();
        for (document_id, position) in self.index.iter() {
            while let Some(entry) = added.next_if(|(id, _)| *id < *document_id) {
                index.push(*entry);
            }
            while removed.next_if(|id| **id < *document_id).is_some() {}
            if removed.next_if(|id| **id == *document_id).is_some() {
                continue;
            }
            index.push((
                *document_id,
                (*position as i32 + shift.at(*position)) as u32,
            ));
        }
        index.extend(added.copied());

        debug_assert_eq!(index.len(), len, "the index must cover every message");

        Self::from_parts(change_id, blocks, starts, index.into(), keywords, len)
    }

    #[inline(always)]
    pub fn custom_keywords_of(&self, document_id: u32) -> &[CompactString] {
        self.keywords
            .binary_search_by_key(&document_id, |entry| entry.document_id)
            .map_or(&[][..], |idx| &self.keywords[idx].names)
    }
}

#[derive(Clone, Copy)]
pub struct MessageRef<'x> {
    cache: &'x MessagesCache,
    block: u32,
    slot: u32,
}

impl<'x> MessageRef<'x> {
    #[inline(always)]
    fn col(&self) -> &'x ColBlock {
        &self.cache.blocks[self.block as usize]
    }

    #[inline(always)]
    pub fn position(&self) -> u32 {
        self.cache.starts[self.block as usize] + self.slot
    }

    #[inline(always)]
    pub fn document_id(&self) -> u32 {
        self.col().document_ids[self.slot as usize]
    }

    #[inline(always)]
    pub fn mailboxes(&self) -> &'x [MessageUid] {
        self.col().mailboxes(self.slot)
    }

    #[inline(always)]
    pub fn keywords(&self) -> u32 {
        self.col().keywords[self.slot as usize]
    }

    #[inline(always)]
    pub fn thread_id(&self) -> u32 {
        self.col().thread_ids[self.slot as usize]
    }

    #[inline(always)]
    pub fn change_id(&self) -> u64 {
        self.col().change_ids[self.slot as usize]
    }

    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.col().sizes[self.slot as usize]
    }

    #[inline(always)]
    pub fn received_at(&self) -> u64 {
        self.col().received_at[self.slot as usize] as u64
    }

    #[inline(always)]
    pub fn sent_at(&self) -> i32 {
        self.col().sent_at[self.slot as usize]
    }

    #[inline(always)]
    pub fn sent_at_absolute(&self) -> i64 {
        self.received_at() as i64 + self.sent_at() as i64
    }

    #[inline(always)]
    pub fn sort_rank(&self) -> (u64, u32) {
        (self.received_at(), self.document_id())
    }

    #[inline(always)]
    pub fn has_mailbox_id(&self, mailbox_id: u32) -> bool {
        self.mailboxes()
            .iter()
            .any(|uid| uid.mailbox_id == mailbox_id)
    }

    #[inline(always)]
    pub fn uid_in(&self, mailbox_id: u32) -> Option<u32> {
        self.mailboxes()
            .iter()
            .find(|uid| uid.mailbox_id == mailbox_id)
            .map(|uid| uid.uid)
    }

    pub fn to_record(&self) -> MessageCache {
        MessageCache::new(
            self.document_id(),
            self.mailboxes().iter().copied().collect(),
            self.keywords(),
            self.thread_id(),
            self.change_id(),
            self.size(),
            self.received_at(),
            self.sent_at(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CACHE_CHUNK;

    const BASE: u64 = 1_700_000_000;

    fn message(document_id: u32, received_at: u64) -> MessageCache {
        let mailboxes = (0..((document_id % 3) + 1))
            .map(|slot| MessageUid {
                mailbox_id: (document_id + slot) % 11,
                uid: document_id + slot,
            })
            .collect();

        MessageCache::new(
            document_id,
            mailboxes,
            document_id % 29,
            document_id / 5,
            (document_id as u64) * 3,
            500 + document_id,
            received_at,
            -20 + (document_id as i32 % 400),
        )
    }

    fn sample(count: u32) -> Vec<MessageCache> {
        let mut items = (0..count)
            .map(|document_id| message(document_id, BASE + (document_id % 13) as u64))
            .collect::<Vec<_>>();
        items.sort_unstable_by_key(|item| item.sort_rank());
        items
    }

    fn custom_keywords(items: &[MessageCache]) -> Vec<CustomKeywords> {
        let mut keywords = items
            .iter()
            .filter(|item| item.document_id % 11 == 0)
            .map(|item| CustomKeywords {
                names: vec![CompactString::from(format!("label-{}", item.document_id))]
                    .into_boxed_slice(),
                document_id: item.document_id,
            })
            .collect::<Vec<_>>();
        keywords.sort_unstable_by_key(|entry| entry.document_id);
        keywords
    }

    fn build(items: &[MessageCache]) -> MessagesCache {
        MessagesCache::new(1, items.to_vec(), custom_keywords(items))
    }

    fn assert_equivalent(spliced: &MessagesCache, expected: &[MessageCache]) {
        let rebuilt = build(expected);

        assert_eq!(spliced.len(), rebuilt.len(), "length");
        assert_eq!(spliced.starts.len(), spliced.blocks.len(), "starts");
        for block in &spliced.blocks {
            assert!(
                block.len() > 0 && block.len() <= CACHE_CHUNK * 2,
                "block of {} rows is out of bounds",
                block.len()
            );
        }

        for (left, right) in spliced.iter().zip(rebuilt.iter()) {
            assert_eq!(left.position(), right.position(), "position");
            assert_eq!(left.document_id(), right.document_id(), "document id");
            assert_eq!(left.change_id(), right.change_id(), "change id");
            assert_eq!(left.received_at(), right.received_at(), "received at");
            assert_eq!(left.sent_at(), right.sent_at(), "sent at");
            assert_eq!(left.size(), right.size(), "size");
            assert_eq!(left.keywords(), right.keywords(), "keywords");
            assert_eq!(left.thread_id(), right.thread_id(), "thread id");
            assert_eq!(left.mailboxes(), right.mailboxes(), "mailboxes");
        }

        assert_eq!(spliced.index.len(), rebuilt.index.len(), "index length");
        assert!(
            spliced
                .index
                .is_sorted_by_key(|(document_id, _)| *document_id),
            "the index must stay ordered by document id"
        );
        for (document_id, _) in rebuilt.index.iter() {
            assert_eq!(
                spliced.position(*document_id),
                rebuilt.position(*document_id),
                "position of document {document_id}"
            );
            assert_eq!(
                spliced.custom_keywords_of(*document_id),
                rebuilt.custom_keywords_of(*document_id),
                "custom keywords of document {document_id}"
            );
        }
    }

    fn splice(
        cache: &MessagesCache,
        items: &[MessageCache],
        deletes: &[u32],
        updates: &[u32],
        inserts: &[MessageCache],
    ) -> (MessagesCache, Vec<MessageCache>) {
        let mut expected = items
            .iter()
            .filter(|item| !deletes.contains(&item.document_id))
            .cloned()
            .collect::<Vec<_>>();
        expected.extend(inserts.iter().cloned());
        expected.sort_unstable_by_key(|item| item.sort_rank());

        let updates = updates
            .iter()
            .map(|document_id| {
                let position = cache.position(*document_id).expect("unknown document");
                let mut record = cache.by_id(*document_id).unwrap().to_record();
                record.keywords ^= 1 << 3;
                record.change_id += 100;
                record.mailboxes.push(MessageUid {
                    mailbox_id: 31,
                    uid: *document_id,
                });
                (position, record)
            })
            .collect::<Vec<_>>();

        for (_, record) in &updates {
            let slot = expected
                .iter_mut()
                .find(|item| item.document_id == record.document_id)
                .expect("an updated document must survive");
            *slot = record.clone();
        }

        let mut deletes = deletes.to_vec();
        deletes.sort_unstable();
        let keywords = custom_keywords(&expected);

        (
            cache.splice(1, &deletes, &updates, inserts, keywords.into()),
            expected,
        )
    }

    #[test]
    fn locate_resolves_block_boundaries() {
        let items = sample(CACHE_CHUNK as u32 * 2 + 1);
        let cache = build(&items);

        assert_eq!(cache.blocks.len(), 3);
        assert_eq!(
            cache.starts,
            vec![0, CACHE_CHUNK as u32, CACHE_CHUNK as u32 * 2]
        );

        for position in [
            0,
            CACHE_CHUNK as u32 - 1,
            CACHE_CHUNK as u32,
            CACHE_CHUNK as u32 * 2 - 1,
            CACHE_CHUNK as u32 * 2,
            cache.len() as u32 - 1,
        ] {
            let item = cache.at(position).expect("position must resolve");
            assert_eq!(item.position(), position);
            assert_eq!(
                item.document_id(),
                items[position as usize].document_id,
                "position {position}"
            );
            assert_eq!(cache.position(item.document_id()), Some(position));
        }

        assert!(cache.at(cache.len() as u32).is_none());
    }

    #[test]
    fn patch_rewrites_one_block_at_a_time() {
        let items = sample(CACHE_CHUNK as u32 * 2 + 1);
        let cache = build(&items);

        let touched = [
            CACHE_CHUNK as u32 + 5,
            CACHE_CHUNK as u32 + 6,
            (CACHE_CHUNK as u32 * 2),
        ];
        let (patched, expected) = {
            let updates = touched
                .iter()
                .map(|position| {
                    let mut record = cache.at(*position).unwrap().to_record();
                    record.keywords ^= 1 << 4;
                    record.change_id += 7;
                    record.mailboxes.push(MessageUid {
                        mailbox_id: 42,
                        uid: record.document_id,
                    });
                    (*position, record)
                })
                .collect::<Vec<_>>();

            let mut expected = items.clone();
            for (position, record) in &updates {
                expected[*position as usize] = record.clone();
            }

            (cache.patch(1, &updates, cache.shared_keywords()), expected)
        };

        assert_equivalent(&patched, &expected);
        assert!(
            Arc::ptr_eq(
                &cache.blocks[0].document_ids,
                &patched.blocks[0].document_ids
            ),
            "an untouched block must be shared, not rebuilt"
        );
    }

    #[test]
    fn patch_rewrites_a_whole_block_of_mailboxes() {
        let items = sample(CACHE_CHUNK as u32 + 10);
        let cache = build(&items);

        let updates = (0..CACHE_CHUNK as u32)
            .map(|position| {
                let mut record = cache.at(position).unwrap().to_record();
                record.mailboxes.clear();
                record.mailboxes.push(MessageUid {
                    mailbox_id: 42,
                    uid: record.document_id,
                });
                (position, record)
            })
            .collect::<Vec<_>>();

        let mut expected = items.clone();
        for (position, record) in &updates {
            expected[*position as usize] = record.clone();
        }

        let patched = cache.patch(1, &updates, cache.shared_keywords());
        assert_equivalent(&patched, &expected);
    }

    #[test]
    fn splice_appends_to_the_last_block() {
        let items = sample(CACHE_CHUNK as u32 * 2 + 1);
        let cache = build(&items);
        let inserts = vec![message(90_000, BASE + 500)];

        let (spliced, expected) = splice(&cache, &items, &[], &[], &inserts);
        assert_equivalent(&spliced, &expected);
        assert_eq!(spliced.blocks.len(), 3);
        assert!(Arc::ptr_eq(
            &cache.blocks[0].document_ids,
            &spliced.blocks[0].document_ids
        ));
    }

    #[test]
    fn splice_inserts_out_of_order() {
        let items = sample(CACHE_CHUNK as u32 * 2 + 1);
        let cache = build(&items);
        let mut inserts = vec![
            message(90_001, BASE - 100),
            message(90_002, BASE + 3),
            message(90_003, BASE + 12),
            message(90_004, BASE + 400),
        ];
        inserts.sort_unstable_by_key(|item| item.sort_rank());

        let (spliced, expected) = splice(&cache, &items, &[], &[], &inserts);
        assert_equivalent(&spliced, &expected);
    }

    #[test]
    fn splice_deletes_scattered_messages() {
        let items = sample(CACHE_CHUNK as u32 * 2 + 1);
        let cache = build(&items);
        let deletes = (0..40u32).map(|n| n * 811).collect::<Vec<_>>();

        let (spliced, expected) = splice(&cache, &items, &deletes, &[], &[]);
        assert_equivalent(&spliced, &expected);
    }

    #[test]
    fn splice_applies_a_mixed_window() {
        let items = sample(CACHE_CHUNK as u32 * 2 + 1);
        let cache = build(&items);
        let deletes = (0..25u32).map(|n| 3 + n * 1_291).collect::<Vec<_>>();
        let updates = (0..30u32).map(|n| 7 + n * 977).collect::<Vec<_>>();
        let mut inserts = (0..10u32)
            .map(|n| message(90_000 + n, BASE + (n % 13) as u64))
            .collect::<Vec<_>>();
        inserts.sort_unstable_by_key(|item| item.sort_rank());

        let (spliced, expected) = splice(&cache, &items, &deletes, &updates, &inserts);
        assert_equivalent(&spliced, &expected);
    }

    #[test]
    fn splice_splits_an_oversized_block() {
        let items = sample(100);
        let cache = build(&items);
        let mut inserts = (0..(CACHE_CHUNK as u32 * 2))
            .map(|n| message(90_000 + n, BASE + 6))
            .collect::<Vec<_>>();
        inserts.sort_unstable_by_key(|item| item.sort_rank());

        let (spliced, expected) = splice(&cache, &items, &[], &[], &inserts);
        assert_equivalent(&spliced, &expected);
        assert!(
            spliced.blocks.len() > 1,
            "a block past twice the chunk size must be split"
        );
    }

    #[test]
    fn splice_drops_an_emptied_block() {
        let items = sample(CACHE_CHUNK as u32 + 10);
        let cache = build(&items);
        assert_eq!(cache.blocks.len(), 2);

        let deletes = items[CACHE_CHUNK..]
            .iter()
            .map(|item| item.document_id)
            .collect::<Vec<_>>();

        let (spliced, expected) = splice(&cache, &items, &deletes, &[], &[]);
        assert_equivalent(&spliced, &expected);
        assert_eq!(spliced.blocks.len(), 1);
    }

    #[test]
    fn splice_into_an_empty_cache() {
        let cache = MessagesCache::new(1, Vec::new(), Vec::new());
        let inserts = sample(20);

        let (spliced, expected) = splice(&cache, &[], &[], &[], &inserts);
        assert_equivalent(&spliced, &expected);
        assert_eq!(spliced.len(), 20);
    }

    #[test]
    fn splice_empties_the_cache() {
        let items = sample(50);
        let cache = build(&items);
        let deletes = items
            .iter()
            .map(|item| item.document_id)
            .collect::<Vec<_>>();

        let (spliced, expected) = splice(&cache, &items, &deletes, &[], &[]);
        assert_equivalent(&spliced, &expected);
        assert!(spliced.is_empty());
        assert!(spliced.blocks.is_empty());
    }
}
