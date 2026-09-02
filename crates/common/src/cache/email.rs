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
            "received_at {} exceeds the representable range, protocol input must reject it",
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

    fn weight(&self) -> u64 {
        ((self.document_ids.len()
            * (std::mem::size_of::<u32>() * 5
                + std::mem::size_of::<i32>()
                + std::mem::size_of::<u64>() * 2))
            + (self.mb_offsets.len() * std::mem::size_of::<u32>())
            + (self.mb_arena.len() * std::mem::size_of::<MessageUid>())
            + std::mem::size_of::<ColBlock>()) as u64
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

        let mut blocks = Vec::with_capacity(items.len().div_ceil(CACHE_CHUNK).max(1));
        let mut starts = Vec::with_capacity(blocks.capacity());
        let mut start = 0u32;
        for chunk in items.chunks(CACHE_CHUNK) {
            starts.push(start);
            start += chunk.len() as u32;
            blocks.push(ColBlock::from_records(chunk));
        }

        Self::assemble(change_id, blocks, starts, items.len(), keywords.into())
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
        let mut touched: Vec<(usize, Vec<(u32, &MessageCache)>)> = Vec::new();
        for (position, record) in updates {
            let Some((block, slot)) = self.locate(*position) else {
                continue;
            };
            debug_assert_eq!(
                blocks[block as usize].document_ids[slot as usize], record.document_id,
                "a patch must not move a message to a different position"
            );
            match touched.iter_mut().find(|(idx, _)| *idx == block as usize) {
                Some((_, slots)) => slots.push((slot, record)),
                None => touched.push((block as usize, vec![(slot, record)])),
            }
        }

        for (block_idx, slots) in touched {
            let block = &mut blocks[block_idx];

            if slots
                .iter()
                .any(|(slot, record)| block.change_ids[*slot as usize] != record.change_id)
            {
                let mut column = block.change_ids.to_vec();
                for (slot, record) in &slots {
                    column[*slot as usize] = record.change_id;
                }
                block.change_ids = column.into();
            }
            if slots
                .iter()
                .any(|(slot, record)| block.keywords[*slot as usize] != record.keywords)
            {
                let mut column = block.keywords.to_vec();
                for (slot, record) in &slots {
                    column[*slot as usize] = record.keywords;
                }
                block.keywords = column.into();
            }
            if slots
                .iter()
                .any(|(slot, record)| block.thread_ids[*slot as usize] != record.thread_id)
            {
                let mut column = block.thread_ids.to_vec();
                for (slot, record) in &slots {
                    column[*slot as usize] = record.thread_id;
                }
                block.thread_ids = column.into();
            }
            if slots
                .iter()
                .any(|(slot, record)| block.sizes[*slot as usize] != record.size)
            {
                let mut column = block.sizes.to_vec();
                for (slot, record) in &slots {
                    column[*slot as usize] = record.size;
                }
                block.sizes = column.into();
            }

            if slots
                .iter()
                .any(|(slot, record)| block.mailboxes(*slot) != record.mailboxes.as_slice())
            {
                let mut mb_offsets = Vec::with_capacity(block.len() + 1);
                let mut mb_arena = Vec::with_capacity(block.mb_arena.len());
                let mut offset = 0u32;
                for slot in 0..block.len() as u32 {
                    mb_offsets.push(offset);
                    let mailboxes = match slots.iter().find(|(s, _)| *s == slot) {
                        Some((_, record)) => record.mailboxes.as_slice(),
                        None => block.mailboxes(slot),
                    };
                    mb_arena.extend_from_slice(mailboxes);
                    offset += mailboxes.len() as u32;
                }
                mb_offsets.push(offset);
                block.mb_offsets = mb_offsets.into();
                block.mb_arena = mb_arena.into();
            }
        }

        let size = keywords
            .iter()
            .map(|entry| {
                std::mem::size_of::<CustomKeywords>()
                    + (entry.names.len() * std::mem::size_of::<String>())
            })
            .sum::<usize>() as u64
            + blocks.iter().map(ColBlock::weight).sum::<u64>()
            + (self.index.len() * std::mem::size_of::<(u32, u32)>()) as u64;

        MessagesCache {
            change_id,
            blocks,
            starts: self.starts.clone(),
            index: self.index.clone(),
            keywords,
            len: self.len,
            size,
        }
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
