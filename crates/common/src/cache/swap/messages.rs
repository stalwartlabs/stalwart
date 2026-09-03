/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SwapPart, frame::SwapFrame};
use crate::{CACHE_CHUNK, ColBlock, CustomKeywords, MessageUid, MessagesCache};
use compact_str::CompactString;
use rkyv::{
    rend::unaligned::{i32_ule, u32_ule, u64_ule},
    with::InlineAsBox,
};
use std::sync::Arc;

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedBlock<'x> {
    #[rkyv(with = InlineAsBox)]
    pub document_ids: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub change_ids: &'x [u64],
    #[rkyv(with = InlineAsBox)]
    pub received_at: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub sent_at: &'x [i32],
    #[rkyv(with = InlineAsBox)]
    pub sizes: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub keywords: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub thread_ids: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub mb_offsets: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub mb_arena: &'x [u64],
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedMessages<'x> {
    pub change_id: u64,
    pub len: u32,
    #[rkyv(with = InlineAsBox)]
    pub starts: &'x [u32],
    pub blocks: Vec<ArchivedBlock<'x>>,
    pub index_ids: Vec<u32>,
    pub index_positions: Vec<u32>,
    pub custom_ids: Vec<u32>,
    pub custom_offsets: Vec<u32>,
    #[rkyv(with = rkyv::with::Map<InlineAsBox>)]
    pub custom_names: Vec<&'x str>,
}

impl MessagesCache {
    pub fn to_snapshot(&self) -> Option<Vec<u8>> {
        let arenas = self.mailbox_arenas();
        Self::seal_snapshot(&self.pack(&arenas), self.change_id, self.len as u32)
    }

    fn mailbox_arenas(&self) -> Vec<Vec<u64>> {
        self.blocks
            .iter()
            .map(|block| block.mb_arena.iter().map(MessageUid::pack).collect())
            .collect()
    }

    fn pack<'x>(&'x self, arenas: &'x [Vec<u64>]) -> ArchivedMessages<'x> {
        let mut blocks = Vec::with_capacity(self.blocks.len());
        for (block, mb_arena) in self.blocks.iter().zip(arenas.iter()) {
            blocks.push(ArchivedBlock {
                document_ids: &block.document_ids,
                change_ids: &block.change_ids,
                received_at: &block.received_at,
                sent_at: &block.sent_at,
                sizes: &block.sizes,
                keywords: &block.keywords,
                thread_ids: &block.thread_ids,
                mb_offsets: &block.mb_offsets,
                mb_arena,
            });
        }

        let (index_ids, index_positions): (Vec<u32>, Vec<u32>) = self.index.iter().copied().unzip();

        let mut custom_ids = Vec::with_capacity(self.keywords.len());
        let mut custom_offsets = Vec::with_capacity(self.keywords.len() + 1);
        let mut custom_names = Vec::new();
        custom_offsets.push(0u32);
        for entry in self.keywords.iter() {
            custom_ids.push(entry.document_id);
            for name in entry.names.iter() {
                custom_names.push(name.as_str());
            }
            custom_offsets.push(custom_names.len() as u32);
        }

        ArchivedMessages {
            change_id: self.change_id,
            len: self.len as u32,
            starts: &self.starts,
            blocks,
            index_ids,
            index_positions,
            custom_ids,
            custom_offsets,
            custom_names,
        }
    }

    fn seal_snapshot(
        archived: &ArchivedMessages<'_>,
        change_id: u64,
        count: u32,
    ) -> Option<Vec<u8>> {
        let mut out = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(
            archived,
            SwapFrame::reserve_header(),
        )
        .ok()?;

        SwapFrame::seal(&mut out, SwapPart::Messages, change_id, count).then_some(out)
    }

    pub fn from_snapshot(buf: &[u8]) -> Option<Self> {
        let frame = SwapFrame::parse(buf)?;
        if frame.part() != SwapPart::Messages {
            return None;
        }

        let archived =
            rkyv::access::<ArchivedArchivedMessages, rkyv::rancor::Error>(frame.payload()).ok()?;
        let len = archived.len.to_native() as usize;
        if archived.index_ids.len() != len || archived.index_positions.len() != len {
            return None;
        }

        let starts = archived
            .starts
            .iter()
            .map(|start| start.to_native())
            .collect::<Vec<_>>();
        if starts.len() != archived.blocks.len() {
            return None;
        }

        let mut blocks = Vec::with_capacity(archived.blocks.len());
        let mut total = 0usize;
        for (block, start) in archived.blocks.iter().zip(&starts) {
            let count = block.document_ids.len();
            if count == 0 || count > CACHE_CHUNK * 2 {
                return None;
            }
            if block.change_ids.len() != count
                || block.received_at.len() != count
                || block.sent_at.len() != count
                || block.sizes.len() != count
                || block.keywords.len() != count
                || block.thread_ids.len() != count
                || block.mb_offsets.len() != count + 1
            {
                return None;
            }
            if block.mb_offsets[0].to_native() != 0
                || block.mb_offsets[count].to_native() as usize != block.mb_arena.len()
                || !block
                    .mb_offsets
                    .iter()
                    .map(|offset| offset.to_native())
                    .is_sorted()
            {
                return None;
            }
            if *start as usize != total {
                return None;
            }

            total += count;
            blocks.push(ColBlock {
                document_ids: copy_u32(&block.document_ids),
                change_ids: copy_u64(&block.change_ids),
                received_at: copy_u32(&block.received_at),
                sent_at: copy_i32(&block.sent_at),
                sizes: copy_u32(&block.sizes),
                keywords: copy_u32(&block.keywords),
                thread_ids: copy_u32(&block.thread_ids),
                mb_offsets: copy_u32(&block.mb_offsets),
                mb_arena: copy_uid(&block.mb_arena),
            });
        }
        if total != len {
            return None;
        }

        let mut index = Vec::with_capacity(len);
        for (document_id, position) in archived
            .index_ids
            .iter()
            .zip(archived.index_positions.iter())
        {
            let position = position.to_native();
            if position as usize >= len {
                return None;
            }
            index.push((document_id.to_native(), position));
        }
        let index: Arc<[(u32, u32)]> = index.into();

        let custom_count = archived.custom_ids.len();
        if archived.custom_offsets.len() != custom_count + 1 {
            return None;
        }
        let mut keywords = Vec::with_capacity(custom_count);
        for (document_id, range) in archived
            .custom_ids
            .iter()
            .zip(archived.custom_offsets.windows(2))
        {
            let document_id = document_id.to_native();
            let from = range[0].to_native() as usize;
            let to = range[1].to_native() as usize;
            let names = archived.custom_names.get(from..to)?;
            keywords.push(CustomKeywords {
                names: names
                    .iter()
                    .map(|name| CompactString::from(&**name))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                document_id,
            });
        }

        Some(MessagesCache::from_parts(
            archived.change_id.to_native(),
            blocks,
            starts,
            index,
            keywords.into(),
            len,
        ))
    }
}

impl MessageUid {
    fn pack(&self) -> u64 {
        ((self.uid as u64) << 32) | self.mailbox_id as u64
    }

    fn unpack(packed: u64) -> Self {
        MessageUid {
            mailbox_id: packed as u32,
            uid: (packed >> 32) as u32,
        }
    }
}

fn copy_u32(src: &[u32_ule]) -> Arc<[u32]> {
    src.iter().map(|value| value.to_native()).collect()
}

fn copy_i32(src: &[i32_ule]) -> Arc<[i32]> {
    src.iter().map(|value| value.to_native()).collect()
}

fn copy_u64(src: &[u64_ule]) -> Arc<[u64]> {
    src.iter().map(|value| value.to_native()).collect()
}

fn copy_uid(src: &[u64_ule]) -> Arc<[MessageUid]> {
    src.iter()
        .map(|value| MessageUid::unpack(value.to_native()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{super::frame, *};
    use crate::{CACHE_CHUNK, MessageCache};
    use tinyvec::TinyVec;

    fn sample(count: usize) -> MessagesCache {
        let mut items = Vec::with_capacity(count);
        let mut keywords = Vec::new();

        for document_id in 0..count as u32 {
            let mut mailboxes: TinyVec<[MessageUid; 2]> = TinyVec::new();
            for slot in 0..((document_id % 5) + 1) {
                mailboxes.push(MessageUid {
                    mailbox_id: (document_id + slot) % 17,
                    uid: document_id + slot,
                });
            }

            if document_id % 7 == 0 {
                keywords.push(CustomKeywords {
                    names: vec![
                        CompactString::from("project-atlas"),
                        CompactString::from(format!("label-{document_id}")),
                    ]
                    .into_boxed_slice(),
                    document_id,
                });
            }

            items.push(MessageCache::new(
                document_id,
                mailboxes,
                document_id % 31,
                document_id / 3,
                (document_id as u64) * 2,
                1000 + document_id,
                1_700_000_000 + (document_id as u64 % 13),
                -30 + (document_id as i32 % 600),
            ));
        }

        items.sort_unstable_by_key(|item| item.sort_rank());
        MessagesCache::new(0xdead_beef, items, keywords)
    }

    fn assert_same(left: &MessagesCache, right: &MessagesCache) {
        assert_eq!(left.change_id, right.change_id);
        assert_eq!(left.len(), right.len());
        assert_eq!(left.starts, right.starts);
        assert_eq!(left.index.as_ref(), right.index.as_ref());
        assert_eq!(left.keywords.len(), right.keywords.len());
        for (a, b) in left.keywords.iter().zip(right.keywords.iter()) {
            assert_eq!(a.document_id, b.document_id);
            assert_eq!(a.names, b.names);
        }
        assert_eq!(left.size, right.size);

        for (a, b) in left.iter().zip(right.iter()) {
            assert_eq!(a.position(), b.position());
            assert_eq!(a.document_id(), b.document_id());
            assert_eq!(a.change_id(), b.change_id());
            assert_eq!(a.received_at(), b.received_at());
            assert_eq!(a.sent_at(), b.sent_at());
            assert_eq!(a.size(), b.size());
            assert_eq!(a.keywords(), b.keywords());
            assert_eq!(a.thread_id(), b.thread_id());
            assert_eq!(a.mailboxes(), b.mailboxes());
        }

        for (document_id, _) in left.index.iter() {
            assert_eq!(
                left.by_id(*document_id).map(|item| item.position()),
                right.by_id(*document_id).map(|item| item.position()),
            );
            assert_eq!(
                left.custom_keywords_of(*document_id),
                right.custom_keywords_of(*document_id)
            );
        }
    }

    #[test]
    fn snapshot_round_trips_single_block() {
        let cache = sample(500);
        let encoded = cache.to_snapshot().expect("encode");
        let decoded = MessagesCache::from_snapshot(&encoded).expect("decode");
        assert_eq!(decoded.blocks.len(), 1);
        assert_same(&cache, &decoded);
    }

    #[test]
    fn snapshot_round_trips_many_blocks() {
        let cache = sample(CACHE_CHUNK + (CACHE_CHUNK / 2));
        let encoded = cache.to_snapshot().expect("encode");
        let decoded = MessagesCache::from_snapshot(&encoded).expect("decode");
        assert_eq!(decoded.blocks.len(), 2);
        assert_same(&cache, &decoded);
    }

    #[test]
    fn snapshot_round_trips_empty() {
        let cache = MessagesCache::new(7, Vec::new(), Vec::new());
        let encoded = cache.to_snapshot().expect("encode");
        let decoded = MessagesCache::from_snapshot(&encoded).expect("decode");
        assert_same(&cache, &decoded);
    }

    #[test]
    fn corrupt_snapshot_is_rejected() {
        let cache = sample(300);
        let encoded = cache.to_snapshot().expect("encode");

        assert!(MessagesCache::from_snapshot(&[]).is_none());
        assert!(MessagesCache::from_snapshot(&encoded[..encoded.len() - 1]).is_none());
        assert!(MessagesCache::from_snapshot(&encoded[..8]).is_none());

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 0xff;
        assert!(MessagesCache::from_snapshot(&bad_magic).is_none());

        let mut bad_version = encoded.clone();
        bad_version[4] ^= 0xff;
        assert!(MessagesCache::from_snapshot(&bad_version).is_none());

        let mut bad_part = encoded.clone();
        bad_part[6] = SwapPart::Resources.code();
        assert!(MessagesCache::from_snapshot(&bad_part).is_none());

        for offset in [40usize, 512, 1024] {
            let mut flipped = encoded.clone();
            if offset < flipped.len() {
                flipped[offset] ^= 0x01;
                assert!(
                    MessagesCache::from_snapshot(&flipped).is_none(),
                    "a payload byte flip at {offset} was not rejected"
                );
            }
        }
    }

    #[test]
    fn an_inconsistent_payload_with_a_valid_checksum_is_rejected() {
        let cache = sample(CACHE_CHUNK + 200);
        let arenas = cache.mailbox_arenas();
        assert!(cache.blocks.len() > 1, "fixture must span several blocks");

        let broken_starts = vec![1u32; cache.blocks.len()];
        let mut archived = cache.pack(&arenas);
        archived.starts = &broken_starts;
        let encoded =
            MessagesCache::seal_snapshot(&archived, cache.change_id, cache.len as u32).unwrap();
        assert!(
            MessagesCache::from_snapshot(&encoded).is_none(),
            "block start offsets that do not match the block lengths were accepted"
        );

        let mut archived = cache.pack(&arenas);
        archived.index_positions[3] = cache.len as u32;
        let encoded =
            MessagesCache::seal_snapshot(&archived, cache.change_id, cache.len as u32).unwrap();
        assert!(
            MessagesCache::from_snapshot(&encoded).is_none(),
            "an index position past the end of the cache was accepted"
        );
    }

    #[test]
    fn an_empty_block_with_a_valid_checksum_is_rejected() {
        let cache = sample(CACHE_CHUNK + 200);
        let arenas = cache.mailbox_arenas();

        let mut starts = cache.starts.clone();
        starts.push(cache.len as u32);
        let mut archived = cache.pack(&arenas);
        archived.starts = &starts;
        archived.blocks.push(ArchivedBlock {
            document_ids: &[],
            change_ids: &[],
            received_at: &[],
            sent_at: &[],
            sizes: &[],
            keywords: &[],
            thread_ids: &[],
            mb_offsets: &[0],
            mb_arena: &[],
        });
        let encoded =
            MessagesCache::seal_snapshot(&archived, cache.change_id, cache.len as u32).unwrap();
        assert!(
            MessagesCache::from_snapshot(&encoded).is_none(),
            "an empty block was accepted, which breaks locate and locate_insert"
        );
    }

    #[test]
    fn spliced_snapshot_is_rejected() {
        let first = sample(400);
        let mut items = Vec::new();
        for item in first.iter() {
            let mut record = item.to_record();
            record.keywords ^= 1;
            items.push(record);
        }
        let second = MessagesCache::new(first.change_id + 1, items, first.keywords.to_vec());

        let head = second.to_snapshot().expect("encode");
        let body = first.to_snapshot().expect("encode");
        assert_eq!(head.len(), body.len());

        let mut spliced = head[..frame::HEADER_LEN].to_vec();
        spliced.extend_from_slice(&body[frame::HEADER_LEN..]);
        assert!(MessagesCache::from_snapshot(&spliced).is_none());
    }
}

#[cfg(test)]
mod perf_probe {
    #![allow(clippy::items_after_test_module)]
    use super::*;
    use crate::{CACHE_CHUNK, MessageCache};
    use std::time::Instant;
    use tinyvec::TinyVec;

    fn big(count: usize) -> MessagesCache {
        let mut items = Vec::with_capacity(count);
        let mut keywords = Vec::new();
        for document_id in 0..count as u32 {
            let mut mailboxes: TinyVec<[MessageUid; 2]> = TinyVec::new();
            let n = if document_id % 33 == 0 { 4 } else { 1 };
            for slot in 0..n {
                mailboxes.push(MessageUid {
                    mailbox_id: (document_id + slot) % 20,
                    uid: document_id + slot,
                });
            }
            if document_id % 50 == 0 {
                keywords.push(CustomKeywords {
                    names: vec![CompactString::from("project-atlas")].into_boxed_slice(),
                    document_id,
                });
            }
            items.push(MessageCache::new(
                document_id,
                mailboxes,
                document_id % 31,
                document_id / 3,
                document_id as u64,
                1000 + document_id,
                1_450_000_000 + (document_id as u64 % 300_000_000),
                (document_id % 600) as i32,
            ));
        }
        items.sort_unstable_by_key(|item| item.sort_rank());
        keywords.sort_unstable_by_key(|k| k.document_id);
        MessagesCache::new(1, items, keywords)
    }

    fn p50(mut v: Vec<f64>) -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    }

    #[test]
    fn product_codec_throughput() {
        if std::env::var("SWAP_PERF").is_err() {
            return;
        }
        let n = 1_000_000;
        let cache = big(n);
        let encoded = cache.to_snapshot().expect("encode");
        println!("blocks           = {}", cache.blocks.len());
        println!("chunk            = {CACHE_CHUNK}");
        println!("snapshot bytes   = {}", encoded.len());
        println!("bytes per msg    = {:.2}", encoded.len() as f64 / n as f64);

        for _ in 0..2 {
            std::hint::black_box(MessagesCache::from_snapshot(&encoded));
        }

        let mut decode = Vec::new();
        for _ in 0..25 {
            let t = Instant::now();
            let out = MessagesCache::from_snapshot(&encoded).expect("decode");
            decode.push(t.elapsed().as_secs_f64() * 1000.0);
            std::hint::black_box(out.len());
        }
        println!("decode p50 ms    = {:.4}", p50(decode));

        let mut encode = Vec::new();
        for _ in 0..15 {
            let t = Instant::now();
            let out = cache.to_snapshot().expect("encode");
            encode.push(t.elapsed().as_secs_f64() * 1000.0);
            std::hint::black_box(out.len());
        }
        println!("encode p50 ms    = {:.4}", p50(encode));

        let items = (0..n as u32)
            .map(|document_id| cache.by_id(document_id).unwrap().to_record())
            .collect::<Vec<_>>();
        let kw = cache.keywords.to_vec();
        let mut build = Vec::new();
        for _ in 0..10 {
            let t = Instant::now();
            let out = MessagesCache::new(1, items.clone(), kw.clone());
            build.push(t.elapsed().as_secs_f64() * 1000.0);
            std::hint::black_box(out.len());
        }
        println!("in-memory rebuild p50 ms = {:.4}", p50(build));
    }
}
