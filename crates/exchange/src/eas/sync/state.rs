/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use exchange_proto::eas::{
    commands::sync::{Ghosting, MAX_OPTIONS, SyncOptions},
    tokens::Tag,
};
use smallvec::SmallVec;
use std::mem;
use store::roaring::RoaringBitmap;

const OPTIONS_VERSION: u8 = 1;
const VIEW_VERSION: u8 = 2;
const HAS_DELETES_AS_MOVES: u8 = 0x01;
const DELETES_AS_MOVES: u8 = 0x02;
const HAS_CONVERSATION_MODE: u8 = 0x04;
const CONVERSATION_MODE: u8 = 0x08;
const HAS_PAGE: u8 = 0x01;
const SUPPORTED_VERSION: u8 = 1;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CollectionOptions {
    pub window_size: Option<u32>,
    pub deletes_as_moves: Option<bool>,
    pub conversation_mode: Option<bool>,
    pub options: SmallVec<[SyncOptions; 2]>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SupportedFields(Option<SmallVec<[Tag; 16]>>);

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClientView {
    pub page: Option<u32>,
    pub held: RoaringBitmap,
    pub added: RoaringBitmap,
    pub removed: RoaringBitmap,
    pub pending: RoaringBitmap,
    pub changed: RoaringBitmap,
    pub hidden: RoaringBitmap,
}

impl CollectionOptions {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        let mut flags = 0u8;
        if let Some(value) = self.deletes_as_moves {
            flags |= HAS_DELETES_AS_MOVES | if value { DELETES_AS_MOVES } else { 0 };
        }
        if let Some(value) = self.conversation_mode {
            flags |= HAS_CONVERSATION_MODE | if value { CONVERSATION_MODE } else { 0 };
        }
        out.extend_from_slice(&[OPTIONS_VERSION, flags]);
        out.extend_from_slice(&self.window_size.unwrap_or_default().to_le_bytes());
        out.push(u8::try_from(self.options.len()).unwrap_or(u8::MAX));
        let mut block = Vec::with_capacity(32);
        for options in &self.options {
            block.clear();
            options.encode_state(&mut block);
            out.extend_from_slice(&u16::try_from(block.len()).unwrap_or(0).to_le_bytes());
            out.extend_from_slice(&block);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&[OPTIONS_VERSION, flags], rest) = bytes.split_first_chunk::<2>()? else {
            return None;
        };
        let (window, rest) = rest.split_first_chunk::<4>()?;
        let (&count, mut rest) = rest.split_first()?;
        if usize::from(count) > MAX_OPTIONS {
            return None;
        }
        let mut options = SmallVec::new();
        for _ in 0..count {
            let (len, tail) = rest.split_first_chunk::<2>()?;
            let (block, tail) = tail.split_at_checked(usize::from(u16::from_le_bytes(*len)))?;
            options.push(SyncOptions::decode_state(block)?);
            rest = tail;
        }
        let window = u32::from_le_bytes(*window);
        Some(CollectionOptions {
            window_size: (window != 0).then_some(window),
            deletes_as_moves: (flags & HAS_DELETES_AS_MOVES != 0)
                .then_some(flags & DELETES_AS_MOVES != 0),
            conversation_mode: (flags & HAS_CONVERSATION_MODE != 0)
                .then_some(flags & CONVERSATION_MODE != 0),
            options,
        })
    }
}

impl SupportedFields {
    pub fn new(tags: Option<&[Tag]>) -> Self {
        SupportedFields(tags.map(SmallVec::from_slice))
    }

    pub fn ghosting(&self) -> Ghosting<'_> {
        match &self.0 {
            Some(tags) => Ghosting::Except(tags),
            None => Ghosting::Off,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let Some(tags) = &self.0 else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(1 + tags.len() * 2);
        out.push(SUPPORTED_VERSION);
        for tag in tags {
            out.extend_from_slice(&tag.raw().to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Self {
        match bytes.split_first() {
            Some((&SUPPORTED_VERSION, tags)) => SupportedFields(Some(
                tags.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|raw| Tag::from_raw(u16::from_le_bytes(*raw)))
                    .collect(),
            )),
            _ => SupportedFields(None),
        }
    }
}

impl ClientView {
    fn bitmaps(&self) -> [&RoaringBitmap; 6] {
        [
            &self.held,
            &self.added,
            &self.removed,
            &self.pending,
            &self.changed,
            &self.hidden,
        ]
    }

    pub fn shows(&self, document_id: u32) -> bool {
        self.held.contains(document_id) && !self.hidden.contains(document_id)
    }

    pub fn encode(&self) -> Vec<u8> {
        let bitmaps = self.bitmaps();
        let mut out = Vec::with_capacity(
            6 + bitmaps
                .iter()
                .map(|bitmap| bitmap.serialized_size() + 4)
                .sum::<usize>(),
        );
        match self.page {
            Some(page) => {
                out.extend_from_slice(&[VIEW_VERSION, HAS_PAGE]);
                out.extend_from_slice(&page.to_le_bytes());
            }
            None => out.extend_from_slice(&[VIEW_VERSION, 0]),
        }
        for bitmap in bitmaps {
            let len = u32::try_from(bitmap.serialized_size()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_le_bytes());
            let _ = bitmap.serialize_into(&mut out);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&[VIEW_VERSION, flags], mut rest) = bytes.split_first_chunk::<2>()? else {
            return None;
        };
        let page = if flags & HAS_PAGE != 0 {
            let (page, tail) = rest.split_first_chunk::<4>()?;
            rest = tail;
            Some(u32::from_le_bytes(*page))
        } else {
            None
        };
        let mut bitmaps: [RoaringBitmap; 6] = Default::default();
        for bitmap in &mut bitmaps {
            let (len, tail) = rest.split_first_chunk::<4>()?;
            let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
            let (block, tail) = tail.split_at_checked(len)?;
            *bitmap = RoaringBitmap::deserialize_from(block).ok()?;
            rest = tail;
        }
        let [held, added, removed, pending, changed, hidden] = bitmaps;
        rest.is_empty().then_some(ClientView {
            page,
            held,
            added,
            removed,
            pending,
            changed,
            hidden,
        })
    }

    pub fn rewind(&mut self) -> RoaringBitmap {
        self.held -= &self.added;
        self.held |= &self.removed;
        self.hidden -= &self.changed;
        self.pending |= &self.changed;
        self.added.clear();
        self.changed.clear();
        mem::take(&mut self.removed)
    }

    pub fn queue_changes(&mut self, changed: &RoaringBitmap) {
        let retry = &self.hidden & changed;
        self.held -= &retry;
        self.hidden -= &retry;
        self.pending |= changed;
        self.pending &= &self.held;
        self.pending -= &self.hidden;
    }

    pub fn hide_changed(&mut self, document_id: u32) {
        self.hidden.insert(document_id);
    }

    pub fn withdraw_changed(&mut self, document_id: u32) {
        self.held.remove(document_id);
        self.removed.insert(document_id);
    }

    pub fn advance(&mut self) {
        self.added.clear();
        self.removed.clear();
        self.changed.clear();
    }
}
