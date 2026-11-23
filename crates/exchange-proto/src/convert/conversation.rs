/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::{
    FileTime, UtcSeconds,
    base64::{Base64Mode, base64_decode_into},
};
use bytes::Bytes;

pub const MAX_THREAD_INDEX: usize = 4096;
pub const CONVERSATION_INDEX_HEADER_LEN: usize = 22;
const CONVERSATION_INDEX_RESERVED: u8 = 0x01;
const CONVERSATION_INDEX_CHILD_LEN: usize = 5;
const CONVERSATION_INDEX_TIME_END: usize = 6;
const CHILD_LONG_DELTA_MASK: u64 = 0x00FE_0000;
const CHILD_LONG_DELTA_CODE: u32 = 0x8000_0000;
const CHILD_DELTA_BITS: u64 = 0x7FFF_FFFF;
const CHILD_SHORT_SHIFT: u32 = 18;
const CHILD_LONG_SHIFT: u32 = 23;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationIndex(Bytes);

impl ConversationIndex {
    pub fn resolve(thread_index: Option<&[u8]>, delivered: UtcSeconds, thread_id: u32) -> Self {
        thread_index
            .and_then(Self::from_thread_index)
            .unwrap_or_else(|| Self::synthesized(delivered, thread_id))
    }

    pub fn from_thread_index(header: &[u8]) -> Option<Self> {
        let mut index = Vec::new();
        base64_decode_into(header, &mut index, MAX_THREAD_INDEX, Base64Mode::Lenient).ok()?;
        Self::is_well_formed(&index).then(|| ConversationIndex(index.into()))
    }

    pub fn is_well_formed(index: &[u8]) -> bool {
        index.first() == Some(&CONVERSATION_INDEX_RESERVED)
            && index
                .len()
                .checked_sub(CONVERSATION_INDEX_HEADER_LEN)
                .is_some_and(|children| children % CONVERSATION_INDEX_CHILD_LEN == 0)
    }

    pub fn synthesized(delivered: UtcSeconds, thread_id: u32) -> Self {
        let [t0, t1, t2, t3, t4, ..] = FileTime::from_utc(delivered, 0).0.to_be_bytes();
        let [g0, g1, g2, g3] = thread_id.to_be_bytes();
        let index: [u8; CONVERSATION_INDEX_HEADER_LEN] = [
            CONVERSATION_INDEX_RESERVED,
            t0,
            t1,
            t2,
            t3,
            t4,
            g0,
            g1,
            g2,
            g3,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        ConversationIndex(Bytes::copy_from_slice(&index))
    }

    pub fn child(&self, now: FileTime, random: u8) -> Option<Self> {
        let [_, t0, t1, t2, t3, t4, ..] = *self.0.as_ref() else {
            return None;
        };
        if self.0.len() + CONVERSATION_INDEX_CHILD_LEN > MAX_THREAD_INDEX {
            return None;
        }
        let header = u64::from_be_bytes([t0, t1, t2, t3, t4, 0, 0, 0]);
        let diff = now.0.saturating_sub(header);
        let delta = if (diff >> 32) & CHILD_LONG_DELTA_MASK == 0 {
            ((diff >> CHILD_SHORT_SHIFT) & CHILD_DELTA_BITS) as u32
        } else {
            CHILD_LONG_DELTA_CODE | ((diff >> CHILD_LONG_SHIFT) & CHILD_DELTA_BITS) as u32
        };
        let [d0, d1, d2, d3] = delta.to_be_bytes();
        let mut index = Vec::with_capacity(self.0.len() + CONVERSATION_INDEX_CHILD_LEN);
        index.extend_from_slice(&self.0);
        index.extend_from_slice(&[d0, d1, d2, d3, random]);
        Some(ConversationIndex(index.into()))
    }

    pub fn timestamps(&self) -> Vec<u8> {
        let time = self
            .0
            .get(1..CONVERSATION_INDEX_TIME_END)
            .unwrap_or_default();
        let children = self
            .0
            .get(CONVERSATION_INDEX_HEADER_LEN..)
            .unwrap_or_default();
        let mut out = Vec::with_capacity(time.len() + children.len());
        out.extend_from_slice(time);
        out.extend_from_slice(children);
        out
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/convert/conversation/tests.rs"]
mod tests;
