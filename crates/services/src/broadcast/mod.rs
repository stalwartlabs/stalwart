/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::ipc::BroadcastEvent;
use std::borrow::Borrow;
use types::type_state::StateChange;
use utils::{
    codec::leb128::{Leb128Iterator, Leb128Writer},
    map::bitmap::Bitmap,
};

pub mod publisher;
pub mod subscriber;

#[derive(Debug)]
pub(crate) struct BroadcastBatch<T> {
    messages: T,
}

const MAX_BATCH_SIZE: usize = 100;
pub(crate) const BROADCAST_TOPIC: &str = "stwt.agora";

impl BroadcastBatch<Vec<BroadcastEvent>> {
    pub fn init() -> Self {
        Self {
            messages: Vec::with_capacity(MAX_BATCH_SIZE),
        }
    }

    pub fn insert(&mut self, message: BroadcastEvent) -> bool {
        self.messages.push(message);
        self.messages.len() < MAX_BATCH_SIZE
    }

    pub fn serialize(&self, node_id: u16) -> Vec<u8> {
        let mut serialized =
            Vec::with_capacity((self.messages.len() * 10) + std::mem::size_of::<u16>());
        let _ = serialized.write_leb128(node_id);
        for message in &self.messages {
            match message {
                BroadcastEvent::StateChange(state_change) => {
                    serialized.push(0u8);
                    let _ = serialized.write_leb128(state_change.change_id);
                    let _ = serialized.write_leb128(*state_change.types.as_ref());
                    let _ = serialized.write_leb128(state_change.account_id);
                }
                BroadcastEvent::InvalidateAccessTokens(items) => {
                    serialized.push(1u8);
                    let _ = serialized.write_leb128(items.len());
                    for item in items {
                        let _ = serialized.write_leb128(*item);
                    }
                }
                BroadcastEvent::InvalidateDavCache(items) => {
                    serialized.push(2u8);
                    let _ = serialized.write_leb128(items.len());
                    for item in items {
                        let _ = serialized.write_leb128(*item);
                    }
                }
                BroadcastEvent::ReloadSettings => {
                    serialized.push(3u8);
                }
                BroadcastEvent::ReloadBlockedIps => {
                    serialized.push(4u8);
                }
            }
        }
        serialized
    }

    pub fn clear(&mut self) {
        self.messages.clear();
    }
}

impl<T, I> BroadcastBatch<T>
where
    T: Iterator<Item = I> + Leb128Iterator<I>,
    I: Borrow<u8>,
{
    pub fn node_id(&mut self) -> Option<u16> {
        self.messages.next_leb128::<u16>()
    }

    pub fn next_event(&mut self) -> Result<Option<BroadcastEvent>, ()> {
        if let Some(id) = self.messages.next() {
            match id.borrow() {
                0 => Ok(Some(BroadcastEvent::StateChange(StateChange {
                    change_id: self.messages.next_leb128().ok_or(())?,
                    types: Bitmap::from(self.messages.next_leb128::<u64>().ok_or(())?),
                    account_id: self.messages.next_leb128().ok_or(())?,
                }))),
                1 => {
                    let count = self.messages.next_leb128::<usize>().ok_or(())?;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        items.push(self.messages.next_leb128().ok_or(())?);
                    }
                    Ok(Some(BroadcastEvent::InvalidateAccessTokens(items)))
                }
                2 => {
                    let count = self.messages.next_leb128::<usize>().ok_or(())?;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        items.push(self.messages.next_leb128().ok_or(())?);
                    }
                    Ok(Some(BroadcastEvent::InvalidateDavCache(items)))
                }
                3 => Ok(Some(BroadcastEvent::ReloadSettings)),

                4 => Ok(Some(BroadcastEvent::ReloadBlockedIps)),

                _ => Err(()),
            }
        } else {
            Ok(None)
        }
    }
}

impl<T> BroadcastBatch<T> {
    pub fn new(messages: T) -> Self {
        Self { messages }
    }
}
