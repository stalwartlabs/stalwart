/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::error::TransportError;
use crate::codec::Uid;
use bytes::Bytes;
use std::{mem, task::Poll, task::Waker};

const NONE: u32 = u32::MAX;

pub(crate) type ReplyResult = Result<Bytes, TransportError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlotKey {
    index: u32,
    generation: u32,
}

impl SlotKey {
    pub(crate) const fn token_second(self) -> u64 {
        ((self.generation as u64) << 32) | self.index as u64
    }

    const fn from_token_second(second: u64) -> Self {
        Self {
            index: second as u32,
            generation: (second >> 32) as u32,
        }
    }
}

enum SlotState {
    Vacant { next: u32 },
    Waiting { waker: Waker, dest: Uid },
    Ready(ReplyResult),
}

struct Slot {
    generation: u32,
    state: SlotState,
}

impl Slot {
    fn vacate(&mut self, next: u32) -> SlotState {
        self.generation = self.generation.wrapping_add(1);
        mem::replace(&mut self.state, SlotState::Vacant { next })
    }
}

pub(crate) struct Slots {
    slots: Vec<Slot>,
    free: u32,
    waiting: usize,
}

impl Slots {
    pub(crate) const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: NONE,
            waiting: 0,
        }
    }

    pub(crate) fn waiting(&self) -> usize {
        self.waiting
    }

    pub(crate) fn insert(&mut self, waker: &Waker, dest: Uid) -> SlotKey {
        let state = SlotState::Waiting {
            waker: waker.clone(),
            dest,
        };
        self.waiting += 1;
        let index = self.free;
        if let Some(slot) = self.slots.get_mut(index as usize) {
            if let SlotState::Vacant { next } = mem::replace(&mut slot.state, state) {
                self.free = next;
            }
            return SlotKey {
                index,
                generation: slot.generation,
            };
        }
        let index = self.slots.len() as u32;
        self.slots.push(Slot {
            generation: 0,
            state,
        });
        SlotKey {
            index,
            generation: 0,
        }
    }

    pub(crate) fn is_waiting(&self, key: SlotKey) -> bool {
        self.slots.get(key.index as usize).is_some_and(|slot| {
            slot.generation == key.generation && matches!(slot.state, SlotState::Waiting { .. })
        })
    }

    pub(crate) fn poll(&mut self, key: SlotKey, waker: &Waker) -> Poll<ReplyResult> {
        let Some(slot) = live_slot(&mut self.slots, key) else {
            return Poll::Ready(Err(TransportError::MaybeDelivered));
        };
        match &mut slot.state {
            SlotState::Waiting { waker: stored, .. } => {
                if !stored.will_wake(waker) {
                    stored.clone_from(waker);
                }
                return Poll::Pending;
            }
            SlotState::Vacant { .. } => return Poll::Ready(Err(TransportError::MaybeDelivered)),
            SlotState::Ready(_) => {}
        }
        let state = slot.vacate(self.free);
        self.free = key.index;
        match state {
            SlotState::Ready(result) => Poll::Ready(result),
            SlotState::Waiting { .. } | SlotState::Vacant { .. } => {
                Poll::Ready(Err(TransportError::MaybeDelivered))
            }
        }
    }

    pub(crate) fn remove(&mut self, key: SlotKey) {
        let Some(slot) = live_slot(&mut self.slots, key) else {
            return;
        };
        if matches!(slot.state, SlotState::Vacant { .. }) {
            return;
        }
        if let SlotState::Waiting { .. } = slot.vacate(self.free) {
            self.waiting -= 1;
        }
        self.free = key.index;
    }

    pub(crate) fn complete(&mut self, token_second: u64, result: ReplyResult) -> Option<Waker> {
        let slot = live_slot(&mut self.slots, SlotKey::from_token_second(token_second))?;
        if !matches!(slot.state, SlotState::Waiting { .. }) {
            return None;
        }
        self.waiting -= 1;
        match mem::replace(&mut slot.state, SlotState::Ready(result)) {
            SlotState::Waiting { waker, .. } => Some(waker),
            SlotState::Ready(_) | SlotState::Vacant { .. } => None,
        }
    }

    pub(crate) fn fail_all(&mut self, error: TransportError, wakers: &mut Vec<Waker>) {
        self.fail_matching(error, wakers, |_| true);
    }

    pub(crate) fn fail_dest(&mut self, dest: Uid, error: TransportError, wakers: &mut Vec<Waker>) {
        self.fail_matching(error, wakers, |slot_dest| slot_dest == dest);
    }

    fn fail_matching(
        &mut self,
        error: TransportError,
        wakers: &mut Vec<Waker>,
        matches: impl Fn(Uid) -> bool,
    ) {
        if self.waiting == 0 {
            return;
        }
        for slot in &mut self.slots {
            if let SlotState::Waiting { dest, .. } = &slot.state
                && matches(*dest)
                && let SlotState::Waiting { waker, .. } =
                    mem::replace(&mut slot.state, SlotState::Ready(Err(error)))
            {
                wakers.push(waker);
                self.waiting -= 1;
            }
        }
    }
}

fn live_slot(slots: &mut [Slot], key: SlotKey) -> Option<&mut Slot> {
    slots
        .get_mut(key.index as usize)
        .filter(|slot| slot.generation == key.generation)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/transport/slots/tests.rs"]
mod tests;
