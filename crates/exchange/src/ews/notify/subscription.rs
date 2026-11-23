/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::scan::{Cursor, MAX_EVENTS_PER_BATCH, ScanEvent, ScanInput, Scope};
use common::network::memory::MemoryReservation;
use exchange_proto::{
    ews::types::subscription::EventTypes,
    ids::ews::{EwsSubscriptionId, EwsSubscriptionKind, EwsWatermark},
};
use std::{
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

pub(crate) const STREAMING_IDLE_TTL: Duration = Duration::from_secs(30 * 60);
pub(crate) const TOMBSTONE_TTL: Duration = Duration::from_secs(15 * 60);
const EVENT_WEIGHT: u64 = 32;
const RESERVATION_ALLOWANCE: u64 = 16 * 1024;

pub(crate) struct EwsSubscription {
    pub owner: u32,
    pub id: EwsSubscriptionId,
    pub scope: Scope,
    pub events: EventTypes,
    pub mail: bool,
    pub data_types: Bitmap<DataType>,
    pub stream: AtomicU64,
    pub closed: AtomicBool,
    pub wake: Notify,
    ttl: u64,
    deadline: AtomicU64,
    state: Mutex<SubscriptionState>,
}

pub(crate) struct EwsTombstone {
    pub subscription: Arc<EwsSubscription>,
    pub until: u64,
}

struct SubscriptionState {
    seq: u64,
    cursor: Cursor,
    replay: Option<Batch>,
    reservation: MemoryReservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Batch {
    pub previous: u64,
    pub events: Vec<ScanEvent>,
    pub timestamp: u64,
    pub more: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
    Pull { expected: u64 },
    Stream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Next {
    Batch(Batch),
    Replay(Batch),
    Empty,
    InvalidWatermark,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerBusy;

impl Batch {
    pub fn watermark(&self, index: usize) -> u64 {
        self.previous
            .saturating_add(1)
            .saturating_add(u64::try_from(index).unwrap_or(u64::MAX))
    }

    fn weight(&self) -> u64 {
        self.events.len() as u64 * EVENT_WEIGHT
    }
}

pub(crate) struct NewSubscription {
    pub owner: u32,
    pub id: EwsSubscriptionId,
    pub scope: Scope,
    pub events: EventTypes,
    pub mail: bool,
    pub data_types: Bitmap<DataType>,
    pub ttl: Duration,
}

impl EwsSubscription {
    pub fn new(
        subscription: NewSubscription,
        cursor: Cursor,
        mut reservation: MemoryReservation,
        now: u64,
    ) -> Result<Self, ServerBusy> {
        if !reserve(&mut reservation, cursor.weight()) {
            return Err(ServerBusy);
        }
        let ttl = subscription.ttl.as_secs().max(1);
        Ok(EwsSubscription {
            owner: subscription.owner,
            id: subscription.id,
            scope: subscription.scope,
            events: subscription.events,
            mail: subscription.mail,
            data_types: subscription.data_types,
            stream: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            wake: Notify::new(),
            ttl,
            deadline: AtomicU64::new(now.saturating_add(ttl)),
            state: Mutex::new(SubscriptionState {
                seq: 0,
                cursor,
                replay: None,
                reservation,
            }),
        })
    }

    pub fn groupware_window(&self, index: usize) -> (u64, u64) {
        self.lock().cursor.groupware_window(index, &self.scope)
    }

    pub fn is_streaming(&self) -> bool {
        self.id.kind == EwsSubscriptionKind::Streaming
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake.notify_waiters();
    }

    pub fn touch(&self, now: u64) -> bool {
        self.deadline
            .try_update(Ordering::AcqRel, Ordering::Acquire, |deadline| {
                (now < deadline).then(|| now.saturating_add(self.ttl))
            })
            .is_ok()
    }

    pub fn tombstone_until(&self) -> u64 {
        self.deadline
            .load(Ordering::Acquire)
            .saturating_add(TOMBSTONE_TTL.as_secs())
    }

    pub fn bury(&self, now: u64) {
        self.deadline.fetch_min(now, Ordering::AcqRel);
        self.close();
        self.lock().replay = None;
    }

    pub fn open_stream(&self) -> u64 {
        let generation = self.stream.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        self.wake.notify_waiters();
        generation
    }

    pub fn stream_generation(&self) -> u64 {
        self.stream.load(Ordering::Acquire)
    }

    pub fn watermark(&self, seq: u64) -> EwsWatermark {
        EwsWatermark {
            account: self.id.account,
            subscription: self.id.id,
            seq,
        }
    }

    pub fn current_seq(&self) -> u64 {
        self.lock().seq
    }

    pub fn cursor_at(&self, seq: u64) -> Option<Cursor> {
        let state = self.lock();
        (state.seq == seq).then(|| state.cursor.clone())
    }

    pub fn accepts(&self, watermark: &EwsWatermark) -> bool {
        let state = self.lock();
        watermark.account == self.id.account
            && watermark.subscription == self.id.id
            && (watermark.seq == state.seq
                || state
                    .replay
                    .as_ref()
                    .is_some_and(|replay| replay.previous == watermark.seq))
    }

    pub fn next_batch(
        &self,
        input: &ScanInput<'_>,
        delivery: Delivery,
    ) -> Result<Next, ServerBusy> {
        let mut state = self.lock();
        if self.is_closed() {
            return Ok(Next::Closed);
        }
        let SubscriptionState {
            seq,
            cursor,
            replay,
            reservation,
        } = &mut *state;
        if let Delivery::Pull { expected } = delivery
            && expected != *seq
        {
            return Ok(match replay {
                Some(replay) if replay.previous == expected => Next::Replay(replay.clone()),
                _ => Next::InvalidWatermark,
            });
        }
        let held = cursor
            .weight()
            .saturating_add(replay.as_ref().map_or(0, Batch::weight));
        if !reserve(reservation, held) {
            return Err(ServerBusy);
        }
        let scanned = cursor.scan(input, self.events, MAX_EVENTS_PER_BATCH);
        if scanned.events.is_empty() && delivery == Delivery::Stream {
            return Ok(Next::Empty);
        }
        let batch = Batch {
            previous: *seq,
            timestamp: input.now,
            more: scanned.more,
            events: scanned.events,
        };
        *seq = batch.watermark(batch.events.len().saturating_sub(1));
        match delivery {
            Delivery::Pull { .. } => {
                reserve(reservation, cursor.weight().saturating_add(batch.weight()));
                *replay = Some(batch.clone());
            }
            Delivery::Stream => {
                reserve(reservation, cursor.weight());
            }
        }
        Ok(Next::Batch(batch))
    }

    fn lock(&self) -> MutexGuard<'_, SubscriptionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn reserve(reservation: &mut MemoryReservation, weight: u64) -> bool {
    reservation.reserve_to(weight.saturating_sub(RESERVATION_ALLOWANCE))
}
