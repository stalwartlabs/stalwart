/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cell::UnsafeCell,
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use rtrb::{Consumer, Producer, PushError, RingBuffer};

use crate::{
    Error, Event, EventType,
    ipc::collector::{COLLECTOR_THREAD, COLLECTOR_UPDATES, Update},
};

use super::collector::{Collector, CollectorThread};

pub(crate) static CHANNEL_FLAGS: AtomicU64 = AtomicU64::new(0);
pub(crate) const CHANNEL_SIZE: usize = 10240;
pub(crate) const CHANNEL_UPDATE_MARKER: u64 = 1 << 63;
const OVERFLOW_SIZE: usize = CHANNEL_SIZE * 2;

thread_local! {
    static EVENT_TX: UnsafeCell<Sender> = {
        let (tx, rx) = RingBuffer::new(CHANNEL_SIZE);
        let dropped = Arc::new(AtomicU64::new(0));

        COLLECTOR_UPDATES.lock().push(Update::RegisterReceiver {
            receiver: Receiver { rx, dropped: dropped.clone() },
        });

        let collector = COLLECTOR_THREAD.clone();
        CHANNEL_FLAGS.fetch_or(CHANNEL_UPDATE_MARKER, Ordering::Relaxed);
        collector.thread().unpark();

        UnsafeCell::new(Sender {
            tx,
            collector,
            overflow: VecDeque::new(),
            dropped,
        })
    };
}

pub struct Sender {
    tx: Producer<Event<EventType>>,
    collector: Arc<CollectorThread>,
    overflow: VecDeque<Event<EventType>>,
    dropped: Arc<AtomicU64>,
}

pub struct Receiver {
    rx: Consumer<Event<EventType>>,
    dropped: Arc<AtomicU64>,
}

#[derive(Debug)]
pub struct ChannelError;

impl Sender {
    pub fn send(&mut self, event: Event<EventType>) -> Result<(), ChannelError> {
        if self.overflow.is_empty() {
            match self.tx.push(event) {
                Ok(()) => Ok(()),
                Err(PushError::Full(event)) => self.spill(event),
            }
        } else {
            self.send_with_overflow(event)
        }
    }

    #[cold]
    fn send_with_overflow(&mut self, event: Event<EventType>) -> Result<(), ChannelError> {
        while let Some(pending) = self.overflow.pop_front() {
            if let Err(PushError::Full(pending)) = self.tx.push(pending) {
                self.overflow.push_front(pending);
                return self.spill(event);
            }
        }

        match self.tx.push(event) {
            Ok(()) => Ok(()),
            Err(PushError::Full(event)) => self.spill(event),
        }
    }

    #[cold]
    fn spill(&mut self, event: Event<EventType>) -> Result<(), ChannelError> {
        if self.overflow.len() <= OVERFLOW_SIZE {
            self.overflow.push_back(event);
            Ok(())
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            Err(ChannelError)
        }
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        if self.overflow.is_empty() {
            return;
        }

        let pending = self.overflow.len();
        while let Some(event) = self.overflow.pop_front() {
            if self.tx.push(event).is_err() {
                self.dropped
                    .fetch_add(self.overflow.len() as u64 + 1, Ordering::Relaxed);
                break;
            }
        }
        CHANNEL_FLAGS.fetch_add(pending as u64, Ordering::Relaxed);
        self.collector.thread().unpark();
    }
}

impl Receiver {
    pub fn try_recv(&mut self) -> Result<Option<Event<EventType>>, ChannelError> {
        match self.rx.pop() {
            Ok(event) => Ok(Some(event)),
            Err(_) => {
                if !self.rx.is_abandoned() {
                    Ok(None)
                } else {
                    Err(ChannelError)
                }
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.rx.is_abandoned() && self.rx.is_empty()
    }

    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

impl Event<EventType> {
    pub fn send(self) {
        // SAFETY: EVENT_TX is thread-local.
        let _ = EVENT_TX.try_with(|tx| unsafe {
            let tx = &mut *tx.get();
            if tx.send(self).is_ok() {
                CHANNEL_FLAGS.fetch_add(1, Ordering::Relaxed);
                tx.collector.thread().unpark();
            }
        });
    }

    pub fn send_with_metrics(self) {
        Collector::record_metric(self.inner, self.inner.to_id() as usize, &self.keys);
        self.send();
    }
}

impl Error {
    pub fn send(self) {
        self.0.send();
    }
}
