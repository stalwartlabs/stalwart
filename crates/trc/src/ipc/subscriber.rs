/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use tokio::sync::mpsc::{self, error::TrySendError};

use crate::{Event, EventDetails, EventType, Level, TOTAL_EVENT_COUNT};

use super::{
    USIZE_BITS,
    bitset::Bitset,
    channel::ChannelError,
    collector::{COLLECTOR_UPDATES, Collector, Update},
};

const MAX_BATCH_SIZE: usize = 32768;
const MAX_LOSSLESS_BATCH_SIZE: usize = MAX_BATCH_SIZE * 16;

pub type Interests = Box<Bitset<{ TOTAL_EVENT_COUNT.div_ceil(USIZE_BITS) }>>;
pub type EventBatch = Vec<Arc<Event<EventDetails>>>;

#[derive(Debug)]
pub(crate) struct Subscriber {
    pub id: String,
    pub interests: Interests,
    pub tx: mpsc::Sender<EventBatch>,
    pub lossy: bool,
    pub batch: EventBatch,
}

pub struct SubscriberBuilder {
    pub id: String,
    pub interests: Interests,
    pub lossy: bool,
}

impl Subscriber {
    #[inline(always)]
    pub fn push_event(&mut self, event_id: usize, trace: &Arc<Event<EventDetails>>) {
        if self.interests.get(event_id) {
            self.batch.push(trace.clone());
        }
    }

    pub fn send_batch(&mut self) -> Result<u64, ChannelError> {
        if self.batch.is_empty() {
            return Ok(0);
        }

        match self
            .tx
            .try_send(std::mem::replace(&mut self.batch, Vec::with_capacity(128)))
        {
            Ok(_) => Ok(0),
            Err(TrySendError::Full(mut events)) => {
                let total = events.len();
                if self.lossy {
                    if total > MAX_BATCH_SIZE {
                        events.retain(|e| e.inner.level == Level::Error);
                        events.truncate(MAX_BATCH_SIZE);
                    }
                } else if total > MAX_LOSSLESS_BATCH_SIZE {
                    events.truncate(MAX_LOSSLESS_BATCH_SIZE);
                }
                let dropped = (total - events.len()) as u64;
                self.batch = events;
                Ok(dropped)
            }
            Err(TrySendError::Closed(_)) => Err(ChannelError),
        }
    }
}

impl SubscriberBuilder {
    pub fn new(id: String) -> Self {
        Self {
            id,
            interests: Default::default(),
            lossy: true,
        }
    }

    pub fn with_default_interests(mut self, level: Level) -> Self {
        for event in EventType::variants() {
            if level.is_contained(event.level()) {
                self.interests.set(*event);
            }
        }
        self
    }

    pub fn with_interests(mut self, interests: Interests) -> Self {
        self.interests = interests;
        self
    }

    pub fn set_interests(mut self, interest: impl IntoIterator<Item = impl Into<usize>>) -> Self {
        for level in interest {
            self.interests.set(level);
        }
        self
    }

    pub fn with_lossy(mut self, lossy: bool) -> Self {
        self.lossy = lossy;
        self
    }

    pub fn register(self) -> (mpsc::Sender<EventBatch>, mpsc::Receiver<EventBatch>) {
        let (tx, rx) = mpsc::channel(8192);

        COLLECTOR_UPDATES.lock().push(Update::RegisterSubscriber {
            subscriber: Subscriber {
                id: self.id,
                interests: self.interests,
                tx: tx.clone(),
                lossy: self.lossy,
                batch: Vec::new(),
            },
        });

        // Notify collector
        Collector::reload();

        (tx, rx)
    }
}
