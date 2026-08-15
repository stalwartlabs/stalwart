/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Message, QueueId, Status, spool::SmtpSpool};
use crate::queue::{
    Recipient,
    spool::{INFINITE_LOCK, LOCK_EXPIRY, QUEUE_REFRESH},
};
use ahash::AHashMap;
use common::{
    BuildServer, Inner,
    config::smtp::queue::{QueueExpiry, QueueName},
    ipc::{QueueEvent, QueueEventStatus},
};
use rand::{RngExt, seq::SliceRandom};
use std::{
    collections::hash_map::Entry,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use store::write::now;
use tokio::sync::mpsc;

pub struct Queue {
    pub core: Arc<Inner>,
    pub locked: AHashMap<(QueueId, QueueName), LockedMessage>,
    pub locked_revision: u64,
    pub stats: AHashMap<QueueName, QueueStats>,
    pub next_refresh: Instant,
    pub rx: mpsc::Receiver<QueueEvent>,
    pub is_paused: bool,
    pub scan_from: u64,
    pub scan_ceiling: u64,
    pub has_pending_work: bool,
    pub pending_refresh: bool,
    pub urgent_refresh: bool,
    pub last_scan: Instant,
    pub last_full_scan: Instant,
}

#[derive(Debug)]
pub struct QueueStats {
    pub in_flight: usize,
    pub max_in_flight: usize,
    pub budget: usize,
    pub last_warning: Instant,
}

#[derive(Debug)]
pub struct LockedMessage {
    pub expires: u64,
    pub revision: u64,
    pub due: u64,
}

impl SpawnQueue for mpsc::Receiver<QueueEvent> {
    fn spawn(self, core: Arc<Inner>) {
        tokio::spawn(async move {
            Queue::new(core, self).start().await;
        });
    }
}

const BACK_PRESSURE_WARN_INTERVAL: Duration = Duration::from_secs(60);
const MIN_SCAN_INTERVAL: Duration = Duration::from_millis(100);
const FULL_SCAN_INTERVAL: Duration = Duration::from_secs(QUEUE_REFRESH / 2);

impl Queue {
    pub fn new(core: Arc<Inner>, rx: mpsc::Receiver<QueueEvent>) -> Self {
        let now = Instant::now();

        Queue {
            core,
            locked: AHashMap::with_capacity(128),
            locked_revision: 0,
            stats: AHashMap::new(),
            next_refresh: now + Duration::from_secs(1),
            is_paused: false,
            rx,
            scan_from: 0,
            scan_ceiling: u64::MAX,
            has_pending_work: false,
            pending_refresh: false,
            urgent_refresh: false,
            last_scan: now.checked_sub(MIN_SCAN_INTERVAL).unwrap_or(now),
            last_full_scan: now,
        }
    }

    pub async fn start(&mut self) {
        trc::event!(Queue(trc::QueueEvent::Started));

        loop {
            let mut refresh_queue;

            match tokio::time::timeout(
                self.next_refresh.duration_since(Instant::now()),
                self.rx.recv(),
            )
            .await
            {
                Ok(Some(event)) => {
                    refresh_queue = self.handle_event(event).await;

                    while let Ok(event) = self.rx.try_recv() {
                        refresh_queue = self.handle_event(event).await || refresh_queue;
                    }
                }
                Err(_) => {
                    refresh_queue = true;
                    self.urgent_refresh = true;
                }
                Ok(None) => {
                    break;
                }
            };

            if self.is_paused {
                self.next_refresh = Instant::now() + Duration::from_secs(86400);
                continue;
            }

            self.pending_refresh |= refresh_queue;
            if !self.pending_refresh && self.next_refresh > Instant::now() {
                continue;
            }

            // Coalesce bursts of worker notifications into a single scan
            let scan_at = self.last_scan + MIN_SCAN_INTERVAL;
            if !self.urgent_refresh && scan_at > Instant::now() {
                self.next_refresh = scan_at;
                continue;
            }

            if self.scan_from != 0 && self.last_full_scan.elapsed() >= FULL_SCAN_INTERVAL {
                self.scan_from = 0;
            }
            if self.scan_from == 0 {
                self.last_full_scan = Instant::now();
            }
            let scan_floor = self.scan_from;
            self.pending_refresh = false;
            self.urgent_refresh = false;

            // Process queue events
            let server = self.core.build_server();
            let mut queue_events = server.next_event(self).await;
            self.last_scan = Instant::now();

            if queue_events.messages.len() > 3 {
                queue_events.messages.shuffle(&mut rand::rng());
            }

            // A truncated scan left events behind
            let now = now();
            self.has_pending_work = self.scan_ceiling != u64::MAX;

            for queue_event in &queue_events.messages {
                // A message may hold more than one event key, dispatch it only once
                if self
                    .locked
                    .get(&(queue_event.queue_id, queue_event.queue_name))
                    .is_some_and(|locked| locked.expires > now)
                {
                    continue;
                }

                // Fetch queue stats
                let stats = match self.stats.get_mut(&queue_event.queue_name) {
                    Some(stats) => stats,
                    None => {
                        let queue_config =
                            server.get_virtual_queue_or_default(&queue_event.queue_name);
                        self.stats.insert(
                            queue_event.queue_name,
                            QueueStats::new(queue_config.threads),
                        );
                        self.stats.get_mut(&queue_event.queue_name).unwrap()
                    }
                };

                // Enforce concurrency limits
                if stats.has_capacity() {
                    // Deliver message
                    stats.in_flight += 1;
                    self.locked.insert(
                        (queue_event.queue_id, queue_event.queue_name),
                        LockedMessage {
                            expires: now + INFINITE_LOCK,
                            revision: self.locked_revision,
                            due: queue_event.due,
                        },
                    );
                    queue_event.try_deliver(server.clone());
                } else {
                    if stats.last_warning.elapsed() >= BACK_PRESSURE_WARN_INTERVAL {
                        stats.last_warning = Instant::now();
                        trc::event!(
                            Queue(trc::QueueEvent::BackPressure),
                            Reason = "Processing capacity for this queue exceeded.",
                            QueueName = queue_event.queue_name.to_string(),
                            Limit = stats.max_in_flight,
                        );
                    }
                    self.has_pending_work = true;
                    if queue_event.due < self.scan_from {
                        self.scan_from = queue_event.due;
                    }
                }
            }

            // Remove expired locks, revisiting any event they were holding back
            let scan_ceiling = self.scan_ceiling;
            let mut dropped_due = u64::MAX;
            self.locked.retain(|_, locked| {
                let keep = locked.expires > now
                    && (locked.revision == self.locked_revision
                        || locked.due < scan_floor
                        || locked.due >= scan_ceiling);
                if !keep && locked.due < dropped_due {
                    dropped_due = locked.due;
                }
                keep
            });

            // Do not wait for the next scheduled event while there is work left over
            let mut next_refresh = queue_events.next_refresh.saturating_sub(now);
            if self.has_pending_work {
                next_refresh = std::cmp::min(next_refresh, FULL_SCAN_INTERVAL.as_secs());
            }
            let mut next_refresh = Instant::now() + Duration::from_secs(next_refresh);

            // A released lock uncovered an event below the floor that no scan can see
            if dropped_due < self.scan_from {
                self.scan_from = dropped_due;
                self.has_pending_work = true;
                self.pending_refresh = true;

                let scan_at = self.last_scan + MIN_SCAN_INTERVAL;
                if scan_at < next_refresh {
                    next_refresh = scan_at;
                }
            }

            self.next_refresh = next_refresh;
        }
    }

    async fn handle_event(&mut self, event: QueueEvent) -> bool {
        match event {
            QueueEvent::WorkerDone {
                queue_id,
                queue_name,
                status,
            } => {
                let has_capacity = match self.stats.get_mut(&queue_name) {
                    Some(queue_stats) => {
                        queue_stats.in_flight = queue_stats.in_flight.saturating_sub(1);
                        queue_stats.has_capacity()
                    }
                    None => true,
                };

                match status {
                    QueueEventStatus::Completed => {
                        self.core.ipc.task_tx.notify_one();
                        self.locked.remove(&(queue_id, queue_name));
                        !self.locked.is_empty() || !has_capacity || self.has_pending_work
                    }
                    QueueEventStatus::Locked => {
                        let expires = LOCK_EXPIRY + rand::rng().random_range(5..10);
                        let due_in = Instant::now() + Duration::from_secs(expires);
                        if due_in < self.next_refresh {
                            self.next_refresh = due_in;
                        }

                        // The event was not delivered, so it has to be visited again
                        // once the remote lock expires.
                        let expires = now() + expires;
                        let due = match self.locked.entry((queue_id, queue_name)) {
                            Entry::Occupied(mut entry) => {
                                let locked = entry.get_mut();
                                locked.expires = expires;
                                locked.revision = self.locked_revision;
                                locked.due
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(LockedMessage {
                                    expires,
                                    revision: self.locked_revision,
                                    due: 0,
                                });
                                0
                            }
                        };
                        if due < self.scan_from {
                            self.scan_from = due;
                        }
                        self.locked.len() > 1 || !has_capacity || self.has_pending_work
                    }
                    QueueEventStatus::Deferred => {
                        self.locked.remove(&(queue_id, queue_name));
                        self.scan_from = 0;
                        true
                    }
                }
            }
            QueueEvent::Refresh => {
                self.scan_from = 0;
                self.urgent_refresh = true;
                true
            }
            QueueEvent::Paused(paused) => {
                self.core
                    .data
                    .queue_status
                    .store(!paused, Ordering::Relaxed);
                self.is_paused = paused;
                self.scan_from = 0;
                self.urgent_refresh = !paused;
                !paused
            }
            QueueEvent::ReloadSettings => {
                let server = self.core.build_server();
                let virtual_queues = &server.core.smtp.queue.virtual_queues;
                for (name, settings) in virtual_queues {
                    if let Some(stats) = self.stats.get_mut(name) {
                        stats.max_in_flight = settings.threads;
                    } else {
                        self.stats.insert(*name, QueueStats::new(settings.threads));
                    }
                }
                self.stats
                    .retain(|name, stats| stats.in_flight > 0 || virtual_queues.contains_key(name));
                self.scan_from = 0;
                false
            }
            QueueEvent::Stop => {
                self.rx.close();
                self.is_paused = true;
                false
            }
        }
    }
}

impl Message {
    pub fn next_event(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut next_event = None;

        for rcpt in &self.recipients {
            if matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
                && queue.is_none_or(|q| rcpt.queue == q)
            {
                let mut earlier_event = std::cmp::min(rcpt.retry.due, rcpt.notify.due);

                if let Some(expires) = rcpt.expiration_time(self.created) {
                    earlier_event = std::cmp::min(earlier_event, expires);
                }

                if let Some(next_event) = &mut next_event {
                    if earlier_event < *next_event {
                        *next_event = earlier_event;
                    }
                } else {
                    next_event = Some(earlier_event);
                }
            }
        }

        next_event
    }

    pub fn next_delivery_event(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut next_delivery = None;

        for rcpt in self.recipients.iter().filter(|rcpt| {
            matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
                && queue.is_none_or(|q| rcpt.queue == q)
        }) {
            if let Some(next_delivery) = &mut next_delivery {
                if rcpt.retry.due < *next_delivery {
                    *next_delivery = rcpt.retry.due;
                }
            } else {
                next_delivery = Some(rcpt.retry.due);
            }
        }

        next_delivery
    }

    pub fn next_dsn(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut next_dsn = None;

        for rcpt in self.recipients.iter().filter(|rcpt| {
            matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
                && queue.is_none_or(|q| rcpt.queue == q)
        }) {
            if let Some(next_dsn) = &mut next_dsn {
                if rcpt.notify.due < *next_dsn {
                    *next_dsn = rcpt.notify.due;
                }
            } else {
                next_dsn = Some(rcpt.notify.due);
            }
        }

        next_dsn
    }

    pub fn expires(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut expires = None;

        for rcpt in self.recipients.iter().filter(|d| {
            matches!(d.status, Status::Scheduled | Status::TemporaryFailure(_))
                && queue.is_none_or(|q| d.queue == q)
        }) {
            if let Some(rcpt_expires) = rcpt.expiration_time(self.created) {
                if let Some(expires) = &mut expires {
                    if rcpt_expires > *expires {
                        *expires = rcpt_expires;
                    }
                } else {
                    expires = Some(rcpt_expires)
                }
            }
        }

        expires
    }

    pub fn next_events(&self) -> AHashMap<QueueName, u64> {
        let mut next_events = AHashMap::new();

        for rcpt in &self.recipients {
            if matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_)) {
                let mut earlier_event = std::cmp::min(rcpt.retry.due, rcpt.notify.due);

                if let Some(expires) = rcpt.expiration_time(self.created) {
                    earlier_event = std::cmp::min(earlier_event, expires);
                }

                match next_events.entry(rcpt.queue) {
                    Entry::Occupied(mut entry) => {
                        let entry = entry.get_mut();
                        if earlier_event < *entry {
                            *entry = earlier_event;
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(earlier_event);
                    }
                }
            }
        }

        next_events
    }
}

impl Recipient {
    pub fn expiration_time(&self, created: u64) -> Option<u64> {
        match self.expires {
            QueueExpiry::Ttl(time) => Some(created + time),
            QueueExpiry::Attempts(_) => None,
        }
    }

    pub fn is_expired(&self, created: u64, now: u64) -> bool {
        match self.expires {
            QueueExpiry::Ttl(time) => created + time <= now,
            QueueExpiry::Attempts(count) => self.retry.inner >= count,
        }
    }
}

pub trait SpawnQueue {
    fn spawn(self, core: Arc<Inner>);
}

impl QueueStats {
    pub(crate) fn new(max_in_flight: usize) -> Self {
        QueueStats {
            in_flight: 0,
            max_in_flight,
            budget: 0,
            last_warning: Instant::now()
                .checked_sub(BACK_PRESSURE_WARN_INTERVAL)
                .unwrap_or_else(Instant::now),
        }
    }

    #[inline]
    pub fn has_capacity(&self) -> bool {
        self.in_flight < self.max_in_flight
    }
}
