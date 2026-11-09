/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Message, QueueId, QueuedMessage, Status,
    walk::{QueueWalk, WalkStep, walk_queues},
};
use crate::queue::{
    Recipient,
    spool::{LOCK_EXPIRY, QUEUE_REFRESH, SmtpSpool},
};
use ahash::AHashMap;
use common::{
    BuildServer, Inner, Server,
    config::smtp::queue::{QueueExpiry, QueueName},
    ipc::{QueueEvent, QueueEventStatus, QueueRefresh},
};
use compact_str::ToCompactString;
use rand::RngExt;
use std::{
    collections::hash_map::Entry,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use store::{
    IterateParams, ValueKey,
    write::{QueueClass, ValueClass, now},
};
use tokio::sync::mpsc;

pub struct Queue {
    core: Arc<Inner>,
    rx: mpsc::Receiver<QueueEvent>,
    queues: Vec<VirtualQueueState>,
    revision: u64,
    is_paused: bool,
    next_wake: Instant,
    walk_at: Instant,
    is_walk_due: bool,
}

struct VirtualQueueState {
    name: QueueName,
    max_in_flight: usize,
    in_flight: usize,
    tracked: AHashMap<QueueId, Tracked>,
    ready: Vec<QueueId>,
    ready_at: Instant,
    next_due: u64,
    has_more: bool,
    rescan: Rescan,
    scanned_at: Instant,
    wake_at: Instant,
    last_warning: Instant,
}

struct Tracked {
    due: u64,
    revision: u64,
    state: TrackedState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rescan {
    None,
    Coalesced,
    Urgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackedState {
    Ready,
    InFlight,
    Parked { expires: u64 },
}

struct ScanCursor {
    revision: u64,
    want: usize,
    limit: usize,
    rows: usize,
    taken: usize,
    last_due: u64,
    end: ScanEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanEnd {
    Future(u64),
    Exhausted,
    Truncated(u64),
    Failed,
}

impl SpawnQueue for mpsc::Receiver<QueueEvent> {
    fn spawn(self, core: Arc<Inner>) {
        tokio::spawn(async move {
            Queue::new(core, self).start().await;
        });
    }

    fn discard(mut self) {
        tokio::spawn(async move {
            while let Some(event) = self.recv().await {
                if matches!(event, QueueEvent::Stop) {
                    break;
                }
            }
        });
    }
}

const BACK_PRESSURE_WARN_INTERVAL: Duration = Duration::from_secs(60);
const MIN_SCAN_INTERVAL: Duration = Duration::from_millis(100);
const FULL_SCAN_INTERVAL: Duration = Duration::from_secs(QUEUE_REFRESH / 2);
const SCAN_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const CLUSTER_READY_TTL: Duration = Duration::from_secs(1);
const STARTUP_DELAY: Duration = Duration::from_secs(1);
const CANDIDATE_OVERSCAN: usize = 4;
const PAUSED_WAKE: Duration = Duration::from_secs(86400);
const WALK_UNKNOWN_QUEUE_ROWS: usize = 128;
pub const QUEUE_DRAIN_TIMEOUT: Duration = Duration::from_secs(8);

impl Queue {
    pub fn new(core: Arc<Inner>, rx: mpsc::Receiver<QueueEvent>) -> Self {
        let now = Instant::now();

        Queue {
            core,
            rx,
            queues: Vec::with_capacity(8),
            revision: 0,
            is_paused: false,
            next_wake: now + STARTUP_DELAY,
            walk_at: now + FULL_SCAN_INTERVAL,
            is_walk_due: true,
        }
    }

    pub async fn start(&mut self) {
        trc::event!(Queue(trc::QueueEvent::Started));

        let server = self.core.build_server();
        self.reload_settings(&server);

        loop {
            let event = tokio::time::timeout(
                self.next_wake.saturating_duration_since(Instant::now()),
                self.rx.recv(),
            )
            .await;
            let server = self.core.build_server();
            match event {
                Ok(Some(mut event)) => loop {
                    match event {
                        QueueEvent::WorkerDone {
                            queue_id,
                            queue_name,
                            status,
                        } => {
                            let is_cluster = server.core.storage.coordinator.is_enabled();
                            virtual_queue(&mut self.queues, queue_name, &server)
                                .worker_done(queue_id, status, is_cluster);
                        }
                        QueueEvent::Refresh(QueueRefresh::Queued(events)) => {
                            let now = now();
                            for event in events {
                                virtual_queue(&mut self.queues, event.queue_name, &server)
                                    .add_event(event.queue_id, event.due, self.revision, now);
                            }
                        }
                        QueueEvent::Refresh(QueueRefresh::Queues(names)) => {
                            for name in names.iter() {
                                virtual_queue(&mut self.queues, name, &server)
                                    .request_rescan(Rescan::Coalesced);
                            }
                        }
                        QueueEvent::Refresh(QueueRefresh::All) => {
                            self.is_walk_due = true;
                        }
                        QueueEvent::Paused(paused) => {
                            self.core
                                .data
                                .queue_status
                                .store(!paused, Ordering::Relaxed);
                            self.is_paused = paused;
                            self.is_walk_due |= !paused;
                        }
                        QueueEvent::ReloadSettings => {
                            self.reload_settings(&server);
                        }
                        QueueEvent::Stop => {
                            self.stop(&server).await;
                        }
                    }
                    match self.rx.try_recv() {
                        Ok(next) => event = next,
                        Err(_) => break,
                    }
                },
                Err(_) => {}
                Ok(None) => {
                    break;
                }
            };

            if self.is_paused {
                self.next_wake = Instant::now() + PAUSED_WAKE;
                continue;
            }

            self.process(&server).await;
        }
    }

    async fn stop(&mut self, server: &Server) {
        let deadline = tokio::time::Instant::now() + QUEUE_DRAIN_TIMEOUT;
        let is_cluster = server.core.storage.coordinator.is_enabled();
        while self.queues.iter().any(|queue| queue.in_flight > 0) {
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Ok(Some(QueueEvent::WorkerDone {
                    queue_id,
                    queue_name,
                    status,
                })) => {
                    virtual_queue(&mut self.queues, queue_name, server)
                        .worker_done(queue_id, status, is_cluster);
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        for queue in &self.queues {
            for (queue_id, tracked) in &queue.tracked {
                if tracked.state == TrackedState::InFlight {
                    server.unlock_event(*queue_id, queue.name).await;
                }
            }
        }

        self.rx.close();
        self.is_paused = true;
    }

    fn reload_settings(&mut self, server: &Server) {
        let virtual_queues = &server.core.smtp.queue.virtual_queues;
        for (name, settings) in virtual_queues {
            virtual_queue(&mut self.queues, *name, server).max_in_flight = settings.threads;
        }
        self.queues.retain(|queue| {
            queue.in_flight > 0
                || !queue.tracked.is_empty()
                || virtual_queues.contains_key(&queue.name)
        });
        self.is_walk_due = true;
    }

    async fn process(&mut self, server: &Server) {
        let is_cluster = server.core.storage.coordinator.is_enabled();
        let mut now_instant = Instant::now();
        let mut now_timestamp = now();

        if self.is_walk_due || self.walk_at <= now_instant {
            for queue in &mut self.queues {
                queue.expire_ready(now_instant, is_cluster);
                queue.fill(server);
            }
            self.walk(server, now_instant, now_timestamp).await;
            now_instant = Instant::now();
            now_timestamp = now();
        }

        self.queues
            .sort_unstable_by_key(|queue| queue.service_order(now_timestamp));
        let Queue {
            queues, revision, ..
        } = self;
        for queue in queues.iter_mut() {
            queue
                .service(server, revision, now_instant, now_timestamp, is_cluster)
                .await;
        }

        let now_instant = Instant::now();
        let now_timestamp = now();
        self.next_wake = self.queues.iter().fold(
            self.walk_at
                .min(now_instant + Duration::from_secs(QUEUE_REFRESH)),
            |next_wake, queue| next_wake.min(queue.next_wake(now_instant, now_timestamp)),
        );
    }

    async fn walk(&mut self, server: &Server, now: Instant, now_timestamp: u64) {
        self.is_walk_due = false;
        self.walk_at = now + FULL_SCAN_INTERVAL;
        self.revision += 1;
        let revision = self.revision;
        let read_limit = self
            .queues
            .iter()
            .map(|queue| queue.tracked.len() + queue.ready_capacity() + 1)
            .sum::<usize>()
            + WALK_UNKNOWN_QUEUE_ROWS;

        let queues = &mut self.queues;
        let mut walked = vec![false; queues.len()];
        let mut current: Option<(usize, Option<ScanCursor>)> = None;
        let result = walk_queues(server.store(), QueueWalk::ascending(read_limit), |event| {
            let name = QueueName::from(event.queue_name);
            if current
                .as_ref()
                .is_none_or(|(idx, _)| queues[*idx].name != name)
            {
                if let Some((idx, Some(cursor))) = current.take() {
                    let queue = &mut queues[idx];
                    queue.end_scan(cursor, now, now_timestamp);
                    queue.fill(server);
                }
                let idx = queue_index(queues, name, server);
                walked.resize(queues.len(), false);
                walked[idx] = true;
                current = Some((idx, queues[idx].begin_scan(revision, now)));
            }

            match &mut current {
                Some((idx, cursor @ Some(_))) => {
                    let queue = &mut queues[*idx];
                    if let Some(open) = cursor
                        && queue.visit(open, event, now_timestamp)
                    {
                        WalkStep::Continue
                    } else {
                        if let Some(open) = cursor.take() {
                            queue.end_scan(open, now, now_timestamp);
                            queue.fill(server);
                        }
                        WalkStep::NextQueue
                    }
                }
                _ => WalkStep::NextQueue,
            }
        })
        .await;

        let is_failed = match result {
            Ok(()) => false,
            Err(err) => {
                trc::error!(
                    err.details("Failed to read queues.")
                        .caused_by(trc::location!())
                );
                true
            }
        };
        if let Some((idx, Some(mut cursor))) = current {
            if is_failed {
                cursor.end = ScanEnd::Failed;
            }
            let queue = &mut queues[idx];
            queue.end_scan(cursor, now, now_timestamp);
            queue.fill(server);
        }
        for (queue, _) in queues
            .iter_mut()
            .zip(walked.iter().copied().chain(std::iter::repeat(false)))
            .filter(|(_, is_walked)| !is_walked)
        {
            if is_failed {
                queue.request_rescan(Rescan::Coalesced);
            } else if let Some(cursor) = queue.begin_scan(revision, now) {
                queue.end_scan(cursor, now, now_timestamp);
            }
        }
        if is_failed {
            self.walk_at = now + SCAN_RETRY_INTERVAL;
        }
    }
}

fn queue_index(queues: &mut Vec<VirtualQueueState>, name: QueueName, server: &Server) -> usize {
    match queues.iter().position(|queue| queue.name == name) {
        Some(idx) => idx,
        None => {
            queues.push(VirtualQueueState::new(
                name,
                server.get_virtual_queue_or_default(&name).threads,
            ));
            queues.len() - 1
        }
    }
}

fn virtual_queue<'x>(
    queues: &'x mut Vec<VirtualQueueState>,
    name: QueueName,
    server: &Server,
) -> &'x mut VirtualQueueState {
    let idx = queue_index(queues, name, server);
    &mut queues[idx]
}

impl VirtualQueueState {
    fn new(name: QueueName, max_in_flight: usize) -> Self {
        let now = Instant::now();

        VirtualQueueState {
            name,
            max_in_flight,
            in_flight: 0,
            tracked: AHashMap::new(),
            ready: Vec::new(),
            ready_at: now,
            next_due: u64::MAX,
            has_more: false,
            rescan: Rescan::Urgent,
            scanned_at: now.checked_sub(MIN_SCAN_INTERVAL).unwrap_or(now),
            wake_at: now + FULL_SCAN_INTERVAL,
            last_warning: now.checked_sub(BACK_PRESSURE_WARN_INTERVAL).unwrap_or(now),
        }
    }

    fn request_rescan(&mut self, rescan: Rescan) {
        self.rescan = self.rescan.max(rescan);
    }

    fn is_urgent(&self, now: Instant) -> bool {
        self.rescan == Rescan::Urgent || self.wake_at <= now
    }

    fn should_rescan(&self, now: Instant) -> bool {
        self.is_urgent(now)
            || (self.rescan == Rescan::Coalesced && self.scanned_at + MIN_SCAN_INTERVAL <= now)
    }

    fn service_order(&self, now_timestamp: u64) -> u8 {
        if !self.ready.is_empty() || self.has_more || self.next_due <= now_timestamp {
            0
        } else if self.rescan == Rescan::Urgent {
            1
        } else {
            2
        }
    }

    fn expire_ready(&mut self, now: Instant, is_cluster: bool) {
        if is_cluster
            && self.in_flight < self.max_in_flight
            && !self.ready.is_empty()
            && self.ready_at + CLUSTER_READY_TTL <= now
        {
            self.clear_ready();
            self.request_rescan(Rescan::Coalesced);
        }
    }

    fn ready_capacity(&self) -> usize {
        self.max_in_flight.saturating_mul(CANDIDATE_OVERSCAN)
    }

    fn worker_done(&mut self, queue_id: QueueId, status: QueueEventStatus, is_cluster: bool) {
        self.in_flight = self.in_flight.saturating_sub(1);

        match status {
            QueueEventStatus::Completed => {
                self.tracked.remove(&queue_id);
            }
            QueueEventStatus::Deferred => {
                self.tracked.remove(&queue_id);
                if !self.has_more {
                    self.request_rescan(Rescan::Coalesced);
                }
            }
            QueueEventStatus::Locked => {
                if let Some(tracked) = self.tracked.get_mut(&queue_id) {
                    let park_for =
                        if is_cluster { LOCK_EXPIRY } else { 0 } + rand::rng().random_range(5..10);
                    tracked.state = TrackedState::Parked {
                        expires: now() + park_for,
                    };
                    self.wake_at = self
                        .wake_at
                        .min(Instant::now() + Duration::from_secs(park_for));
                }
            }
        }
    }

    fn add_event(&mut self, queue_id: QueueId, due: u64, revision: u64, now: u64) {
        let has_room = self.ready.len() < self.ready_capacity();
        if due > now {
            self.next_due = self.next_due.min(due);
        } else if let Entry::Vacant(entry) = self.tracked.entry(queue_id) {
            if has_room {
                entry.insert(Tracked {
                    due,
                    revision,
                    state: TrackedState::Ready,
                });
                if self.ready.is_empty() {
                    self.ready_at = Instant::now();
                }
                self.ready.push(queue_id);
            } else {
                self.has_more = true;
            }
        }
    }

    async fn service(
        &mut self,
        server: &Server,
        revision: &mut u64,
        now: Instant,
        now_timestamp: u64,
        is_cluster: bool,
    ) {
        self.expire_ready(now, is_cluster);

        self.fill(server);

        let mut is_scanned = false;
        if self.in_flight < self.max_in_flight && self.should_rescan(now) {
            *revision += 1;
            self.scan(server, *revision, now, now_timestamp).await;
            self.fill(server);
            is_scanned = true;
        }

        if !is_scanned
            && self.ready.len() < self.max_in_flight
            && (self.has_more || self.next_due <= now_timestamp)
        {
            *revision += 1;
            self.scan(server, *revision, now, now_timestamp).await;
            self.fill(server);
        }

        if self.in_flight >= self.max_in_flight
            && (self.has_more || !self.ready.is_empty())
            && self.last_warning + BACK_PRESSURE_WARN_INTERVAL <= now
        {
            self.last_warning = now;
            trc::event!(
                Queue(trc::QueueEvent::BackPressure),
                Reason = "Processing capacity for this queue exceeded.",
                QueueName = self.name.to_compact_string(),
                Limit = self.max_in_flight,
            );
        }
    }

    fn next_wake(&self, now: Instant, now_timestamp: u64) -> Instant {
        if self.in_flight >= self.max_in_flight {
            return now + Duration::from_secs(QUEUE_REFRESH);
        }

        if self.should_rescan(now) {
            return now;
        }

        let mut wake = self.wake_at;
        if self.rescan == Rescan::Coalesced {
            wake = wake.min(self.scanned_at + MIN_SCAN_INTERVAL);
        }
        if self.next_due != u64::MAX {
            wake = wake.min(now + Duration::from_secs(self.next_due.saturating_sub(now_timestamp)));
        }
        wake.max(now)
    }

    fn fill(&mut self, server: &Server) {
        let mut rng = rand::rng();
        while self.in_flight < self.max_in_flight && !self.ready.is_empty() {
            let queue_id = self
                .ready
                .swap_remove(rng.random_range(0..self.ready.len()));
            if let Some(tracked) = self.tracked.get_mut(&queue_id)
                && tracked.state == TrackedState::Ready
            {
                tracked.state = TrackedState::InFlight;
                self.in_flight += 1;
                QueuedMessage {
                    due: tracked.due,
                    queue_id,
                    queue_name: self.name,
                }
                .try_deliver(server.clone());
            }
        }
    }

    fn clear_ready(&mut self) {
        for queue_id in self.ready.drain(..) {
            if let Entry::Occupied(entry) = self.tracked.entry(queue_id)
                && entry.get().state == TrackedState::Ready
            {
                entry.remove();
            }
        }
    }

    fn begin_scan(&mut self, revision: u64, now: Instant) -> Option<ScanCursor> {
        self.scanned_at = now;
        self.rescan = Rescan::None;

        let want = self.ready_capacity().saturating_sub(self.ready.len());
        if want == 0 {
            self.has_more = true;
            self.wake_at = self.wake_at.max(now + MIN_SCAN_INTERVAL);
            return None;
        }
        if self.ready.is_empty() {
            self.ready_at = now;
        }

        Some(ScanCursor {
            revision,
            want,
            limit: self.tracked.len() + want + 1,
            rows: 0,
            taken: 0,
            last_due: 0,
            end: ScanEnd::Exhausted,
        })
    }

    fn visit(
        &mut self,
        cursor: &mut ScanCursor,
        event: &store::write::QueueEvent,
        now_timestamp: u64,
    ) -> bool {
        cursor.rows += 1;
        if event.due > now_timestamp {
            cursor.end = ScanEnd::Future(event.due);
            return false;
        }
        cursor.last_due = event.due;

        let is_ready = match self.tracked.entry(event.queue_id) {
            Entry::Occupied(mut entry) => {
                let entry = entry.get_mut();
                entry.revision = cursor.revision;
                match entry.state {
                    TrackedState::Parked { expires } if expires <= now_timestamp => {
                        entry.state = TrackedState::Ready;
                        entry.due = event.due;
                        true
                    }
                    _ => false,
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(Tracked {
                    due: event.due,
                    revision: cursor.revision,
                    state: TrackedState::Ready,
                });
                true
            }
        };

        if is_ready {
            self.ready.push(event.queue_id);
            cursor.taken += 1;
            if cursor.taken == cursor.want {
                cursor.end = ScanEnd::Truncated(event.due);
                return false;
            }
        }
        if cursor.rows >= cursor.limit {
            cursor.end = ScanEnd::Truncated(cursor.last_due);
            return false;
        }

        true
    }

    fn end_scan(&mut self, cursor: ScanCursor, now: Instant, now_timestamp: u64) {
        self.finish_scan(cursor.end, cursor.revision, now, now_timestamp);
    }

    async fn scan(&mut self, server: &Server, revision: u64, now: Instant, now_timestamp: u64) {
        let Some(mut cursor) = self.begin_scan(revision, now) else {
            return;
        };

        let queue_name = self.name.into_inner();
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
            store::write::QueueEvent {
                due: 0,
                queue_id: 0,
                queue_name,
            },
        )));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
            store::write::QueueEvent {
                due: now_timestamp + QUEUE_REFRESH,
                queue_id: u64::MAX,
                queue_name,
            },
        )));

        let result = server
            .store()
            .iterate(
                IterateParams::new(from_key, to_key)
                    .ascending()
                    .no_values()
                    .limit(cursor.limit),
                |key, _| {
                    let event = store::write::QueueEvent::deserialize(key)?;
                    Ok(self.visit(&mut cursor, &event, now_timestamp))
                },
            )
            .await;

        if let Err(err) = result {
            trc::error!(
                err.details("Failed to read queue.")
                    .caused_by(trc::location!())
            );
            cursor.end = ScanEnd::Failed;
        }
        self.end_scan(cursor, now, now_timestamp);
    }

    fn finish_scan(&mut self, end: ScanEnd, revision: u64, now: Instant, now_timestamp: u64) {
        let mut wake_at = now + FULL_SCAN_INTERVAL;
        let evict_below = match end {
            ScanEnd::Future(due) => {
                self.next_due = due;
                self.has_more = false;
                self.ready_at = now;
                u64::MAX
            }
            ScanEnd::Exhausted => {
                self.next_due = u64::MAX;
                self.has_more = false;
                self.ready_at = now;
                u64::MAX
            }
            ScanEnd::Truncated(last_due) => {
                self.next_due = u64::MAX;
                self.has_more = true;
                last_due
            }
            ScanEnd::Failed => {
                self.next_due = u64::MAX;
                self.has_more = false;
                wake_at = now + SCAN_RETRY_INTERVAL;
                0
            }
        };

        let mut has_evicted_ready = false;
        self.tracked.retain(|_, tracked| match tracked.state {
            TrackedState::InFlight => true,
            state => {
                let keep = tracked.revision == revision || tracked.due >= evict_below;
                if !keep {
                    has_evicted_ready |= state == TrackedState::Ready;
                } else if let TrackedState::Parked { expires } = state
                    && expires > now_timestamp
                {
                    wake_at = wake_at.min(now + Duration::from_secs(expires - now_timestamp));
                }
                keep
            }
        });
        if has_evicted_ready {
            let tracked = &self.tracked;
            self.ready.retain(|queue_id| tracked.contains_key(queue_id));
        }
        self.wake_at = wake_at;
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
    fn discard(self);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/smtp/src/queue/manager/tests.rs"]
mod tests;
