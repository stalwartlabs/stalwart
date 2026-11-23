/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod timer;

use super::{
    coordinator::{ProxyWatch, Shutdown, shut_down},
    proxies::{Delivery, ProxyRole, ProxySet},
    read_version::VersionCache,
    transaction::Attempt,
};
use crate::{
    api::{
        error::{Error, ErrorCode, Result},
        read::Priority,
        transaction::Causality,
        version::Version,
    },
    codec::Uid,
    transport::{ProtocolVersion, QueuedFrame},
    wire::{Dialect, GetReadVersionReply, GetReadVersionRequest, Reply},
};
use bytes::Bytes;
use parking_lot::Mutex;
use std::{
    mem,
    pin::pin,
    ptr,
    sync::{
        Arc, Weak,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use timer::WindowTimer;
use tokio::{
    runtime::Handle,
    select,
    sync::{mpsc, oneshot},
    task::yield_now,
    time::{Instant, sleep_until},
};

const MAX_BATCH_SIZE: usize = 1000;
const GRV_BATCH_TIMEOUT: f64 = 0.005;
const PRIORITY_DEFAULT: u32 = 8 << 24;
const PRIORITY_BATCH: u32 = 1 << 24;
const FLAG_CAUSAL_READ_RISKY: u32 = 1;
const QUEUES: usize = 4;

pub(crate) enum Waiter {
    Attempt(Arc<Attempt>),
    Reply(oneshot::Sender<Result<Version>>),
    LockAware(oneshot::Sender<Result<Version>>),
}

pub(crate) struct ReadVersions {
    queues: [mpsc::UnboundedSender<Waiter>; QUEUES],
}

struct Batcher {
    waiters: mpsc::UnboundedReceiver<Waiter>,
    proxies: ProxyWatch,
    shutdown: Shutdown,
    versions: Arc<VersionCache>,
    runtime: Handle,
    flags: u32,
    timer: Option<WindowTimer>,
    pacing: Pacing,
    last: LastBatch,
    parked: Arc<Parked>,
}

#[derive(Default)]
struct LastBatch(Option<Arc<LiveBatch>>);

#[derive(Default)]
struct Pacing {
    batch_time: f64,
}

#[derive(Default)]
struct Parked {
    batches: Mutex<Vec<Weak<LiveBatch>>>,
}

struct LiveBatch {
    state: Mutex<BatchState>,
    transaction_count: AtomicU32,
    flags: u32,
}

struct BatchState {
    waiters: Vec<Waiter>,
    frame: PendingFrame,
}

enum PendingFrame {
    Unqueued,
    Queued(QueuedFrame),
    Merged,
    Closed,
}

enum Join {
    Joined,
    Later(Waiter),
    Never(Waiter),
}

#[derive(Clone, Copy)]
struct Grv {
    version: Version,
    locked: bool,
}

impl ReadVersions {
    pub(crate) fn spawn(
        runtime: &Handle,
        proxies: &ProxyWatch,
        versions: &Arc<VersionCache>,
        shutdown: &Shutdown,
    ) -> Self {
        let queues = [
            (Priority::Default, Causality::Strict),
            (Priority::Default, Causality::ReadRisky),
            (Priority::Batch, Causality::Strict),
            (Priority::Batch, Causality::ReadRisky),
        ]
        .map(|(priority, causality)| {
            let (sender, waiters) = mpsc::unbounded_channel();
            runtime.spawn(
                Batcher {
                    waiters,
                    proxies: proxies.clone(),
                    shutdown: shutdown.clone(),
                    versions: versions.clone(),
                    runtime: runtime.clone(),
                    flags: flags(priority, causality),
                    timer: None,
                    pacing: Pacing::default(),
                    last: LastBatch::default(),
                    parked: Arc::default(),
                }
                .run(),
            );
            sender
        });
        ReadVersions { queues }
    }

    pub(crate) fn request(&self, waiter: Waiter, priority: Priority, causality: Causality) {
        let index = match (priority, causality) {
            (Priority::Default, Causality::Strict) => 0,
            (Priority::Default, Causality::ReadRisky) => 1,
            (Priority::Batch, Causality::Strict) => 2,
            (Priority::Batch, Causality::ReadRisky) => 3,
        };
        if let Some(queue) = self.queues.get(index)
            && let Err(rejected) = queue.send(waiter)
        {
            rejected
                .0
                .complete(Err(Error::new(ErrorCode::OPERATION_CANCELLED)));
        }
    }

    pub(crate) fn fetch(
        &self,
        priority: Priority,
        causality: Causality,
    ) -> impl Future<Output = Result<Version>> + Send + 'static {
        self.fetch_with(Waiter::Reply, priority, causality)
    }

    pub(crate) fn fetch_lock_aware(
        &self,
        priority: Priority,
        causality: Causality,
    ) -> impl Future<Output = Result<Version>> + Send + 'static {
        self.fetch_with(Waiter::LockAware, priority, causality)
    }

    fn fetch_with(
        &self,
        waiter: fn(oneshot::Sender<Result<Version>>) -> Waiter,
        priority: Priority,
        causality: Causality,
    ) -> impl Future<Output = Result<Version>> + Send + 'static {
        let (sender, receiver) = oneshot::channel();
        self.request(waiter(sender), priority, causality);
        async move {
            receiver
                .await
                .unwrap_or(Err(Error::new(ErrorCode::OPERATION_CANCELLED)))
        }
    }
}

impl Waiter {
    fn is_live(&self) -> bool {
        match self {
            Waiter::Attempt(attempt) => attempt.check().is_ok(),
            Waiter::Reply(sender) | Waiter::LockAware(sender) => !sender.is_closed(),
        }
    }

    fn complete(self, result: Result<Grv>) {
        match self {
            Waiter::Attempt(attempt) => attempt.fill(result.and_then(Grv::unlocked)),
            Waiter::Reply(sender) => {
                let _ = sender.send(result.and_then(Grv::unlocked));
            }
            Waiter::LockAware(sender) => {
                let _ = sender.send(result.map(|grv| grv.version));
            }
        }
    }
}

impl Grv {
    fn unlocked(self) -> Result<Version> {
        if self.locked {
            Err(Error::new(ErrorCode::DATABASE_LOCKED))
        } else {
            Ok(self.version)
        }
    }
}

impl Batcher {
    async fn run(mut self) {
        let (latency_sender, mut latencies) = mpsc::unbounded_channel::<f64>();
        while let Some(first) = self.waiters.recv().await {
            let Some(first) = self.last.join(first) else {
                continue;
            };
            self.pacing.drain(&mut latencies);
            let mut batch = vec![first];
            let window = Duration::from_secs_f64(self.pacing.batch_time);
            if window.is_zero() {
                yield_now().await;
            } else {
                let timer = &*self.timer.get_or_insert_with(WindowTimer::new);
                let fallback = (!timer.arm(window)).then(|| Instant::now() + window);
                let mut closed = pin!(async move {
                    match fallback {
                        None => timer.expired().await,
                        Some(at) => sleep_until(at).await,
                    }
                });
                while batch.len() < MAX_BATCH_SIZE && fallback.is_none_or(|at| Instant::now() < at)
                {
                    select! {
                        biased;
                        Some(latency) = latencies.recv() => self.pacing.completed(latency),
                        waiter = self.waiters.recv() => match waiter {
                            Some(waiter) => batch.extend(self.last.join(waiter)),
                            None => break,
                        },
                        () = &mut closed => break,
                    }
                }
            }
            while batch.len() < MAX_BATCH_SIZE
                && let Ok(waiter) = self.waiters.try_recv()
            {
                batch.extend(self.last.join(waiter));
            }
            let batch = LiveBatch::new(batch, self.flags);
            self.last = LastBatch(Some(batch.clone()));
            self.runtime.spawn(fetch_batch(
                batch,
                self.proxies.clone(),
                self.shutdown.clone(),
                self.versions.clone(),
                self.parked.clone(),
                latency_sender.clone(),
            ));
        }
    }
}

impl BatchState {
    fn forget_frame(&mut self) {
        if matches!(self.frame, PendingFrame::Queued(..)) {
            self.frame = PendingFrame::Unqueued;
        }
    }

    fn live(&self) -> usize {
        self.waiters
            .iter()
            .filter(|waiter| waiter.is_live())
            .count()
    }
}

impl Parked {
    fn register(&self, batch: &Arc<LiveBatch>) {
        self.batches.lock().push(Arc::downgrade(batch));
    }

    fn merge_into(&self, leader: &Arc<LiveBatch>) -> bool {
        let mut parked = self.batches.lock();
        let mut lead = leader.state.lock();
        match lead.frame {
            PendingFrame::Unqueued => {}
            PendingFrame::Merged => return false,
            PendingFrame::Queued(..) | PendingFrame::Closed => return true,
        }
        let mut room = MAX_BATCH_SIZE.saturating_sub(lead.live());
        parked.retain(|entry| {
            if ptr::eq(entry.as_ptr(), Arc::as_ptr(leader)) {
                return false;
            }
            if room == 0 {
                return true;
            }
            let Some(donor) = entry.upgrade() else {
                return false;
            };
            let mut give = donor.state.lock();
            if !matches!(give.frame, PendingFrame::Unqueued) {
                return false;
            }
            let live = give.live();
            if live > room {
                return true;
            }
            room -= live;
            lead.waiters
                .extend(give.waiters.extract_if(.., |waiter| waiter.is_live()));
            give.frame = PendingFrame::Merged;
            false
        });
        true
    }
}

impl Pacing {
    fn drain(&mut self, latencies: &mut mpsc::UnboundedReceiver<f64>) {
        while let Ok(latency) = latencies.try_recv() {
            self.completed(latency);
        }
    }

    fn completed(&mut self, latency: f64) {
        self.batch_time = (0.05 * latency + 0.9 * self.batch_time).min(GRV_BATCH_TIMEOUT);
    }
}

impl LastBatch {
    fn join(&mut self, waiter: Waiter) -> Option<Waiter> {
        let Some(batch) = &self.0 else {
            return Some(waiter);
        };
        match batch.join(waiter) {
            Join::Joined => None,
            Join::Later(waiter) => Some(waiter),
            Join::Never(waiter) => {
                self.0 = None;
                Some(waiter)
            }
        }
    }
}

#[expect(clippy::manual_async_fn)]
fn fetch_batch(
    batch: Arc<LiveBatch>,
    mut proxies: ProxyWatch,
    mut shutdown: Shutdown,
    versions: Arc<VersionCache>,
    parked: Arc<Parked>,
    latencies: mpsc::UnboundedSender<f64>,
) -> impl Future<Output = ()> + Send + 'static {
    async move {
        let sequence = versions.request_started();
        let (result, latency) = select! {
            result = request(&mut proxies, &parked, &batch) => {
                let latency = result.is_ok().then(|| versions.secs_since(sequence));
                (result.inspect(|grv| versions.store(grv.version, sequence)), latency)
            }
            () = shut_down(&mut shutdown) => (Err(Error::new(ErrorCode::OPERATION_CANCELLED)), None),
        };
        for waiter in batch.close() {
            waiter.complete(result);
        }
        if let Some(latency) = latency {
            let _ = latencies.send(latency);
        }
    }
}

async fn request(proxies: &mut ProxyWatch, parked: &Parked, live: &Arc<LiveBatch>) -> Result<Grv> {
    let mut registered = false;
    loop {
        let current = proxies.borrow_and_update().clone();
        let Some(set) = current else {
            if !mem::replace(&mut registered, true) {
                parked.register(live);
            }
            proxies
                .changed()
                .await
                .map_err(|_| Error::new(ErrorCode::OPERATION_CANCELLED))?;
            continue;
        };
        if mem::take(&mut registered) && !parked.merge_into(live) {
            return Err(Error::new(ErrorCode::OPERATION_CANCELLED));
        }
        select! {
            result = send(&set, live) => return result,
            changed = proxies.changed() => {
                changed.map_err(|_| Error::new(ErrorCode::OPERATION_CANCELLED))?;
                registered = true;
                parked.register(live);
                yield_now().await;
            }
        }
    }
}

async fn send(set: &ProxySet, live: &LiveBatch) -> Result<Grv> {
    let _forget = ForgetFrame(live);
    set.request_while(
        ProxyRole::Grv,
        Delivery::AtLeastOnce,
        || live.recount(),
        |frame| live.queued(frame),
        |reply, version, out| live.encode(reply, version, out),
        decode,
    )
    .await
}

struct ForgetFrame<'a>(&'a LiveBatch);

impl Drop for ForgetFrame<'_> {
    fn drop(&mut self) {
        self.0.state.lock().forget_frame();
    }
}

impl LiveBatch {
    fn new(waiters: Vec<Waiter>, flags: u32) -> Arc<Self> {
        Arc::new(LiveBatch {
            state: Mutex::new(BatchState {
                waiters,
                frame: PendingFrame::Unqueued,
            }),
            transaction_count: AtomicU32::new(0),
            flags,
        })
    }

    fn recount(&self) -> bool {
        let mut state = self.state.lock();
        state.forget_frame();
        let live = state.live();
        self.transaction_count
            .store(u32::try_from(live).unwrap_or(u32::MAX), Ordering::Relaxed);
        live > 0
    }

    fn queued(&self, frame: QueuedFrame) {
        let mut state = self.state.lock();
        if matches!(state.frame, PendingFrame::Unqueued) {
            state.frame = PendingFrame::Queued(frame);
        }
    }

    fn join(&self, waiter: Waiter) -> Join {
        let mut state = self.state.lock();
        let frame = match &state.frame {
            PendingFrame::Queued(frame) => frame,
            PendingFrame::Unqueued => return Join::Later(waiter),
            PendingFrame::Merged | PendingFrame::Closed => return Join::Never(waiter),
        };
        if state.waiters.len() >= MAX_BATCH_SIZE {
            return Join::Never(waiter);
        }
        if !waiter.is_live() {
            state.waiters.push(waiter);
            return Join::Joined;
        }
        let transaction_count = self
            .transaction_count
            .load(Ordering::Relaxed)
            .saturating_add(1);
        let amended = frame.amend(|reply, version, out| {
            encode_request(transaction_count, self.flags, reply, version, out)
        });
        if amended.is_err() {
            state.frame = PendingFrame::Unqueued;
            return Join::Never(waiter);
        }
        self.transaction_count
            .store(transaction_count, Ordering::Relaxed);
        state.waiters.push(waiter);
        Join::Joined
    }

    fn close(&self) -> Vec<Waiter> {
        let mut state = self.state.lock();
        state.frame = PendingFrame::Closed;
        mem::take(&mut state.waiters)
    }

    fn encode(&self, reply: Uid, version: ProtocolVersion, out: &mut Vec<u8>) {
        encode_request(
            self.transaction_count.load(Ordering::Relaxed),
            self.flags,
            reply,
            version,
            out,
        );
    }
}

fn encode_request(
    transaction_count: u32,
    flags: u32,
    reply: Uid,
    version: ProtocolVersion,
    out: &mut Vec<u8>,
) {
    GetReadVersionRequest {
        transaction_count,
        flags,
    }
    .encode(Dialect::of(version.get()), reply, out);
}

fn decode(bytes: Bytes, version: ProtocolVersion) -> Result<Grv, ErrorCode> {
    let dialect = Dialect::of(version.get());
    match GetReadVersionReply::decode(dialect, &bytes) {
        Ok(Reply::Value(reply)) => Version::new(reply.version)
            .map(|version| Grv {
                version,
                locked: reply.locked,
            })
            .ok_or(ErrorCode::INTERNAL_ERROR),
        Ok(Reply::Error(code)) => Err(ErrorCode::from_grv_wire(dialect, code)),
        Err(_) => Err(ErrorCode::INTERNAL_ERROR),
    }
}

const fn flags(priority: Priority, causality: Causality) -> u32 {
    let priority = match priority {
        Priority::Default => PRIORITY_DEFAULT,
        Priority::Batch => PRIORITY_BATCH,
    };
    match causality {
        Causality::Strict => priority,
        Causality::ReadRisky => priority | FLAG_CAUSAL_READ_RISKY,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/grv/tests.rs"]
mod tests;
