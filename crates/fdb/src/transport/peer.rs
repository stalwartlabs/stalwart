/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    config::{Coalesce, PeerAddress},
    control::{self, ENDPOINT_NOT_FOUND, PING, UNAUTHORIZED_ENDPOINT, VOID_REPLY},
    error::{AmendError, ConnectFailure, TransportError},
    floor::ReplyFloor,
    frame::{self, Frame, FrameError, FrameGuard, Framing},
    health::EndpointHealth,
    network::TransportShared,
    protocol::{PeerHello, ProtocolVersion},
    rng::Rng,
    slots::{SlotKey, Slots},
};
use crate::codec::Uid;
use bytes::BytesMut;
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    mem,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Instant,
};
use tokio::sync::{Notify, watch};

const MAX_FAILED_ENDPOINTS: usize = 100_000;
pub(crate) const MAX_RETAINED_BUFFER: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameKind {
    Data,
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSize {
    Small,
    Large,
}

impl FrameSize {
    pub const fn for_len(len: usize) -> Self {
        if len > MAX_RETAINED_BUFFER {
            Self::Large
        } else {
            Self::Small
        }
    }
}

pub(crate) struct SeparateFrame {
    pub(crate) at: usize,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct Outbox {
    pub(crate) buf: Vec<u8>,
    pub(crate) separate: Vec<SeparateFrame>,
}

impl Outbox {
    pub(crate) fn len(&self) -> usize {
        self.separate
            .iter()
            .fold(self.buf.len(), |len, frame| len + frame.bytes.len())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty() && self.separate.is_empty()
    }

    pub(crate) fn segments(&self) -> impl Iterator<Item = &[u8]> {
        let mut from = 0;
        self.separate
            .iter()
            .flat_map(move |frame| {
                let before = self.buf.get(from..frame.at).unwrap_or_default();
                from = frame.at;
                [before, frame.bytes.as_slice()]
            })
            .chain(
                self.separate
                    .last()
                    .map_or(Some(self.buf.as_slice()), |last| self.buf.get(last.at..)),
            )
            .filter(|segment| !segment.is_empty())
    }

    pub(crate) fn clear(&mut self) {
        self.buf.clear();
        self.separate.clear();
    }

    fn append(&mut self, queued: &mut Outbox) {
        let base = self.buf.len();
        self.buf.extend_from_slice(&queued.buf);
        queued.buf.clear();
        self.separate
            .extend(queued.separate.drain(..).map(|frame| SeparateFrame {
                at: base + frame.at,
                bytes: frame.bytes,
            }));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointFailure {
    NotFound,
    Unauthorized,
}

impl EndpointFailure {
    const fn error(self) -> TransportError {
        match self {
            Self::NotFound => TransportError::MaybeDelivered,
            Self::Unauthorized => TransportError::Unauthorized,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerStats {
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub writes: u64,
    pub frames_received: u64,
    pub bytes_received: u64,
    pub reads: u64,
}

struct SendState {
    queue: Outbox,
    consumer: Option<Waker>,
    scheduled: bool,
    frames: u64,
    data_frames: u64,
    epoch: u64,
    takes: u64,
    version: ProtocolVersion,
    connected: bool,
    #[cfg(all(test, stalwart_tests))]
    separate_frames: u64,
}

#[derive(Debug, Clone, Copy)]
struct Placement {
    version: ProtocolVersion,
    takes: u64,
    start: usize,
    len: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct QueuedAt {
    dest: Uid,
    reply: Uid,
    placement: Placement,
}

impl QueuedAt {
    pub(crate) const fn version(&self) -> ProtocolVersion {
        self.placement.version
    }
}

impl SendState {
    fn wake_consumer(&mut self) -> Option<Waker> {
        if self.scheduled {
            None
        } else {
            self.scheduled = true;
            self.consumer.take()
        }
    }

    fn park_consumer(&mut self, waker: &Waker) {
        self.scheduled = false;
        if !self
            .consumer
            .as_ref()
            .is_some_and(|consumer| consumer.will_wake(waker))
        {
            self.consumer = Some(waker.clone());
        }
    }
}

struct PendingState {
    slots: Slots,
    floor: ReplyFloor,
    failed_endpoints: HashMap<Uid, EndpointFailure>,
    refusal: Option<TransportError>,
    epoch: u64,
}

impl PendingState {
    fn admit(
        &mut self,
        dest: Uid,
        kind: FrameKind,
        waker: &Waker,
    ) -> Result<(SlotKey, u64), TransportError> {
        if let Some(refusal) = self.refusal
            && (kind == FrameKind::Data || refusal == TransportError::Shutdown)
        {
            return Err(refusal);
        }
        if kind == FrameKind::Data
            && !self.failed_endpoints.is_empty()
            && let Some(failure) = self.failed_endpoints.get(&dest)
        {
            return Err(failure.error());
        }
        let key = self.slots.insert(waker, dest);
        if kind == FrameKind::Data {
            self.floor.admitted(key, &self.slots, Instant::now);
        }
        Ok((key, self.epoch))
    }

    fn endpoint_failed(&self, token: Uid) -> bool {
        !self.failed_endpoints.is_empty() && self.failed_endpoints.contains_key(&token)
    }

    fn fail_endpoint(
        &mut self,
        token: Uid,
        failure: EndpointFailure,
        wakers: &mut Vec<Waker>,
    ) -> bool {
        if token.is_well_known() {
            return false;
        }
        if self.failed_endpoints.len() >= MAX_FAILED_ENDPOINTS {
            self.failed_endpoints.clear();
        }
        let added = self.failed_endpoints.insert(token, failure).is_none();
        self.slots.fail_dest(token, failure.error(), wakers);
        added
    }
}

struct AdmittedSlot<'a> {
    pending: &'a Mutex<PendingState>,
    key: SlotKey,
}

impl AdmittedSlot<'_> {
    fn keep(self) -> SlotKey {
        let key = self.key;
        mem::forget(self);
        key
    }
}

impl Drop for AdmittedSlot<'_> {
    fn drop(&mut self) {
        self.pending.lock().slots.remove(self.key);
    }
}

#[derive(Default)]
pub(crate) struct Dispatch {
    frames: Vec<Frame>,
    wakers: Vec<Waker>,
    pings: Vec<Uid>,
}

pub(crate) struct PeerShared {
    pub(crate) address: PeerAddress,
    pub(crate) framing: Framing,
    pub(crate) transport: Arc<TransportShared>,
    pub(crate) control: Notify,
    nonce: u64,
    pending: Mutex<PendingState>,
    send: Mutex<SendState>,
    failed: AtomicBool,
    failure_generation: AtomicU64,
    connect_failures: AtomicU64,
    last_failure: Mutex<Option<ConnectFailure>>,
    references: AtomicUsize,
    server_version: AtomicU64,
    bytes_received: AtomicU64,
    reads: AtomicU64,
    frames_received: AtomicU64,
    reply_floor: AtomicU32,
    bytes_sent: AtomicU64,
    writes: AtomicU64,
    state: watch::Sender<()>,
    #[cfg(all(test, stalwart_tests))]
    rx_capacity: AtomicUsize,
    #[cfg(all(test, stalwart_tests))]
    gate_stats: Mutex<super::gate::GateStats>,
    #[cfg(all(test, stalwart_tests))]
    burst_stats: Mutex<super::burst::BurstStats>,
}

impl PeerShared {
    pub(crate) fn new(address: PeerAddress, transport: Arc<TransportShared>) -> Self {
        let version = transport.protocol_version();
        let floor = match transport.config.coalesce {
            Coalesce::Burst => ReplyFloor::probing(),
            Coalesce::Immediate | Coalesce::Requeue | Coalesce::Yield => ReplyFloor::off(),
        };
        Self {
            framing: Framing::for_address(address.tls),
            address,
            transport,
            control: Notify::new(),
            nonce: Rng::new().next_u64() & !1,
            pending: Mutex::new(PendingState {
                slots: Slots::new(),
                floor,
                failed_endpoints: HashMap::new(),
                refusal: None,
                epoch: 0,
            }),
            send: Mutex::new(SendState {
                queue: Outbox::default(),
                consumer: None,
                scheduled: false,
                frames: 0,
                data_frames: 0,
                epoch: 0,
                takes: 0,
                version,
                connected: false,
                #[cfg(all(test, stalwart_tests))]
                separate_frames: 0,
            }),
            failed: AtomicBool::new(false),
            failure_generation: AtomicU64::new(0),
            connect_failures: AtomicU64::new(0),
            last_failure: Mutex::new(None),
            references: AtomicUsize::new(1),
            server_version: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            reply_floor: AtomicU32::new(0),
            bytes_sent: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            state: watch::Sender::new(()),
            #[cfg(all(test, stalwart_tests))]
            rx_capacity: AtomicUsize::new(0),
            #[cfg(all(test, stalwart_tests))]
            gate_stats: Mutex::new(super::gate::GateStats::default()),
            #[cfg(all(test, stalwart_tests))]
            burst_stats: Mutex::new(super::burst::BurstStats::default()),
        }
    }

    pub(crate) fn start<F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>)>(
        &self,
        dest: Uid,
        kind: FrameKind,
        size: FrameSize,
        encode: F,
        waker: &Waker,
    ) -> Result<(SlotKey, QueuedAt), TransportError> {
        if kind == FrameKind::Data && self.failed.load(Ordering::Relaxed) {
            return Err(TransportError::MaybeDelivered);
        }
        let (key, epoch) = self.pending.lock().admit(dest, kind, waker)?;
        let slot = AdmittedSlot {
            pending: &self.pending,
            key,
        };
        let reply = Uid::new(self.nonce, key.token_second());
        let placement = self.enqueue(dest, kind, size, epoch, |version, out| {
            encode(reply, version, out)
        })?;
        Ok((
            slot.keep(),
            QueuedAt {
                dest,
                reply,
                placement,
            },
        ))
    }

    pub(crate) fn amend<F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>)>(
        &self,
        at: &QueuedAt,
        encode: F,
    ) -> Result<(), AmendError> {
        let Placement {
            version,
            takes,
            start,
            len,
        } = at.placement;
        let mut guard = self.send.lock();
        let send = &mut *guard;
        if send.takes != takes {
            return Err(AmendError::Taken);
        }
        let buf = &mut send.queue.buf;
        let tail = buf.len();
        let mut frame = FrameGuard::begin(buf, self.framing, at.dest);
        encode(at.reply, version, frame.buf());
        let fits = frame.finish().is_ok() && buf.len() - tail == len;
        if fits {
            buf.copy_within(tail.., start);
        }
        buf.truncate(tail);
        if fits {
            Ok(())
        } else {
            Err(AmendError::Layout)
        }
    }

    pub(crate) fn poll_reply(
        &self,
        key: SlotKey,
        waker: &Waker,
    ) -> Poll<Result<bytes::Bytes, TransportError>> {
        self.pending.lock().slots.poll(key, waker)
    }

    pub(crate) fn cancel(&self, key: SlotKey) {
        self.pending.lock().slots.remove(key);
    }

    fn enqueue<F: FnOnce(ProtocolVersion, &mut Vec<u8>)>(
        &self,
        dest: Uid,
        kind: FrameKind,
        size: FrameSize,
        epoch: u64,
        encode: F,
    ) -> Result<Placement, TransportError> {
        let (placement, consumer) = {
            let mut guard = self.send.lock();
            let send = &mut *guard;
            if send.epoch != epoch {
                return Err(TransportError::MaybeDelivered);
            }
            let version = send.version;
            let queue = &mut send.queue;
            let start = queue.buf.len();
            let len = match size {
                FrameSize::Small => {
                    let mut frame = FrameGuard::begin(&mut queue.buf, self.framing, dest);
                    encode(version, frame.buf());
                    frame.finish()?;
                    queue.buf.len() - start
                }
                FrameSize::Large => {
                    let mut bytes = Vec::new();
                    let mut frame = FrameGuard::begin(&mut bytes, self.framing, dest);
                    encode(version, frame.buf());
                    frame.finish()?;
                    queue.separate.push(SeparateFrame { at: start, bytes });
                    0
                }
            };
            send.frames += 1;
            if kind == FrameKind::Data {
                send.data_frames += 1;
            }
            #[cfg(all(test, stalwart_tests))]
            if size == FrameSize::Large {
                send.separate_frames += 1;
            }
            let placement = Placement {
                version,
                takes: send.takes,
                start,
                len,
            };
            (placement, send.wake_consumer())
        };
        if let Some(consumer) = consumer {
            consumer.wake();
        }
        Ok(placement)
    }

    pub(crate) fn open_connection(&self) -> Option<ProtocolVersion> {
        let mut send = self.send.lock();
        if send.version != self.transport.protocol_version() {
            return None;
        }
        send.connected = true;
        Some(send.version)
    }

    pub(crate) fn adopt_version(&self) {
        let mut send = self.send.lock();
        if !send.connected && send.queue.is_empty() {
            send.version = self.transport.protocol_version();
        }
    }

    pub(crate) fn poll_queued(&self, cx: &mut Context<'_>) -> Poll<u64> {
        let mut send = self.send.lock();
        if !send.queue.is_empty() {
            return Poll::Ready(send.frames);
        }
        send.park_consumer(cx.waker());
        Poll::Pending
    }

    pub(crate) fn poll_frames(&self, cx: &mut Context<'_>, taken: u64, at_least: u64) -> Poll<()> {
        let mut send = self.send.lock();
        if send.queue.is_empty() || send.frames.wrapping_sub(taken) >= at_least {
            return Poll::Ready(());
        }
        send.park_consumer(cx.waker());
        Poll::Pending
    }

    pub(crate) fn take_queued(&self, out: &mut Outbox) -> u64 {
        let mut send = self.send.lock();
        mem::swap(&mut send.queue, out);
        send.takes += 1;
        send.frames
    }

    pub(crate) fn append_queued(&self, out: &mut Outbox) -> u64 {
        let mut send = self.send.lock();
        out.append(&mut send.queue);
        send.takes += 1;
        send.frames
    }

    pub(crate) fn waiting_replies(&self) -> usize {
        self.pending.lock().slots.waiting()
    }

    pub(crate) fn queued_frames(&self) -> u64 {
        self.send.lock().frames
    }

    pub(crate) fn frames_received(&self) -> u64 {
        self.frames_received.load(Ordering::Relaxed)
    }

    pub(crate) fn reply_floor(&self) -> u32 {
        self.reply_floor.load(Ordering::Relaxed)
    }

    pub(crate) fn has_queued(&self) -> bool {
        !self.send.lock().queue.is_empty()
    }

    pub(crate) fn is_quiet(&self) -> bool {
        self.pending.lock().slots.waiting() == 0 && !self.has_queued()
    }

    pub(crate) fn data_frames(&self) -> u64 {
        self.send.lock().data_frames
    }

    pub(crate) fn references(&self) -> usize {
        self.references.load(Ordering::Acquire)
    }

    pub(crate) fn add_reference(&self) {
        self.references.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn release_reference(&self) {
        if self.references.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.control.notify_one();
        }
    }

    pub(crate) fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    pub(crate) fn record_read(&self, bytes: usize) {
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.reads.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn separate_frames(&self) -> u64 {
        self.send.lock().separate_frames
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn record_rx_capacity(&self, capacity: usize) {
        self.rx_capacity.store(capacity, Ordering::Relaxed);
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn rx_capacity(&self) -> usize {
        self.rx_capacity.load(Ordering::Relaxed)
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn record_gate(&self, stats: super::gate::GateStats) {
        *self.gate_stats.lock() = stats;
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn gate_stats(&self) -> super::gate::GateStats {
        *self.gate_stats.lock()
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn record_burst(&self, stats: super::burst::BurstStats) {
        *self.burst_stats.lock() = stats;
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn burst_stats(&self) -> super::burst::BurstStats {
        super::burst::BurstStats {
            floor_us: self.reply_floor(),
            ..*self.burst_stats.lock()
        }
    }

    pub(crate) fn record_writes(&self, bytes: usize, writes: u64) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.writes.fetch_add(writes, Ordering::Relaxed);
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    pub(crate) fn set_failed(&self, failed: bool) {
        if self.failed.swap(failed, Ordering::Relaxed) != failed {
            self.notify_state();
        }
    }

    pub(crate) fn endpoint_failed(&self, health: &EndpointHealth) -> bool {
        let generation = self.failure_generation.load(Ordering::Acquire);
        if generation == 0 {
            return false;
        }
        if let Some(failed) = health.get(generation) {
            return failed;
        }
        let pending = self.pending.lock();
        let generation = self.failure_generation.load(Ordering::Relaxed);
        let failed = pending.endpoint_failed(health.token());
        drop(pending);
        health.set(generation, failed);
        failed
    }

    pub(crate) fn mark_endpoint_failed(&self, token: Uid) {
        let mut wakers = Vec::new();
        let changed = self.fail_endpoint(
            &mut self.pending.lock(),
            token,
            EndpointFailure::NotFound,
            &mut wakers,
        );
        wake_all(&mut wakers);
        if changed {
            self.notify_state();
        }
    }

    fn fail_endpoint(
        &self,
        pending: &mut PendingState,
        token: Uid,
        failure: EndpointFailure,
        wakers: &mut Vec<Waker>,
    ) -> bool {
        let changed = pending.fail_endpoint(token, failure, wakers);
        if changed {
            self.failure_generation
                .store(self.transport.next_failure_generation(), Ordering::Release);
        }
        changed
    }

    pub(crate) fn connect_failures(&self) -> u64 {
        self.connect_failures.load(Ordering::Relaxed)
    }

    pub(crate) fn record_connect_failure(&self, failure: ConnectFailure) {
        self.connect_failures.fetch_add(1, Ordering::Relaxed);
        let mut last = self.last_failure.lock();
        if failure != ConnectFailure::Throttled || last.is_none() {
            *last = Some(failure);
        }
    }

    #[cold]
    pub(crate) fn record_session_failure(&self, failure: ConnectFailure) {
        *self.last_failure.lock() = Some(failure);
    }

    pub(crate) fn last_connect_failure(&self) -> Option<ConnectFailure> {
        self.last_failure.lock().clone()
    }

    pub(crate) fn server_version(&self) -> Option<ProtocolVersion> {
        match self.server_version.load(Ordering::Relaxed) {
            0 => None,
            version => Some(ProtocolVersion::new(version)),
        }
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<()> {
        self.state.subscribe()
    }

    pub(crate) fn stats(&self) -> PeerStats {
        PeerStats {
            frames_sent: self.send.lock().frames,
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            reads: self.reads.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn on_hello(&self, hello: PeerHello) {
        self.server_version
            .store(hello.version.get(), Ordering::Relaxed);
        if hello.compatible {
            self.last_failure.lock().take();
            return;
        }
        self.record_session_failure(ConnectFailure::Incompatible {
            server: hello.version,
        });
        let error = TransportError::Incompatible {
            server: hello.version,
        };
        let mut wakers = Vec::new();
        {
            let mut pending = self.pending.lock();
            pending.refusal.get_or_insert(error);
            pending.slots.fail_all(error, &mut wakers);
        }
        wake_all(&mut wakers);
        self.notify_state();
    }

    pub(crate) fn dispatch(
        &self,
        buf: &mut BytesMut,
        scratch: &mut Dispatch,
    ) -> Result<(), FrameError> {
        let mut frames = 0u64;
        let result = loop {
            match frame::next_frame(buf, self.framing) {
                Ok(Some(frame)) => {
                    frames += 1;
                    if frame.token == PING {
                        scratch
                            .pings
                            .extend(control::ping_reply_token(&frame.message));
                    } else if frame.token.first == self.nonce || frame.token.is_well_known() {
                        scratch.frames.push(frame);
                    }
                }
                Ok(None) => break Ok(()),
                Err(err) => break Err(err),
            }
        };
        self.frames_received.fetch_add(frames, Ordering::Relaxed);
        if !scratch.frames.is_empty() || !scratch.pings.is_empty() {
            self.deliver(scratch);
        }
        result
    }

    fn deliver(&self, scratch: &mut Dispatch) {
        let Dispatch {
            frames,
            wakers,
            pings,
        } = scratch;
        let mut endpoints_changed = false;
        let epoch = {
            let mut pending = self.pending.lock();
            for frame in frames.drain(..) {
                if frame.token.first == self.nonce {
                    if let Some(waker) = pending
                        .slots
                        .complete(frame.token.second, Ok(frame.message))
                    {
                        wakers.push(waker);
                        if let Some(floor) = pending.floor.replied(frame.token.second, Instant::now)
                        {
                            self.reply_floor.store(floor, Ordering::Relaxed);
                        }
                    }
                } else {
                    endpoints_changed |= self.on_control(frame, &mut pending, wakers);
                }
            }
            pending.epoch
        };
        wake_all(wakers);
        for reply in pings.drain(..) {
            let _ = self.enqueue(
                reply,
                FrameKind::Control,
                FrameSize::Small,
                epoch,
                |_, out| out.extend_from_slice(&VOID_REPLY),
            );
        }
        if endpoints_changed {
            self.notify_state();
        }
    }

    fn on_control(
        &self,
        frame: Frame,
        pending: &mut PendingState,
        wakers: &mut Vec<Waker>,
    ) -> bool {
        match frame.token {
            ENDPOINT_NOT_FOUND => control::uid_message(&frame.message).is_some_and(|token| {
                self.fail_endpoint(pending, token, EndpointFailure::NotFound, wakers)
            }),
            UNAUTHORIZED_ENDPOINT => control::uid_message(&frame.message).is_some_and(|token| {
                self.fail_endpoint(pending, token, EndpointFailure::Unauthorized, wakers)
            }),
            _ => false,
        }
    }

    pub(crate) fn teardown(&self, error: TransportError) {
        let mut wakers = Vec::new();
        {
            let mut pending = self.pending.lock();
            let mut send = self.send.lock();
            send.queue.clear();
            send.takes += 1;
            if send.queue.buf.capacity() > MAX_RETAINED_BUFFER {
                send.queue.buf = Vec::new();
            }
            pending.epoch = pending.epoch.wrapping_add(1);
            send.epoch = pending.epoch;
            send.version = self.transport.protocol_version();
            send.connected = false;
            pending.slots.fail_all(error, &mut wakers);
            if pending.refusal != Some(TransportError::Shutdown) {
                pending.refusal = (error == TransportError::Shutdown).then_some(error);
            }
        }
        wake_all(&mut wakers);
        self.notify_state();
    }

    fn notify_state(&self) {
        self.state.send_replace(());
    }
}

fn wake_all(wakers: &mut Vec<Waker>) {
    for waker in wakers.drain(..) {
        waker.wake();
    }
}
