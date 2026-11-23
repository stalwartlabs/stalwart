/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::error::{Error, ErrorCode, Result},
    client::{
        coordinator::{Shutdown, shut_down},
        grv::timer::WindowTimer,
    },
};
use crossbeam_utils::CachePadded;
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use std::{
    array,
    num::NonZeroU32,
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    runtime::Handle,
    select,
    sync::Notify,
    time::{Instant, sleep_until},
};

const SHARD_BITS: u32 = 4;
const SHARDS: usize = 1 << SHARD_BITS;
const MAX_INDEX: u32 = (u32::MAX >> SHARD_BITS) - 1;
const FIBONACCI: u64 = 0x9e37_79b9_7f4a_7c15;
const IDLE: u64 = u64::MAX;
const TICK_NANOS: u64 = 1 << 12;
const GROUP_TICKS: u64 = 16;
const WHEEL: usize = 64;
const SPAN: u64 = WHEEL as u64 * GROUP_TICKS;
const MAX_ARM: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy)]
pub(crate) enum Precision {
    Coarse,
    Fine,
}

pub(crate) struct Deadlines {
    base: Instant,
    waking: Waking,
    next: AtomicU64,
    lowered: Notify,
    shards: [CachePadded<Mutex<Slots>>; SHARDS],
    #[cfg(all(test, stalwart_tests))]
    sweeps: AtomicU64,
    #[cfg(all(test, stalwart_tests))]
    arms: AtomicU64,
    #[cfg(all(test, stalwart_tests))]
    swept_nanos: AtomicU64,
}

#[expect(clippy::large_enum_variant)]
enum Waking {
    Tokio,
    Timerfd(Alarm),
}

struct Alarm {
    timer: WindowTimer,
    armed: Mutex<u64>,
    groups: [AtomicU32; WHEEL],
    fine: [FineCounts; WHEEL],
}

#[derive(Default)]
#[repr(align(64))]
struct FineCounts([AtomicU32; GROUP_TICKS as usize]);

const _: () = assert!(size_of::<FineCounts>() == 64);

#[derive(Default)]
struct Slots {
    entries: Vec<Entry>,
    free: Vec<u32>,
}

struct Entry {
    at: u64,
    waker: Option<Waker>,
}

#[derive(Clone, Copy)]
struct Slot(NonZeroU32);

pub(crate) struct Timer<'a> {
    deadlines: &'a Deadlines,
    slot: Option<Slot>,
}

pin_project! {
    pub(crate) struct Expiry<'a, F> {
        #[pin]
        future: F,
        deadline: Option<Instant>,
        timer: Timer<'a>,
    }
}

impl Deadlines {
    pub(crate) fn spawn(runtime: &Handle, shutdown: Shutdown, precision: Precision) -> Arc<Self> {
        let deadlines = Arc::new(Deadlines {
            base: Instant::now(),
            waking: match precision {
                Precision::Coarse => Waking::Tokio,
                Precision::Fine => Waking::fine(runtime),
            },
            next: AtomicU64::new(IDLE),
            lowered: Notify::new(),
            shards: array::from_fn(|_| CachePadded::default()),
            #[cfg(all(test, stalwart_tests))]
            sweeps: AtomicU64::new(0),
            #[cfg(all(test, stalwart_tests))]
            arms: AtomicU64::new(0),
            #[cfg(all(test, stalwart_tests))]
            swept_nanos: AtomicU64::new(0),
        });
        runtime.spawn(deadlines.clone().sweep(shutdown));
        deadlines
    }

    fn insert(&self, deadline: Instant, waker: &Waker) -> Option<Slot> {
        let at = self.ticks_after(deadline);
        let shard = ((waker.data() as usize as u64).wrapping_mul(FIBONACCI)
            >> (u64::BITS - SHARD_BITS)) as usize;
        let mut slots = self.shards[shard].lock();
        let index = slots.insert(at, waker.clone())?;
        self.waking.enliven(at);
        drop(slots);
        self.lower(at);
        Slot::new(shard, index)
    }

    fn rearm(&self, slot: Slot, waker: &Waker) {
        let mut slots = self.shards[slot.shard()].lock();
        let Some(entry) = slots.entries.get_mut(slot.index()) else {
            return;
        };
        if entry
            .waker
            .as_ref()
            .is_some_and(|current| current.will_wake(waker))
        {
            return;
        }
        let replaced = entry.waker.replace(waker.clone());
        let at = entry.at;
        if replaced.is_none() {
            self.waking.enliven(at);
        }
        drop(slots);
        if replaced.is_none() {
            self.lower(at);
        }
    }

    fn remove(&self, slot: Slot) {
        let mut slots = self.shards[slot.shard()].lock();
        let Some(entry) = slots.entries.get_mut(slot.index()) else {
            return;
        };
        let at = entry.at;
        let waker = entry.waker.take();
        slots.free.push(slot.index() as u32);
        let emptied = waker.is_some() && self.waking.deaden(at);
        drop(slots);
        drop(waker);
        if emptied && let Waking::Timerfd(alarm) = &self.waking {
            self.retire(alarm, at);
        }
    }

    fn lower(&self, at: u64) {
        match &self.waking {
            Waking::Tokio => {
                if at < self.next.load(Ordering::Relaxed)
                    && self.next.fetch_min(at, Ordering::Relaxed) > at
                {
                    self.lowered.notify_one();
                }
            }
            Waking::Timerfd(alarm) => {
                if at < self.next.load(Ordering::SeqCst) {
                    let mut armed = alarm.armed.lock();
                    if at < *armed {
                        self.arm(alarm, &mut armed, at);
                    }
                }
            }
        }
    }

    fn retire(&self, alarm: &Alarm, at: u64) {
        if self.next.load(Ordering::Relaxed) != at {
            return;
        }
        let mut armed = alarm.armed.lock();
        if *armed != at {
            return;
        }
        let first = alarm.first_live(at, IDLE);
        self.next.store(first, Ordering::SeqCst);
        let first = alarm.first_live(at, first);
        if first == at {
            self.next.store(at, Ordering::SeqCst);
        } else {
            self.arm(alarm, &mut armed, first);
        }
    }

    fn arm(&self, alarm: &Alarm, armed: &mut u64, at: u64) {
        #[cfg(all(test, stalwart_tests))]
        self.arms.fetch_add(1, Ordering::Relaxed);
        *armed = at;
        self.next.store(at, Ordering::SeqCst);
        if at == IDLE {
            alarm.timer.disarm();
        } else {
            alarm.timer.arm(
                self.instant(at)
                    .saturating_duration_since(Instant::now())
                    .min(MAX_ARM),
            );
        }
    }

    async fn sweep(self: Arc<Self>, mut shutdown: Shutdown) {
        let mut wakers = Vec::new();
        if let Waking::Timerfd(alarm) = &self.waking {
            loop {
                select! {
                    () = shut_down(&mut shutdown) => return,
                    () = alarm.timer.expired() => self.wake_expired(&mut wakers),
                }
            }
        }
        let mut timer = pin!(sleep_until(self.base));
        loop {
            let next = self.next.load(Ordering::Relaxed);
            if next != IDLE {
                timer.as_mut().reset(self.instant(next));
            }
            select! {
                () = shut_down(&mut shutdown) => return,
                () = self.lowered.notified() => {}
                () = &mut timer, if next != IDLE => self.wake_expired(&mut wakers),
            }
        }
    }

    fn wake_expired(&self, wakers: &mut Vec<Waker>) {
        #[cfg(all(test, stalwart_tests))]
        self.sweeps.fetch_add(1, Ordering::Relaxed);
        match &self.waking {
            Waking::Tokio => self.next.store(IDLE, Ordering::Relaxed),
            Waking::Timerfd(alarm) => {
                let mut armed = alarm.armed.lock();
                *armed = IDLE;
                self.next.store(IDLE, Ordering::SeqCst);
            }
        }
        let now = Instant::now();
        #[cfg(all(test, stalwart_tests))]
        self.swept_nanos
            .store(self.nanos_until(now), Ordering::Relaxed);
        let now = self.ticks_until(now);
        let mut earliest = IDLE;
        for shard in &self.shards {
            let mut slots = shard.lock();
            for entry in &mut slots.entries {
                if entry.waker.is_none() {
                    continue;
                }
                if entry.at <= now {
                    wakers.extend(entry.waker.take());
                    self.waking.deaden(entry.at);
                } else {
                    earliest = earliest.min(entry.at);
                }
            }
            drop(slots);
            wakers.drain(..).for_each(Waker::wake);
        }
        match &self.waking {
            Waking::Tokio => {
                self.next.fetch_min(earliest, Ordering::Relaxed);
            }
            Waking::Timerfd(alarm) => {
                let mut armed = alarm.armed.lock();
                let first = alarm.first_live(earliest, *armed);
                if first < *armed {
                    self.arm(alarm, &mut armed, first);
                }
            }
        }
    }

    fn ticks_after(&self, deadline: Instant) -> u64 {
        self.nanos_until(deadline).div_ceil(TICK_NANOS)
    }

    fn ticks_until(&self, now: Instant) -> u64 {
        self.nanos_until(now) / TICK_NANOS
    }

    fn nanos_until(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.base).as_nanos()).unwrap_or(u64::MAX)
    }

    fn instant(&self, ticks: u64) -> Instant {
        self.base
            .checked_add(Duration::from_nanos(ticks.saturating_mul(TICK_NANOS)))
            .unwrap_or(self.base)
    }
}

impl Waking {
    fn fine(runtime: &Handle) -> Self {
        let _runtime = runtime.enter();
        let timer = WindowTimer::new();
        if !timer.is_available() {
            return Waking::Tokio;
        }
        Waking::Timerfd(Alarm::new(timer))
    }

    fn enliven(&self, at: u64) {
        if let Waking::Timerfd(alarm) = self {
            alarm.tick_count(at).fetch_add(1, Ordering::SeqCst);
            alarm.group_count(at).fetch_add(1, Ordering::SeqCst);
        }
    }

    fn deaden(&self, at: u64) -> bool {
        match self {
            Waking::Tokio => false,
            Waking::Timerfd(alarm) => {
                let emptied = alarm.tick_count(at).fetch_sub(1, Ordering::SeqCst) == 1;
                alarm.group_count(at).fetch_sub(1, Ordering::SeqCst);
                emptied
            }
        }
    }
}

impl Alarm {
    fn new(timer: WindowTimer) -> Self {
        Alarm {
            timer,
            armed: Mutex::new(IDLE),
            groups: array::from_fn(|_| AtomicU32::new(0)),
            fine: array::from_fn(|_| FineCounts::default()),
        }
    }

    fn group_index(at: u64) -> usize {
        (at / GROUP_TICKS % WHEEL as u64) as usize
    }

    fn group_count(&self, at: u64) -> &AtomicU32 {
        &self.groups[Self::group_index(at)]
    }

    fn tick_count(&self, at: u64) -> &AtomicU32 {
        &self.fine[Self::group_index(at)].0[(at % GROUP_TICKS) as usize]
    }

    fn first_live(&self, from: u64, until: u64) -> u64 {
        let end = until.min(from.saturating_add(SPAN));
        let mut tick = from;
        while tick < end {
            let start = tick - tick % GROUP_TICKS;
            let stop = start.saturating_add(GROUP_TICKS).min(end);
            let group = Self::group_index(tick);
            if self.groups[group].load(Ordering::SeqCst) != 0
                && let Some(offset) = self.fine[group]
                    .0
                    .get((tick - start) as usize..(stop - start) as usize)
                    .and_then(|counts| {
                        counts
                            .iter()
                            .position(|count| count.load(Ordering::SeqCst) != 0)
                    })
            {
                return tick + offset as u64;
            }
            tick = stop;
        }
        until
    }
}

impl Slot {
    fn new(shard: usize, index: u32) -> Option<Self> {
        if index > MAX_INDEX || shard >= SHARDS {
            return None;
        }
        NonZeroU32::new((index << SHARD_BITS | shard as u32) + 1).map(Slot)
    }

    fn shard(self) -> usize {
        (self.0.get() - 1) as usize % SHARDS
    }

    fn index(self) -> usize {
        ((self.0.get() - 1) >> SHARD_BITS) as usize
    }
}

impl Slots {
    fn insert(&mut self, at: u64, waker: Waker) -> Option<u32> {
        let entry = Entry {
            at,
            waker: Some(waker),
        };
        if let Some(index) = self.free.pop()
            && let Some(slot) = self.entries.get_mut(index as usize)
        {
            *slot = entry;
            return Some(index);
        }
        let index = u32::try_from(self.entries.len())
            .ok()
            .filter(|&index| index <= MAX_INDEX)?;
        self.entries.push(entry);
        Some(index)
    }
}

impl<'a> Timer<'a> {
    pub(crate) fn new(deadlines: &'a Deadlines) -> Self {
        Timer {
            deadlines,
            slot: None,
        }
    }

    pub(crate) fn is_armed(&self) -> bool {
        self.slot.is_some()
    }

    pub(crate) fn poll_expired(&mut self, deadline: Instant, cx: &mut Context<'_>) -> Poll<()> {
        match self.slot {
            None => self.slot = self.deadlines.insert(deadline, cx.waker()),
            Some(_) if is_expired(deadline) => return Poll::Ready(()),
            Some(slot) => self.deadlines.rearm(slot, cx.waker()),
        }
        Poll::Pending
    }
}

impl Drop for Timer<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            self.deadlines.remove(slot);
        }
    }
}

impl<'a, F> Expiry<'a, F> {
    pub(crate) fn new(deadlines: &'a Deadlines, deadline: Option<Instant>, future: F) -> Self {
        Expiry {
            future,
            deadline,
            timer: Timer::new(deadlines),
        }
    }
}

impl<F: Future<Output = Result<T>>, T> Future for Expiry<'_, F> {
    type Output = Result<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let Some(deadline) = *this.deadline else {
            return this.future.poll(cx);
        };
        if !this.timer.is_armed() && is_expired(deadline) {
            return Poll::Ready(Err(timed_out()));
        }
        if let Poll::Ready(output) = this.future.poll(cx) {
            return Poll::Ready(output);
        }
        this.timer
            .poll_expired(deadline, cx)
            .map(|()| Err(timed_out()))
    }
}

pub(crate) fn deadline_after(timeout: Option<Duration>) -> Option<Instant> {
    timeout
        .filter(|timeout| !timeout.is_zero())
        .and_then(|timeout| Instant::now().checked_add(timeout))
}

pub(crate) fn is_expired(deadline: Instant) -> bool {
    Instant::now() >= deadline
}

#[cold]
pub(crate) fn timed_out() -> Error {
    Error::new(ErrorCode::TRANSACTION_TIMED_OUT)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/expiry/tests.rs"]
mod tests;
