/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::error::ErrorCode, transport::TransportError};
use std::{
    mem,
    sync::atomic::{AtomicI32, Ordering},
};

const QUEUE_MODEL_SMOOTHING_AMOUNT: f64 = 2.0;
const INITIAL_PENALTY: f64 = 1.0;
const MAX_PENALTY: f64 = 1e6;
const FUTURE_VERSION_INITIAL_BACKOFF: f64 = 1.0;
const FUTURE_VERSION_MAX_BACKOFF: f64 = 8.0;
const FUTURE_VERSION_BACKOFF_GROWTH: f64 = 2.0;
const LOAD_BALANCE_MAX_BAD_OPTIONS: usize = 1;
const LOAD_BALANCE_START_BACKOFF: f64 = 0.01;
const LOAD_BALANCE_BACKOFF_RATE: f64 = 2.0;
const LOAD_BALANCE_MAX_BACKOFF: f64 = 5.0;
const BAD_PENALTY: f64 = 1.001;
const NO_METRIC: f64 = 1e9;
const NO_METRIC_THRESHOLD: f64 = 1e8;
const ALTERNATIVES_FAILURE_RESET_TIME: f64 = 5.0;
const ALTERNATIVES_FAILURE_MIN_DELAY: f64 = 0.05;
const ALTERNATIVES_FAILURE_DELAY_RATIO: f64 = 0.2;
const ALTERNATIVES_FAILURE_MAX_DELAY: f64 = 1.0;
const ALTERNATIVES_FAILURE_SLOW_DELAY_RATIO: f64 = 0.04;
const ALTERNATIVES_FAILURE_SLOW_MAX_DELAY: f64 = 30.0;
const ALTERNATIVES_FAILURE_SKIP_DELAY: f64 = 1.0;
const DELAY_JITTER_OFFSET: f64 = 0.9;
const DELAY_JITTER_RANGE: f64 = 0.2;
const INITIAL_LATENCY: f64 = 0.001;
const BASE_SECOND_REQUEST_TIME: f64 = 0.0005;
const INSTANT_SECOND_REQUEST_MULTIPLIER: f64 = 2.0;
const SECOND_REQUEST_MULTIPLIER_UNIT: f64 = 0.00025;
const SECOND_REQUEST_MULTIPLIER_GROWTH: i32 = 40;
const SECOND_REQUEST_MAX_MULTIPLIER: i32 = 1 << 30;
const SECOND_REQUEST_MAX_BUDGET: i32 = 2000;
const SECOND_REQUEST_COST: i32 = 20;
const NO_HEDGE: f32 = f32::INFINITY;
const SPILL_DEPTH: f32 = 8.0;

struct Smoother {
    total: f64,
    time: f64,
    estimate: f64,
}

pub(crate) struct QueueData {
    outstanding: Smoother,
    latency: f64,
    penalty: f64,
    failed_until: f64,
    future_version_backoff: f64,
    increase_backoff_time: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Measurement {
    pub(crate) outstanding: f64,
    pub(crate) latency: f64,
    pub(crate) penalty: f64,
    pub(crate) depth: Depth,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Depth {
    pub(crate) in_flight: f32,
    pub(crate) recovered: bool,
}

const _: () = assert!(size_of::<Option<Measurement>>() <= 32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Completion {
    Response,
    FutureVersion,
    ProcessBehind,
    NoResponse,
}

pub(crate) struct Replicas<R> {
    replicas: Box<[R]>,
    count_best: usize,
}

pub(crate) struct Attempts<'a, R> {
    replicas: &'a [R],
    best: u32,
    next: u32,
    offset: u32,
    failures: u32,
    backoff: f64,
    hedge: f32,
    tried_all: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Selected<'a, R> {
    pub(crate) replica: &'a R,
    pub(crate) index: usize,
    pub(crate) backoff: f64,
    pub(crate) tried_all: bool,
    pub(crate) hedge: Option<f64>,
}

#[derive(Clone, Copy)]
struct Latencies {
    best: f64,
    next: f64,
}

pub(crate) struct Hedging {
    budget: AtomicI32,
    multiplier: AtomicI32,
}

pub(crate) struct AlternativesFailed {
    oldest: f64,
    newest: f64,
    last_skip: f64,
}

impl Smoother {
    const fn new() -> Self {
        Smoother {
            total: 0.0,
            time: 0.0,
            estimate: 0.0,
        }
    }

    fn update(&mut self, now: f64) {
        let elapsed = now - self.time;
        if elapsed > 0.0 {
            self.time = now;
            self.estimate += (self.total - self.estimate)
                * (1.0 - (-elapsed / QUEUE_MODEL_SMOOTHING_AMOUNT).exp());
        }
    }

    fn add_delta(&mut self, delta: f64, now: f64) {
        self.update(now);
        self.total += delta;
    }

    fn smooth_total(&mut self, now: f64) -> f64 {
        self.update(now);
        self.estimate
    }
}

impl QueueData {
    pub(crate) const fn new() -> Self {
        QueueData {
            outstanding: Smoother::new(),
            latency: INITIAL_LATENCY,
            penalty: INITIAL_PENALTY,
            failed_until: f64::NEG_INFINITY,
            future_version_backoff: FUTURE_VERSION_INITIAL_BACKOFF,
            increase_backoff_time: f64::NEG_INFINITY,
        }
    }

    pub(crate) fn add_request(&mut self, now: f64) -> f64 {
        self.outstanding.add_delta(self.penalty, now);
        self.penalty
    }

    pub(crate) fn end_request(
        &mut self,
        now: f64,
        delta: f64,
        elapsed: Option<f64>,
        penalty: Option<f64>,
        completion: Completion,
    ) {
        self.outstanding.add_delta(-delta, now);
        self.outstanding.total = self.outstanding.total.max(0.0);
        let clean = matches!(completion, Completion::Response | Completion::FutureVersion);
        if let Some(elapsed) = elapsed {
            self.latency = if clean {
                elapsed
            } else {
                self.latency.max(elapsed)
            };
        }
        if matches!(
            completion,
            Completion::FutureVersion | Completion::ProcessBehind
        ) {
            if now > self.increase_backoff_time {
                self.future_version_backoff = (self.future_version_backoff
                    * FUTURE_VERSION_BACKOFF_GROWTH)
                    .min(FUTURE_VERSION_MAX_BACKOFF);
                self.increase_backoff_time = now + self.future_version_backoff;
            }
            self.failed_until = now + self.future_version_backoff;
        } else if clean {
            self.future_version_backoff = FUTURE_VERSION_INITIAL_BACKOFF;
            self.increase_backoff_time = f64::NEG_INFINITY;
        }
        if let Some(penalty) = penalty
            && penalty.is_finite()
            && penalty > 0.0
        {
            self.penalty = penalty.clamp(INITIAL_PENALTY, MAX_PENALTY);
        }
    }

    pub(crate) fn measure(&mut self, now: f64) -> Option<Measurement> {
        (now > self.failed_until).then(|| Measurement {
            outstanding: self.outstanding.smooth_total(now),
            latency: self.latency,
            penalty: self.penalty,
            depth: Depth {
                in_flight: self.outstanding.total as f32,
                recovered: self.future_version_backoff == FUTURE_VERSION_INITIAL_BACKOFF,
            },
        })
    }
}

impl Completion {
    pub(crate) const fn of_transport(error: &TransportError) -> Completion {
        match error {
            TransportError::Unauthorized => Completion::Response,
            _ => Completion::NoResponse,
        }
    }

    pub(crate) const fn from_error_code(code: ErrorCode) -> Completion {
        match code {
            ErrorCode::BROKEN_PROMISE | ErrorCode::REQUEST_MAYBE_DELIVERED => {
                Completion::NoResponse
            }
            ErrorCode::PROCESS_BEHIND => Completion::ProcessBehind,
            ErrorCode::FUTURE_VERSION => Completion::FutureVersion,
            _ => Completion::Response,
        }
    }
}

impl<R> Replicas<R> {
    pub(crate) fn new(replicas: Box<[R]>, count_best: usize) -> Option<Self> {
        (u32::try_from(replicas.len()).is_ok() && (1..=replicas.len()).contains(&count_best))
            .then_some(Replicas {
                replicas,
                count_best,
            })
    }

    pub(crate) fn as_slice(&self) -> &[R] {
        &self.replicas
    }

    pub(crate) fn choose(&self, measure: impl FnMut(&R) -> Option<Measurement>) -> Attempts<'_, R> {
        self.rank(measure).0
    }

    pub(crate) fn choose_hedged(
        &self,
        measure: impl FnMut(&R) -> Option<Measurement>,
        multiplier: f64,
    ) -> Attempts<'_, R> {
        let (attempts, latencies) = self.rank(measure);
        match latencies.hedge_delay(multiplier) {
            Some(delay) => Attempts {
                hedge: delay as f32,
                ..attempts
            },
            None => attempts,
        }
    }

    fn rank(
        &self,
        mut measure: impl FnMut(&R) -> Option<Measurement>,
    ) -> (Attempts<'_, R>, Latencies) {
        let len = self.replicas.len();
        if len == 1 {
            return (Attempts::new(&self.replicas, 0, 0), Latencies::NONE);
        }
        let mut best_time = NO_METRIC;
        let mut next_time = NO_METRIC;
        let mut best = fastrand::usize(..self.count_best);
        let mut next = fastrand::usize(..len - 1);
        if next >= best {
            next += 1;
        }
        let mut best_metric = NO_METRIC;
        let mut next_metric = NO_METRIC;
        let mut best_depth = Depth::UNMEASURED;
        let mut next_depth = Depth::UNMEASURED;
        let mut bad = 0;
        for (i, replica) in self.replicas.iter().enumerate() {
            if i == self.count_best && bad < i.min(LOAD_BALANCE_MAX_BAD_OPTIONS + 1) {
                break;
            }
            let Some(measurement) = measure(replica) else {
                bad += 1;
                continue;
            };
            if measurement.penalty > BAD_PENALTY {
                bad += 1;
            }
            if measurement.outstanding < best_metric {
                if i != best {
                    next = best;
                    next_metric = best_metric;
                    next_time = best_time;
                    next_depth = best_depth;
                }
                best = i;
                best_metric = measurement.outstanding;
                best_time = measurement.latency;
                best_depth = measurement.depth;
            } else if measurement.outstanding < next_metric {
                next = i;
                next_metric = measurement.outstanding;
                next_time = measurement.latency;
                next_depth = measurement.depth;
            }
        }
        if next_metric > NO_METRIC_THRESHOLD {
            for (i, replica) in self.replicas.iter().enumerate().skip(self.count_best) {
                if let Some(measurement) = measure(replica)
                    && measurement.outstanding < next_metric
                {
                    next = i;
                    next_metric = measurement.outstanding;
                    next_time = measurement.latency;
                    next_depth = measurement.depth;
                }
            }
        }
        if next < self.count_best && best_depth.spills_to(next_depth) {
            (best, next) = (next, best);
            (best_time, next_time) = (next_time, best_time);
        }
        (
            Attempts::new(&self.replicas, best, next),
            Latencies {
                best: best_time,
                next: next_time,
            },
        )
    }
}

impl Depth {
    const UNMEASURED: Depth = Depth {
        in_flight: f32::INFINITY,
        recovered: false,
    };

    fn spills_to(self, next: Depth) -> bool {
        self.in_flight >= SPILL_DEPTH && next.recovered && next.in_flight < self.in_flight
    }
}

impl<'a, R> Attempts<'a, R> {
    const fn new(replicas: &'a [R], best: usize, next: usize) -> Self {
        Attempts {
            replicas,
            best: best as u32,
            next: next as u32,
            offset: 0,
            failures: 0,
            backoff: 0.0,
            hedge: NO_HEDGE,
            tried_all: false,
        }
    }

    fn position(&self) -> usize {
        let len = self.replicas.len();
        let (best, next, offset) = (self.best as usize, self.next as usize, self.offset as usize);
        let distance = (best + len - next) % len;
        if offset == 0 {
            best
        } else if offset <= distance {
            (next + offset - 1) % len
        } else {
            (next + offset) % len
        }
    }

    pub(crate) fn advance(&mut self) {
        self.offset += 1;
        if self.offset as usize == self.replicas.len() {
            self.offset = 0;
            self.tried_all = true;
        }
    }

    pub(crate) fn select(
        &mut self,
        mut healthy: impl FnMut(&R) -> bool,
    ) -> Option<Selected<'a, R>> {
        let hedge = mem::replace(&mut self.hedge, NO_HEDGE);
        for _ in 0..self.replicas.len() {
            let index = self.position();
            let replica = &self.replicas[index];
            if healthy(replica) {
                return Some(Selected {
                    replica,
                    index,
                    backoff: self.backoff,
                    tried_all: self.tried_all,
                    hedge: hedge.is_finite().then_some(f64::from(hedge)),
                });
            }
            self.advance();
        }
        None
    }

    pub(crate) fn failed(&mut self) {
        self.failures += 1;
        if self.failures as usize >= self.replicas.len() {
            self.backoff = (self.backoff * LOAD_BALANCE_BACKOFF_RATE)
                .clamp(LOAD_BALANCE_START_BACKOFF, LOAD_BALANCE_MAX_BACKOFF);
        }
        self.advance();
    }

    pub(crate) fn recovered(&mut self) {
        self.failures = 0;
        self.advance();
    }
}

impl Latencies {
    const NONE: Latencies = Latencies {
        best: NO_METRIC,
        next: NO_METRIC,
    };

    fn hedge_delay(&self, multiplier: f64) -> Option<f64> {
        (self.next < NO_METRIC).then(|| {
            let delay = multiplier * self.next + BASE_SECOND_REQUEST_TIME;
            if self.best > INSTANT_SECOND_REQUEST_MULTIPLIER * delay {
                0.0
            } else {
                delay
            }
        })
    }
}

impl Hedging {
    pub(crate) const fn new() -> Self {
        Hedging {
            budget: AtomicI32::new(0),
            multiplier: AtomicI32::new(0),
        }
    }

    pub(crate) fn lone_reply(&self) {
        if self.budget.load(Ordering::Relaxed) < SECOND_REQUEST_MAX_BUDGET {
            self.budget.fetch_add(1, Ordering::Relaxed);
        }
        if self.multiplier.load(Ordering::Relaxed) > 0 {
            self.multiplier.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn try_hedge(&self) -> bool {
        let mut budget = self.budget.load(Ordering::Relaxed);
        loop {
            let available = budget.min(SECOND_REQUEST_MAX_BUDGET);
            if available < SECOND_REQUEST_COST {
                return false;
            }
            match self.budget.compare_exchange_weak(
                budget,
                available - SECOND_REQUEST_COST,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    if self.multiplier.load(Ordering::Relaxed) < SECOND_REQUEST_MAX_MULTIPLIER {
                        self.multiplier
                            .fetch_add(SECOND_REQUEST_MULTIPLIER_GROWTH, Ordering::Relaxed);
                    }
                    return true;
                }
                Err(current) => budget = current,
            }
        }
    }

    pub(crate) fn multiplier(&self) -> f64 {
        1.0 + f64::from(self.multiplier.load(Ordering::Relaxed).max(0))
            * SECOND_REQUEST_MULTIPLIER_UNIT
    }
}

impl AlternativesFailed {
    pub(crate) const fn new() -> Self {
        AlternativesFailed {
            oldest: f64::NEG_INFINITY,
            newest: f64::NEG_INFINITY,
            last_skip: f64::NEG_INFINITY,
        }
    }

    pub(crate) fn delay(&mut self, now: f64) -> f64 {
        if now - self.newest > ALTERNATIVES_FAILURE_RESET_TIME {
            self.oldest = now;
        }
        let mut delay = ALTERNATIVES_FAILURE_MIN_DELAY;
        if now - self.last_skip > ALTERNATIVES_FAILURE_SKIP_DELAY {
            self.last_skip = now;
        } else {
            let elapsed = now - self.oldest;
            delay = delay
                .max(
                    (elapsed * ALTERNATIVES_FAILURE_DELAY_RATIO)
                        .min(ALTERNATIVES_FAILURE_MAX_DELAY),
                )
                .max(
                    (elapsed * ALTERNATIVES_FAILURE_SLOW_DELAY_RATIO)
                        .min(ALTERNATIVES_FAILURE_SLOW_MAX_DELAY),
                );
        }
        self.newest = now;
        delay * (DELAY_JITTER_OFFSET + DELAY_JITTER_RANGE * fastrand::f64())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/balance/tests.rs"]
mod tests;

#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/balance/test_support.rs"]
mod test_support;
