/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::peer::PeerShared;
use crate::client::grv::timer::WindowTimer;
use std::{
    future::poll_fn,
    time::{Duration, Instant},
};
use tokio::select;

const WINDOW: Duration = Duration::from_micros(50);
const OVERSHOOT: Duration = Duration::from_micros(200);
const MAX_OVERSHOOTS: u32 = 2;
const SPLIT_ONE: u32 = 1 << 16;
const SPLIT_SHIFT: u32 = 4;
const ARM_AT: u32 = SPLIT_ONE / 8;
const DISARM_BELOW: u32 = SPLIT_ONE / 16;
const SHARE_WINDOW: u8 = 16;
const MAX_TIMEOUTS: u32 = 8;
const REST_BURSTS: u32 = 1024;
const MAX_REST_SHIFT: u8 = 6;
const YIELD_PROBE_LOOPS: u8 = 16;
const YIELD_DEPTH: u64 = 2;
pub(crate) const FLOOR_GATE_US: u32 = 4 * WINDOW.as_micros() as u32;

const _: () = assert!(SHARE_WINDOW as u32 == u16::BITS);
const _: () = assert!(YIELD_PROBE_LOOPS.is_power_of_two());

#[derive(Default)]
pub(crate) struct BurstHold {
    timer: HoldTimer,
    expected: u64,
    split: u32,
    armed: bool,
    overshoots: u16,
    share: TimeoutShare,
    open: Option<OpenBurst>,
    yields: YieldGate,
    #[cfg(all(test, stalwart_tests))]
    stats: BurstStats,
}

struct YieldGate {
    gains: u16,
    loops: u8,
}

#[derive(Default)]
pub(super) struct TimeoutShare {
    timeouts: u16,
    held: u8,
    trips: u8,
    rest: u32,
}

#[derive(Default)]
enum HoldTimer {
    #[default]
    Unused,
    Ready(WindowTimer),
    Off,
}

struct OpenBurst {
    lead: Instant,
    received: u64,
    frames: u64,
    late: u64,
    split: bool,
    capped: bool,
}

pub(crate) enum Take {
    Joins,
    Leads { at: Instant, hold: Hold },
}

pub(crate) enum Hold {
    None,
    Caught { queued: u64 },
    TimedOut { queued: u64 },
}

#[cfg(all(test, stalwart_tests))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BurstStats {
    pub bursts: u64,
    pub split: u64,
    pub joins: u64,
    pub holds: u64,
    pub caught: u64,
    pub timeouts: u64,
    pub armed: bool,
    pub off: bool,
    pub resting: bool,
    pub expected: u64,
    pub gated: u64,
    pub floor_us: u32,
    pub yields: u32,
    pub yield_skips: u32,
}

impl BurstHold {
    pub(crate) fn admits_yield(&mut self, depth: u64) -> bool {
        let admits = self.yields.admits(depth);
        #[cfg(all(test, stalwart_tests))]
        {
            self.stats.yields += u32::from(admits);
            self.stats.yield_skips += u32::from(!admits);
        }
        admits
    }

    pub(crate) fn record_yield(&mut self, take: Option<&Take>, arrived: u64) {
        if !take.is_some_and(Take::held) {
            self.yields.record(arrived > 0);
        }
    }

    pub(crate) fn gated(&mut self, floor_us: u32) -> bool {
        if floor_us >= FLOOR_GATE_US {
            return false;
        }
        self.open = None;
        self.split = 0;
        self.armed = false;
        #[cfg(all(test, stalwart_tests))]
        {
            self.stats.gated += 1;
        }
        true
    }

    pub(crate) async fn prepare(&mut self, peer: &PeerShared, taken: u64, queued: u64) -> Take {
        let now = Instant::now();
        let received = peer.frames_received();
        if self.open.as_ref().is_some_and(|open| {
            open.received == received && now.duration_since(open.lead) <= WINDOW
        }) {
            return Take::Joins;
        }
        if let Some(open) = self.open.take() {
            self.close(open);
        }
        if !self.armed
            || matches!(self.timer, HoldTimer::Off)
            || self.share.resting()
            || queued.wrapping_sub(taken) >= self.expected
        {
            return Take::Leads {
                at: now,
                hold: Hold::None,
            };
        }
        let hold = self.hold(peer, taken).await;
        let at = match hold {
            Hold::None => now,
            Hold::Caught { .. } => Instant::now(),
            Hold::TimedOut { .. } => {
                let at = Instant::now();
                self.timed_out(at.duration_since(now));
                at
            }
        };
        Take::Leads { at, hold }
    }

    pub(super) fn timed_out(&mut self, held: Duration) {
        self.overshoots = self.overshoots << 1 | u16::from(held >= OVERSHOOT);
        if self.overshoots.count_ones() >= MAX_OVERSHOOTS {
            self.timer = HoldTimer::Off;
        }
    }

    pub(crate) fn record(&mut self, take: Take, frames: u64, received: u64) {
        match take {
            Take::Joins => {
                if let Some(open) = &mut self.open {
                    open.late += frames;
                    open.split = true;
                }
                #[cfg(all(test, stalwart_tests))]
                {
                    self.stats.joins += 1;
                }
            }
            Take::Leads { at, hold } => {
                let (split, capped) = match hold {
                    Hold::None => (false, false),
                    Hold::Caught { queued } => {
                        self.share.settle(false);
                        (frames > queued, false)
                    }
                    Hold::TimedOut { queued } => {
                        self.share.settle(true);
                        (frames > queued, true)
                    }
                };
                #[cfg(all(test, stalwart_tests))]
                {
                    let held = !matches!(hold, Hold::None);
                    self.stats.holds += u64::from(held);
                    self.stats.caught += u64::from(held && !capped);
                    self.stats.timeouts += u64::from(capped);
                }
                self.open = Some(OpenBurst {
                    lead: at,
                    received,
                    frames,
                    late: 0,
                    split,
                    capped,
                });
            }
        }
    }

    async fn hold(&mut self, peer: &PeerShared, taken: u64) -> Hold {
        let expected = self.expected;
        let queued = peer.queued_frames().wrapping_sub(taken);
        if queued >= expected {
            return Hold::None;
        }
        if matches!(self.timer, HoldTimer::Unused) {
            self.timer = HoldTimer::Ready(WindowTimer::new());
        }
        let HoldTimer::Ready(timer) = &self.timer else {
            return Hold::None;
        };
        if !timer.arm(WINDOW) {
            self.timer = HoldTimer::Off;
            return Hold::None;
        }
        let caught = select! {
            biased;
            () = poll_fn(|cx| peer.poll_frames(cx, taken, expected)) => true,
            () = timer.expired() => false,
        };
        if caught {
            timer.disarm();
            Hold::Caught { queued }
        } else {
            Hold::TimedOut { queued }
        }
    }

    fn close(&mut self, open: OpenBurst) {
        self.expected = if open.capped {
            open.frames
        } else {
            open.frames + open.late
        };
        self.split = self.split - (self.split >> SPLIT_SHIFT)
            + if open.split {
                SPLIT_ONE >> SPLIT_SHIFT
            } else {
                0
            };
        self.armed = self.split >= if self.armed { DISARM_BELOW } else { ARM_AT };
        self.share.spend_burst();
        #[cfg(all(test, stalwart_tests))]
        {
            self.stats.bursts += 1;
            self.stats.split += u64::from(open.split);
        }
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn stats(&self) -> BurstStats {
        BurstStats {
            armed: self.armed,
            off: matches!(self.timer, HoldTimer::Off),
            resting: self.share.resting(),
            expected: self.expected,
            ..self.stats
        }
    }
}

impl Take {
    fn held(&self) -> bool {
        matches!(
            self,
            Take::Leads {
                hold: Hold::Caught { .. } | Hold::TimedOut { .. },
                ..
            }
        )
    }
}

impl Default for YieldGate {
    fn default() -> Self {
        Self {
            gains: u16::MAX,
            loops: 0,
        }
    }
}

impl YieldGate {
    fn admits(&mut self, depth: u64) -> bool {
        let probe = self.loops.is_multiple_of(YIELD_PROBE_LOOPS);
        self.loops = self.loops.wrapping_add(1);
        self.gains != 0 || depth >= YIELD_DEPTH || probe
    }

    fn record(&mut self, gained: bool) {
        self.gains = self.gains << 1 | u16::from(gained);
    }
}

impl TimeoutShare {
    pub(super) fn settle(&mut self, timed_out: bool) {
        self.timeouts = self.timeouts << 1 | u16::from(timed_out);
        if self.timeouts.count_ones() >= MAX_TIMEOUTS {
            self.rest = REST_BURSTS << self.trips;
            self.trips = (self.trips + 1).min(MAX_REST_SHIFT);
            self.timeouts = 0;
            self.held = 0;
        } else if self.held < SHARE_WINDOW {
            self.held += 1;
            if self.held == SHARE_WINDOW {
                self.trips = 0;
            }
        }
    }

    pub(super) fn resting(&self) -> bool {
        self.rest > 0
    }

    pub(super) fn spend_burst(&mut self) {
        self.rest = self.rest.saturating_sub(1);
    }
}
