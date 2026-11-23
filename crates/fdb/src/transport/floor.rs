/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::slots::{SlotKey, Slots};
use std::time::Instant;

const EPOCH_SAMPLES: u8 = 8;
const OVERTAKES: u32 = 8;

pub(crate) struct ReplyFloor {
    probe: Probe,
    epoch_min: u32,
    previous_min: u32,
    samples: u8,
}

#[derive(Clone, Copy)]
enum Probe {
    Off,
    Idle,
    Active {
        key: SlotKey,
        sent: Instant,
        others_left: u32,
    },
}

impl ReplyFloor {
    pub(crate) const fn off() -> Self {
        Self::with(Probe::Off)
    }

    pub(crate) const fn probing() -> Self {
        Self::with(Probe::Idle)
    }

    const fn with(probe: Probe) -> Self {
        Self {
            probe,
            epoch_min: u32::MAX,
            previous_min: 0,
            samples: 0,
        }
    }

    pub(crate) fn admitted(&mut self, key: SlotKey, slots: &Slots, now: impl FnOnce() -> Instant) {
        match self.probe {
            Probe::Off => {}
            Probe::Active { key: active, .. } if slots.is_waiting(active) => {}
            Probe::Idle | Probe::Active { .. } => {
                let ahead = u32::try_from(slots.waiting().saturating_sub(1)).unwrap_or(u32::MAX);
                self.probe = Probe::Active {
                    key,
                    sent: now(),
                    others_left: ahead.saturating_add(OVERTAKES),
                };
            }
        }
    }

    pub(crate) fn replied(
        &mut self,
        token_second: u64,
        now: impl FnOnce() -> Instant,
    ) -> Option<u32> {
        let Probe::Active {
            key,
            sent,
            others_left,
        } = &mut self.probe
        else {
            return None;
        };
        if key.token_second() != token_second {
            *others_left -= 1;
            if *others_left == 0 {
                self.probe = Probe::Idle;
            }
            return None;
        }
        let sent = *sent;
        self.probe = Probe::Idle;
        let sample =
            u32::try_from(now().saturating_duration_since(sent).as_micros()).unwrap_or(u32::MAX);
        self.epoch_min = self.epoch_min.min(sample);
        self.samples += 1;
        if self.samples == EPOCH_SAMPLES {
            self.previous_min = self.epoch_min;
            self.epoch_min = u32::MAX;
            self.samples = 0;
        }
        Some(self.previous_min.min(self.epoch_min))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/transport/floor/tests.rs"]
mod tests;
