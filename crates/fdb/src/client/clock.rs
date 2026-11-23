/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(crate) struct Clock {
    base: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Deadline(f64);

impl Clock {
    pub(crate) fn new() -> Self {
        Clock {
            base: Instant::now(),
        }
    }

    pub(crate) fn now(&self) -> f64 {
        self.base.elapsed().as_secs_f64()
    }

    pub(crate) fn deadline(&self, at: Option<Instant>) -> Deadline {
        at.map_or(Deadline::NONE, |at| {
            Deadline(at.saturating_duration_since(self.base).as_secs_f64())
        })
    }

    pub(crate) fn instant(&self, deadline: Deadline) -> Option<Instant> {
        let offset = Duration::try_from_secs_f64(deadline.0).ok()?;
        self.base.checked_add(offset)
    }
}

impl Deadline {
    pub(crate) const NONE: Deadline = Deadline(f64::INFINITY);

    pub(crate) const fn at(secs: f64) -> Self {
        Deadline(secs)
    }
}
