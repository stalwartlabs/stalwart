/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use windows_sys::Win32::Media::{TIMERR_NOERROR, timeBeginPeriod, timeEndPeriod};

const PERIOD_MS: u32 = 1;

pub(crate) struct TimerResolution(());

impl TimerResolution {
    pub(crate) fn raise() -> Option<Self> {
        (unsafe { timeBeginPeriod(PERIOD_MS) } == TIMERR_NOERROR).then_some(TimerResolution(()))
    }
}

impl Drop for TimerResolution {
    fn drop(&mut self) {
        unsafe { timeEndPeriod(PERIOD_MS) };
    }
}
