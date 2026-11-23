/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
mod kqueue;
#[cfg(windows)]
mod resolution;
#[cfg(target_os = "linux")]
mod timerfd;

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub(crate) use kqueue::WindowTimer;
#[cfg(windows)]
pub(crate) use resolution::TimerResolution;
#[cfg(not(fine_timer))]
use std::{future::pending, time::Duration};
#[cfg(target_os = "linux")]
pub(crate) use timerfd::WindowTimer;

#[cfg(not(fine_timer))]
pub(crate) struct WindowTimer;

#[cfg(not(fine_timer))]
impl WindowTimer {
    pub(crate) fn new() -> Self {
        WindowTimer
    }

    pub(crate) fn is_available(&self) -> bool {
        false
    }

    pub(crate) fn arm(&self, _after: Duration) -> bool {
        false
    }

    pub(crate) fn disarm(&self) {}

    pub(crate) async fn expired(&self) {
        pending().await
    }
}
