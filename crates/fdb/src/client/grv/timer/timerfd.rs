/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rustix::{
    io::read,
    time::{
        Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec, timerfd_create,
        timerfd_settime,
    },
};
use std::{future::pending, io, os::fd::OwnedFd, time::Duration};
use tokio::io::{Interest, unix::AsyncFd};

pub(crate) struct WindowTimer(Option<AsyncFd<OwnedFd>>);

impl WindowTimer {
    pub(crate) fn new() -> Self {
        let Ok(fd) = timerfd_create(
            TimerfdClockId::Monotonic,
            TimerfdFlags::NONBLOCK | TimerfdFlags::CLOEXEC,
        ) else {
            return WindowTimer(None);
        };
        WindowTimer(unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }.ok())
    }

    pub(crate) fn is_available(&self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn arm(&self, after: Duration) -> bool {
        let Some(fd) = &self.0 else {
            return false;
        };
        let nanos = after.subsec_nanos().max(1);
        let value = Itimerspec {
            it_interval: Timespec::default(),
            it_value: Timespec {
                tv_sec: i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: nanos.into(),
            },
        };
        timerfd_settime(fd.get_ref(), TimerfdTimerFlags::empty(), &value).is_ok()
    }

    pub(crate) fn disarm(&self) {
        if let Some(fd) = &self.0 {
            let _ = timerfd_settime(
                fd.get_ref(),
                TimerfdTimerFlags::empty(),
                &Itimerspec {
                    it_interval: Timespec::default(),
                    it_value: Timespec::default(),
                },
            );
        }
    }

    pub(crate) async fn expired(&self) {
        let Some(fd) = &self.0 else {
            return pending().await;
        };
        let mut expirations = [0u8; 8];
        loop {
            let Ok(mut ready) = fd.readable().await else {
                return;
            };
            if ready
                .try_io(|fd| read(fd.get_ref(), &mut expirations).map_err(io::Error::from))
                .is_ok()
            {
                return;
            }
        }
    }
}
