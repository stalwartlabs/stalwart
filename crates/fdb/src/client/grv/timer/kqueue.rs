/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(target_os = "macos")]
use libc::NOTE_CRITICAL;
use libc::{
    EV_ADD, EV_DELETE, EV_ONESHOT, EV_RECEIPT, EVFILT_TIMER, F_SETFD, FD_CLOEXEC, NOTE_NSECONDS,
    c_int, fcntl, kevent, kqueue, timespec,
};
use std::{
    future::pending,
    io,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};
use tokio::io::{Interest, unix::AsyncFd};

#[cfg(target_os = "macos")]
const TIMER_FLAGS: u32 = NOTE_NSECONDS | NOTE_CRITICAL;
#[cfg(not(target_os = "macos"))]
const TIMER_FLAGS: u32 = NOTE_NSECONDS;
const TIMER_IDENT: usize = 0;
const NO_WAIT: timespec = timespec {
    tv_sec: 0,
    tv_nsec: 0,
};

pub(crate) struct WindowTimer(Option<AsyncFd<OwnedFd>>);

impl WindowTimer {
    pub(crate) fn new() -> Self {
        let raw = unsafe { kqueue() };
        if raw < 0 {
            return WindowTimer(None);
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { fcntl(raw, F_SETFD, FD_CLOEXEC) } != 0 {
            return WindowTimer(None);
        }
        WindowTimer(unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }.ok())
    }

    pub(crate) fn is_available(&self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn arm(&self, after: Duration) -> bool {
        let Some(fd) = &self.0 else {
            return false;
        };
        let mut add = timer_change(EV_ADD | EV_ONESHOT | EV_RECEIPT);
        let Ok(nanos) = after.as_nanos().max(1).try_into() else {
            return false;
        };
        add.data = nanos;
        let changes = [timer_change(EV_DELETE | EV_RECEIPT), add];
        let mut receipts = [zeroed_event(); 2];
        let [_, added] = match submit(fd.get_ref(), &changes, &mut receipts) {
            Ok(2) => receipts,
            _ => return false,
        };
        added.data == 0
    }

    pub(crate) fn disarm(&self) {
        if let Some(fd) = &self.0 {
            let mut receipt = [zeroed_event()];
            let _ = submit(
                fd.get_ref(),
                &[timer_change(EV_DELETE | EV_RECEIPT)],
                &mut receipt,
            );
        }
    }

    pub(crate) async fn expired(&self) {
        let Some(fd) = &self.0 else {
            return pending().await;
        };
        loop {
            let Ok(mut ready) = fd.readable().await else {
                return;
            };
            if ready
                .try_io(
                    |fd| match submit(fd.get_ref(), &[], &mut [zeroed_event()])? {
                        0 => Err(io::ErrorKind::WouldBlock.into()),
                        _ => Ok(()),
                    },
                )
                .is_ok()
            {
                return;
            }
        }
    }
}

fn zeroed_event() -> kevent {
    unsafe { MaybeUninit::<kevent>::zeroed().assume_init() }
}

fn timer_change(flags: u16) -> kevent {
    let mut change = zeroed_event();
    change.ident = TIMER_IDENT;
    change.filter = EVFILT_TIMER;
    change.flags = flags;
    change.fflags = TIMER_FLAGS;
    change
}

fn submit(fd: &OwnedFd, changes: &[kevent], events: &mut [kevent]) -> io::Result<usize> {
    let too_many = |_| io::Error::from(io::ErrorKind::InvalidInput);
    let nchanges = c_int::try_from(changes.len()).map_err(too_many)?;
    let nevents = c_int::try_from(events.len()).map_err(too_many)?;
    let applied = unsafe {
        kevent(
            fd.as_raw_fd(),
            changes.as_ptr(),
            nchanges,
            events.as_mut_ptr(),
            nevents,
            &NO_WAIT,
        )
    };
    usize::try_from(applied).map_err(|_| io::Error::last_os_error())
}
