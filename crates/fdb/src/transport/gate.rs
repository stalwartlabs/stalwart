/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    config::FirstRead,
    frame::{self, Framing},
    reader::ReceiveBuffer,
};
#[cfg(target_os = "linux")]
use crate::client::grv::timer::WindowTimer;
#[cfg(target_os = "linux")]
use std::num::NonZeroUsize;
use std::{
    future::{Future, ready},
    io,
};
use tokio::{io::ReadHalf, net::tcp::OwnedReadHalf};

pub(crate) const GATE_FULL: usize = 56 << 10;
const ARM_READS: u32 = 64;
#[cfg(target_os = "linux")]
const MAX_TIMEOUTS: u32 = 4;

pub(crate) enum Gated {
    Pass,
    #[cfg_attr(not(target_os = "linux"), expect(dead_code))]
    Read(usize),
}

enum Arming {
    Off,
    Cold,
    Warm { reads_left: u32 },
}

#[cfg(target_os = "linux")]
enum Window {
    Closed,
    Open {
        mss: NonZeroUsize,
        max_queued: usize,
    },
}

pub(crate) struct FirstReadGate {
    arming: Arming,
    #[cfg(target_os = "linux")]
    timeouts: u16,
    #[cfg(target_os = "linux")]
    timer: Option<WindowTimer>,
    #[cfg(target_os = "linux")]
    window: Window,
    #[cfg(target_os = "linux")]
    recheck_in: u32,
    #[cfg(all(test, stalwart_tests))]
    stats: GateStats,
}

#[cfg(all(test, stalwart_tests))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateStats {
    pub probes: u64,
    pub queue_reads: u32,
    pub unaligned: u64,
    pub waits: u64,
    pub timeouts: u64,
    pub disabled: bool,
}

impl FirstReadGate {
    pub(crate) fn new(mode: FirstRead, framing: Framing) -> Self {
        let arming = match (mode, framing) {
            (FirstRead::Gated, Framing::Checksum) => Arming::Cold,
            _ => Arming::Off,
        };
        Self {
            arming,
            #[cfg(target_os = "linux")]
            timeouts: 0,
            #[cfg(target_os = "linux")]
            timer: None,
            #[cfg(target_os = "linux")]
            window: Window::Closed,
            #[cfg(target_os = "linux")]
            recheck_in: 0,
            #[cfg(all(test, stalwart_tests))]
            stats: GateStats::default(),
        }
    }

    pub(crate) fn is_armed(&self) -> bool {
        matches!(self.arming, Arming::Warm { .. })
    }

    pub(crate) fn observe_read(&mut self, buf: &[u8], framing: Framing) {
        if matches!(self.arming, Arming::Off) {
            return;
        }
        if frame::pending_frame_len(buf, framing).is_some_and(|len| len >= GATE_FULL) {
            self.arming = Arming::Warm {
                reads_left: ARM_READS,
            };
            #[cfg(target_os = "linux")]
            {
                self.recheck_in = self.recheck_in.saturating_sub(1);
            }
        } else if let Arming::Warm { reads_left } = &mut self.arming {
            *reads_left -= 1;
            if *reads_left == 0 {
                self.arming = Arming::Cold;
            }
        }
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn stats(&self) -> GateStats {
        self.stats
    }
}

#[cfg(target_os = "linux")]
impl FirstReadGate {
    fn record(&mut self, grew: bool) {
        self.timeouts = self.timeouts << 1 | u16::from(!grew);
        #[cfg(all(test, stalwart_tests))]
        {
            self.stats.waits += 1;
            self.stats.timeouts += u64::from(!grew);
        }
        if self.timeouts.count_ones() >= MAX_TIMEOUTS {
            self.disable();
        }
    }

    fn disable(&mut self) {
        self.arming = Arming::Off;
        self.timer = None;
        #[cfg(all(test, stalwart_tests))]
        {
            self.stats.disabled = true;
        }
    }
}

pub(crate) trait ReadGate {
    fn gate(
        &mut self,
        gate: &mut FirstReadGate,
        buf: &mut ReceiveBuffer,
    ) -> impl Future<Output = io::Result<Gated>> + Send;

    fn reset_low_water(&self) -> io::Result<()> {
        Ok(())
    }
}

impl<T> ReadGate for ReadHalf<T> {
    fn gate(
        &mut self,
        _: &mut FirstReadGate,
        _: &mut ReceiveBuffer,
    ) -> impl Future<Output = io::Result<Gated>> + Send {
        ready(Ok(Gated::Pass))
    }
}

#[cfg(not(target_os = "linux"))]
impl ReadGate for OwnedReadHalf {
    fn gate(
        &mut self,
        _: &mut FirstReadGate,
        _: &mut ReceiveBuffer,
    ) -> impl Future<Output = io::Result<Gated>> + Send {
        ready(Ok(Gated::Pass))
    }
}

#[cfg(target_os = "linux")]
impl ReadGate for OwnedReadHalf {
    fn gate(
        &mut self,
        gate: &mut FirstReadGate,
        buf: &mut ReceiveBuffer,
    ) -> impl Future<Output = io::Result<Gated>> + Send {
        linux::gate(OwnedReadHalf::as_ref(self), gate, buf)
    }

    fn reset_low_water(&self) -> io::Result<()> {
        linux::reset_low_water(OwnedReadHalf::as_ref(self))
    }
}

#[cfg(target_os = "linux")]
impl FirstRead {
    pub(crate) fn supported(self) -> Self {
        if linux::kernel_supported() {
            self
        } else {
            FirstRead::Immediate
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl FirstRead {
    pub(crate) fn supported(self) -> Self {
        FirstRead::Immediate
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{FirstReadGate, GATE_FULL, Gated, ReceiveBuffer, Window};
    use crate::transport::reader::QUEUED_READ_CAP;
    use bytes::BytesMut;
    use libc::{
        IPPROTO_TCP, MSG_DONTWAIT, SO_RCVBUF, SO_RCVLOWAT, SOL_SOCKET, TCP_INFO, c_int, getsockopt,
        recv, setsockopt, socklen_t, tcp_info,
    };
    use rustix::{io::ioctl_fionread, system::uname};
    use std::{
        future::poll_fn,
        io,
        mem::{MaybeUninit, offset_of},
        num::NonZeroUsize,
        os::fd::{AsFd, AsRawFd, BorrowedFd},
        time::Duration,
    };
    use tokio::{io::Interest, net::TcpStream, select};

    const GATE_WAIT: Duration = Duration::from_micros(100);
    const WINDOW_FACTOR: usize = 4;
    const WINDOW_RECHECK: u32 = 64;
    const MIN_KERNEL: (u32, u32) = (4, 18);
    const C_INT_LEN: socklen_t = size_of::<c_int>() as socklen_t;
    const TCP_INFO_LEN: socklen_t = size_of::<tcp_info>() as socklen_t;
    const RCV_MSS_END: socklen_t =
        (offset_of!(tcp_info, tcpi_rcv_mss) + size_of::<u32>()) as socklen_t;

    pub(super) async fn gate(
        stream: &TcpStream,
        gate: &mut FirstReadGate,
        buf: &mut ReceiveBuffer,
    ) -> io::Result<Gated> {
        let mut stale = true;
        let queued = loop {
            poll_fn(|cx| stream.poll_read_ready(cx)).await?;
            match stream.try_io(Interest::READABLE, || {
                #[cfg(all(test, stalwart_tests))]
                {
                    gate.stats.queue_reads += 1;
                }
                queued_or_block(stream.as_fd())
            }) {
                Ok(queued) => break queued,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock && stale => stale = false,
                Err(_) => return Ok(Gated::Pass),
            }
        };
        #[cfg(all(test, stalwart_tests))]
        {
            gate.stats.probes += 1;
        }
        if queued < GATE_FULL {
            return Ok(Gated::Pass);
        }
        let wait = match open_window(gate, stream.as_fd()) {
            Some((mss, max_queued)) if queued <= max_queued => {
                let aligned = queued % mss == 0;
                #[cfg(all(test, stalwart_tests))]
                {
                    gate.stats.unaligned += u64::from(!aligned);
                }
                aligned
            }
            _ => false,
        };
        if wait {
            Box::pin(wait_for_tail(stream, gate, buf, queued)).await
        } else {
            buf.reserve_queued(queued);
            Ok(Gated::Pass)
        }
    }

    async fn wait_for_tail(
        stream: &TcpStream,
        gate: &mut FirstReadGate,
        buf: &mut ReceiveBuffer,
        queued: usize,
    ) -> io::Result<Gated> {
        let _ = stream.try_io(Interest::READABLE, || {
            Err::<(), _>(io::Error::from(io::ErrorKind::WouldBlock))
        });
        if set_rcvlowat(stream.as_fd(), queued.saturating_add(1)).is_err() {
            gate.disable();
            return Ok(Gated::Pass);
        }
        let timer = gate.timer.get_or_insert_with(super::WindowTimer::new);
        if !timer.arm(GATE_WAIT) {
            set_rcvlowat(stream.as_fd(), 1)?;
            gate.disable();
            return Ok(Gated::Pass);
        }
        let grew = select! {
            biased;
            readable = stream.readable() => readable.is_ok(),
            () = timer.expired() => false,
        };
        if grew {
            timer.disarm();
        }
        buf.reserve_queued(QUEUED_READ_CAP);
        let read = if grew {
            recv_draining(stream, &mut buf.bytes)
        } else {
            recv_queued(stream.as_fd(), &mut buf.bytes)
        };
        gate.record(grew);
        match read {
            Ok(read) => Ok(Gated::Read(read)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                set_rcvlowat(stream.as_fd(), 1)?;
                Ok(Gated::Pass)
            }
            Err(err) => Err(err),
        }
    }

    pub(super) fn reset_low_water(stream: &TcpStream) -> io::Result<()> {
        set_rcvlowat(stream.as_fd(), 1)
    }

    fn recv_draining(stream: &TcpStream, bytes: &mut BytesMut) -> io::Result<usize> {
        let mut read = None;
        let result = stream.try_io(Interest::READABLE, || {
            let spare = bytes.spare_capacity_mut().len();
            let received = recv_queued(stream.as_fd(), bytes)?;
            read = Some(received);
            if received < spare {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(())
            }
        });
        if let Some(read) = read {
            return Ok(read);
        }
        match result {
            Err(err) if err.kind() != io::ErrorKind::WouldBlock => Err(err),
            _ => recv_queued(stream.as_fd(), bytes),
        }
    }

    fn recv_queued(fd: BorrowedFd<'_>, bytes: &mut BytesMut) -> io::Result<usize> {
        let spare = bytes.spare_capacity_mut();
        let result = unsafe {
            recv(
                fd.as_raw_fd(),
                spare.as_mut_ptr().cast(),
                spare.len(),
                MSG_DONTWAIT,
            )
        };
        let read = usize::try_from(result).map_err(|_| io::Error::last_os_error())?;
        unsafe { bytes.set_len(bytes.len() + read) };
        Ok(read)
    }

    fn open_window(gate: &mut FirstReadGate, fd: BorrowedFd<'_>) -> Option<(NonZeroUsize, usize)> {
        if gate.recheck_in == 0 {
            gate.recheck_in = WINDOW_RECHECK;
            match int_option(fd, SOL_SOCKET, SO_RCVBUF) {
                Some(rcvbuf) if rcvbuf >= WINDOW_FACTOR * GATE_FULL => {
                    let Some(mss) = receive_mss(fd) else {
                        gate.disable();
                        return None;
                    };
                    gate.window = Window::Open {
                        mss,
                        max_queued: rcvbuf / WINDOW_FACTOR,
                    };
                }
                _ => {}
            }
        }
        match gate.window {
            Window::Open { mss, max_queued } => Some((mss, max_queued)),
            Window::Closed => None,
        }
    }

    fn receive_mss(fd: BorrowedFd<'_>) -> Option<NonZeroUsize> {
        let mut info = MaybeUninit::<tcp_info>::zeroed();
        let mut len = TCP_INFO_LEN;
        let result = unsafe {
            getsockopt(
                fd.as_raw_fd(),
                IPPROTO_TCP,
                TCP_INFO,
                info.as_mut_ptr().cast(),
                &raw mut len,
            )
        };
        if result != 0 || len < RCV_MSS_END {
            return None;
        }
        let mss = unsafe { info.assume_init() }.tcpi_rcv_mss;
        NonZeroUsize::new(usize::try_from(mss).ok()?)
    }

    fn inq(fd: BorrowedFd<'_>) -> io::Result<usize> {
        let queued = ioctl_fionread(fd)?;
        Ok(usize::try_from(queued).unwrap_or(usize::MAX))
    }

    fn queued_or_block(fd: BorrowedFd<'_>) -> io::Result<usize> {
        match inq(fd)? {
            0 => Err(io::ErrorKind::WouldBlock.into()),
            queued => Ok(queued),
        }
    }

    fn set_rcvlowat(fd: BorrowedFd<'_>, bytes: usize) -> io::Result<()> {
        let value = c_int::try_from(bytes).unwrap_or(c_int::MAX);
        let result = unsafe {
            setsockopt(
                fd.as_raw_fd(),
                SOL_SOCKET,
                SO_RCVLOWAT,
                (&raw const value).cast(),
                C_INT_LEN,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn int_option(fd: BorrowedFd<'_>, level: c_int, name: c_int) -> Option<usize> {
        let mut value: c_int = 0;
        let mut len = C_INT_LEN;
        let result = unsafe {
            getsockopt(
                fd.as_raw_fd(),
                level,
                name,
                (&raw mut value).cast(),
                &raw mut len,
            )
        };
        (result == 0).then(|| usize::try_from(value).ok()).flatten()
    }

    pub(super) fn kernel_supported() -> bool {
        release_supported(uname().release().to_bytes())
    }

    pub(super) fn release_supported(release: &[u8]) -> bool {
        let mut numbers = release
            .split(|byte| !byte.is_ascii_digit())
            .map(|digits| str::from_utf8(digits).ok()?.parse::<u32>().ok());
        matches!(
            (numbers.next(), numbers.next()),
            (Some(Some(major)), Some(Some(minor))) if (major, minor) >= MIN_KERNEL
        )
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/transport/gate/tests.rs"]
mod tests;
