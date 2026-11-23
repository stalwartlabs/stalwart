/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    error::ConnectFailure,
    frame::{self, Framing},
    gate::{FirstReadGate, Gated, ReadGate},
    keeper::Closed,
    peer::{Dispatch, PeerShared},
    protocol::{ProtocolVersion, parse_connect_packet},
};
use bytes::{Buf, BytesMut};
use std::{
    io, mem,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncRead, AsyncReadExt};

const MIN_FREE: usize = 256;
#[cfg(any(target_os = "linux", all(test, stalwart_tests)))]
pub(crate) const QUEUED_READ_CAP: usize = 256 << 10;

pub(crate) async fn run<R: AsyncRead + ReadGate + Unpin>(
    peer: &PeerShared,
    mut half: R,
    local: ProtocolVersion,
    hello_received: &AtomicBool,
) -> Closed {
    let mut buf = ReceiveBuffer::new(peer.transport.config.read_buffer_size);
    let mut scratch = Dispatch::default();
    let mut hello = false;
    let mut gate = FirstReadGate::new(peer.transport.config.first_read, peer.framing);
    loop {
        let gated = if hello && buf.bytes.is_empty() && gate.is_armed() {
            let gated = half.gate(&mut gate, &mut buf).await;
            #[cfg(all(test, stalwart_tests))]
            peer.record_gate(gate.stats());
            match gated {
                Ok(gated) => gated,
                Err(_) => return Closed::Failed,
            }
        } else {
            Gated::Pass
        };
        let (read, low_water_raised) = match gated {
            Gated::Read(read) => (Ok(read), true),
            Gated::Pass => {
                buf.reserve(hello.then_some(peer.framing));
                #[cfg(all(test, stalwart_tests))]
                peer.record_rx_capacity(buf.bytes.capacity());
                (half.read_buf(&mut buf.bytes).await, false)
            }
        };
        match read {
            Ok(0) => {
                if !hello {
                    peer.record_session_failure(ConnectFailure::Closed(
                        io::ErrorKind::UnexpectedEof,
                    ));
                }
                return Closed::Failed;
            }
            Err(err) => {
                if !hello {
                    peer.record_session_failure(ConnectFailure::from_io(
                        err,
                        ConnectFailure::Closed,
                    ));
                }
                return Closed::Failed;
            }
            Ok(read) => peer.record_read(read),
        }
        if !hello {
            match parse_connect_packet(&buf.bytes, local) {
                Ok(Some(packet)) => {
                    buf.bytes.advance(packet.consumed);
                    hello = true;
                    hello_received.store(true, Ordering::Relaxed);
                    peer.on_hello(packet);
                }
                Ok(None) => continue,
                Err(_) => {
                    peer.record_session_failure(ConnectFailure::Protocol);
                    return Closed::Protocol;
                }
            }
        }
        gate.observe_read(&buf.bytes, peer.framing);
        if peer.dispatch(&mut buf.bytes, &mut scratch).is_err() {
            return Closed::Protocol;
        }
        if low_water_raised && half.reset_low_water().is_err() {
            return Closed::Failed;
        }
        buf.release_oversized();
    }
}

pub(crate) struct ReceiveBuffer {
    pub(crate) bytes: BytesMut,
    spare: Option<BytesMut>,
    read_size: usize,
    oversized: bool,
}

impl ReceiveBuffer {
    fn new(read_size: usize) -> Self {
        Self {
            bytes: BytesMut::with_capacity(read_size),
            spare: None,
            read_size,
            oversized: false,
        }
    }

    fn reserve(&mut self, framing: Option<Framing>) {
        let target = framing
            .and_then(|framing| frame::pending_frame_len(&self.bytes, framing))
            .unwrap_or(0)
            .max(self.bytes.len() + MIN_FREE);
        if self.bytes.capacity() >= target {
            return;
        }
        if target > self.read_size {
            self.replace(target);
            self.oversized = true;
        } else if self.oversized {
            self.replace(self.read_size);
            self.oversized = false;
        } else {
            self.bytes.reserve(self.read_size - self.bytes.len());
        }
    }

    fn release_oversized(&mut self) {
        if self.oversized && self.bytes.is_empty() {
            match self.spare.take() {
                Some(spare) => self.bytes = spare,
                None => self.replace(self.read_size),
            }
            self.oversized = false;
        }
    }

    #[cfg(any(target_os = "linux", all(test, stalwart_tests)))]
    pub(crate) fn reserve_queued(&mut self, queued: usize) {
        let wanted = queued.min(QUEUED_READ_CAP);
        if wanted > self.bytes.capacity() - self.bytes.len() {
            self.replace(self.bytes.len() + wanted);
            self.oversized = true;
        }
    }

    fn replace(&mut self, capacity: usize) {
        if self.bytes.try_reclaim(capacity - self.bytes.len())
            && self.bytes.capacity() <= capacity.max(self.read_size)
        {
            return;
        }
        let mut fresh = match self.spare.take() {
            Some(spare) if spare.capacity() >= capacity => spare,
            spare => {
                self.spare = spare;
                BytesMut::with_capacity(capacity)
            }
        };
        fresh.extend_from_slice(&self.bytes);
        let mut old = mem::replace(&mut self.bytes, fresh);
        if capacity > self.read_size && self.spare.is_none() {
            old.clear();
            if old.try_reclaim(self.read_size) && old.capacity() == self.read_size {
                self.spare = Some(old);
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/transport/reader/tests.rs"]
mod tests;
