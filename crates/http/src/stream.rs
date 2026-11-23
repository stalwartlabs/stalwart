/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::network::limiter::InFlight;
use std::{
    future::Future,
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep, sleep},
};

#[cfg(not(stalwart_tests))]
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(stalwart_tests)]
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct InFlightStream<T> {
    stream: T,
    write_stall: Option<Pin<Box<Sleep>>>,
    is_write_stalled: bool,
    _in_flight: InFlight,
}

impl<T> InFlightStream<T> {
    pub(crate) fn new(stream: T, in_flight: InFlight) -> Self {
        Self {
            stream,
            write_stall: None,
            is_write_stalled: false,
            _in_flight: in_flight,
        }
    }

    fn check_write<R>(
        &mut self,
        cx: &mut Context<'_>,
        result: Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        if result.is_ready() {
            self.is_write_stalled = false;
            return result;
        }

        let timer = match &mut self.write_stall {
            Some(timer) => {
                if !self.is_write_stalled {
                    timer.as_mut().reset(Instant::now() + WRITE_STALL_TIMEOUT);
                }
                timer
            }
            None => self
                .write_stall
                .insert(Box::pin(sleep(WRITE_STALL_TIMEOUT))),
        };
        self.is_write_stalled = true;

        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP response write timed out",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for InFlightStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for InFlightStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_write(cx, buf);
        this.check_write(cx, result)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_write_vectored(cx, bufs);
        this.check_write(cx, result)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_flush(cx);
        this.check_write(cx, result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_shutdown(cx);
        this.check_write(cx, result)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/http/src/stream/tests.rs"]
mod tests;
