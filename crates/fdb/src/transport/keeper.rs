/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    control::{self, PING},
    error::{ConnectFailure, TransportError},
    gate::ReadGate,
    peer::{FrameKind, PeerShared},
    protocol::connect_packet,
    reader,
    request::{NoHook, Request},
    rng::Rng,
    writer,
};
use rustls_pki_types::ServerName;
use std::{
    future::poll_fn,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, split},
    net::TcpStream,
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use tokio_rustls::client::TlsStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Closed {
    Failed,
    Protocol,
    Idle,
    Unreferenced,
    Reset,
    Shutdown,
}

pub(crate) enum Link {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

struct WriterTask(JoinHandle<io::Result<()>>);

impl Drop for WriterTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct Keeper {
    peer: Arc<PeerShared>,
    rng: Rng,
    reconnection_delay: Duration,
    last_connect: Option<Instant>,
    first_failure: Option<Instant>,
    retry_connect: bool,
}

impl Drop for Keeper {
    fn drop(&mut self) {
        self.peer.teardown(TransportError::Shutdown);
        self.peer.transport.remove(&self.peer);
    }
}

impl Keeper {
    pub(crate) fn new(peer: Arc<PeerShared>) -> Self {
        Self {
            reconnection_delay: peer.transport.config.timings.initial_reconnection,
            peer,
            rng: Rng::new(),
            last_connect: None,
            first_failure: None,
            retry_connect: false,
        }
    }

    pub(crate) async fn run(mut self) {
        while self.wait_for_work().await {
            let peer = self.peer.clone();
            let connected = tokio::select! {
                connected = self.throttle_and_connect() => connected,
                () = shutdown(&peer) => break,
            };
            let closed = match connected {
                Ok(link) => {
                    self.peer.set_failed(false);
                    if !self.peer.has_queued() {
                        self.retry_connect = false;
                        continue;
                    }
                    self.first_failure = None;
                    match link {
                        Link::Plain(stream) => {
                            let (read, write) = stream.into_split();
                            self.run_connection(read, write).await
                        }
                        Link::Tls(stream) => {
                            let (read, write) = split(stream);
                            self.run_connection(read, write).await
                        }
                    }
                }
                Err(failure) => {
                    self.peer.record_connect_failure(failure);
                    Closed::Failed
                }
            };
            if !self.on_closed(closed) {
                break;
            }
        }
    }

    async fn wait_for_work(&mut self) -> bool {
        let peer = &*self.peer;
        let timings = &peer.transport.config.timings;
        loop {
            if peer.transport.is_shutdown() || peer.transport.remove_if_unused(peer) {
                return false;
            }
            let retry = if !self.retry_connect {
                None
            } else if peer.is_failed() {
                Some(timings.server_request_interval)
            } else {
                Some(timings.failure_detection_delay)
            };
            tokio::select! {
                _ = poll_fn(|cx| peer.poll_queued(cx)) => return true,
                () = peer.control.notified() => {}
                () = sleep(retry.unwrap_or_default()), if retry.is_some() => return true,
            }
        }
    }

    async fn throttle_and_connect(&mut self) -> Result<Link, ConnectFailure> {
        if let Some(last) = self.last_connect {
            let wait = (last + self.reconnection_delay).saturating_duration_since(Instant::now());
            if !wait.is_zero() {
                sleep(self.rng.jitter(wait)).await;
            }
        }
        self.last_connect = Some(Instant::now());
        self.connect().await
    }

    async fn connect(&mut self) -> Result<Link, ConnectFailure> {
        let peer = &*self.peer;
        let config = &peer.transport.config;
        let address = peer.address;
        let connector = match (&config.tls, address.tls) {
            (Some(tls), true) => Some(tls.connector().map_err(ConnectFailure::TlsConfig)?),
            (None, true) => return Err(ConnectFailure::TlsNotConfigured),
            (Some(tls), false) if tls.refuses_plaintext() => {
                return Err(ConnectFailure::PlaintextRefused);
            }
            _ => None,
        };
        if connector.is_some() && peer.transport.tls_throttled(address.addr) {
            sleep(config.timings.monitor_timeout).await;
            return Err(ConnectFailure::Throttled);
        }
        let stream = timeout(
            config.timings.connect_timeout,
            TcpStream::connect(address.addr),
        )
        .await
        .map_err(|_| ConnectFailure::ConnectTimeout)?
        .map_err(|err| ConnectFailure::Connect(err.kind()))?;
        stream
            .set_nodelay(true)
            .map_err(|err| ConnectFailure::Connect(err.kind()))?;
        let Some(connector) = connector else {
            return Ok(Link::Plain(stream));
        };
        let name = ServerName::IpAddress(address.addr.ip().into());
        match timeout(
            config.timings.tls_handshake_timeout,
            connector.connect(name, stream),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(Link::Tls(Box::new(stream))),
            Ok(Err(err)) => {
                peer.transport.record_tls_failure(address.addr);
                Err(ConnectFailure::from_io(err, ConnectFailure::Handshake))
            }
            Err(_) => {
                peer.transport.record_tls_failure(address.addr);
                Err(ConnectFailure::HandshakeTimeout)
            }
        }
    }

    async fn run_connection<R, W>(&mut self, read_half: R, write_half: W) -> Closed
    where
        R: AsyncRead + ReadGate + Unpin,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let peer = self.peer.clone();
        let Some(version) = peer.open_connection() else {
            return Closed::Reset;
        };
        let mut writer = WriterTask(peer.transport.config.runtime.spawn(writer::run(
            peer.clone(),
            write_half,
            connect_packet(version),
        )));
        let mut writer_finished = false;
        let connected_at = Instant::now();
        let hello = AtomicBool::new(false);
        let reader = reader::run(&peer, read_half, version, &hello);
        let monitor = monitor(&peer, connected_at, &mut self.rng);
        tokio::pin!(reader, monitor);
        let closed = loop {
            tokio::select! {
                closed = &mut reader => break closed,
                closed = &mut monitor => {
                    if closed == Closed::Failed && !hello.load(Ordering::Relaxed) {
                        peer.record_session_failure(ConnectFailure::NoHello);
                    }
                    break closed;
                }
                result = &mut writer.0 => {
                    writer_finished = true;
                    if !hello.load(Ordering::Relaxed) {
                        peer.record_session_failure(match result {
                            Ok(Err(err)) => ConnectFailure::from_io(err, ConnectFailure::Closed),
                            _ => ConnectFailure::NoHello,
                        });
                    }
                    break Closed::Failed;
                }
                () = peer.control.notified() => {
                    if peer.transport.is_shutdown() {
                        break Closed::Shutdown;
                    }
                    if peer.transport.protocol_version() != version {
                        break Closed::Reset;
                    }
                }
            }
        };
        if !writer_finished {
            writer.0.abort();
            let _ = (&mut writer.0).await;
        }
        closed
    }

    fn on_closed(&mut self, closed: Closed) -> bool {
        let now = Instant::now();
        let timings = &self.peer.transport.config.timings;
        self.reconnection_delay = match self.last_connect {
            Some(last) if now.duration_since(last) <= timings.reconnection_reset => self
                .reconnection_delay
                .mul_f64(timings.reconnection_growth)
                .min(timings.max_reconnection),
            _ => timings.initial_reconnection,
        };
        let first_failure = *self.first_failure.get_or_insert(now);
        self.retry_connect = true;
        if closed == Closed::Failed
            && now.duration_since(first_failure) > timings.failure_detection_delay
        {
            self.peer.set_failed(true);
        }
        if closed == Closed::Shutdown {
            return false;
        }
        self.peer.teardown(TransportError::MaybeDelivered);
        true
    }
}

#[cfg(all(test, stalwart_tests))]
pub(crate) fn future_sizes(peer: &Arc<PeerShared>, stream: TcpStream) -> (usize, usize, usize) {
    let detached = Arc::new(PeerShared::new(peer.address, peer.transport.clone()));
    let keeper = size_of_val(&Keeper::new(detached).run());
    let hello = AtomicBool::new(false);
    let (read, write) = stream.into_split();
    let version = peer.transport.protocol_version();
    let reader = size_of_val(&reader::run(peer, read, version, &hello));
    let writer = size_of_val(&writer::run(peer.clone(), write, connect_packet(version)));
    (keeper, reader, writer)
}

async fn shutdown(peer: &PeerShared) {
    while !peer.transport.is_shutdown() {
        peer.control.notified().await;
    }
}

async fn monitor(peer: &Arc<PeerShared>, connected_at: Instant, rng: &mut Rng) -> Closed {
    let timings = &peer.transport.config.timings;
    let mut last_frames = peer.data_frames();
    let mut last_data = Instant::now();
    loop {
        let now = Instant::now();
        let frames = peer.data_frames();
        if frames != last_frames {
            last_frames = frames;
            last_data = now;
        }
        if peer.is_quiet() {
            let idle_for = now.duration_since(last_data);
            if peer.references() == 0 && idle_for > timings.unreferenced_close_delay {
                return Closed::Unreferenced;
            }
            if now.duration_since(connected_at) > timings.idle_timeout
                && idle_for > timings.idle_timeout
            {
                return Closed::Idle;
            }
        }
        sleep(rng.jitter(timings.monitor_loop)).await;
        let ping = Request::new(
            peer,
            FrameKind::Control,
            PING,
            |reply, _, out: &mut Vec<u8>| control::encode_ping_request(reply, out),
            NoHook,
        );
        tokio::pin!(ping);
        let mut received = peer.bytes_received();
        loop {
            tokio::select! {
                _ = &mut ping => break,
                () = sleep(timings.monitor_timeout) => {
                    let now_received = peer.bytes_received();
                    if now_received == received {
                        return Closed::Failed;
                    }
                    received = now_received;
                }
            }
        }
    }
}
