/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    config::PeerAddress,
    error::{AmendError, ConnectFailure, TransportError},
    health::EndpointHealth,
    peer::{FrameKind, FrameSize, PeerShared, PeerStats, QueuedAt},
    protocol::ProtocolVersion,
    slots::SlotKey,
};
use crate::codec::Uid;
use bytes::Bytes;
use std::{
    future::Future,
    mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker, ready},
};
use tokio::sync::watch;

pub struct Peer {
    shared: Arc<PeerShared>,
}

impl Peer {
    pub(crate) fn from_counted(shared: Arc<PeerShared>) -> Self {
        Self { shared }
    }

    pub fn request<F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>)>(
        &self,
        dest: Uid,
        encode: F,
    ) -> Request<'_, F> {
        Request::new(&self.shared, FrameKind::Data, dest, encode, NoHook)
    }

    pub fn request_with<F, H>(&self, dest: Uid, encode: F, on_queued: H) -> Request<'_, F, Hook<H>>
    where
        F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>),
        H: FnOnce(QueuedFrame),
    {
        Request::new(&self.shared, FrameKind::Data, dest, encode, Hook(on_queued))
    }

    pub fn send<F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>)>(
        &self,
        dest: Uid,
        encode: F,
    ) -> Result<PendingReply, TransportError> {
        let (key, at) = self.shared.start(
            dest,
            FrameKind::Data,
            FrameSize::Small,
            encode,
            Waker::noop(),
        )?;
        Ok(PendingReply {
            peer: self.shared.clone(),
            key: Some(key),
            version: at.version(),
        })
    }

    pub fn adopt<F, H>(&self, mut request: Request<'_, F, H>) -> Option<PendingReply> {
        if !Arc::ptr_eq(request.peer, &self.shared) {
            return None;
        }
        let RequestState::Waiting { key, version } =
            mem::replace(&mut request.state, RequestState::Done)
        else {
            return None;
        };
        Some(PendingReply {
            peer: self.shared.clone(),
            key: Some(key),
            version,
        })
    }

    pub fn address(&self) -> PeerAddress {
        self.shared.address
    }

    pub fn is_failed(&self) -> bool {
        self.shared.is_failed()
    }

    pub fn is_endpoint_failed(&self, health: &EndpointHealth) -> bool {
        self.shared.endpoint_failed(health)
    }

    pub fn only_endpoint_failed(&self, health: &EndpointHealth) -> bool {
        !self.shared.is_failed() && self.shared.endpoint_failed(health)
    }

    pub fn mark_endpoint_failed(&self, token: Uid) {
        self.shared.mark_endpoint_failed(token);
    }

    pub fn watch_state(&self) -> watch::Receiver<()> {
        self.shared.subscribe()
    }

    pub fn server_version(&self) -> Option<ProtocolVersion> {
        self.shared.server_version()
    }

    pub fn connect_failures(&self) -> u64 {
        self.shared.connect_failures()
    }

    pub fn last_connect_failure(&self) -> Option<ConnectFailure> {
        self.shared.last_connect_failure()
    }

    pub fn stats(&self) -> PeerStats {
        self.shared.stats()
    }

    #[cfg(all(test, stalwart_tests))]
    pub fn rx_capacity(&self) -> usize {
        self.shared.rx_capacity()
    }

    #[cfg(all(test, stalwart_tests))]
    pub fn gate_stats(&self) -> super::gate::GateStats {
        self.shared.gate_stats()
    }

    #[cfg(all(test, stalwart_tests))]
    pub fn burst_stats(&self) -> super::burst::BurstStats {
        self.shared.burst_stats()
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn shared(&self) -> &Arc<PeerShared> {
        &self.shared
    }

    #[cfg(all(test, stalwart_tests))]
    pub fn future_sizes(&self, stream: tokio::net::TcpStream) -> (usize, usize, usize) {
        super::keeper::future_sizes(&self.shared, stream)
    }
}

impl Clone for Peer {
    fn clone(&self) -> Self {
        self.shared.add_reference();
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.shared.release_reference();
    }
}

pub struct PendingReply {
    peer: Arc<PeerShared>,
    key: Option<SlotKey>,
    version: ProtocolVersion,
}

const _: () = assert!(size_of::<PendingReply>() <= 32);

impl Future for PendingReply {
    type Output = Result<(Bytes, ProtocolVersion), TransportError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(key) = this.key else {
            return Poll::Ready(Err(TransportError::MaybeDelivered));
        };
        let result = ready!(this.peer.poll_reply(key, cx.waker()));
        this.key = None;
        Poll::Ready(result.map(|reply| (reply, this.version)))
    }
}

impl Drop for PendingReply {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            self.peer.cancel(key);
        }
    }
}

pub struct QueuedFrame {
    peer: Arc<PeerShared>,
    at: QueuedAt,
}

const _: () = assert!(size_of::<QueuedFrame>() <= 72);

impl QueuedFrame {
    pub fn amend<F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>)>(
        &self,
        encode: F,
    ) -> Result<(), AmendError> {
        self.peer.amend(&self.at, encode)
    }
}

pub trait OnQueued {
    fn queued(self, frame: impl FnOnce() -> QueuedFrame);
}

pub struct NoHook;

impl OnQueued for NoHook {
    fn queued(self, _: impl FnOnce() -> QueuedFrame) {}
}

pub struct Hook<H>(H);

impl<H: FnOnce(QueuedFrame)> OnQueued for Hook<H> {
    fn queued(self, frame: impl FnOnce() -> QueuedFrame) {
        (self.0)(frame())
    }
}

enum RequestState<F, H> {
    Unsent {
        dest: Uid,
        encode: F,
        on_queued: H,
    },
    Waiting {
        key: SlotKey,
        version: ProtocolVersion,
    },
    Done,
}

pub struct Request<'a, F, H = NoHook> {
    peer: &'a Arc<PeerShared>,
    kind: FrameKind,
    size: FrameSize,
    state: RequestState<F, H>,
}

impl<'a, F, H> Request<'a, F, H> {
    pub(crate) fn new(
        peer: &'a Arc<PeerShared>,
        kind: FrameKind,
        dest: Uid,
        encode: F,
        on_queued: H,
    ) -> Self {
        Self {
            peer,
            kind,
            size: FrameSize::Small,
            state: RequestState::Unsent {
                dest,
                encode,
                on_queued,
            },
        }
    }

    pub fn with_size(mut self, size: FrameSize) -> Self {
        self.size = size;
        self
    }
}

impl<F, H> Unpin for Request<'_, F, H> {}

impl<F, H> Future for Request<'_, F, H>
where
    F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>),
    H: OnQueued,
{
    type Output = Result<(Bytes, ProtocolVersion), TransportError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match mem::replace(&mut this.state, RequestState::Done) {
            RequestState::Unsent {
                dest,
                encode,
                on_queued,
            } => match this
                .peer
                .start(dest, this.kind, this.size, encode, cx.waker())
            {
                Ok((key, at)) => {
                    this.state = RequestState::Waiting {
                        key,
                        version: at.version(),
                    };
                    on_queued.queued(|| QueuedFrame {
                        peer: this.peer.clone(),
                        at,
                    });
                    Poll::Pending
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            RequestState::Waiting { key, version } => {
                let result = this.peer.poll_reply(key, cx.waker());
                if result.is_pending() {
                    this.state = RequestState::Waiting { key, version };
                }
                result.map_ok(|reply| (reply, version))
            }
            RequestState::Done => Poll::Ready(Err(TransportError::MaybeDelivered)),
        }
    }
}

impl<F, H> Drop for Request<'_, F, H> {
    fn drop(&mut self) {
        if let RequestState::Waiting { key, .. } = self.state {
            self.peer.cancel(key);
        }
    }
}
