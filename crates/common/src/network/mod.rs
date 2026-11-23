/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::limiter::{ConcurrencyLimiter, InFlight};
use crate::{Server, config::server::ServerProtocol};
use compact_str::{CompactString, ToCompactString};
use futures::FutureExt;
use registry::types::ipmask::IpAddrOrMask;
use rustls::ServerConfig;
use std::fmt::Debug;
use std::{
    borrow::Cow,
    future::Future,
    io,
    net::{IpAddr, Ipv6Addr},
    pin::pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tinyvec::ArrayVec;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    time::timeout,
};
use tokio_rustls::{Accept, TlsAcceptor};
use trc::{Event, EventType, Key};
use utils::snowflake::SnowflakeIdGenerator;

pub mod acme;
pub mod asn;
pub mod autoconfig;
pub mod dkim;
pub mod dns;
pub mod forwarded;
pub mod limiter;
pub mod listen;
pub mod masked;
pub mod memory;
pub mod mta;
pub mod security;
pub mod stream;
pub mod tls;
pub mod webpush;

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub enum RcptResolution {
    Accept,
    Expand(Arc<[Box<str>]>),
    Rewrite(String),
    #[default]
    UnknownRecipient,
    UnknownDomain,
}

pub struct ServerInstance {
    pub id: String,
    pub protocol: ServerProtocol,
    pub acceptor: TcpAcceptor,
    pub limiter: ConcurrencyLimiter,
    pub proxy_networks: Vec<IpAddrOrMask>,
    pub tls_timeout: Duration,
    pub shutdown_rx: watch::Receiver<bool>,
    pub span_id_gen: Arc<SnowflakeIdGenerator>,
}

#[derive(Default)]
pub enum TcpAcceptor {
    Tls {
        config: Arc<ServerConfig>,
        acceptor: TlsAcceptor,
        implicit: bool,
    },
    #[default]
    Plain,
}

#[allow(clippy::large_enum_variant)]
pub enum TcpAcceptorResult<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    Tls(Accept<IO>),
    Plain(IO),
    Close,
}

pub struct SessionData<T: SessionStream> {
    pub stream: T,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: ServerProtocol,
    pub session_id: u64,
    pub in_flight: InFlight,
    pub instance: Arc<ServerInstance>,
}

pub trait SessionStream: AsyncRead + AsyncWrite + Unpin + 'static + Sync + Send {
    fn is_tls(&self) -> bool;
    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>);
}

pub async fn ready_or_timeout<F: Future>(duration: Duration, future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    match future.as_mut().now_or_never() {
        Some(output) => Some(output),
        None => timeout(duration, future).await.ok(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionResult {
    Continue,
    Close,
    UpgradeTls,
}

pub trait SessionManager: Sync + Send + 'static + Clone {
    fn spawn<T: SessionStream>(
        &self,
        mut session: SessionData<T>,
        is_tls: bool,
        acme_core: Option<Server>,
        span_start: EventType,
        span_end: EventType,
    ) {
        let manager = self.clone();

        tokio::spawn(async move {
            let start_time = Instant::now();
            let local_port = session.local_port;
            let session_id;

            if is_tls {
                let tls_timeout = session.instance.tls_timeout;
                match timeout(
                    tls_timeout,
                    session
                        .instance
                        .acceptor
                        .accept(session.stream, acme_core, &session.instance),
                )
                .await
                {
                    Ok(TcpAcceptorResult::Tls(accept)) => {
                        match timeout(tls_timeout.saturating_sub(start_time.elapsed()), accept)
                            .await
                            .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)))
                        {
                            Ok(stream) => {
                                // Generate sessionId
                                session.session_id = session.instance.span_id_gen.generate();
                                session_id = session.session_id;

                                // Send span
                                Event::with_keys(
                                    span_start,
                                    vec![
                                        (
                                            Key::ListenerId,
                                            CompactString::from(session.instance.id.as_str())
                                                .into(),
                                        ),
                                        (Key::LocalPort, session.local_port.into()),
                                        (Key::RemoteIp, session.remote_ip.into()),
                                        (Key::RemotePort, session.remote_port.into()),
                                        (Key::SpanId, session.session_id.into()),
                                    ],
                                )
                                .send_with_metrics();

                                manager
                                    .handle(SessionData {
                                        stream,
                                        local_ip: session.local_ip,
                                        local_port: session.local_port,
                                        remote_ip: session.remote_ip,
                                        remote_port: session.remote_port,
                                        protocol: session.protocol,
                                        session_id: session.session_id,
                                        in_flight: session.in_flight,
                                        instance: session.instance,
                                    })
                                    .await;
                            }
                            Err(err) => {
                                trc::event!(
                                    Tls(trc::TlsEvent::HandshakeError),
                                    ListenerId = session.instance.id.clone(),
                                    LocalPort = local_port,
                                    RemoteIp = session.remote_ip,
                                    RemotePort = session.remote_port,
                                    Reason = err.to_compact_string(),
                                );

                                return;
                            }
                        }
                    }
                    Ok(TcpAcceptorResult::Plain(stream)) => {
                        // Generate sessionId
                        session.session_id = session.instance.span_id_gen.generate();
                        session_id = session.session_id;

                        // Send span
                        Event::with_keys(
                            span_start,
                            vec![
                                (
                                    Key::ListenerId,
                                    CompactString::from(session.instance.id.as_str()).into(),
                                ),
                                (Key::LocalPort, session.local_port.into()),
                                (Key::RemoteIp, session.remote_ip.into()),
                                (Key::RemotePort, session.remote_port.into()),
                                (Key::SpanId, session.session_id.into()),
                            ],
                        )
                        .send_with_metrics();

                        session.stream = stream;
                        manager.handle(session).await;
                    }
                    Ok(TcpAcceptorResult::Close) => return,
                    Err(_) => {
                        trc::event!(
                            Tls(trc::TlsEvent::HandshakeError),
                            ListenerId = session.instance.id.clone(),
                            LocalPort = local_port,
                            RemoteIp = session.remote_ip,
                            RemotePort = session.remote_port,
                            Reason = io::Error::from(io::ErrorKind::TimedOut).to_compact_string(),
                        );

                        return;
                    }
                }
            } else {
                // Generate sessionId
                session.session_id = session.instance.span_id_gen.generate();
                session_id = session.session_id;

                // Send span
                Event::with_keys(
                    span_start,
                    vec![
                        (
                            Key::ListenerId,
                            CompactString::from(session.instance.id.as_str()).into(),
                        ),
                        (Key::LocalPort, session.local_port.into()),
                        (Key::RemoteIp, session.remote_ip.into()),
                        (Key::RemotePort, session.remote_port.into()),
                        (Key::SpanId, session.session_id.into()),
                    ],
                )
                .send_with_metrics();

                manager.handle(session).await;
            }

            // End span
            Event::with_keys(
                span_end,
                vec![
                    (Key::SpanId, session_id.into()),
                    (Key::Elapsed, start_time.elapsed().into()),
                ],
            )
            .send_with_metrics();
        });
    }

    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send;

    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send;
}

impl Debug for TcpAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls {
                config, implicit, ..
            } => f
                .debug_struct("Tls")
                .field("config", config)
                .field("implicit", implicit)
                .finish(),
            Self::Plain => write!(f, "Plain"),
        }
    }
}

pub const IPV6_PREFIX_MASK: u128 = u128::MAX << 64;

pub fn ipv6_prefix(addr: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from_bits(addr.to_bits() & IPV6_PREFIX_MASK)
}

pub fn ip_rate_key(ip: &IpAddr) -> ArrayVec<[u8; 16]> {
    let mut bytes = ArrayVec::new();
    match ip.to_canonical() {
        IpAddr::V4(ip) => bytes.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => bytes.extend_from_slice(&((ip.to_bits() >> 64) as u64).to_be_bytes()),
    }
    bytes
}

pub fn ip_to_bytes_prefix(prefix: u8, ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => {
            let mut buf = Vec::with_capacity(5);
            buf.push(prefix);
            buf.extend_from_slice(&ip.octets());
            buf
        }
        IpAddr::V6(ip) => {
            let mut buf = Vec::with_capacity(17);
            buf.push(prefix);
            buf.extend_from_slice(&ip.octets());
            buf
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/network/tests.rs"]
mod tests;
