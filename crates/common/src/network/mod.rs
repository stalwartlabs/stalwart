/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::limiter::{ConcurrencyLimiter, InFlight};
use crate::{
    Server,
    config::server::ServerProtocol,
    expr::{functions::ResolveVariable, *},
};
use compact_str::ToCompactString;
use registry::{schema::enums::ExpressionVariable, types::ipmask::IpAddrOrMask};
use rustls::ServerConfig;
use std::fmt::Debug;
use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tokio_rustls::{Accept, TlsAcceptor};
use trc::{Event, EventType, Key};
use utils::snowflake::SnowflakeIdGenerator;

pub mod acme;
pub mod asn;
pub mod autoconfig;
pub mod dkim;
pub mod dns;
pub mod limiter;
pub mod listen;
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
                match session
                    .instance
                    .acceptor
                    .accept(session.stream, acme_core, &session.instance)
                    .await
                {
                    TcpAcceptorResult::Tls(accept) => match accept.await {
                        Ok(stream) => {
                            // Generate sessionId
                            session.session_id = session.instance.span_id_gen.generate();
                            session_id = session.session_id;

                            // Send span
                            Event::with_keys(
                                span_start,
                                vec![
                                    (Key::ListenerId, session.instance.id.clone().into()),
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
                                Reason = err.to_string(),
                            );

                            return;
                        }
                    },
                    TcpAcceptorResult::Plain(stream) => {
                        // Generate sessionId
                        session.session_id = session.instance.span_id_gen.generate();
                        session_id = session.session_id;

                        // Send span
                        Event::with_keys(
                            span_start,
                            vec![
                                (Key::ListenerId, session.instance.id.clone().into()),
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
                    TcpAcceptorResult::Close => return,
                }
            } else {
                // Generate sessionId
                session.session_id = session.instance.span_id_gen.generate();
                session_id = session.session_id;

                // Send span
                Event::with_keys(
                    span_start,
                    vec![
                        (Key::ListenerId, session.instance.id.clone().into()),
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

impl<T: SessionStream> ResolveVariable for SessionData<T> {
    fn resolve_variable(&self, variable: ExpressionVariable) -> crate::expr::Variable<'_> {
        match variable {
            ExpressionVariable::RemoteIp => self.remote_ip.to_compact_string().into(),
            ExpressionVariable::RemotePort => self.remote_port.into(),
            ExpressionVariable::LocalIp => self.local_ip.to_compact_string().into(),
            ExpressionVariable::LocalPort => self.local_port.into(),
            ExpressionVariable::Listener => self.instance.id.as_str().into(),
            ExpressionVariable::Protocol => self.protocol.as_str().into(),
            ExpressionVariable::IsTls => self.stream.is_tls().into(),
            _ => crate::expr::Variable::default(),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
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

pub fn is_global_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_ipv4(ip),
        IpAddr::V6(ip) => is_global_ipv6(ip),
    }
}

fn is_global_ipv4(ip: &Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let is_this_network = a == 0;
    let is_shared = a == 100 && (64..128).contains(&b);
    let is_protocol_assignment = a == 192 && b == 0 && c == 0;
    let is_benchmarking = a == 198 && (b & 0xfe) == 18;
    let is_relay_6to4 = a == 192 && b == 88 && c == 99;
    let is_reserved = a >= 240;

    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || is_this_network
        || is_shared
        || is_protocol_assignment
        || is_benchmarking
        || is_relay_6to4
        || is_reserved)
}

fn is_global_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }

    if let Some(ip) = ip.to_ipv4() {
        return is_global_ipv4(&ip);
    }

    let segments = ip.segments();

    if segments[0] == 0x2002 {
        return is_global_ipv4(&Ipv4Addr::from(
            ((segments[1] as u32) << 16) | segments[2] as u32,
        ));
    }

    if segments[0] == 0x0064 && segments[1] == 0xff9b {
        let is_well_known_prefix =
            segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0;

        return is_well_known_prefix
            && is_global_ipv4(&Ipv4Addr::from(
                ((segments[6] as u32) << 16) | segments[7] as u32,
            ));
    }

    let is_unique_local = (segments[0] & 0xfe00) == 0xfc00;
    let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
    let is_site_local = (segments[0] & 0xffc0) == 0xfec0;
    let is_discard_only =
        segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0;
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let is_teredo = segments[0] == 0x2001 && segments[1] == 0;
    let is_orchid = segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020;

    !(is_unique_local
        || is_link_local
        || is_site_local
        || is_discard_only
        || is_documentation
        || is_teredo
        || is_orchid)
}

pub fn ip_to_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
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

#[cfg(test)]
mod tests {
    use super::is_global_ip;
    use std::net::IpAddr;

    #[test]
    fn global_ip_classification() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "198.20.0.1",
            "192.0.3.1",
            "2606:4700::1111",
            "2a00:1450:4001::200e",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:0808:0808::",
            "2001:db9::1",
        ] {
            assert!(
                is_global_ip(&ip.parse::<IpAddr>().unwrap()),
                "expected {ip} to be global"
            );
        }

        for ip in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.0.1",
            "192.0.2.5",
            "192.88.99.1",
            "240.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "2001:db8::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b:1::7f00:1",
            "2002:7f00:1::",
            "2002:c0a8:101::",
            "100::1",
            "2001::1",
            "2001:20::1",
        ] {
            assert!(
                !is_global_ip(&ip.parse::<IpAddr>().unwrap()),
                "expected {ip} to be rejected"
            );
        }
    }
}
