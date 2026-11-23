/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::protocol::ProtocolVersion;
use crate::tls::TlsError;
use std::{fmt, io};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    MaybeDelivered,
    Unauthorized,
    Incompatible { server: ProtocolVersion },
    PacketTooLarge,
    EmptyMessage,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmendError {
    Taken,
    Layout,
}

impl TransportError {
    pub const fn code(&self) -> u16 {
        match self {
            Self::MaybeDelivered | Self::Shutdown => 1030,
            Self::Unauthorized => 6001,
            Self::Incompatible { .. } => 2100,
            Self::PacketTooLarge => 1500,
            Self::EmptyMessage => 4100,
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaybeDelivered => f.write_str("request may or may not have been delivered"),
            Self::Unauthorized => f.write_str("unauthorized endpoint"),
            Self::Incompatible { server } => {
                write!(
                    f,
                    "incompatible server protocol version {:#018x}",
                    server.get()
                )
            }
            Self::PacketTooLarge => f.write_str("packet exceeds the size limit"),
            Self::EmptyMessage => f.write_str("request has an empty message"),
            Self::Shutdown => f.write_str("transport shut down"),
        }
    }
}

impl std::error::Error for TransportError {}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectFailure {
    TlsConfig(TlsError),
    TlsNotConfigured,
    PlaintextRefused,
    Throttled,
    ConnectTimeout,
    Connect(io::ErrorKind),
    HandshakeTimeout,
    Handshake(io::ErrorKind),
    Tls(rustls::Error),
    Closed(io::ErrorKind),
    NoHello,
    Protocol,
    Incompatible { server: ProtocolVersion },
}

impl ConnectFailure {
    #[cold]
    pub(crate) fn from_io(err: io::Error, other: fn(io::ErrorKind) -> Self) -> Self {
        match err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(tls) => Self::Tls(tls.clone()),
            None => other(err.kind()),
        }
    }
}

impl fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsConfig(err) => write!(f, "TLS configuration: {err}"),
            Self::TlsNotConfigured => f.write_str("TLS address without a TLS configuration"),
            Self::PlaintextRefused => f.write_str("plaintext connections are refused"),
            Self::Throttled => f.write_str("throttled after failed TLS handshakes"),
            Self::ConnectTimeout => f.write_str("connect timed out"),
            Self::Connect(kind) => write!(f, "connect failed: {kind}"),
            Self::HandshakeTimeout => f.write_str("TLS handshake timed out"),
            Self::Handshake(kind) => write!(f, "TLS handshake failed: {kind}"),
            Self::Tls(err) => write!(f, "TLS: {err}"),
            Self::Closed(kind) => write!(f, "connection lost before the server hello: {kind}"),
            Self::NoHello => f.write_str("no server hello before the connection ended"),
            Self::Protocol => f.write_str("malformed server hello"),
            Self::Incompatible { server } => write!(
                f,
                "incompatible server protocol version {:#018x}",
                server.get()
            ),
        }
    }
}

impl std::error::Error for ConnectFailure {}
