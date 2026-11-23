/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::protocol::ProtocolVersion;
use crate::tls::TlsContext;
use std::{net::SocketAddr, time::Duration};
use tokio::runtime::Handle;

const DEFAULT_READ_BUFFER: usize = 64 * 1024;
const DEFAULT_COALESCE: Coalesce = if cfg!(fine_timer) {
    Coalesce::Burst
} else {
    Coalesce::Yield
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerAddress {
    pub addr: SocketAddr,
    pub tls: bool,
}

impl PeerAddress {
    pub const fn new(addr: SocketAddr, tls: bool) -> Self {
        Self { addr, tls }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coalesce {
    Immediate,
    Requeue,
    Yield,
    Burst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstRead {
    Gated,
    Immediate,
}

#[derive(Debug, Clone)]
pub struct Timings {
    pub connect_timeout: Duration,
    pub tls_handshake_timeout: Duration,
    pub tls_throttle_window: Duration,
    pub monitor_loop: Duration,
    pub monitor_timeout: Duration,
    pub idle_timeout: Duration,
    pub unreferenced_close_delay: Duration,
    pub initial_reconnection: Duration,
    pub max_reconnection: Duration,
    pub reconnection_growth: f64,
    pub reconnection_reset: Duration,
    pub failure_detection_delay: Duration,
    pub server_request_interval: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            tls_handshake_timeout: Duration::from_secs(2),
            tls_throttle_window: Duration::from_secs(11),
            monitor_loop: Duration::from_secs(1),
            monitor_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(180),
            unreferenced_close_delay: Duration::from_secs(2),
            initial_reconnection: Duration::from_millis(50),
            max_reconnection: Duration::from_millis(500),
            reconnection_growth: 1.2,
            reconnection_reset: Duration::from_secs(5),
            failure_detection_delay: Duration::from_secs(4),
            server_request_interval: Duration::from_secs(1),
        }
    }
}

#[derive(Clone)]
pub struct TransportConfig {
    pub runtime: Handle,
    pub protocol_version: ProtocolVersion,
    pub coalesce: Coalesce,
    pub first_read: FirstRead,
    pub read_buffer_size: usize,
    pub timings: Timings,
    pub tls: Option<TlsContext>,
}

impl TransportConfig {
    pub fn new(runtime: Handle, protocol_version: ProtocolVersion) -> Self {
        Self {
            runtime,
            protocol_version,
            coalesce: DEFAULT_COALESCE,
            first_read: FirstRead::Gated,
            read_buffer_size: DEFAULT_READ_BUFFER,
            timings: Timings::default(),
            tls: None,
        }
    }
}
