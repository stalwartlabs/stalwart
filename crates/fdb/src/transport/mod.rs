/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod burst;
mod config;
mod control;
mod error;
mod floor;
mod frame;
mod gate;
mod health;
mod keeper;
mod network;
mod peer;
mod protocol;
mod reader;
mod request;
mod rng;
mod slots;
mod writer;

pub use crate::codec::Uid;
pub use config::{Coalesce, FirstRead, PeerAddress, Timings, TransportConfig};
pub use error::{AmendError, ConnectFailure, TransportError};
pub use health::EndpointHealth;
pub use network::Transport;
pub use peer::{FrameSize, PeerStats};
pub use protocol::ProtocolVersion;
pub use request::{Peer, PendingReply, QueuedFrame, Request};

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/transport/tests.rs"]
mod tests;
