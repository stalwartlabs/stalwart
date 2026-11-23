/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    config::{PeerAddress, TransportConfig},
    keeper::Keeper,
    peer::PeerShared,
    protocol::ProtocolVersion,
    request::Peer,
};
#[cfg(windows)]
use crate::client::grv::timer::TimerResolution;
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    net::SocketAddr,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::time::Instant;

const TLS_THROTTLE_ATTEMPTS: u32 = 1;
const TLS_FAILURES_PRUNE: usize = 64;

pub(crate) struct TransportShared {
    pub(crate) config: TransportConfig,
    protocol: AtomicU64,
    peers: Mutex<HashMap<PeerAddress, Arc<PeerShared>>>,
    shutdown: AtomicBool,
    failure_generation: AtomicU64,
    tls_failures: Mutex<HashMap<SocketAddr, TlsFailures>>,
}

struct TlsFailures {
    repeated: u32,
    until: Instant,
}

impl TransportShared {
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::new(self.protocol.load(Ordering::Acquire))
    }

    pub(crate) fn next_failure_generation(&self) -> u64 {
        self.failure_generation.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn tls_throttled(&self, addr: SocketAddr) -> bool {
        let mut failures = self.tls_failures.lock();
        let Some(entry) = failures.get(&addr) else {
            return false;
        };
        if Instant::now() >= entry.until {
            failures.remove(&addr);
            false
        } else {
            entry.repeated >= TLS_THROTTLE_ATTEMPTS
        }
    }

    pub(crate) fn record_tls_failure(&self, addr: SocketAddr) {
        let mut failures = self.tls_failures.lock();
        let now = Instant::now();
        if failures.len() >= TLS_FAILURES_PRUNE {
            failures.retain(|_, entry| now < entry.until);
        }
        failures
            .entry(addr)
            .and_modify(|entry| entry.repeated = entry.repeated.saturating_add(1))
            .or_insert_with(|| TlsFailures {
                repeated: 0,
                until: now + self.config.timings.tls_throttle_window,
            });
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    pub(crate) fn remove_if_unused(&self, peer: &PeerShared) -> bool {
        let mut peers = self.peers.lock();
        if peer.references() != 0 || !peer.is_quiet() {
            return false;
        }
        remove_entry(&mut peers, peer);
        true
    }

    pub(crate) fn remove(&self, peer: &PeerShared) {
        remove_entry(&mut self.peers.lock(), peer);
    }

    fn notify_peers(&self) {
        for peer in self.peers.lock().values() {
            peer.control.notify_one();
        }
    }

    fn adopt_version(&self) {
        for peer in self.peers.lock().values() {
            peer.adopt_version();
            peer.control.notify_one();
        }
    }
}

fn remove_entry(peers: &mut HashMap<PeerAddress, Arc<PeerShared>>, peer: &PeerShared) {
    if peers
        .get(&peer.address)
        .is_some_and(|existing| ptr::eq(Arc::as_ptr(existing), peer))
    {
        peers.remove(&peer.address);
    }
}

struct Owner {
    shared: Arc<TransportShared>,
    #[cfg(windows)]
    _resolution: Option<TimerResolution>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::Release);
        self.shared.notify_peers();
    }
}

#[derive(Clone)]
pub struct Transport {
    owner: Arc<Owner>,
}

impl Transport {
    pub fn new(mut config: TransportConfig) -> Self {
        config.first_read = config.first_read.supported();
        let protocol = AtomicU64::new(config.protocol_version.get());
        Self {
            owner: Arc::new(Owner {
                shared: Arc::new(TransportShared {
                    config,
                    protocol,
                    peers: Mutex::new(HashMap::new()),
                    shutdown: AtomicBool::new(false),
                    failure_generation: AtomicU64::new(0),
                    tls_failures: Mutex::new(HashMap::new()),
                }),
                #[cfg(windows)]
                _resolution: TimerResolution::raise(),
            }),
        }
    }

    pub fn peer(&self, address: PeerAddress) -> Peer {
        let shared = &self.owner.shared;
        let peer = {
            let mut peers = shared.peers.lock();
            if let Some(peer) = peers.get(&address) {
                peer.add_reference();
                return Peer::from_counted(peer.clone());
            }
            let peer = Arc::new(PeerShared::new(address, shared.clone()));
            peers.insert(address, peer.clone());
            peer
        };
        shared.config.runtime.spawn(Keeper::new(peer.clone()).run());
        Peer::from_counted(peer)
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.owner.shared.protocol_version()
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn detached_peer(&self, address: PeerAddress) -> Peer {
        Peer::from_counted(Arc::new(PeerShared::new(
            address,
            self.owner.shared.clone(),
        )))
    }

    #[cfg(all(test, stalwart_tests))]
    pub fn has_peer(&self, address: PeerAddress) -> bool {
        self.owner.shared.peers.lock().contains_key(&address)
    }

    pub fn set_protocol_version(&self, version: ProtocolVersion) {
        let shared = &self.owner.shared;
        if shared.protocol.swap(version.get(), Ordering::AcqRel) != version.get() {
            shared.adopt_version();
        }
    }
}
