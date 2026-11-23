/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    balance::{Measurement, QueueData, Replicas},
    endpoint::adjusted_token,
};
use crate::transport::{EndpointHealth, Peer, PeerAddress, Transport, Uid};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

const FAILED_ENDPOINT_GRACE_PERIOD: f64 = 60.0;
const FAILED_ENDPOINT_RETRY_INTERVAL: f64 = 60.0;
const FAILED_ENDPOINT_STATE_RETENTION: f64 = 2.0 * FAILED_ENDPOINT_RETRY_INTERVAL;
const NO_FAILURE: u64 = u64::MAX;
const MIN_PRUNE_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Channel {
    Value,
    Key,
    KeyValues,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Distance {
    SameDc,
    Distant,
}

pub(crate) struct ServerInterface<'a> {
    pub(crate) id: Uid,
    pub(crate) address: PeerAddress,
    pub(crate) get_value: Uid,
    pub(crate) datacenter_id: Option<&'a [u8]>,
}

#[repr(align(128))]
struct Endpoint {
    health: EndpointHealth,
    queue: Mutex<QueueData>,
    failed_since: AtomicU64,
    refreshed: AtomicU64,
}

type Endpoints = [Endpoint; Channel::COUNT];

pub(crate) struct StorageServer {
    id: Uid,
    peer: Peer,
    distance: Distance,
    endpoints: Arc<Endpoints>,
}

pub(crate) type Location = Replicas<Arc<StorageServer>>;

pub(crate) struct ServerRegistry {
    datacenter_id: Option<Box<[u8]>>,
    servers: Mutex<Servers>,
}

struct Servers {
    map: HashMap<Uid, Entry>,
    prune_at: usize,
}

struct Entry {
    server: Weak<StorageServer>,
    address: PeerAddress,
    endpoints: Arc<Endpoints>,
}

impl Channel {
    const COUNT: usize = 3;

    const fn index(self) -> usize {
        match self {
            Channel::Value => 0,
            Channel::Key => 1,
            Channel::KeyValues => 2,
        }
    }

    const fn token(self, get_value: Uid) -> Uid {
        adjusted_token(get_value, self.index() as u32)
    }
}

impl Endpoint {
    fn new(token: Uid) -> Self {
        Endpoint {
            health: EndpointHealth::new(token),
            queue: Mutex::new(QueueData::new()),
            failed_since: AtomicU64::new(NO_FAILURE),
            refreshed: AtomicU64::new(NO_FAILURE),
        }
    }

    fn all(get_value: Uid) -> Arc<Endpoints> {
        Arc::new(
            [Channel::Value, Channel::Key, Channel::KeyValues]
                .map(|channel| Endpoint::new(channel.token(get_value))),
        )
    }

    fn refreshed_within(&self, now: f64, window: f64) -> bool {
        self.failed_since.load(Ordering::Relaxed) != NO_FAILURE
            && now - f64::from_bits(self.refreshed.load(Ordering::Relaxed)) <= window
    }
}

impl Entry {
    fn retain(&self, now: f64) -> bool {
        self.server.strong_count() > 0
            || self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.refreshed_within(now, FAILED_ENDPOINT_STATE_RETENTION))
    }
}

impl StorageServer {
    fn new(
        transport: &Transport,
        interface: &ServerInterface<'_>,
        distance: Distance,
        endpoints: Arc<Endpoints>,
    ) -> Self {
        StorageServer {
            id: interface.id,
            peer: transport.peer(interface.address),
            distance,
            endpoints,
        }
    }

    fn endpoint(&self, channel: Channel) -> &Endpoint {
        &self.endpoints[channel.index()]
    }

    fn matches(&self, interface: &ServerInterface<'_>, distance: Distance) -> bool {
        self.distance == distance
            && self.endpoint(Channel::Value).health.token() == interface.get_value
            && self.peer.address() == interface.address
    }

    pub(crate) fn id(&self) -> Uid {
        self.id
    }

    pub(crate) fn peer(&self) -> &Peer {
        &self.peer
    }

    pub(crate) fn token(&self, channel: Channel) -> Uid {
        self.endpoint(channel).health.token()
    }

    pub(crate) fn queue(&self, channel: Channel) -> &Mutex<QueueData> {
        &self.endpoint(channel).queue
    }

    pub(crate) fn is_healthy(&self, channel: Channel) -> bool {
        let endpoint = self.endpoint(channel);
        !self.peer.is_failed() && !self.peer.is_endpoint_failed(&endpoint.health)
    }

    pub(crate) fn measure(&self, channel: Channel, now: f64) -> Option<Measurement> {
        if self.is_healthy(channel) {
            self.queue(channel).lock().measure(now)
        } else {
            None
        }
    }

    fn needs_refresh(&self, channel: Channel, now: impl FnOnce() -> f64) -> bool {
        let endpoint = self.endpoint(channel);
        if !self.peer.only_endpoint_failed(&endpoint.health) {
            if endpoint.failed_since.load(Ordering::Relaxed) != NO_FAILURE {
                endpoint.failed_since.store(NO_FAILURE, Ordering::Relaxed);
            }
            return false;
        }
        let now = now();
        let since = match endpoint.failed_since.load(Ordering::Relaxed) {
            NO_FAILURE => {
                endpoint
                    .failed_since
                    .store(now.to_bits(), Ordering::Relaxed);
                endpoint.refreshed.store(now.to_bits(), Ordering::Relaxed);
                now
            }
            bits => f64::from_bits(bits),
        };
        let refreshed = f64::from_bits(endpoint.refreshed.load(Ordering::Relaxed));
        if now - since < FAILED_ENDPOINT_GRACE_PERIOD
            || now - refreshed > FAILED_ENDPOINT_RETRY_INTERVAL
        {
            endpoint.refreshed.store(now.to_bits(), Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

impl Location {
    pub(crate) fn needs_refresh(&self, channel: Channel, now: impl Fn() -> f64) -> bool {
        let mut at = None;
        self.as_slice().iter().fold(false, |refresh, server| {
            server.needs_refresh(channel, || *at.get_or_insert_with(&now)) | refresh
        })
    }
}

impl ServerRegistry {
    pub(crate) fn new(datacenter_id: Option<&str>) -> Self {
        ServerRegistry {
            datacenter_id: datacenter_id.map(|id| id.as_bytes().into()),
            servers: Mutex::new(Servers {
                map: HashMap::new(),
                prune_at: MIN_PRUNE_SIZE,
            }),
        }
    }

    fn distance(&self, datacenter_id: Option<&[u8]>) -> Distance {
        match (&self.datacenter_id, datacenter_id) {
            (Some(local), Some(remote)) if **local == *remote => Distance::SameDc,
            _ => Distance::Distant,
        }
    }

    pub(crate) fn location<'a>(
        &self,
        transport: &Transport,
        now: f64,
        interfaces: impl ExactSizeIterator<Item = ServerInterface<'a>>,
    ) -> Option<Location> {
        let mut replicas = Vec::with_capacity(interfaces.len());
        let mut servers = self.servers.lock();
        for interface in interfaces {
            let distance = self.distance(interface.datacenter_id);
            let entry = servers.map.get(&interface.id);
            if let Some(server) = entry
                .and_then(|entry| entry.server.upgrade())
                .filter(|server| server.matches(&interface, distance))
            {
                replicas.push(server);
                continue;
            }
            let endpoints = entry
                .filter(|entry| {
                    entry.address == interface.address
                        && entry.endpoints[Channel::Value.index()].health.token()
                            == interface.get_value
                })
                .map_or_else(
                    || Endpoint::all(interface.get_value),
                    |entry| entry.endpoints.clone(),
                );
            let server = Arc::new(StorageServer::new(
                transport,
                &interface,
                distance,
                endpoints.clone(),
            ));
            servers.map.insert(
                interface.id,
                Entry {
                    server: Arc::downgrade(&server),
                    address: interface.address,
                    endpoints,
                },
            );
            replicas.push(server);
        }
        if servers.map.len() >= servers.prune_at {
            servers.map.retain(|_, entry| entry.retain(now));
            servers.prune_at = (servers.map.len() * 2).max(MIN_PRUNE_SIZE);
        }
        drop(servers);
        fastrand::shuffle(&mut replicas);
        replicas.sort_by_key(|server| server.distance);
        let best = replicas.first()?.distance;
        let count_best = replicas
            .iter()
            .take_while(|server| server.distance == best)
            .count();
        Replicas::new(replicas.into_boxed_slice(), count_best)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/server/tests.rs"]
mod tests;
