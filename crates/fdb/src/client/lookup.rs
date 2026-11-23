/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Cluster,
    endpoint::peer_address,
    location::Shard,
    proxies::{Delivery, ProxyRole, with_proxies},
    server::{Channel, Location, ServerInterface},
    transaction::Cancellation,
};
use crate::{
    api::{
        error::{ErrorCode, Result},
        range::Direction,
        version::Version,
    },
    codec::DecodeError,
    transport::ProtocolVersion,
    wire::{Dialect, GetKeyServerLocationsReply, GetKeyServerLocationsRequest, Locality, Reply},
};
use parking_lot::Mutex;
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;

const STORAGE_METRICS_SHARD_LIMIT: i32 = 100;
const KEY_LOCATION_LIMIT: i32 = 100;
const GET_RANGE_SHARD_LIMIT: i32 = 2;
const LATEST_VERSION: i64 = -2;
const DEFAULT_BACKOFF: f64 = 0.01;
const BACKOFF_GROWTH_RATE: f64 = 2.0;
const RESOURCE_CONSTRAINED_MAX_BACKOFF: f64 = 30.0;
const DATACENTER_ID: &[u8] = b"dcid";
pub(super) const ALL_KEYS_END: &[u8] = b"\xff\xff";

const _: () = assert!(KEY_LOCATION_LIMIT == STORAGE_METRICS_SHARD_LIMIT);
const _: () = assert!(KEY_LOCATION_LIMIT as usize <= GetKeyServerLocationsReply::MAX_RESULTS);
const _: () = assert!(GET_RANGE_SHARD_LIMIT as usize <= GetKeyServerLocationsReply::MAX_RESULTS);

pub(crate) type ShardLocation = Arc<Shard<Location>>;

#[derive(Default)]
pub(crate) struct LocationBackoff(Mutex<f64>);

impl LocationBackoff {
    fn delay(&self) -> f64 {
        *self.0.lock()
    }

    fn succeeded(&self) {
        let mut delay = self.0.lock();
        if *delay > 0.0 {
            *delay /= BACKOFF_GROWTH_RATE;
            if *delay < DEFAULT_BACKOFF {
                *delay = 0.0;
            }
        }
    }

    fn overloaded(&self) {
        let mut delay = self.0.lock();
        *delay = if *delay == 0.0 {
            DEFAULT_BACKOFF
        } else {
            (*delay * BACKOFF_GROWTH_RATE).min(RESOURCE_CONSTRAINED_MAX_BACKOFF)
        };
    }
}

impl Cluster {
    pub(crate) fn locate_key<'a>(
        &'a self,
        key: &'a [u8],
        direction: Direction,
        channel: Channel,
        version: Option<Version>,
        cancel: Option<&'a Cancellation>,
    ) -> impl Future<Output = Result<ShardLocation>> + Send + 'a {
        debug_assert!(match direction {
            Direction::Forward => key < ALL_KEYS_END,
            Direction::Reverse => !key.is_empty() && key <= ALL_KEYS_END,
        });
        let request = GetKeyServerLocationsRequest {
            begin: key,
            end: None,
            limit: KEY_LOCATION_LIMIT,
            reverse: direction == Direction::Reverse,
            version: version.map_or(LATEST_VERSION, Version::get),
        };
        self.locate(key, direction, channel, request, cancel)
    }

    pub(crate) fn locate_range<'a>(
        &'a self,
        begin: &'a [u8],
        end: &'a [u8],
        direction: Direction,
        channel: Channel,
        version: Option<Version>,
        cancel: Option<&'a Cancellation>,
    ) -> impl Future<Output = Result<ShardLocation>> + Send + 'a {
        debug_assert!(begin < end);
        let edge = match direction {
            Direction::Forward => begin,
            Direction::Reverse => end,
        };
        let request = GetKeyServerLocationsRequest {
            begin,
            end: Some(end),
            limit: GET_RANGE_SHARD_LIMIT,
            reverse: direction == Direction::Reverse,
            version: version.map_or(LATEST_VERSION, Version::get),
        };
        self.locate(edge, direction, channel, request, cancel)
    }

    async fn locate(
        &self,
        edge: &[u8],
        direction: Direction,
        channel: Channel,
        request: GetKeyServerLocationsRequest<'_>,
        cancel: Option<&Cancellation>,
    ) -> Result<ShardLocation> {
        if let Some(shard) = self.locations.locate(edge, direction) {
            if !shard
                .location()
                .needs_refresh(channel, || self.balancer.now())
            {
                return Ok(shard);
            }
            self.locations.invalidate_key(edge, direction);
        }
        Box::pin(self.fetch_locations(edge, direction, &request, cancel)).await
    }

    async fn fetch_locations(
        &self,
        edge: &[u8],
        direction: Direction,
        request: &GetKeyServerLocationsRequest<'_>,
        cancel: Option<&Cancellation>,
    ) -> Result<ShardLocation> {
        let fetch = self.request_locations(edge, direction, request);
        match cancel {
            Some(cancel) => cancel.race(&self.deadlines, fetch).await?,
            None => fetch.await,
        }
    }

    async fn request_locations(
        &self,
        edge: &[u8],
        direction: Direction,
        request: &GetKeyServerLocationsRequest<'_>,
    ) -> Result<ShardLocation> {
        let mut proxies = self.proxies.clone();
        loop {
            let delay = self.location_backoff.delay();
            if delay > 0.0 {
                sleep(Duration::from_secs_f64(delay)).await;
            }
            let result = with_proxies(&mut proxies, Delivery::AtLeastOnce, |set| async move {
                set.request(
                    ProxyRole::Locations,
                    Delivery::AtLeastOnce,
                    |reply, version, out| {
                        request.encode(Dialect::of(version.get()), reply, out);
                    },
                    |bytes, version| {
                        self.cache_locations(&bytes, version, set.tls(), edge, direction)
                    },
                )
                .await
            })
            .await;
            match result {
                Err(error)
                    if error.error_code() == ErrorCode::COMMIT_PROXY_MEMORY_LIMIT_EXCEEDED =>
                {
                    self.location_backoff.overloaded();
                }
                result => {
                    if result.is_ok() {
                        self.location_backoff.succeeded();
                    }
                    return result;
                }
            }
        }
    }

    fn cache_locations(
        &self,
        bytes: &[u8],
        version: ProtocolVersion,
        tls: bool,
        edge: &[u8],
        direction: Direction,
    ) -> Result<ShardLocation, ErrorCode> {
        let dialect = Dialect::of(version.get());
        let reply = match GetKeyServerLocationsReply::decode(dialect, bytes) {
            Ok(Reply::Value(reply)) => reply,
            Ok(Reply::Error(code)) => return Err(ErrorCode::from_wire(dialect, code)),
            Err(_) => return Err(ErrorCode::INTERNAL_ERROR),
        };
        let now = self.balancer.now();
        let mut interfaces = Vec::new();
        let mut first = None;
        for result in reply.results.iter() {
            let result = result.map_err(|_| ErrorCode::INTERNAL_ERROR)?;
            interfaces.clear();
            let mut refused = false;
            for server in result.servers.iter() {
                let server = server.map_err(|_| ErrorCode::INTERNAL_ERROR)?;
                let endpoint = server.get_value.endpoint;
                let Some(address) = peer_address(&endpoint.addresses, tls, self.plaintext) else {
                    refused = true;
                    continue;
                };
                interfaces.push(ServerInterface {
                    id: server.id,
                    address,
                    get_value: endpoint.token,
                    datacenter_id: datacenter_id(&server.locality)
                        .map_err(|_| ErrorCode::INTERNAL_ERROR)?,
                });
            }
            let location = self
                .servers
                .location(&self.transport, now, interfaces.drain(..));
            let shard = match location {
                Some(location) => Shard::new(result.range.begin, result.range.end, location)
                    .map(|shard| self.locations.insert(shard))
                    .ok_or(ErrorCode::INTERNAL_ERROR)?,
                None if first.is_some() => continue,
                None if refused => return Err(ErrorCode::TLS_ERROR),
                None => return Err(ErrorCode::ALL_ALTERNATIVES_FAILED),
            };
            if first.is_none() {
                if !contains(&shard, edge, direction) {
                    return Err(ErrorCode::INTERNAL_ERROR);
                }
                first = Some(shard);
            }
        }
        first.ok_or(ErrorCode::INTERNAL_ERROR)
    }
}

fn contains(shard: &Shard<Location>, key: &[u8], direction: Direction) -> bool {
    match direction {
        Direction::Forward => shard.begin() <= key && key < shard.end(),
        Direction::Reverse => shard.begin() < key && key <= shard.end(),
    }
}

fn datacenter_id<'a>(locality: &Locality<'a>) -> Result<Option<&'a [u8]>, DecodeError> {
    for entry in locality.entries.iter() {
        let entry = entry?;
        if entry.key == DATACENTER_ID {
            return Ok(entry.value);
        }
    }
    Ok(None)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/lookup/tests.rs"]
mod tests;
