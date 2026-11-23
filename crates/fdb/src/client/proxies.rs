/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    coordinator::ProxyWatch,
    dispatch::{any_state_changed, transport_error},
    endpoint::{adjusted_token, peer_address, socket_addr},
};
use crate::{
    api::error::{Error, ErrorCode, Result},
    codec::{DecodeError, Uid},
    tls::Plaintext,
    transport::{
        ConnectFailure, EndpointHealth, FrameSize, Peer, ProtocolVersion, QueuedFrame, Transport,
        TransportError,
    },
    wire::{ClientDBInfo, RequestStream},
};
use bytes::Bytes;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{select, time::sleep};

pub(crate) const MAX_COMMIT_PROXIES: usize = 5;
pub(crate) const MAX_GRV_PROXIES: usize = 3;
const GET_KEY_SERVER_LOCATIONS_INDEX: u32 = 2;
const START_BACKOFF: f64 = 0.01;
const MAX_BACKOFF: f64 = 5.0;
const BACKOFF_RATE: f64 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyRole {
    Grv,
    Commit,
    Locations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
    AtLeastOnce,
    AtMostOnce,
}

pub(crate) struct ProxySet {
    tls: bool,
    refused: Option<SocketAddr>,
    pub(super) grv: Box<[ProxyEndpoint]>,
    pub(super) commit: Box<[ProxyEndpoint]>,
    pub(super) locations: Box<[ProxyEndpoint]>,
}

pub(super) struct ProxyEndpoint {
    pub(super) peer: Peer,
    pub(super) health: EndpointHealth,
}

#[derive(Default)]
pub(crate) struct ProxySample {
    commit: Sample,
    grv: Sample,
}

#[derive(Default)]
struct Sample {
    tokens: Vec<Uid>,
    chosen: Vec<usize>,
}

impl ProxySet {
    pub(crate) fn from_info(
        transport: &Transport,
        info: &ClientDBInfo<'_>,
        tls: bool,
        plaintext: Plaintext,
        sample: &mut ProxySample,
    ) -> Result<Option<ProxySet>, DecodeError> {
        let mut grv = info
            .grv_proxies
            .iter()
            .map(|proxy| proxy.map(|proxy| (proxy.provisional, proxy.get_consistent_read_version)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut commit = info
            .commit_proxies
            .iter()
            .map(|proxy| proxy.map(|proxy| (proxy.provisional, proxy.commit)))
            .collect::<Result<Vec<_>, _>>()?;
        if grv.is_empty()
            || commit.is_empty()
            || grv
                .iter()
                .chain(&commit)
                .any(|(provisional, _)| *provisional)
        {
            return Ok(None);
        }
        let address =
            |stream: &RequestStream| peer_address(&stream.endpoint.addresses, tls, plaintext);
        let first = |streams: &[(bool, RequestStream)]| {
            streams
                .first()
                .map(|(_, stream)| socket_addr(&stream.endpoint.addresses.address))
        };
        let (first_grv, first_commit) = (first(&grv), first(&commit));
        grv.retain(|(_, stream)| address(stream).is_some());
        commit.retain(|(_, stream)| address(stream).is_some());
        let refused = if grv.is_empty() {
            first_grv
        } else if commit.is_empty() {
            first_commit
        } else {
            None
        };
        let endpoint = |stream: &RequestStream, index: u32| {
            address(stream).map(|address| ProxyEndpoint {
                peer: transport.peer(address),
                health: EndpointHealth::new(adjusted_token(stream.endpoint.token, index)),
            })
        };
        let commit = sample.commit.choose(&commit, MAX_COMMIT_PROXIES);
        let grv = sample.grv.choose(&grv, MAX_GRV_PROXIES);
        Ok(Some(ProxySet {
            tls,
            refused,
            grv: grv.filter_map(|(_, stream)| endpoint(stream, 0)).collect(),
            commit: commit
                .clone()
                .filter_map(|(_, stream)| endpoint(stream, 0))
                .collect(),
            locations: commit
                .filter_map(|(_, stream)| endpoint(stream, GET_KEY_SERVER_LOCATIONS_INDEX))
                .collect(),
        }))
    }

    pub(crate) fn tls(&self) -> bool {
        self.tls
    }

    #[cfg(all(test, stalwart_tests))]
    pub(super) fn grv_only(grv: Box<[ProxyEndpoint]>) -> Self {
        ProxySet {
            tls: false,
            refused: None,
            grv,
            commit: Box::new([]),
            locations: Box::new([]),
        }
    }

    pub(crate) fn refused(&self) -> Option<SocketAddr> {
        self.refused
    }

    pub(crate) fn same_endpoints(&self, other: &ProxySet) -> bool {
        self.tls == other.tls
            && same_endpoints(&self.grv, &other.grv)
            && same_endpoints(&self.commit, &other.commit)
    }

    fn endpoints(&self, role: ProxyRole) -> &[ProxyEndpoint] {
        match role {
            ProxyRole::Grv => &self.grv,
            ProxyRole::Commit => &self.commit,
            ProxyRole::Locations => &self.locations,
        }
    }

    pub(crate) fn request<T>(
        &self,
        role: ProxyRole,
        delivery: Delivery,
        encode: impl Fn(Uid, ProtocolVersion, &mut Vec<u8>),
        decode: impl Fn(Bytes, ProtocolVersion) -> Result<T, ErrorCode>,
    ) -> impl Future<Output = Result<T>> {
        self.request_sized(role, delivery, FrameSize::Small, encode, decode)
    }

    pub(crate) fn request_sized<T>(
        &self,
        role: ProxyRole,
        delivery: Delivery,
        size: FrameSize,
        encode: impl Fn(Uid, ProtocolVersion, &mut Vec<u8>),
        decode: impl Fn(Bytes, ProtocolVersion) -> Result<T, ErrorCode>,
    ) -> impl Future<Output = Result<T>> {
        self.send_until(role, delivery, size, || true, |_| {}, encode, decode)
    }

    pub(crate) fn request_while<T>(
        &self,
        role: ProxyRole,
        delivery: Delivery,
        wanted: impl FnMut() -> bool,
        queued: impl FnMut(QueuedFrame),
        encode: impl Fn(Uid, ProtocolVersion, &mut Vec<u8>),
        decode: impl Fn(Bytes, ProtocolVersion) -> Result<T, ErrorCode>,
    ) -> impl Future<Output = Result<T>> {
        self.send_until(
            role,
            delivery,
            FrameSize::Small,
            wanted,
            queued,
            encode,
            decode,
        )
    }

    #[expect(clippy::too_many_arguments)]
    async fn send_until<T>(
        &self,
        role: ProxyRole,
        delivery: Delivery,
        size: FrameSize,
        mut wanted: impl FnMut() -> bool,
        mut queued: impl FnMut(QueuedFrame),
        encode: impl Fn(Uid, ProtocolVersion, &mut Vec<u8>),
        decode: impl Fn(Bytes, ProtocolVersion) -> Result<T, ErrorCode>,
    ) -> Result<T> {
        let endpoints = self.endpoints(role);
        let count = endpoints.len();
        if count == 0 {
            return Err(Error::new(ErrorCode::TLS_ERROR));
        }
        let mut next = fastrand::usize(..count);
        let mut attempts = 0;
        let mut backoff = 0.0;
        loop {
            let Some((index, endpoint)) = (0..count)
                .map(|offset| (next + offset) % count)
                .filter_map(|index| endpoints.get(index).map(|endpoint| (index, endpoint)))
                .find(|(_, endpoint)| endpoint.is_healthy())
            else {
                Box::pin(wait_for_healthy(endpoints)).await?;
                attempts = 0;
                continue;
            };
            if backoff > 0.0 {
                sleep(Duration::from_secs_f64(backoff)).await;
            }
            if !wanted() {
                return Err(Error::new(ErrorCode::OPERATION_CANCELLED));
            }
            let token = endpoint.health.token();
            match endpoint
                .peer
                .request_with(token, &encode, &mut queued)
                .with_size(size)
                .await
            {
                Ok((bytes, version)) => match decode(bytes, version) {
                    Ok(value) => return Ok(value),
                    Err(ErrorCode::BROKEN_PROMISE) => endpoint.peer.mark_endpoint_failed(token),
                    Err(ErrorCode::REQUEST_MAYBE_DELIVERED) => {}
                    Err(code) => return Err(Error::new(code)),
                },
                Err(TransportError::MaybeDelivered) => {}
                Err(error) => return Err(transport_error(error)),
            }
            if delivery == Delivery::AtMostOnce {
                return Err(Error::new(ErrorCode::REQUEST_MAYBE_DELIVERED));
            }
            attempts += 1;
            if attempts >= count {
                backoff = (backoff * BACKOFF_RATE).clamp(START_BACKOFF, MAX_BACKOFF);
            }
            next = (index + 1) % count;
        }
    }
}

pub(crate) async fn with_proxies<T, Fut>(
    proxies: &mut ProxyWatch,
    delivery: Delivery,
    mut request: impl FnMut(Arc<ProxySet>) -> Fut,
) -> Result<T>
where
    Fut: Future<Output = Result<T>>,
{
    loop {
        let current = proxies.borrow_and_update().clone();
        let Some(set) = current else {
            proxies
                .changed()
                .await
                .map_err(|_| Error::new(ErrorCode::OPERATION_CANCELLED))?;
            continue;
        };
        select! {
            result = request(set) => return result,
            changed = proxies.changed() => {
                changed.map_err(|_| Error::new(ErrorCode::OPERATION_CANCELLED))?;
                if delivery == Delivery::AtMostOnce {
                    return Err(Error::new(ErrorCode::REQUEST_MAYBE_DELIVERED));
                }
            }
        }
    }
}

#[cold]
async fn wait_for_healthy(endpoints: &[ProxyEndpoint]) -> Result<()> {
    let mut states: Vec<_> = endpoints
        .iter()
        .map(|endpoint| endpoint.peer.watch_state())
        .collect();
    while !endpoints.iter().any(ProxyEndpoint::is_healthy) {
        if endpoints.iter().all(ProxyEndpoint::is_refused_locally) {
            return Err(Error::new(ErrorCode::TLS_ERROR));
        }
        any_state_changed(&mut states).await;
    }
    Ok(())
}

impl ProxyEndpoint {
    fn is_healthy(&self) -> bool {
        !self.peer.is_failed() && !self.peer.is_endpoint_failed(&self.health)
    }

    fn is_refused_locally(&self) -> bool {
        matches!(
            self.peer.last_connect_failure(),
            Some(
                ConnectFailure::TlsConfig(_)
                    | ConnectFailure::TlsNotConfigured
                    | ConnectFailure::PlaintextRefused
            )
        )
    }
}

fn same_endpoints(left: &[ProxyEndpoint], right: &[ProxyEndpoint]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.health.token() == right.health.token()
                && left.peer.address() == right.peer.address()
        })
}

impl Sample {
    fn choose<'a>(
        &'a mut self,
        proxies: &'a [(bool, RequestStream)],
        max: usize,
    ) -> impl Iterator<Item = &'a (bool, RequestStream)> + Clone + 'a {
        if proxies.len() > max {
            if self.tokens.len() != proxies.len()
                || self
                    .tokens
                    .iter()
                    .zip(proxies)
                    .any(|(token, (_, proxy))| *token != proxy.endpoint.token)
            {
                self.tokens.clear();
                self.tokens
                    .extend(proxies.iter().map(|(_, proxy)| proxy.endpoint.token));
                self.chosen.clear();
                self.chosen.extend(0..proxies.len());
                fastrand::shuffle(&mut self.chosen);
                self.chosen.truncate(max);
            }
        } else {
            self.tokens.clear();
            self.chosen.clear();
            self.chosen.extend(0..proxies.len());
        }
        self.chosen.iter().filter_map(|&index| proxies.get(index))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/proxies/tests.rs"]
mod tests;
