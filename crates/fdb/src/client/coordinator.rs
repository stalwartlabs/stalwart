/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    cluster_file::{
        ClusterFileRecord, ConnectionString, CoordinatorAddress, CoordinatorHost, Encryption,
    },
    dispatch::transport_error,
    endpoint::network_address,
    proxies::{ProxySample, ProxySet},
};
use crate::{
    api::{
        error::{ConnectError, ConnectPhase, Error, ErrorCode},
        version::{self, ProtocolPolicy},
    },
    codec::Uid,
    tls::Plaintext,
    transport::{ConnectFailure, PeerAddress, ProtocolVersion, Transport, TransportError},
    wire::{ClientDBInfo, Dialect, Hostname, OpenDatabaseCoordRequest, Reply},
};
use rustls::Error as TlsError;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::lookup_host, runtime::Handle, select, sync::watch, time::sleep};

const RECONNECTION_DELAY: Duration = Duration::from_secs(1);
const OPEN_DATABASE_TOKEN_V71: u64 = 3;
const OPEN_DATABASE_TOKEN: u64 = 4;

pub(crate) type ProxyWatch = watch::Receiver<Option<Arc<ProxySet>>>;
pub(crate) type StatusWatch = watch::Receiver<ConnectStatus>;
pub(crate) type Shutdown = watch::Receiver<()>;
type ProxySender = watch::Sender<Option<Arc<ProxySet>>>;

#[derive(Default)]
pub(crate) struct ConnectStatus {
    pub(crate) version: Option<ProtocolVersion>,
    pub(crate) fault: Option<Fault>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fault {
    Unreachable(ConnectError),
    Unusable(ConnectError),
    NoProxies(Box<str>),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ProxyState {
    #[default]
    Usable,
    Refused(SocketAddr),
    Missing,
}

pub(crate) struct Monitor {
    transport: Transport,
    status: watch::Sender<ConnectStatus>,
    record: ClusterFileRecord,
    policy: ProtocolPolicy,
    plaintext: Plaintext,
    known: Uid,
    sample: ProxySample,
    proxy_state: ProxyState,
}

enum Coordinator<'a> {
    Address(&'a CoordinatorAddress),
    Host(&'a CoordinatorHost),
}

enum Outcome {
    Updated,
    Forward(ConnectionString),
    Retry,
    Failed(Failure),
}

struct Failure {
    phase: ConnectPhase,
    code: ErrorCode,
}

impl Monitor {
    pub(crate) fn spawn(
        runtime: &Handle,
        transport: Transport,
        record: ClusterFileRecord,
        policy: ProtocolPolicy,
        plaintext: Plaintext,
        shutdown: Shutdown,
    ) -> (ProxyWatch, StatusWatch) {
        let (sender, receiver) = watch::channel(None);
        let (status, status_receiver) = watch::channel(ConnectStatus::default());
        let monitor = Monitor {
            transport,
            status,
            record,
            policy,
            plaintext,
            known: Uid::ZERO,
            sample: ProxySample::default(),
            proxy_state: ProxyState::Usable,
        };
        runtime.spawn(monitor.run(sender, shutdown));
        (receiver, status_receiver)
    }

    async fn run(mut self, sender: ProxySender, mut shutdown: Shutdown) {
        let mut connection = self.record.connection.clone();
        loop {
            connection = select! {
                () = sender.closed() => return,
                () = shut_down(&mut shutdown) => return,
                next = self.generation(&sender, &connection) => next,
            };
        }
    }

    async fn generation(
        &mut self,
        sender: &ProxySender,
        connection: &ConnectionString,
    ) -> ConnectionString {
        let services: Vec<String> = connection
            .hostnames
            .iter()
            .map(|host| host.port.to_string())
            .collect();
        let mut coordinators: Vec<Coordinator<'_>> = connection
            .hostnames
            .iter()
            .map(Coordinator::Host)
            .chain(connection.addresses.iter().map(Coordinator::Address))
            .collect();
        fastrand::shuffle(&mut coordinators);
        let count = coordinators.len();
        let mut index = 0;
        let mut success = 0;
        let mut all_failed = false;
        loop {
            if all_failed && let Some(stored) = self.record.changed_on_disk() {
                self.record.connection = stored.clone();
                self.switched();
                return stored;
            }
            let Some(coordinator) = coordinators.get(index) else {
                sleep(RECONNECTION_DELAY).await;
                return self.record.connection.clone();
            };
            match self
                .open_database(sender, connection, &services, coordinator)
                .await
            {
                Outcome::Updated => {
                    if *connection != self.record.connection {
                        self.record.connection = connection.clone();
                        let _ = self.record.persist();
                    }
                    success = index;
                    all_failed = false;
                }
                Outcome::Forward(next) => {
                    self.switched();
                    return next;
                }
                Outcome::Retry => {}
                Outcome::Failed(failure) => {
                    index = (index + 1) % count;
                    if index == success {
                        self.failed(failure, coordinator);
                        all_failed = true;
                        sleep(RECONNECTION_DELAY).await;
                    }
                }
            }
        }
    }

    async fn open_database(
        &mut self,
        sender: &ProxySender,
        connection: &ConnectionString,
        services: &[String],
        coordinator: &Coordinator<'_>,
    ) -> Outcome {
        let address = match coordinator {
            Coordinator::Address(address) => {
                PeerAddress::new(address.addr, address.encryption == Encryption::Tls)
            }
            Coordinator::Host(host) => match resolve(host).await {
                Some(address) => address,
                None => {
                    return Outcome::Failed(Failure::new(
                        ConnectPhase::Resolve,
                        ErrorCode::CONNECTION_FAILED,
                    ));
                }
            },
        };
        let peer = self.transport.peer(address);
        let token = Uid::well_known(match Dialect::of(self.transport.protocol_version().get()) {
            Dialect::V71 => OPEN_DATABASE_TOKEN_V71,
            _ => OPEN_DATABASE_TOKEN,
        });
        let known = self.known;
        let mut state = peer.watch_state();
        let reply = peer
            .request(token, |reply, version, out| {
                OpenDatabaseCoordRequest {
                    known_client_info_id: known,
                    cluster_key: connection.key.as_bytes(),
                    coordinators: connection.addresses.iter().map(|address| {
                        network_address(address.addr, address.encryption == Encryption::Tls)
                    }),
                    hostnames: connection
                        .hostnames
                        .iter()
                        .zip(services)
                        .map(|(host, service)| Hostname {
                            host: host.host.as_bytes(),
                            service: service.as_bytes(),
                            is_tls: host.encryption == Encryption::Tls,
                        }),
                }
                .encode(Dialect::of(version.get()), reply, out);
            })
            .await;
        let (bytes, version) = match reply {
            Ok(reply) => reply,
            Err(TransportError::Incompatible { server })
                if server == self.transport.protocol_version() =>
            {
                return select! {
                    _ = state.changed() => Outcome::Retry,
                    () = sleep(RECONNECTION_DELAY) => Outcome::Failed(Failure::INCOMPATIBLE),
                };
            }
            Err(TransportError::Incompatible { server }) => return self.adopt(server),
            Err(TransportError::MaybeDelivered) => {
                return Outcome::Failed(peer.last_connect_failure().map_or(
                    Failure::new(
                        ConnectPhase::Coordinator,
                        ErrorCode::REQUEST_MAYBE_DELIVERED,
                    ),
                    Failure::from_connect,
                ));
            }
            Err(error) => {
                return Outcome::Failed(Failure::new(
                    ConnectPhase::Coordinator,
                    transport_error(error).error_code(),
                ));
            }
        };
        let dialect = Dialect::of(version.get());
        let info = match ClientDBInfo::decode(dialect, &bytes) {
            Ok(Reply::Value(info)) => info,
            Ok(Reply::Error(code)) => {
                return Outcome::Failed(Failure::new(
                    ConnectPhase::Coordinator,
                    ErrorCode::from_wire(dialect, code),
                ));
            }
            Err(_) => return Outcome::Failed(Failure::INVALID_REPLY),
        };
        if let Some(forward) = info.forward {
            return self.forward(forward);
        }
        if info.id == self.known {
            self.connected(version, coordinator);
            return Outcome::Updated;
        }
        let Ok(proxies) = ProxySet::from_info(
            &self.transport,
            &info,
            connection.uses_tls(),
            self.plaintext,
            &mut self.sample,
        ) else {
            return Outcome::Failed(Failure::INVALID_REPLY);
        };
        self.known = info.id;
        self.proxy_state = match &proxies {
            Some(set) => set
                .refused()
                .map_or(ProxyState::Usable, ProxyState::Refused),
            None => ProxyState::Missing,
        };
        self.connected(version, coordinator);
        sender.send_if_modified(|current| {
            let changed = match (current.as_deref(), &proxies) {
                (Some(current), Some(next)) => !current.same_endpoints(next),
                (None, None) => false,
                _ => true,
            };
            if changed {
                *current = proxies.map(Arc::new);
            }
            changed
        });
        Outcome::Updated
    }

    fn forward(&self, forward: &[u8]) -> Outcome {
        match ConnectionString::parse(forward) {
            Ok(next) if next.uses_tls() || self.plaintext == Plaintext::Allowed => {
                Outcome::Forward(next)
            }
            Ok(_) => Outcome::Failed(Failure::new(
                ConnectPhase::Coordinator,
                ErrorCode::TLS_ERROR,
            )),
            Err(_) => Outcome::Failed(Failure::new(
                ConnectPhase::Coordinator,
                ErrorCode::CONNECTION_STRING_INVALID,
            )),
        }
    }

    fn adopt(&self, server: ProtocolVersion) -> Outcome {
        let supported = match self.policy {
            ProtocolPolicy::Negotiate => Dialect::from_protocol(server.get()).is_some(),
            ProtocolPolicy::Fixed(series) => {
                version::ProtocolVersion::new(server.get()).series() == Some(series)
            }
        };
        if supported && server != self.transport.protocol_version() {
            self.transport.set_protocol_version(server);
            Outcome::Retry
        } else {
            Outcome::Failed(Failure::INCOMPATIBLE)
        }
    }

    fn connected(&self, version: ProtocolVersion, coordinator: &Coordinator<'_>) {
        let fault = match self.proxy_state {
            ProxyState::Usable => None,
            ProxyState::Refused(address) => Some(Fault::Unusable(ConnectError {
                phase: ConnectPhase::Connect,
                address: Some(address.to_string().into_boxed_str()),
                error: Error::new(ErrorCode::TLS_ERROR),
            })),
            ProxyState::Missing => Some(Fault::NoProxies(coordinator.address())),
        };
        self.status.send_if_modified(|status| {
            let changed = status.version != Some(version) || status.fault != fault;
            status.version = Some(version);
            status.fault = fault;
            changed
        });
    }

    #[cold]
    fn failed(&self, failure: Failure, coordinator: &Coordinator<'_>) {
        let error = ConnectError {
            phase: failure.phase,
            address: Some(coordinator.address()),
            error: Error::new(failure.code),
        };
        self.status.send_modify(|status| {
            status.fault = match status.fault.take() {
                _ if failure.is_permanent() => Some(Fault::Unusable(error)),
                Some(Fault::Unusable(previous)) => Some(Fault::Unusable(previous)),
                _ => Some(Fault::Unreachable(error)),
            };
        });
    }

    fn switched(&self) {
        self.status.send_if_modified(|status| {
            let unreachable = matches!(status.fault, Some(Fault::Unreachable(_)));
            if unreachable {
                status.fault = None;
            }
            unreachable
        });
    }
}

impl Coordinator<'_> {
    fn address(&self) -> Box<str> {
        match self {
            Coordinator::Address(address) => address.to_string(),
            Coordinator::Host(host) => host.to_string(),
        }
        .into_boxed_str()
    }
}

impl Fault {
    pub(crate) fn blocking(&self, published: bool) -> Option<&ConnectError> {
        match self {
            Fault::Unusable(error) => Some(error),
            Fault::Unreachable(error) => (!published).then_some(error),
            Fault::NoProxies(_) => None,
        }
    }
}

impl Failure {
    const INCOMPATIBLE: Failure = Failure::new(
        ConnectPhase::Protocol,
        ErrorCode::INCOMPATIBLE_PROTOCOL_VERSION,
    );
    const INVALID_REPLY: Failure =
        Failure::new(ConnectPhase::Coordinator, ErrorCode::INTERNAL_ERROR);

    const fn new(phase: ConnectPhase, code: ErrorCode) -> Self {
        Failure { phase, code }
    }

    fn is_permanent(&self) -> bool {
        self.code == ErrorCode::INCOMPATIBLE_PROTOCOL_VERSION
    }

    #[cold]
    fn from_connect(failure: ConnectFailure) -> Self {
        let (phase, code) = match failure {
            ConnectFailure::ConnectTimeout
            | ConnectFailure::Connect(_)
            | ConnectFailure::Throttled => (ConnectPhase::Connect, ErrorCode::CONNECTION_FAILED),
            ConnectFailure::PlaintextRefused | ConnectFailure::TlsNotConfigured => {
                (ConnectPhase::Connect, ErrorCode::TLS_ERROR)
            }
            ConnectFailure::TlsConfig(_)
            | ConnectFailure::HandshakeTimeout
            | ConnectFailure::Handshake(_) => (ConnectPhase::TlsHandshake, ErrorCode::TLS_ERROR),
            ConnectFailure::Tls(TlsError::InvalidCertificate(_)) => {
                (ConnectPhase::PeerVerification, ErrorCode::TLS_ERROR)
            }
            ConnectFailure::Tls(_) => (ConnectPhase::TlsHandshake, ErrorCode::TLS_ERROR),
            ConnectFailure::Closed(_) | ConnectFailure::NoHello | ConnectFailure::Protocol => {
                (ConnectPhase::Protocol, ErrorCode::CONNECTION_FAILED)
            }
            ConnectFailure::Incompatible { .. } => (
                ConnectPhase::Protocol,
                ErrorCode::INCOMPATIBLE_PROTOCOL_VERSION,
            ),
        };
        Failure::new(phase, code)
    }
}

pub(crate) async fn shut_down(shutdown: &mut Shutdown) {
    while shutdown.changed().await.is_ok() {}
}

async fn resolve(host: &CoordinatorHost) -> Option<PeerAddress> {
    let addr = lookup_host((&*host.host, host.port)).await.ok()?.next()?;
    Some(PeerAddress::new(addr, host.encryption == Encryption::Tls))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/coordinator/tests.rs"]
mod tests;
