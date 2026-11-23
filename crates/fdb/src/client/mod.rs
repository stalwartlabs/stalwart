/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod balance;
pub(crate) mod clock;
pub(crate) mod cluster_file;
pub(crate) mod commit;
pub(crate) mod commit_buffer;
pub(crate) mod coordinator;
pub(crate) mod cursor;
pub(crate) mod dispatch;
pub(crate) mod endpoint;
pub(crate) mod expiry;
pub(crate) mod grv;
pub(crate) mod lagging;
pub(crate) mod location;
pub(crate) mod lookup;
pub(crate) mod proxies;
pub(crate) mod read_version;
pub(crate) mod retry;
#[cfg_attr(not(all(test, stalwart_tests)), expect(dead_code))]
pub(crate) mod server;
pub(crate) mod storage;
pub(crate) mod transaction;

use crate::api::{
    config::ClusterConfig,
    database::LoadBalanceStats,
    error::{ConnectError, ConnectPhase, Error, ErrorCode, OpenError, Result},
    read::Priority,
    transaction::Causality,
    version::{
        ProtocolPolicy, ProtocolVersion, ReadVersionCache, ReadVersionPolicy, Series, Version,
    },
};
use crate::{
    tls::{DEFAULT_REFRESH, Plaintext, TlsContext},
    transport::{self, Transport, TransportConfig},
};
use clock::Deadline;
use cluster_file::{ClusterFileRecord, ConnectionString};
use coordinator::{Monitor, ProxyWatch, StatusWatch};
use dispatch::Balancer;
use expiry::{Deadlines, Expiry, Precision, is_expired, timed_out};
use grv::{ReadVersions, Waiter};
use location::{LOCATION_CACHE_EVICTION_SIZE, LocationCache};
use lookup::LocationBackoff;
use read_version::{Lookup, VersionCache};
use server::{Location, ServerRegistry};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
};
use tokio::{runtime::Handle, select, sync::watch, time::Instant};

pub(crate) use cursor::CursorState;
pub(crate) use retry::Retry;
pub(crate) use transaction::TransactionState;

pub(crate) struct Cluster {
    #[expect(dead_code)]
    config: ClusterConfig,
    proxies: ProxyWatch,
    status: StatusWatch,
    grv: ReadVersions,
    versions: Arc<VersionCache>,
    runtime: Handle,
    transport: Transport,
    servers: ServerRegistry,
    locations: LocationCache<Location>,
    location_backoff: LocationBackoff,
    balancer: Balancer,
    plaintext: Plaintext,
    deadlines: Arc<Deadlines>,
    cluster_file: Option<PathBuf>,
    connection: ConnectionString,
    _shutdown: watch::Sender<()>,
}

impl Cluster {
    pub(crate) fn open(config: ClusterConfig) -> Result<Cluster, OpenError> {
        let runtime = Handle::try_current().map_err(|_| OpenError::NoRuntime)?;
        if config.read_version_cache.max_age > ReadVersionCache::MAX_AGE_LIMIT
            || config.read_version_cache.refresh_after > config.read_version_cache.max_age
        {
            return Err(OpenError::InvalidOption {
                reason: "read version cache ages must satisfy refresh_after <= max_age <= 5s"
                    .into(),
            });
        }
        let record = ClusterFileRecord::load(&config.cluster)?;
        let series = match config.protocol {
            ProtocolPolicy::Negotiate => Series::NEWEST,
            ProtocolPolicy::Fixed(series) => series,
        };
        let tls = TlsContext::from_mode(&config.tls, DEFAULT_REFRESH);
        if record.connection.uses_tls() {
            tls.validate().map_err(|error| OpenError::Tls {
                reason: error.to_string().into(),
            })?;
        }
        let plaintext = if tls.refuses_plaintext() {
            Plaintext::Refused
        } else {
            Plaintext::Allowed
        };
        let transport = Transport::new(TransportConfig {
            tls: Some(tls),
            ..TransportConfig::new(
                runtime.clone(),
                transport::ProtocolVersion::new(series.protocol_version().get()),
            )
        });
        let cluster_file = record.path.clone();
        let connection = record.connection.clone();
        let (shutdown_sender, shutdown) = watch::channel(());
        let (proxies, status) = Monitor::spawn(
            &runtime,
            transport.clone(),
            record,
            config.protocol,
            plaintext,
            shutdown.clone(),
        );
        let versions = Arc::new(VersionCache::new(config.read_version_cache));
        let deadlines = Deadlines::spawn(&runtime, shutdown.clone(), Precision::Coarse);
        Ok(Cluster {
            grv: ReadVersions::spawn(&runtime, &proxies, &versions, &shutdown),
            versions,
            proxies,
            status,
            servers: ServerRegistry::new(config.locality.datacenter_id.as_deref()),
            locations: LocationCache::new(LOCATION_CACHE_EVICTION_SIZE),
            location_backoff: LocationBackoff::default(),
            balancer: Balancer::new(&runtime, shutdown.clone()),
            plaintext,
            deadlines,
            cluster_file,
            connection,
            _shutdown: shutdown_sender,
            transport,
            config,
            runtime,
        })
    }

    pub(crate) fn cluster_file(&self) -> Option<&Path> {
        self.cluster_file.as_deref()
    }

    pub(crate) fn connection(&self) -> &ConnectionString {
        &self.connection
    }

    pub(crate) async fn read_version(
        &self,
        policy: ReadVersionPolicy,
        priority: Priority,
    ) -> Result<Version> {
        match policy {
            ReadVersionPolicy::At(version) => Ok(version),
            ReadVersionPolicy::Fresh => self.read_version_flight(priority).await,
            ReadVersionPolicy::Cached => match self.versions.lookup() {
                Lookup::Fresh(version) => Ok(version),
                Lookup::Stale(version) => {
                    self.refresh_in_background();
                    Ok(version)
                }
                Lookup::Expired => {
                    self.versions
                        .get_or_refresh(&self.runtime, || {
                            self.read_version_flight(Priority::Default)
                        })
                        .await
                }
            },
        }
    }

    fn refresh_in_background(&self) {
        self.versions.refresh_in_background(&self.runtime, || {
            self.read_version_flight(Priority::Default)
        });
    }

    fn read_version_flight(
        &self,
        priority: Priority,
    ) -> impl Future<Output = Result<Version>> + Send + 'static {
        self.grv.fetch(priority, Causality::Strict)
    }

    pub(crate) fn request_read_version(
        &self,
        waiter: Waiter,
        priority: Priority,
        causality: Causality,
    ) {
        self.grv.request(waiter, priority, causality);
    }

    pub(crate) fn advance_read_version(&self, version: Version) {
        self.versions.advance(version);
    }

    pub(crate) fn invalidate_read_version(&self) {
        self.versions.invalidate();
    }

    pub(crate) fn invalidate_read_version_if(&self, version: Version) {
        self.versions.invalidate_if(version);
    }

    pub(crate) fn committed(&self, version: Version) {
        self.versions.raise_floor(version);
    }

    pub(crate) fn last_committed_version(&self) -> Option<Version> {
        self.versions.last_committed()
    }

    pub(crate) async fn ready(&self) -> Result<(), ConnectError> {
        let mut proxies = self.proxies.clone();
        let mut status = self.status.clone();
        loop {
            let published = proxies.borrow_and_update().is_some();
            if let Some(error) = status
                .borrow_and_update()
                .fault
                .as_ref()
                .and_then(|fault| fault.blocking(published))
                && (published || proxies.borrow().is_none())
            {
                return Err(error.clone());
            }
            if published {
                return Ok(());
            }
            let changed = select! {
                changed = proxies.changed() => changed,
                changed = status.changed() => changed,
            };
            if changed.is_err() {
                return Err(ConnectError {
                    phase: ConnectPhase::Coordinator,
                    address: None,
                    error: Error::new(ErrorCode::OPERATION_CANCELLED),
                });
            }
        }
    }

    pub(crate) fn deadline(&self, at: Option<Instant>) -> Deadline {
        self.balancer.clock().deadline(at)
    }

    pub(crate) fn expiry<F>(&self, deadline: Deadline, future: F) -> Expiry<'_, F> {
        Expiry::new(
            &self.deadlines,
            self.balancer.clock().instant(deadline),
            future,
        )
    }

    pub(crate) fn deadlines(&self) -> &Deadlines {
        &self.deadlines
    }

    pub(crate) fn load_balance_stats(&self) -> LoadBalanceStats {
        let counters = self.balancer.counters();
        LoadBalanceStats {
            hedges_granted: counters.hedges_granted.load(Ordering::Relaxed),
            hedges_refused: counters.hedges_refused.load(Ordering::Relaxed),
            lagging_requests: counters.lagging.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn check_deadline(&self, deadline: Deadline) -> Result<()> {
        match self.balancer.clock().instant(deadline) {
            Some(at) if is_expired(at) => Err(timed_out()),
            _ => Ok(()),
        }
    }

    pub(crate) fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.status
            .borrow()
            .version
            .map(|version| ProtocolVersion::new(version.get()))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/tests.rs"]
mod tests;
