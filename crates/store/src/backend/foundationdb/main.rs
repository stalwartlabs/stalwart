/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::FdbStore;
use crate::{
    Store,
    backend::foundationdb_config::{ClusterLocation, ManualTls, OpenReport, Pem, cluster_opened},
    registry::bootstrap::Bootstrap,
};
use fdb::{
    ClusterConfig, ClusterSource, ConnectPhase, ConnectionString, Database, Locality, PemSource,
    Plaintext, ProtocolPolicy, Series, TlsConfig, TlsMode, TransactionDefaults,
};
use registry::{
    schema::{
        enums::FoundationDbProtocol,
        prelude::ObjectType,
        structs::{self, FoundationDbTls},
    },
    types::id::ObjectId,
};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
use trc::{Key, StoreEvent};

const READY_TIMEOUT: Duration = Duration::from_secs(10);

enum NotReady {
    Fault(trc::Error),
    Timeout(trc::Error),
}

impl FdbStore {
    pub async fn open(config: structs::FoundationDbStore) -> Result<Store, String> {
        Self::open_with(config, OpenReport::Event, ObjectType::DataStore.singleton()).await
    }

    pub async fn open_shared(
        config: structs::FoundationDbStore,
        bp: &mut Bootstrap,
        object_id: ObjectId,
    ) -> Result<Store, String> {
        Self::open_with(config, OpenReport::Bootstrap(bp), object_id).await
    }

    pub fn report_opened(&self, bp: &mut Bootstrap) {
        bp.notices.push(database_opened(&self.db));
    }

    async fn open_with(
        config: structs::FoundationDbStore,
        mut report: OpenReport<'_>,
        object_id: ObjectId,
    ) -> Result<Store, String> {
        let cluster = cluster_config(&config).await?;
        let defaults = TransactionDefaults {
            timeout: config.transaction_timeout.map(|value| value.into_inner()),
            retry_limit: config
                .transaction_retry_limit
                .map(|value| u32::try_from(value).unwrap_or(u32::MAX)),
            max_retry_delay: config
                .transaction_retry_delay
                .map_or(TransactionDefaults::default().max_retry_delay, |value| {
                    value.into_inner()
                }),
        };

        let shared = match &report {
            OpenReport::Bootstrap(bp) => match &bp.data_store {
                Store::FoundationDb(store) if store.cluster == cluster => Some(store.db.clone()),
                _ => None,
            },
            OpenReport::Event => None,
        };
        let db = match shared {
            Some(db) => db.with_defaults(defaults),
            None => {
                let db = Database::open(cluster.clone())
                    .map_err(|err| format!("Failed to open FoundationDB cluster: {err}"))?
                    .with_defaults(defaults);
                report.opened(database_opened(&db));
                match (wait_ready(&db).await, &mut report) {
                    (None, _) => db,
                    (Some(not_ready), OpenReport::Event) => return Err(not_ready.into_message()),
                    (Some(not_ready), OpenReport::Bootstrap(bp)) => {
                        not_ready.report(bp, object_id);
                        db
                    }
                }
            }
        };

        Ok(Store::FoundationDb(Arc::new(Self {
            db,
            cluster,
            windows: Default::default(),
        })))
    }
}

pub(crate) async fn cluster_config(
    config: &structs::FoundationDbStore,
) -> Result<ClusterConfig, String> {
    Ok(ClusterConfig {
        cluster: match ClusterLocation::new(&config.cluster) {
            ClusterLocation::DefaultFile => ClusterSource::DefaultFile,
            ClusterLocation::File(path) => ClusterSource::File(path.into()),
            ClusterLocation::Manual(manual) => ClusterSource::Coordinators(
                ConnectionString::from_parts(
                    &manual.description,
                    &manual.id,
                    manual.coordinators.iter().map(String::as_str),
                )
                .map_err(|err| format!("Invalid FoundationDB coordinators: {err}"))?,
            ),
        },
        tls: match &config.tls {
            FoundationDbTls::Default => TlsMode::DefaultFiles,
            FoundationDbTls::Manual(manual) => {
                let tls = ManualTls::resolve(manual).await?;
                TlsMode::Explicit(TlsConfig {
                    certificate: tls.certificate.map(pem_source),
                    key: tls.key.map(pem_source),
                    key_password: tls.password,
                    ca: tls.ca.map(pem_source),
                    verify_peers: tls.verify_peers,
                    plaintext: if tls.refuse_plaintext {
                        Plaintext::Refused
                    } else {
                        Plaintext::Allowed
                    },
                })
            }
        },
        locality: Locality {
            machine_id: config.machine_id.as_deref().map(Box::from),
            datacenter_id: config.datacenter_id.as_deref().map(Box::from),
        },
        protocol: match config.protocol {
            FoundationDbProtocol::Negotiate => ProtocolPolicy::Negotiate,
            FoundationDbProtocol::V71 => ProtocolPolicy::Fixed(Series::V7_1),
            FoundationDbProtocol::V72 => ProtocolPolicy::Fixed(Series::V7_2),
            FoundationDbProtocol::V73 => ProtocolPolicy::Fixed(Series::V7_3),
            FoundationDbProtocol::V74 => ProtocolPolicy::Fixed(Series::V7_4),
            FoundationDbProtocol::V80 => ProtocolPolicy::Fixed(Series::V8_0),
        },
        ..Default::default()
    })
}

fn pem_source(pem: Pem) -> PemSource {
    match pem {
        Pem::Bytes(bytes) => PemSource::Pem(bytes),
        Pem::Path(path) => PemSource::Path(path),
    }
}

fn database_opened(db: &Database) -> trc::Error {
    cluster_opened(
        db.cluster_file()
            .map(|path| path.to_string_lossy().into_owned()),
        Some(db.connection_string().to_string()),
    )
}

impl NotReady {
    fn into_message(self) -> String {
        match self {
            NotReady::Fault(err) => format!("FoundationDB cluster is unreachable: {err}"),
            NotReady::Timeout(err) => format!(
                "FoundationDB cluster is not ready after {}s: {err}",
                READY_TIMEOUT.as_secs()
            ),
        }
    }

    fn report(&self, bp: &mut Bootstrap, object_id: ObjectId) {
        match self {
            NotReady::Fault(err) => bp.build_error(object_id, err.to_string()),
            NotReady::Timeout(err) => bp.build_warning(object_id, err.to_string()),
        }
    }
}

async fn wait_ready(db: &Database) -> Option<NotReady> {
    match timeout(READY_TIMEOUT, db.ready()).await {
        Ok(Ok(())) => None,
        Ok(Err(err)) => Some(NotReady::Fault(
            StoreEvent::FoundationdbError
                .ctx(Key::Details, phase_name(err.phase))
                .ctx_opt(Key::Hostname, err.address)
                .ctx(Key::Code, err.error.code())
                .ctx(Key::Reason, err.error.message()),
        )),
        Err(_) => Some(NotReady::Timeout(
            StoreEvent::FoundationdbError
                .ctx(Key::Details, "cluster not ready")
                .ctx(
                    Key::Reason,
                    "No blocking fault was reported: the coordinators may be wedged or \
                 leaderless, or answer without usable proxies",
                ),
        )),
    }
}

fn phase_name(phase: ConnectPhase) -> &'static str {
    match phase {
        ConnectPhase::Resolve => "resolve",
        ConnectPhase::Connect => "connect",
        ConnectPhase::TlsHandshake => "TLS handshake",
        ConnectPhase::PeerVerification => "peer verification",
        ConnectPhase::Protocol => "protocol",
        ConnectPhase::Coordinator => "coordinator",
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/foundationdb/config.rs"]
mod tests;
