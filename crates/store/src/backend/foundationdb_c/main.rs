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
use foundationdb::{
    Database, FdbError, FdbResult,
    api::{self, NetworkAutoStop, NetworkBuilder},
    options::{DatabaseOption, NetworkOption},
};
use parking_lot::Mutex;
use registry::{
    schema::{
        enums::FoundationDbProtocol,
        structs::{self, FoundationDbClusterManual, FoundationDbTls},
    },
    types::{EnumImpl, id::ObjectId},
};
use std::{
    ffi::CString,
    fs::File,
    io::Read,
    ptr::{NonNull, null_mut},
    sync::Arc,
};

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const DEFAULT_CLUSTER_FILE: &str = "/usr/local/etc/foundationdb/fdb.cluster";
#[cfg(windows)]
const DEFAULT_CLUSTER_FILE: &str = "C:\\ProgramData\\foundationdb\\fdb.cluster";
#[cfg(not(any(windows, target_os = "macos", target_os = "freebsd")))]
const DEFAULT_CLUSTER_FILE: &str = "/etc/foundationdb/fdb.cluster";

const CONNECTION_STRING_INVALID: i32 = 2104;
const INTERNAL_ERROR: i32 = 4100;
const MAX_CLUSTER_FILE_BYTES: u64 = 64 * 1024;

enum Network {
    Booted {
        _network: NetworkAutoStop,
        tls: Option<ManualTls>,
    },
    Failed(Box<str>),
}

static FDB_NETWORK: Mutex<Option<Network>> = Mutex::new(None);

extern "C" fn stop_fdb_network() {
    drop(FDB_NETWORK.lock().take());
}

impl FdbStore {
    pub async fn open(config: structs::FoundationDbStore) -> Result<Store, String> {
        Self::open_with(config, OpenReport::Event).await
    }

    pub async fn open_shared(
        config: structs::FoundationDbStore,
        bp: &mut Bootstrap,
        _object_id: ObjectId,
    ) -> Result<Store, String> {
        Self::open_with(config, OpenReport::Bootstrap(bp)).await
    }

    pub fn report_opened(&self, bp: &mut Bootstrap) {
        bp.notices.push(self.cluster_opened());
    }

    fn cluster_opened(&self) -> trc::Error {
        cluster_opened(
            self.cluster_file.as_deref().map(str::to_string),
            self.connection.as_deref().map(str::to_string),
        )
    }

    async fn open_with(
        config: structs::FoundationDbStore,
        mut report: OpenReport<'_>,
    ) -> Result<Store, String> {
        let tls = match &config.tls {
            FoundationDbTls::Default => None,
            FoundationDbTls::Manual(manual) => Some(ManualTls::resolve(manual).await?),
        };
        match config.protocol {
            FoundationDbProtocol::Negotiate | FoundationDbProtocol::V74 => {}
            protocol => {
                return Err(format!(
                    "FoundationDB protocol {} is not supported by the libfdb_c 7.4 backend",
                    protocol.as_str()
                ));
            }
        }
        boot_network(tls)?;

        let (db, path, connection) = match ClusterLocation::new(&config.cluster) {
            ClusterLocation::DefaultFile => (
                Database::new(Some(DEFAULT_CLUSTER_FILE)),
                Some(DEFAULT_CLUSTER_FILE),
                read_connection_string(DEFAULT_CLUSTER_FILE),
            ),
            ClusterLocation::File(path) => (
                Database::new(Some(path)),
                Some(path),
                read_connection_string(path),
            ),
            ClusterLocation::Manual(manual) => {
                let connection = connection_string(manual)?;
                let db = from_connection_string(&connection).map_err(|err| {
                    format!("Invalid FoundationDB coordinators {connection:?}: {err}")
                })?;
                (Ok(db), None, Some(connection))
            }
        };
        let db = db.map_err(|err| format!("Failed to create FoundationDB database: {err}"))?;
        let store = Self {
            db,
            version: Default::default(),
            windows: Default::default(),
            cluster_file: path.map(Box::from),
            connection: connection.map(String::into_boxed_str),
        };
        let db = &store.db;

        if let Some(value) = config.transaction_timeout {
            db.set_option(DatabaseOption::TransactionTimeout(
                value.into_inner().as_millis() as i32,
            ))
            .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }
        if let Some(value) = config.transaction_retry_limit {
            db.set_option(DatabaseOption::TransactionRetryLimit(value as i32))
                .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }
        if let Some(value) = config.transaction_retry_delay {
            db.set_option(DatabaseOption::TransactionMaxRetryDelay(
                value.into_inner().as_millis() as i32,
            ))
            .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }
        if let Some(value) = config.machine_id {
            db.set_option(DatabaseOption::MachineId(value))
                .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }
        if let Some(value) = config.datacenter_id {
            db.set_option(DatabaseOption::DatacenterId(value))
                .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }

        report.opened(store.cluster_opened());
        Ok(Store::FoundationDb(Arc::new(store)))
    }
}

fn boot_network(tls: Option<ManualTls>) -> Result<(), String> {
    let mut guard = FDB_NETWORK.lock();
    match guard.as_ref() {
        Some(Network::Booted { tls: booted, .. }) if *booted == tls => Ok(()),
        Some(Network::Booted { .. }) => Err(
            "The libfdb_c backend supports one FoundationDB TLS configuration per process: \
             every FoundationDB store must use the same TLS settings, and TLS changes take \
             effect only after restarting Stalwart"
                .to_string(),
        ),
        Some(Network::Failed(err)) => Err(format!(
            "{err}. The libfdb_c network can only be started once per process: restart \
             Stalwart to retry"
        )),
        None => match start_network(&tls) {
            Ok(network) => {
                *guard = Some(Network::Booted {
                    _network: network,
                    tls,
                });
                unsafe { libc::atexit(stop_fdb_network) };
                Ok(())
            }
            Err(err) => {
                *guard = Some(Network::Failed(err.as_str().into()));
                Err(err)
            }
        },
    }
}

fn start_network(tls: &Option<ManualTls>) -> Result<NetworkAutoStop, String> {
    let builder = api::FdbApiBuilder::default()
        .build()
        .map_err(|err| format!("Failed to boot FoundationDB: {err:?}"))?;
    let builder = match tls {
        Some(tls) => apply_tls(builder, tls)
            .map_err(|err| format!("Failed to set FoundationDB TLS option: {err}"))?,
        None => builder,
    };
    unsafe { builder.boot() }.map_err(|err| format!("Failed to boot FoundationDB: {err:?}"))
}

fn apply_tls(mut builder: NetworkBuilder, tls: &ManualTls) -> FdbResult<NetworkBuilder> {
    if let Some(password) = &tls.password {
        builder = builder.set_option(NetworkOption::TLSPassword(password.to_string()))?;
    }
    builder = match &tls.certificate {
        Some(Pem::Bytes(bytes)) => {
            builder.set_option(NetworkOption::TLSCertBytes(bytes.to_vec()))?
        }
        Some(Pem::Path(path)) => builder.set_option(NetworkOption::TLSCertPath(
            path.to_string_lossy().into_owned(),
        ))?,
        None => builder,
    };
    builder = match &tls.key {
        Some(Pem::Bytes(bytes)) => {
            builder.set_option(NetworkOption::TLSKeyBytes(bytes.to_vec()))?
        }
        Some(Pem::Path(path)) => builder.set_option(NetworkOption::TLSKeyPath(
            path.to_string_lossy().into_owned(),
        ))?,
        None => builder,
    };
    builder = match &tls.ca {
        Some(Pem::Bytes(bytes)) => builder.set_option(NetworkOption::TLSCaBytes(bytes.to_vec()))?,
        Some(Pem::Path(path)) => builder.set_option(NetworkOption::TLSCaPath(
            path.to_string_lossy().into_owned(),
        ))?,
        None => builder,
    };
    if !tls.verify_peers.is_empty() {
        builder = builder.set_option(NetworkOption::TLSVerifyPeers(
            tls.verify_peers.join("|").into_bytes(),
        ))?;
    }
    if tls.refuse_plaintext {
        builder = builder.set_option(NetworkOption::TLSDisablePlaintextConnection)?;
    }
    Ok(builder)
}

fn connection_string(manual: &FoundationDbClusterManual) -> Result<String, String> {
    if !is_key_part(&manual.description, b"_") {
        return Err(format!(
            "Invalid FoundationDB cluster description {:?}: use letters, digits and underscores",
            manual.description
        ));
    }
    if !is_key_part(&manual.id, b"") {
        return Err(format!(
            "Invalid FoundationDB cluster ID {:?}: use letters and digits",
            manual.id
        ));
    }
    if manual.coordinators.is_empty() {
        return Err("FoundationDB manual cluster configuration has no coordinators".to_string());
    }
    let mut connection = String::with_capacity(manual.description.len() + manual.id.len() + 64);
    connection.push_str(&manual.description);
    connection.push(':');
    connection.push_str(&manual.id);
    let mut separator = '@';
    for (index, coordinator) in manual.coordinators.iter().enumerate() {
        if !is_plain(coordinator) || coordinator.contains([',', '@']) {
            return Err(format!("Invalid FoundationDB coordinator: {coordinator:?}"));
        }
        if manual
            .coordinators
            .iter()
            .take(index)
            .any(|previous| previous.eq_ignore_ascii_case(coordinator))
        {
            return Err(format!(
                "Duplicate FoundationDB coordinator: {coordinator:?}"
            ));
        }
        connection.push(separator);
        connection.push_str(coordinator);
        separator = ',';
    }
    Ok(connection)
}

fn is_key_part(part: &str, extra: &[u8]) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
}

fn read_connection_string(path: &str) -> Option<String> {
    let mut contents = String::new();
    File::open(path)
        .ok()?
        .take(MAX_CLUSTER_FILE_BYTES)
        .read_to_string(&mut contents)
        .ok()?;
    contents
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(line, _)| line).trim())
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn is_plain(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
}

fn from_connection_string(connection: &str) -> FdbResult<Database> {
    let connection =
        CString::new(connection).map_err(|_| FdbError::from_code(CONNECTION_STRING_INVALID))?;
    let mut database = null_mut();
    let code = unsafe {
        foundationdb_sys::fdb_create_database_from_connection_string(
            connection.as_ptr(),
            &mut database,
        )
    };
    if code != 0 {
        return Err(FdbError::from_code(code));
    }
    NonNull::new(database)
        .map(|database| unsafe { Database::new_from_pointer(database) })
        .ok_or_else(|| FdbError::from_code(INTERNAL_ERROR))
}
