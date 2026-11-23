/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::version::{ProtocolPolicy, ReadVersionCache};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub use crate::client::cluster_file::{ConnectionString, InvalidConnectionString};
pub use crate::tls::{PemSource, Plaintext, TlsConfig, TlsMode};

#[cfg(windows)]
const DEFAULT_CONFIG_DIR: &str = "C:\\ProgramData\\foundationdb";
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const DEFAULT_CONFIG_DIR: &str = "/usr/local/etc/foundationdb";
#[cfg(not(any(windows, target_os = "macos", target_os = "freebsd")))]
const DEFAULT_CONFIG_DIR: &str = "/etc/foundationdb";

pub(crate) fn default_config_dir() -> &'static Path {
    Path::new(DEFAULT_CONFIG_DIR)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ClusterConfig {
    pub cluster: ClusterSource,
    pub tls: TlsMode,
    pub locality: Locality,
    pub protocol: ProtocolPolicy,
    pub read_version_cache: ReadVersionCache,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum ClusterSource {
    #[default]
    DefaultFile,
    File(PathBuf),
    Coordinators(ConnectionString),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Locality {
    pub machine_id: Option<Box<str>>,
    pub datacenter_id: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionDefaults {
    pub timeout: Option<Duration>,
    pub retry_limit: Option<u32>,
    pub max_retry_delay: Duration,
}

impl Default for TransactionDefaults {
    fn default() -> Self {
        TransactionDefaults {
            timeout: None,
            retry_limit: None,
            max_retry_delay: Duration::from_secs(1),
        }
    }
}
