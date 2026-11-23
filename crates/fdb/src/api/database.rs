/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    config::{ClusterConfig, ConnectionString, TransactionDefaults},
    error::{ConnectError, OpenError, Result},
    read::{Priority, ReadOptions, ReadTransaction, Snapshot},
    transaction::{Transaction, TransactionOptions},
    version::{ProtocolVersion, ReadVersionPolicy, Version},
};
use crate::client::{Cluster, Retry, expiry::deadline_after};
use std::{path::Path, sync::Arc};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadBalanceStats {
    pub hedges_granted: u64,
    pub hedges_refused: u64,
    pub lagging_requests: usize,
}

#[derive(Clone)]
pub struct Database {
    pub(crate) cluster: Arc<Cluster>,
    pub(crate) defaults: TransactionDefaults,
}

impl Database {
    pub fn open(config: ClusterConfig) -> Result<Database, OpenError> {
        Cluster::open(config).map(|cluster| Database {
            cluster: Arc::new(cluster),
            defaults: TransactionDefaults::default(),
        })
    }

    pub fn with_defaults(&self, defaults: TransactionDefaults) -> Database {
        Database {
            cluster: self.cluster.clone(),
            defaults,
        }
    }

    pub fn defaults(&self) -> &TransactionDefaults {
        &self.defaults
    }

    pub fn cluster_file(&self) -> Option<&Path> {
        self.cluster.cluster_file()
    }

    pub fn connection_string(&self) -> &ConnectionString {
        self.cluster.connection()
    }

    pub async fn ready(&self) -> Result<(), ConnectError> {
        self.cluster.ready().await
    }

    pub async fn read(&self, options: ReadOptions) -> Result<ReadTransaction<'_>> {
        let deadline = self.cluster.deadline(deadline_after(self.defaults.timeout));
        let version = self
            .cluster
            .expiry(
                deadline,
                self.cluster.read_version(options.version, options.priority),
            )
            .await?;
        Ok(ReadTransaction {
            snapshot: Snapshot {
                db: self,
                version,
                deadline,
                priority: options.priority,
            },
            policy: options.version,
            retry: Retry::new(),
        })
    }

    pub fn transaction(&self, options: TransactionOptions) -> Transaction<'_> {
        Transaction::new(self, options)
    }

    pub async fn read_version(&self, policy: ReadVersionPolicy) -> Result<Version> {
        self.cluster.read_version(policy, Priority::Default).await
    }

    pub fn advance_read_version(&self, version: Version) {
        self.cluster.advance_read_version(version);
    }

    pub fn invalidate_read_version(&self) {
        self.cluster.invalidate_read_version();
    }

    pub fn last_committed_version(&self) -> Option<Version> {
        self.cluster.last_committed_version()
    }

    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.cluster.protocol_version()
    }

    pub fn load_balance_stats(&self) -> LoadBalanceStats {
        self.cluster.load_balance_stats()
    }

    pub fn ptr_eq(&self, other: &Database) -> bool {
        Arc::ptr_eq(&self.cluster, &other.cluster)
    }
}
