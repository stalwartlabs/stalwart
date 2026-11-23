/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    KEYSPACE_END,
    database::Database,
    error::{Error, ErrorCode, Result},
    version::{ReadVersionPolicy, Version},
};
use crate::client::{Retry, clock::Deadline, transaction::readable};
use bytes::Bytes;
use tokio::time::sleep;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Priority {
    #[default]
    Default,
    Batch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReadOptions {
    pub version: ReadVersionPolicy,
    pub priority: Priority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySelector<'k> {
    FirstGreaterOrEqual(&'k [u8]),
    FirstGreaterThan(&'k [u8]),
}

#[derive(Clone, Copy)]
pub struct Snapshot<'db> {
    pub(crate) db: &'db Database,
    pub(crate) version: Version,
    pub(crate) deadline: Deadline,
    pub(crate) priority: Priority,
}

pub struct ReadTransaction<'db> {
    pub(crate) snapshot: Snapshot<'db>,
    pub(crate) policy: ReadVersionPolicy,
    pub(crate) retry: Retry,
}

const _: () = assert!(size_of::<Snapshot<'static>>() <= 32);

impl<'db> Snapshot<'db> {
    pub fn version(&self) -> Version {
        self.version
    }

    pub fn priority(&self) -> Priority {
        self.priority
    }

    pub fn database(&self) -> &'db Database {
        self.db
    }

    fn readable(&self, key: &[u8]) -> Result<bool> {
        let readable = readable(key);
        if !matches!(readable, Ok(true)) {
            self.db.cluster.check_deadline(self.deadline)?;
        }
        readable
    }

    pub async fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        if self.readable(key)? {
            let cluster = &self.db.cluster;
            cluster
                .expiry(
                    self.deadline,
                    cluster.get(key, self.version, self.priority, None),
                )
                .await
        } else {
            Ok(None)
        }
    }

    pub async fn exists(&self, key: &[u8]) -> Result<bool> {
        if self.readable(key)? {
            let cluster = &self.db.cluster;
            cluster
                .expiry(
                    self.deadline,
                    cluster.exists(key, self.version, self.priority, None),
                )
                .await
        } else {
            Ok(false)
        }
    }

    pub async fn get_key(&self, selector: KeySelector<'_>) -> Result<Option<Bytes>> {
        let key = match selector {
            KeySelector::FirstGreaterOrEqual(key) | KeySelector::FirstGreaterThan(key) => key,
        };
        if key >= KEYSPACE_END {
            return Err(Error::new(ErrorCode::KEY_OUTSIDE_LEGAL_RANGE));
        }
        let cluster = &self.db.cluster;
        cluster
            .expiry(
                self.deadline,
                cluster.get_key(selector, self.version, self.priority, None),
            )
            .await
    }
}

impl<'db> ReadTransaction<'db> {
    pub fn snapshot(&self) -> Snapshot<'db> {
        self.snapshot
    }

    pub fn version(&self) -> Version {
        self.snapshot.version
    }

    pub async fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        self.snapshot.get(key).await
    }

    pub async fn exists(&self, key: &[u8]) -> Result<bool> {
        self.snapshot.exists(key).await
    }

    pub async fn get_key(&self, selector: KeySelector<'_>) -> Result<Option<Bytes>> {
        self.snapshot.get_key(selector).await
    }

    pub async fn on_error(&mut self, error: Error) -> Result<()> {
        let db = self.snapshot.db;
        let deadline = self.snapshot.deadline;
        self.snapshot.version = db
            .cluster
            .expiry(deadline, async {
                if matches!(self.policy, ReadVersionPolicy::At(_))
                    && error.error_code() == ErrorCode::TRANSACTION_TOO_OLD
                {
                    return Err(error);
                }
                let delay = self.retry.next_delay(error, &db.defaults)?;
                if error.is_retryable_not_committed() {
                    db.cluster.invalidate_read_version_if(self.snapshot.version);
                }
                if !delay.is_zero() {
                    sleep(delay).await;
                }
                db.cluster
                    .read_version(self.policy, self.snapshot.priority)
                    .await
            })
            .await?;
        Ok(())
    }
}
