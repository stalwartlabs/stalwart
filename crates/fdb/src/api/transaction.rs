/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    database::Database,
    error::{Error, Result},
    page::RangePage,
    range::{Direction, RangeCursor},
    read::{Priority, Snapshot},
    version::{ReadVersionPolicy, Version},
};
use crate::client::{
    TransactionState, commit::CommitFailure, commit_buffer::Merged, expiry::Expiry,
    transaction::Read,
};
use bytes::Bytes;
use tokio::time::sleep;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MaybeCommitted {
    #[default]
    Fail,
    Retry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictReport {
    #[default]
    Off,
    On,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Causality {
    #[default]
    Strict,
    ReadRisky,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionOptions {
    pub priority: Priority,
    pub maybe_committed: MaybeCommitted,
    pub read_version: ReadVersionPolicy,
    pub conflict_report: ConflictReport,
    pub causality: Causality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOp {
    Add,
    AppendIfFits,
    CompareAndClear,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRange {
    pub begin: Bytes,
    pub end: Bytes,
}

pub struct Transaction<'db> {
    pub(crate) db: &'db Database,
    pub(crate) state: TransactionState,
}

pub struct CommitError<'db> {
    error: Error,
    conflicts: Option<Box<[KeyRange]>>,
    transaction: Box<Transaction<'db>>,
}

impl Default for TransactionOptions {
    fn default() -> Self {
        TransactionOptions {
            priority: Priority::Default,
            maybe_committed: MaybeCommitted::Fail,
            read_version: ReadVersionPolicy::Fresh,
            conflict_report: ConflictReport::Off,
            causality: Causality::Strict,
        }
    }
}

impl<'db> Transaction<'db> {
    pub(crate) fn new(db: &'db Database, options: TransactionOptions) -> Self {
        Transaction {
            db,
            state: TransactionState::new(options, db.defaults),
        }
    }

    pub fn database(&self) -> &'db Database {
        self.db
    }

    pub fn options(&self) -> &TransactionOptions {
        self.state.options()
    }

    pub async fn read_version(&mut self) -> Result<Version> {
        self.state.buffer.check()?;
        let TransactionOptions {
            read_version,
            priority,
            causality,
            ..
        } = *self.state.options();
        let attempt = self.state.attempt();
        attempt
            .cancellation()
            .race(
                self.db.cluster.deadlines(),
                attempt.version(&self.db.cluster, read_version, priority, causality),
            )
            .await?
    }

    pub async fn snapshot(&mut self) -> Result<Snapshot<'db>> {
        let version = self.read_version().await?;
        Ok(Snapshot {
            db: self.db,
            version,
            deadline: self.db.cluster.deadline(self.state.deadline()),
            priority: self.state.options().priority,
        })
    }

    pub fn get<'k>(
        &mut self,
        key: &'k [u8],
    ) -> impl Future<Output = Result<Option<Bytes>>> + Send + use<'db, 'k> {
        let db = self.db;
        let TransactionOptions {
            read_version,
            priority,
            causality,
            ..
        } = *self.state.options();
        let read = self.state.begin_read(key);
        async move {
            let (attempt, ops) = match read? {
                Read::Done(value) => return Ok(value),
                Read::Storage(attempt, ops) => (attempt, ops),
            };
            let cancellation = attempt.cancellation();
            let version = cancellation
                .race(
                    db.cluster.deadlines(),
                    attempt.version(&db.cluster, read_version, priority, causality),
                )
                .await??;
            let value = cancellation
                .race(
                    db.cluster.deadlines(),
                    db.cluster.get(key, version, priority, Some(cancellation)),
                )
                .await??;
            attempt.check()?;
            Ok(match ops {
                Some(ops) => ops.apply(value),
                None => value,
            })
        }
    }

    pub fn exists<'k>(
        &mut self,
        key: &'k [u8],
    ) -> impl Future<Output = Result<bool>> + Send + use<'db, 'k> {
        let db = self.db;
        let TransactionOptions {
            read_version,
            priority,
            causality,
            ..
        } = *self.state.options();
        let read = self.state.begin_read(key);
        async move {
            let (attempt, ops) = match read? {
                Read::Done(value) => return Ok(value.is_some()),
                Read::Storage(attempt, ops) => (attempt, ops),
            };
            let cancellation = attempt.cancellation();
            let version = cancellation
                .race(
                    db.cluster.deadlines(),
                    attempt.version(&db.cluster, read_version, priority, causality),
                )
                .await??;
            let exists = match ops {
                None => {
                    cancellation
                        .race(
                            db.cluster.deadlines(),
                            db.cluster
                                .exists(key, version, priority, Some(cancellation)),
                        )
                        .await??
                }
                Some(ops) => ops
                    .apply(
                        cancellation
                            .race(
                                db.cluster.deadlines(),
                                db.cluster.get(key, version, priority, Some(cancellation)),
                            )
                            .await??,
                    )
                    .is_some(),
            };
            attempt.check().map(|()| exists)
        }
    }

    pub async fn read_range(&mut self, cursor: &mut RangeCursor<'_>) -> Result<Option<RangePage>> {
        if self.state.buffer.has_mutations() {
            return Box::pin(self.read_range_merged(cursor)).await;
        }
        self.state.buffer.check()?;
        let TransactionOptions {
            read_version,
            priority,
            causality,
            ..
        } = *self.state.options();
        let attempt = self.state.attempt();
        attempt.check()?;
        cursor.core.state.enter_attempt(&attempt)?;
        if cursor.is_done() {
            return Ok(None);
        }
        let cluster = &self.db.cluster;
        let buffer = &mut self.state.buffer;
        let cancellation = attempt.cancellation();
        let version = cancellation
            .race(
                cluster.deadlines(),
                attempt.version(cluster, read_version, priority, causality),
            )
            .await??;
        let rows = cancellation
            .race(
                cluster.deadlines(),
                cursor
                    .core
                    .next_page(cluster, version, Some(cancellation), |begin, end| {
                        buffer.read_range(begin, end)
                    }),
            )
            .await??;
        attempt.check()?;
        Ok(rows.map(RangePage::from_rows))
    }

    async fn read_range_merged(
        &mut self,
        cursor: &mut RangeCursor<'_>,
    ) -> Result<Option<RangePage>> {
        self.state.buffer.check()?;
        let TransactionOptions {
            read_version,
            priority,
            causality,
            ..
        } = *self.state.options();
        let attempt = self.state.attempt();
        attempt.check()?;
        let core = &mut cursor.core;
        core.state.enter_attempt(&attempt)?;
        let direction = core.options.direction;
        let cluster = &self.db.cluster;
        let cancellation = attempt.cancellation();
        let mut start = Vec::new();
        let mut version = None;
        loop {
            start.clear();
            start.extend_from_slice(core.state.edge(core.begin, core.end, direction));
            let to = self.state.buffer.skip_cleared(&start, direction);
            core.state.skip_to(direction, to);
            let rows = if core.state.is_done(core.begin, core.end) {
                None
            } else {
                let version = match version {
                    Some(version) => version,
                    None => {
                        let read = cancellation
                            .race(
                                cluster.deadlines(),
                                attempt.version(cluster, read_version, priority, causality),
                            )
                            .await??;
                        *version.insert(read)
                    }
                };
                let buffer = &mut self.state.buffer;
                let rows = cancellation
                    .race(
                        cluster.deadlines(),
                        core.next_page(cluster, version, Some(cancellation), |begin, end| {
                            buffer.read_range(begin, end)
                        }),
                    )
                    .await??;
                attempt.check()?;
                rows
            };
            let edge = core.state.edge(core.begin, core.end, direction);
            let (low, high) = match direction {
                Direction::Forward => (start.as_slice(), edge),
                Direction::Reverse => (edge, start.as_slice()),
            };
            match self
                .state
                .buffer
                .merge(rows, low, high, direction, core.options.page)?
            {
                Merged::Unchanged(rows) => return Ok(rows.map(RangePage::from_rows)),
                Merged::Rows { rows, cut } => {
                    if let Some(last) = cut {
                        core.state.rewind(direction, &last);
                    }
                    if !rows.is_empty() {
                        return Ok(Some(RangePage::from_rows(rows)));
                    }
                    if core.state.is_done(core.begin, core.end) {
                        return Ok(None);
                    }
                }
            }
        }
    }

    pub fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.state.buffer.set(key, value)
    }

    pub fn clear(&mut self, key: &[u8]) -> Result<()> {
        self.state.buffer.clear(key)
    }

    pub fn clear_range(&mut self, begin: &[u8], end: &[u8]) -> Result<()> {
        self.state.buffer.clear_range(begin, end)
    }

    pub fn atomic_op(&mut self, key: &[u8], param: &[u8], op: AtomicOp) -> Result<()> {
        self.state.buffer.atomic_op(key, param, op)
    }

    pub fn approximate_size(&self) -> usize {
        self.state.buffer.size()
    }

    #[expect(clippy::manual_async_fn)]
    pub fn commit(
        mut self,
    ) -> impl Future<Output = Result<Option<Version>, CommitError<'db>>> + Send + use<'db> {
        async move {
            let db = self.db;
            match db.cluster.commit(&mut self.state, &db.defaults).await {
                Ok(version) => Ok(version),
                Err(CommitFailure { error, conflicts }) => Err(CommitError {
                    error,
                    conflicts,
                    transaction: Box::new(self),
                }),
            }
        }
    }

    pub async fn on_error(&mut self, error: Error) -> Result<()> {
        let delay = self.state.next_delay(error, &self.db.defaults)?;
        if error.is_retryable_not_committed()
            && let Some(version) = self.state.known_version()
        {
            self.db.cluster.invalidate_read_version_if(version);
        }
        self.state.next_attempt();
        if delay.is_zero() {
            return Ok(());
        }
        Expiry::new(self.db.cluster.deadlines(), self.state.deadline(), async {
            sleep(delay).await;
            Ok(())
        })
        .await
    }
}

impl<'db> CommitError<'db> {
    pub fn error(&self) -> Error {
        self.error
    }

    pub fn conflicting_keys(&self) -> &[KeyRange] {
        self.conflicts.as_deref().unwrap_or_default()
    }

    pub fn into_error(self) -> Error {
        self.error
    }

    pub async fn on_error(self) -> Result<Transaction<'db>> {
        if self.error.is_maybe_committed()
            && self.transaction.options().maybe_committed == MaybeCommitted::Fail
        {
            return Err(self.error);
        }
        let mut transaction = *self.transaction;
        transaction.on_error(self.error).await.map(|_| transaction)
    }

    pub fn into_transaction(self) -> Transaction<'db> {
        let mut transaction = *self.transaction;
        transaction.state.reset(&transaction.db.defaults);
        transaction
    }
}

impl From<CommitError<'_>> for Error {
    fn from(error: CommitError<'_>) -> Self {
        error.error
    }
}
