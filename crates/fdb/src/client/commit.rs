/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Cluster, Retry, TransactionState,
    commit_buffer::{self, CommitView, Ranges},
    proxies::{Delivery, ProxyRole, with_proxies},
};
use crate::{
    api::{
        config::TransactionDefaults,
        error::{Error, ErrorCode, Result},
        read::Priority,
        transaction::{Causality, ConflictReport, KeyRange, TransactionOptions},
        version::Version,
    },
    transport::{FrameSize, ProtocolVersion},
    wire::{self, CommitID, CommitTransactionRequest, Dialect, Reply},
};
use bytes::Bytes;
use std::iter;
use tokio::time::sleep;

const INVALID_VERSION: i64 = -1;
const FLAG_IS_LOCK_AWARE: u32 = 1;

pub(crate) struct CommitFailure {
    pub(crate) error: Error,
    pub(crate) conflicts: Option<Box<[KeyRange]>>,
}

enum CommitReply {
    Committed(Version),
    Conflict(Option<Vec<usize>>),
}

impl Cluster {
    pub(crate) async fn commit(
        &self,
        state: &mut TransactionState,
        defaults: &TransactionDefaults,
    ) -> Result<Option<Version>, CommitFailure> {
        let TransactionOptions {
            read_version,
            priority,
            conflict_report,
            ..
        } = *state.options();
        let (attempt, causality) = state.commit_attempt();
        attempt.check()?;
        let Some(view) = state.buffer.prepare(fastrand::u128(..).to_le_bytes())? else {
            return Ok(None);
        };
        let version = attempt
            .cancellation()
            .race(
                &self.deadlines,
                attempt.version(self, read_version, priority, causality),
            )
            .await??;
        let committed = attempt
            .cancellation()
            .race(
                &self.deadlines,
                self.send_commit(&view, version, conflict_report, priority, defaults),
            )
            .await??;
        Ok(Some(committed))
    }

    async fn send_commit(
        &self,
        view: &CommitView<'_>,
        version: Version,
        report: ConflictReport,
        priority: Priority,
        defaults: &TransactionDefaults,
    ) -> Result<Version, CommitFailure> {
        let request = CommitTransactionRequest {
            read_conflict_ranges: view.reads.clone().map(key_range),
            write_conflict_ranges: view.writes.clone().map(key_range),
            mutations: view.mutations.clone().map(mutation),
            read_snapshot: version.get(),
            report_conflicting_keys: report == ConflictReport::On,
            lock_aware: false,
            flags: 0,
        };
        match self
            .request_commit(&request, FrameSize::for_len(view.size()))
            .await
        {
            Ok(CommitReply::Committed(committed)) => {
                self.committed(committed);
                Ok(committed)
            }
            Ok(CommitReply::Conflict(indices)) => Err(CommitFailure {
                error: Error::new(ErrorCode::NOT_COMMITTED),
                conflicts: indices.map(|indices| conflicting_ranges(view.reads.clone(), &indices)),
            }),
            Err(error) if is_maybe_delivered(error) => {
                Box::pin(self.commit_dummy(view.conflict_key, priority, defaults)).await?;
                Err(Error::new(ErrorCode::COMMIT_UNKNOWN_RESULT).into())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn commit_dummy(
        &self,
        key: &[u8],
        priority: Priority,
        defaults: &TransactionDefaults,
    ) -> Result<()> {
        let mut end = Vec::with_capacity(key.len() + 1);
        end.extend_from_slice(key);
        end.push(0);
        let range = wire::KeyRange {
            begin: key,
            end: &end,
        };
        let defaults = TransactionDefaults {
            retry_limit: None,
            ..*defaults
        };
        let mut retry = Retry::new();
        loop {
            let error = match self
                .grv
                .fetch_lock_aware(priority, Causality::ReadRisky)
                .await
            {
                Ok(version) => {
                    let request = CommitTransactionRequest {
                        read_conflict_ranges: iter::once(range),
                        write_conflict_ranges: iter::once(range),
                        mutations: iter::empty(),
                        read_snapshot: version.get(),
                        report_conflicting_keys: false,
                        lock_aware: false,
                        flags: FLAG_IS_LOCK_AWARE,
                    };
                    match self.request_commit(&request, FrameSize::Small).await {
                        Ok(CommitReply::Committed(committed)) => {
                            self.committed(committed);
                            return Ok(());
                        }
                        Ok(CommitReply::Conflict(_)) => Error::new(ErrorCode::NOT_COMMITTED),
                        Err(error) if is_maybe_delivered(error) => {
                            Error::new(ErrorCode::COMMIT_UNKNOWN_RESULT)
                        }
                        Err(error) => error,
                    }
                }
                Err(error) => error,
            };
            let delay = retry.next_delay(error, &defaults)?;
            if !delay.is_zero() {
                sleep(delay).await;
            }
        }
    }

    async fn request_commit<'a, R, W, M>(
        &self,
        request: &CommitTransactionRequest<R, W, M>,
        size: FrameSize,
    ) -> Result<CommitReply>
    where
        R: Iterator<Item = wire::KeyRange<'a>> + ExactSizeIterator + Clone,
        W: Iterator<Item = wire::KeyRange<'a>> + ExactSizeIterator + Clone,
        M: Iterator<Item = wire::Mutation<'a>> + ExactSizeIterator + Clone,
    {
        let mut proxies = self.proxies.clone();
        with_proxies(&mut proxies, Delivery::AtMostOnce, |set| async move {
            set.request_sized(
                ProxyRole::Commit,
                Delivery::AtMostOnce,
                size,
                |reply, version, out| {
                    request.encode(Dialect::of(version.get()), reply, out);
                },
                decode,
            )
            .await
        })
        .await
    }
}

impl From<Error> for CommitFailure {
    fn from(error: Error) -> Self {
        CommitFailure {
            error,
            conflicts: None,
        }
    }
}

fn decode(bytes: Bytes, version: ProtocolVersion) -> Result<CommitReply, ErrorCode> {
    let dialect = Dialect::of(version.get());
    let reply = match CommitID::decode(dialect, &bytes) {
        Ok(Reply::Value(reply)) => reply,
        Ok(Reply::Error(code)) => return Err(ErrorCode::from_wire(dialect, code)),
        Err(_) => return Err(ErrorCode::REQUEST_MAYBE_DELIVERED),
    };
    if reply.version != INVALID_VERSION {
        return Version::new(reply.version)
            .map(CommitReply::Committed)
            .ok_or(ErrorCode::REQUEST_MAYBE_DELIVERED);
    }
    Ok(CommitReply::Conflict(reply.conflicting_key_ranges.map(
        |indices| {
            let mut indices = indices
                .iter()
                .filter_map(|index| usize::try_from(i32::from_le_bytes(*index)).ok())
                .collect::<Vec<_>>();
            indices.sort_unstable();
            indices.dedup();
            indices
        },
    )))
}

fn conflicting_ranges(reads: Ranges<'_>, indices: &[usize]) -> Box<[KeyRange]> {
    let mut indices = indices.iter().peekable();
    reads
        .enumerate()
        .filter(|(position, _)| indices.next_if_eq(&position).is_some())
        .map(|(_, (begin, end))| KeyRange {
            begin: Bytes::copy_from_slice(begin),
            end: Bytes::copy_from_slice(end),
        })
        .collect()
}

fn is_maybe_delivered(error: Error) -> bool {
    matches!(
        error.error_code(),
        ErrorCode::REQUEST_MAYBE_DELIVERED | ErrorCode::COMMIT_UNKNOWN_RESULT
    )
}

fn key_range<'a>((begin, end): (&'a [u8], &'a [u8])) -> wire::KeyRange<'a> {
    wire::KeyRange { begin, end }
}

fn mutation(mutation: commit_buffer::Mutation<'_>) -> wire::Mutation<'_> {
    wire::Mutation {
        kind: mutation.kind as u8,
        param1: mutation.param1,
        param2: mutation.param2,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/commit/tests.rs"]
mod tests;
