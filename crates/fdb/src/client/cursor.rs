/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Cluster,
    dispatch::{PendingRequest, Reply},
    lookup::ShardLocation,
    server::Channel,
    storage::{WRONG_SHARD_SERVER_DELAY, envelope_error, reply_error},
    transaction::{Attempt, Cancellation},
};
use crate::{
    api::{
        KEYSPACE_END,
        error::{Error, ErrorCode, Result},
        range::{Direction, PageSize, Readahead},
        version::Version,
    },
    codec::kv::KeyValuesBuf,
    transport::ProtocolVersion,
    wire::{self, Dialect, GetKeyValuesReply, GetKeyValuesRequest},
};
use bytes::Bytes;
use std::{cmp::Ordering, mem, ops::Bound, sync::Arc};
use tokio::time::sleep;

const DEFAULT_ROW_LIMIT: i32 = 80_000;

#[derive(Default)]
pub(crate) struct CursorState {
    mode: CursorMode,
    position: Option<Position>,
    scratch: Vec<u8>,
    prefetch: Option<Prefetch>,
}

struct Prefetch {
    request: PendingRequest,
    version: Version,
    limits: (i32, i32),
}

#[derive(Default)]
enum CursorMode {
    #[default]
    Unused,
    Serializable(Arc<Attempt>),
    Snapshot,
}

struct Position {
    begin: Vec<u8>,
    end: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Edge<'a> {
    key: &'a [u8],
    nul: bool,
}

pub(crate) struct Scan<'a, 'k> {
    pub(crate) begin: Bound<&'k [u8]>,
    pub(crate) end: Bound<&'k [u8]>,
    pub(crate) direction: Direction,
    pub(crate) page: PageSize,
    pub(crate) readahead: Readahead,
    pub(crate) version: Version,
    pub(crate) cancel: Option<&'a Cancellation>,
}

impl CursorState {
    pub(crate) fn new() -> Self {
        CursorState::default()
    }

    pub(crate) fn enter_attempt(&mut self, attempt: &Arc<Attempt>) -> Result<()> {
        match &self.mode {
            CursorMode::Serializable(tagged) if Arc::ptr_eq(tagged, attempt) => Ok(()),
            CursorMode::Serializable(_) => Err(Error::new(ErrorCode::TRANSACTION_CANCELLED)),
            CursorMode::Snapshot => Err(Error::new(ErrorCode::CLIENT_INVALID_OPERATION)),
            CursorMode::Unused => {
                self.mode = CursorMode::Serializable(attempt.clone());
                Ok(())
            }
        }
    }

    pub(crate) fn enter_snapshot(&mut self) -> Result<()> {
        match self.mode {
            CursorMode::Snapshot => Ok(()),
            CursorMode::Serializable(_) => Err(Error::new(ErrorCode::CLIENT_INVALID_OPERATION)),
            CursorMode::Unused => {
                self.mode = CursorMode::Snapshot;
                Ok(())
            }
        }
    }

    pub(crate) fn is_done(&self, begin: Bound<&[u8]>, end: Bound<&[u8]>) -> bool {
        match &self.position {
            Some(position) => position.begin >= position.end,
            None => Edge::begin(begin).cmp(Edge::end(end)).is_ge(),
        }
    }

    pub(crate) fn edge(
        &mut self,
        begin: Bound<&[u8]>,
        end: Bound<&[u8]>,
        direction: Direction,
    ) -> &[u8] {
        let position = self
            .position
            .get_or_insert_with(|| Position::new(begin, end));
        match direction {
            Direction::Forward => &position.begin,
            Direction::Reverse => &position.end,
        }
    }

    pub(crate) fn skip_to(&mut self, direction: Direction, to: &[u8]) {
        let Some(position) = &mut self.position else {
            return;
        };
        match direction {
            Direction::Forward if to > position.begin.as_slice() => {
                replace(&mut position.begin, to.min(position.end.as_slice()))
            }
            Direction::Reverse if to < position.end.as_slice() => {
                replace(&mut position.end, to.max(position.begin.as_slice()))
            }
            _ => return,
        }
        self.prefetch = None;
    }

    pub(crate) fn rewind(&mut self, direction: Direction, last: &[u8]) {
        let Some(position) = &mut self.position else {
            return;
        };
        match direction {
            Direction::Forward => {
                replace(&mut position.begin, last);
                position.begin.push(0);
            }
            Direction::Reverse => replace(&mut position.end, last),
        }
        self.prefetch = None;
    }

    pub(crate) fn restart(&mut self) {
        self.mode = CursorMode::Unused;
        self.position = None;
        self.prefetch = None;
    }

    pub(crate) fn seek(
        &mut self,
        begin: Bound<&[u8]>,
        end: Bound<&[u8]>,
        target: Bound<&[u8]>,
        direction: Direction,
    ) {
        self.prefetch = None;
        let position = self
            .position
            .get_or_insert_with(|| Position::new(begin, end));
        match direction {
            Direction::Forward => {
                let (target, bound) = (Edge::begin(target), Edge::begin(begin));
                if target.cmp(bound).is_ge() {
                    target
                } else {
                    bound
                }
                .write(&mut position.begin)
            }
            Direction::Reverse => {
                let (target, bound) = (Edge::end(target), Edge::end(end));
                if target.cmp(bound).is_le() {
                    target
                } else {
                    bound
                }
                .write(&mut position.end)
            }
        }
    }

    pub(crate) async fn next_page(
        &mut self,
        cluster: &Cluster,
        scan: Scan<'_, '_>,
        mut read: impl FnMut(&[u8], &[u8]),
    ) -> Result<Option<KeyValuesBuf>> {
        let CursorState {
            position,
            scratch,
            prefetch,
            ..
        } = self;
        let position = position.get_or_insert_with(|| Position::new(scan.begin, scan.end));
        let limits = limits(scan.page, scan.direction);
        let (limit, limit_bytes) = limits;
        if prefetch
            .as_ref()
            .is_some_and(|pending| pending.version != scan.version || pending.limits != limits)
        {
            *prefetch = None;
        }
        loop {
            if position.begin >= position.end {
                return Ok(None);
            }
            let (shard, reply) = match prefetch {
                Some(pending) => {
                    let reply = cluster
                        .balancer
                        .receive(&mut pending.request, decode_rows)
                        .await;
                    let shard = pending.request.shard().clone();
                    *prefetch = None;
                    match reply {
                        Ok(Some(rows)) => (shard, Ok(rows)),
                        Ok(None) => continue,
                        Err(error) => (shard, Err(error)),
                    }
                }
                None => {
                    let shard = match cluster
                        .locate_range(
                            &position.begin,
                            &position.end,
                            scan.direction,
                            Channel::KeyValues,
                            Some(scan.version),
                            scan.cancel,
                        )
                        .await
                    {
                        Ok(shard) => shard,
                        Err(error) if retries_shard(error) => {
                            retry_delay(scan.cancel).await?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    let (low, high) = span(&position.begin, &position.end, &shard, scan.direction);
                    let request = GetKeyValuesRequest {
                        begin: first_greater_or_equal(low),
                        end: first_greater_or_equal(high),
                        version: scan.version.get(),
                        limit,
                        limit_bytes,
                    };
                    let reply = cluster
                        .balancer
                        .request(
                            shard.location(),
                            Channel::KeyValues,
                            move |reply, protocol, out| {
                                request.encode(Dialect::of(protocol.get()), reply, out);
                            },
                            decode_rows,
                            scan.cancel,
                        )
                        .await;
                    (shard, reply)
                }
            };
            let (low, high) = span(&position.begin, &position.end, &shard, scan.direction);
            let (rows, mut more) = match reply {
                Ok(reply) => reply,
                Err(error) if retries_shard(error) => {
                    match scan.direction {
                        Direction::Forward => cluster
                            .locations
                            .invalidate_range(shard.begin(), &position.end),
                        Direction::Reverse => cluster
                            .locations
                            .invalidate_range(&position.begin, shard.end()),
                    }
                    retry_delay(scan.cancel).await?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let view = rows.view();
            if view.len() > limit.unsigned_abs() as usize {
                return Err(Error::new(ErrorCode::INTERNAL_ERROR));
            }
            let (Some((first, _)), Some((last, _))) = (view.iter().next(), view.last()) else {
                if more {
                    return Err(Error::new(ErrorCode::INTERNAL_ERROR));
                }
                match scan.direction {
                    Direction::Forward => {
                        read(&position.begin, high);
                        replace(&mut position.begin, high);
                    }
                    Direction::Reverse => {
                        read(low, &position.end);
                        replace(&mut position.end, low);
                    }
                }
                continue;
            };
            let ordered = match scan.direction {
                Direction::Forward => view.is_strictly_ascending(),
                Direction::Reverse => view.is_strictly_descending(),
            };
            if !ordered {
                return Err(Error::new(ErrorCode::INTERNAL_ERROR));
            }
            let inside = |key: &[u8]| low <= key && key < high;
            if !inside(first) || !inside(last) {
                return Err(Error::new(ErrorCode::INTERNAL_ERROR));
            }
            if scan.direction == Direction::Reverse && last == low {
                more = false;
            }
            match scan.direction {
                Direction::Forward if more => {
                    scratch.clear();
                    scratch.extend_from_slice(last);
                    scratch.push(0);
                    read(&position.begin, scratch);
                    mem::swap(&mut position.begin, scratch);
                }
                Direction::Forward => {
                    read(&position.begin, high);
                    replace(&mut position.begin, high);
                }
                Direction::Reverse => {
                    let to = if more { last } else { low };
                    read(to, &position.end);
                    replace(&mut position.end, to);
                }
            }
            if scan.readahead == Readahead::Next {
                *prefetch = issue(cluster, position, &scan, limits);
            }
            return Ok(Some(rows));
        }
    }
}

impl Position {
    fn new(begin: Bound<&[u8]>, end: Bound<&[u8]>) -> Self {
        let mut position = Position {
            begin: Vec::new(),
            end: Vec::new(),
        };
        Edge::begin(begin).write(&mut position.begin);
        Edge::end(end).write(&mut position.end);
        position
    }
}

impl<'a> Edge<'a> {
    fn begin(bound: Bound<&'a [u8]>) -> Self {
        match bound {
            Bound::Included(key) => Edge { key, nul: false },
            Bound::Excluded(key) => Edge { key, nul: true },
            Bound::Unbounded => Edge {
                key: b"",
                nul: false,
            },
        }
    }

    fn end(bound: Bound<&'a [u8]>) -> Self {
        match bound {
            Bound::Included(key) => Edge { key, nul: true },
            Bound::Excluded(key) => Edge { key, nul: false },
            Bound::Unbounded => Edge {
                key: KEYSPACE_END,
                nul: false,
            },
        }
    }

    fn bytes(self) -> impl Iterator<Item = &'a u8> {
        self.key.iter().chain(self.nul.then_some(&0))
    }

    fn cmp(self, other: Edge<'_>) -> Ordering {
        self.bytes().cmp(other.bytes())
    }

    fn write(self, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(self.key);
        if self.nul {
            out.push(0);
        }
    }
}

fn span<'b, 'e, 's: 'b + 'e>(
    begin: &'b [u8],
    end: &'e [u8],
    shard: &'s ShardLocation,
    direction: Direction,
) -> (&'b [u8], &'e [u8]) {
    match direction {
        Direction::Forward => (begin, end.min(shard.end())),
        Direction::Reverse => (begin.max(shard.begin()), end),
    }
}

fn issue(
    cluster: &Cluster,
    position: &Position,
    scan: &Scan<'_, '_>,
    (limit, limit_bytes): (i32, i32),
) -> Option<Prefetch> {
    if position.begin >= position.end || scan.cancel.is_some_and(|cancel| cancel.check().is_err()) {
        return None;
    }
    let edge = match scan.direction {
        Direction::Forward => &position.begin,
        Direction::Reverse => &position.end,
    };
    let shard = cluster.locations.locate(edge, scan.direction)?;
    if shard
        .location()
        .needs_refresh(Channel::KeyValues, || cluster.balancer.now())
    {
        return None;
    }
    let (low, high) = span(&position.begin, &position.end, &shard, scan.direction);
    let request = GetKeyValuesRequest {
        begin: first_greater_or_equal(low),
        end: first_greater_or_equal(high),
        version: scan.version.get(),
        limit,
        limit_bytes,
    };
    let request =
        cluster
            .balancer
            .send(&shard, Channel::KeyValues, move |reply, protocol, out| {
                request.encode(Dialect::of(protocol.get()), reply, out);
            })?;
    Some(Prefetch {
        request,
        version: scan.version,
        limits: (limit, limit_bytes),
    })
}

fn replace(edge: &mut Vec<u8>, to: &[u8]) {
    edge.clear();
    edge.extend_from_slice(to);
}

pub(crate) fn row_limit(page: PageSize) -> usize {
    limits(page, Direction::Forward).0.unsigned_abs() as usize
}

fn limits(page: PageSize, direction: Direction) -> (i32, i32) {
    let rows = page.rows().map_or(DEFAULT_ROW_LIMIT, |rows| {
        i32::try_from(rows.get()).unwrap_or(i32::MAX)
    });
    let bytes = i32::try_from(page.bytes().get()).unwrap_or(i32::MAX);
    match direction {
        Direction::Forward => (rows, bytes),
        Direction::Reverse => (-rows, bytes),
    }
}

fn first_greater_or_equal(key: &[u8]) -> wire::KeySelector<'_> {
    wire::KeySelector {
        key,
        or_equal: false,
        offset: 1,
    }
}

fn retries_shard(error: Error) -> bool {
    matches!(
        error.error_code(),
        ErrorCode::WRONG_SHARD_SERVER | ErrorCode::ALL_ALTERNATIVES_FAILED
    )
}

async fn retry_delay(cancel: Option<&Cancellation>) -> Result<()> {
    sleep(WRONG_SHARD_SERVER_DELAY).await;
    cancel.map_or(Ok(()), Cancellation::check)
}

fn decode_rows(bytes: Bytes, protocol: ProtocolVersion) -> Reply<(KeyValuesBuf, bool)> {
    let dialect = Dialect::of(protocol.get());
    match GetKeyValuesReply::decode(dialect, &bytes) {
        Ok(wire::Reply::Value(reply)) => Reply {
            penalty: Some(reply.penalty),
            result: match reply.error {
                Some(error) => Err(reply_error(dialect, error)),
                None => KeyValuesBuf::new(&bytes, reply.data)
                    .map(|rows| (rows, reply.more))
                    .map_err(|_| ErrorCode::INTERNAL_ERROR),
            },
        },
        result => envelope_error(dialect, result),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/cursor/tests.rs"]
mod tests;
