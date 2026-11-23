/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Cluster, dispatch::Reply, lookup::ALL_KEYS_END, server::Channel, transaction::Cancellation,
};
use crate::{
    api::{
        KEYSPACE_END,
        error::{Error, ErrorCode, Result},
        range::Direction,
        read::{KeySelector, Priority},
        version::Version,
    },
    codec::{DecodeError, kv::share},
    transport::{ProtocolVersion, Uid},
    wire::{self, Dialect, GetKeyReply, GetKeyRequest, GetValueReply, GetValueRequest, ReplyError},
};
use bytes::Bytes;
use std::{cmp::Ordering, time::Duration};
use tokio::time::sleep;

pub(super) const WRONG_SHARD_SERVER_DELAY: Duration = Duration::from_millis(10);

#[derive(Clone, Copy)]
struct Target<'a> {
    key: &'a [u8],
    direction: Direction,
    channel: Channel,
}

struct Selector {
    key: Bytes,
    or_equal: bool,
    offset: i32,
}

impl Cluster {
    pub(crate) fn get<'a>(
        &'a self,
        key: &'a [u8],
        version: Version,
        priority: Priority,
        cancel: Option<&'a Cancellation>,
    ) -> impl Future<Output = Result<Option<Bytes>>> + Send + 'a {
        let _ = priority;
        let request = GetValueRequest {
            key,
            version: version.get(),
        };
        self.point_read(
            Target {
                key,
                direction: Direction::Forward,
                channel: Channel::Value,
            },
            version,
            cancel,
            move |reply, protocol, out| {
                request.encode(Dialect::of(protocol.get()), reply, out);
            },
            decode_value,
        )
    }

    pub(crate) fn exists<'a>(
        &'a self,
        key: &'a [u8],
        version: Version,
        priority: Priority,
        cancel: Option<&'a Cancellation>,
    ) -> impl Future<Output = Result<bool>> + Send + 'a {
        let _ = priority;
        let request = GetKeyRequest {
            sel: wire::KeySelector {
                key,
                or_equal: false,
                offset: 1,
            },
            version: version.get(),
        };
        self.point_read(
            Target {
                key,
                direction: Direction::Forward,
                channel: Channel::Key,
            },
            version,
            cancel,
            move |reply, protocol, out| {
                request.encode(Dialect::of(protocol.get()), reply, out);
            },
            move |bytes, protocol| {
                decode_key(bytes, protocol).map(|sel| sel.is_resolved() && sel.key == key)
            },
        )
    }

    pub(crate) async fn get_key(
        &self,
        selector: KeySelector<'_>,
        version: Version,
        priority: Priority,
        cancel: Option<&Cancellation>,
    ) -> Result<Option<Bytes>> {
        let _ = priority;
        let (key, or_equal) = match selector {
            KeySelector::FirstGreaterOrEqual(key) => (key, false),
            KeySelector::FirstGreaterThan(key) => (key, true),
        };
        let mut sel = wire::KeySelector {
            key,
            or_equal,
            offset: 1,
        };
        let mut next: Selector;
        loop {
            if sel.key >= KEYSPACE_END && sel.offset > 0 {
                return Ok(None);
            }
            if sel.key.is_empty() && sel.offset <= 0 {
                return Ok(Some(Bytes::new()));
            }
            match sel.key.cmp(ALL_KEYS_END) {
                Ordering::Greater => return Err(Error::new(ErrorCode::INTERNAL_ERROR)),
                Ordering::Equal => sel.or_equal = false,
                Ordering::Less => {}
            }
            let direction = if !sel.or_equal && sel.offset <= 0 {
                Direction::Reverse
            } else {
                Direction::Forward
            };
            let request = GetKeyRequest {
                sel,
                version: version.get(),
            };
            next = self
                .point_read(
                    Target {
                        key: sel.key,
                        direction,
                        channel: Channel::Key,
                    },
                    version,
                    cancel,
                    |reply, protocol, out| {
                        request.encode(Dialect::of(protocol.get()), reply, out);
                    },
                    decode_key,
                )
                .await?;
            if next.is_resolved() {
                return Ok((*next.key < *KEYSPACE_END).then_some(next.key));
            }
            sel = wire::KeySelector {
                key: &next.key,
                or_equal: next.or_equal,
                offset: next.offset,
            };
        }
    }

    async fn point_read<T>(
        &self,
        Target {
            key,
            direction,
            channel,
        }: Target<'_>,
        version: Version,
        cancel: Option<&Cancellation>,
        encode: impl Fn(Uid, ProtocolVersion, &mut Vec<u8>),
        decode: impl Fn(Bytes, ProtocolVersion) -> Reply<T>,
    ) -> Result<T> {
        loop {
            let error = match self
                .locate_key(key, direction, channel, Some(version), cancel)
                .await
            {
                Ok(shard) => match self
                    .balancer
                    .request(shard.location(), channel, &encode, &decode, cancel)
                    .await
                {
                    Ok(value) => return Ok(value),
                    Err(error) => error,
                },
                Err(error) => error,
            };
            if !matches!(
                error.error_code(),
                ErrorCode::WRONG_SHARD_SERVER | ErrorCode::ALL_ALTERNATIVES_FAILED
            ) {
                return Err(error);
            }
            self.locations.invalidate_key(key, direction);
            sleep(WRONG_SHARD_SERVER_DELAY).await;
            cancel.map_or(Ok(()), Cancellation::check)?;
        }
    }
}

impl Selector {
    fn is_resolved(&self) -> bool {
        self.offset == 0 && self.or_equal
    }
}

fn decode_value(bytes: Bytes, protocol: ProtocolVersion) -> Reply<Option<Bytes>> {
    let dialect = Dialect::of(protocol.get());
    match GetValueReply::decode(dialect, &bytes) {
        Ok(wire::Reply::Value(reply)) => Reply {
            penalty: Some(reply.penalty),
            result: match reply.error {
                Some(error) => Err(reply_error(dialect, error)),
                None => reply
                    .value
                    .map(|value| share(&bytes, value).ok_or(ErrorCode::INTERNAL_ERROR))
                    .transpose(),
            },
        },
        result => envelope_error(dialect, result),
    }
}

fn decode_key(bytes: Bytes, protocol: ProtocolVersion) -> Reply<Selector> {
    let dialect = Dialect::of(protocol.get());
    match GetKeyReply::decode(dialect, &bytes) {
        Ok(wire::Reply::Value(reply)) => Reply {
            penalty: Some(reply.penalty),
            result: match reply.error {
                Some(error) => Err(reply_error(dialect, error)),
                None => share(&bytes, reply.sel.key)
                    .map(|key| Selector {
                        key,
                        or_equal: reply.sel.or_equal,
                        offset: reply.sel.offset,
                    })
                    .ok_or(ErrorCode::INTERNAL_ERROR),
            },
        },
        result => envelope_error(dialect, result),
    }
}

pub(super) fn reply_error(dialect: Dialect, error: ReplyError) -> ErrorCode {
    match error.code {
        0 => ErrorCode::INTERNAL_ERROR,
        code => ErrorCode::from_wire(dialect, code),
    }
}

#[cold]
pub(super) fn envelope_error<T, V>(
    dialect: Dialect,
    result: std::result::Result<wire::Reply<V>, DecodeError>,
) -> Reply<T> {
    Reply {
        penalty: None,
        result: Err(match result {
            Ok(wire::Reply::Error(code)) => ErrorCode::from_wire(dialect, code),
            Ok(wire::Reply::Value(_)) | Err(_) => ErrorCode::INTERNAL_ERROR,
        }),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/storage/tests.rs"]
mod tests;
