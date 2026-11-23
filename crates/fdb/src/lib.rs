/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod api;
mod client;
pub mod codec;
pub mod tls;
pub mod transport;
pub mod wire;

pub use api::{
    KEYSPACE_END, MAX_KEY_SIZE, MAX_TRANSACTION_SIZE, MAX_VALUE_SIZE,
    config::{
        ClusterConfig, ClusterSource, ConnectionString, InvalidConnectionString, Locality,
        PemSource, Plaintext, TlsConfig, TlsMode, TransactionDefaults,
    },
    database::{Database, LoadBalanceStats},
    error::{ConnectError, ConnectPhase, Error, ErrorCode, OpenError, Result},
    page::{KeyPage, KeyValue, RangeKeys, RangePage, RangeRows},
    range::{Direction, KeyCursor, PageSize, RangeCursor, RangeOptions, Readahead},
    read::{KeySelector, Priority, ReadOptions, ReadTransaction, Snapshot},
    transaction::{
        AtomicOp, Causality, CommitError, ConflictReport, KeyRange, MaybeCommitted, Transaction,
        TransactionOptions,
    },
    version::{
        ProtocolPolicy, ProtocolVersion, ReadVersionCache, ReadVersionPolicy, Series, Version,
    },
};
pub use bytes::Bytes;
