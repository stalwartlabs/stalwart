/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use core::{fmt, marker::PhantomData};

use crate::codec::{
    DecodeError,
    read::{self, Table},
};

mod api;
mod decode;
mod layout;
mod vt;

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/wire/tests.rs"]
mod tests;

pub use api::{
    AcknowledgementReply, ClientDBInfo, CommitID, CommitProxyInterface, CommitTransactionRequest,
    Endpoint, GetKeyReply, GetKeyRequest, GetKeyServerLocationsReply, GetKeyServerLocationsRequest,
    GetKeyValuesReply, GetKeyValuesRequest, GetKeyValuesStreamReply, GetKeyValuesStreamRequest,
    GetReadVersionReply, GetReadVersionRequest, GetValueReply, GetValueRequest, GrvProxyInterface,
    Hostname, IpAddress, IpAddressValue, KeyRange, KeySelector, Locality, LocalityEntry, Mutation,
    NetworkAddress, NetworkAddressList, OpenDatabaseCoordRequest, PingRequest, ProtocolInfoReply,
    ProtocolInfoRequest, ReplyError, RequestStream, ShardLocations, StorageServerInterface, Void,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dialect {
    V71,
    V72,
    V73,
    V74,
    V80,
}

const COMPATIBLE_MASK: u64 = 0xffffffffffff0000;

impl Dialect {
    pub const ALL: [Dialect; 5] = [
        Dialect::V71,
        Dialect::V72,
        Dialect::V73,
        Dialect::V74,
        Dialect::V80,
    ];

    pub const fn protocol_version(self) -> u64 {
        match self {
            Dialect::V71 => 0x0fdb00b071010000,
            Dialect::V72 => 0x0fdb00b072000000,
            Dialect::V73 => 0x0fdb00b073000000,
            Dialect::V74 => 0x0fdb00b074000000,
            Dialect::V80 => 0x0fdb00b080000000,
        }
    }

    pub const fn from_protocol(version: u64) -> Option<Dialect> {
        match version & COMPATIBLE_MASK {
            0x0fdb00b071010000 => Some(Dialect::V71),
            0x0fdb00b072000000 => Some(Dialect::V72),
            0x0fdb00b073000000 => Some(Dialect::V73),
            0x0fdb00b074000000 => Some(Dialect::V74),
            0x0fdb00b080000000 => Some(Dialect::V80),
            _ => None,
        }
    }

    pub const fn of(version: u64) -> Dialect {
        match version & COMPATIBLE_MASK {
            0x0fdb00b080000000.. => Dialect::V80,
            0x0fdb00b074000000.. => Dialect::V74,
            0x0fdb00b073000000.. => Dialect::V73,
            0x0fdb00b072000000.. => Dialect::V72,
            _ => Dialect::V71,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Reply<T> {
    Value(T),
    Error(u16),
}

pub trait DecodeTable<'a>: Sized {
    fn decode(table: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError>;
}

pub struct List<'a, T> {
    vector: read::Vector<'a>,
    dialect: Dialect,
    item: PhantomData<fn() -> T>,
}

impl<T> Clone for List<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for List<'_, T> {}

impl<T> fmt::Debug for List<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("List")
            .field("len", &self.vector.len())
            .finish()
    }
}

impl<'a, T: DecodeTable<'a> + 'a> List<'a, T> {
    pub(crate) fn new(
        vector: read::Vector<'a>,
        dialect: Dialect,
        max_len: usize,
    ) -> Result<Self, DecodeError> {
        if vector.len() > max_len {
            return Err(DecodeError::Length);
        }
        Ok(List {
            vector,
            dialect,
            item: PhantomData,
        })
    }

    pub fn len(&self) -> usize {
        self.vector.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vector.is_empty()
    }

    pub fn get(&self, index: usize) -> Result<T, DecodeError> {
        T::decode(self.vector.get(index)?.table()?, self.dialect)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Result<T, DecodeError>> + 'a {
        let dialect = self.dialect;
        self.vector
            .tables()
            .map(move |table| table.and_then(|table| T::decode(table, dialect)))
    }
}
