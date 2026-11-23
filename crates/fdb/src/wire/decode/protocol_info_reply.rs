/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{
        DecodeError,
        read::{self, Table},
    },
    wire::{Dialect, ProtocolInfoReply, Reply},
};

fn a(t: Table<'_>) -> Result<ProtocolInfoReply, DecodeError> {
    Ok(ProtocolInfoReply { version: t.u64(0)? })
}

impl ProtocolInfoReply {
    pub const FILE_IDENTIFIER: u32 = 41338730;

    pub fn decode(dialect: Dialect, buf: &[u8]) -> Result<Reply<Self>, DecodeError> {
        let t = match read::reply(buf, Self::FILE_IDENTIFIER)? {
            read::Reply::Value(value) => value.table()?,
            read::Reply::Error(code) => return Ok(Reply::Error(code)),
        };
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => a(t),
        }
        .map(Reply::Value)
    }
}
