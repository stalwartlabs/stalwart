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
    wire::{Dialect, GetReadVersionReply, Reply},
};

fn a<'a>(t: Table<'a>) -> Result<GetReadVersionReply<'a>, DecodeError> {
    Ok(GetReadVersionReply {
        process_busy_time: t.i32(0)?,
        version: t.i64(1)?,
        locked: t.bool(2)?,
        metadata_version: t.optional_bytes(3)?,
        rk_default_throttled: t.bool(7)?,
        rk_batch_throttled: t.bool(8)?,
    })
}

impl<'a> GetReadVersionReply<'a> {
    pub const FILE_IDENTIFIER: u32 = 49263820;

    pub fn decode(dialect: Dialect, buf: &'a [u8]) -> Result<Reply<Self>, DecodeError> {
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
