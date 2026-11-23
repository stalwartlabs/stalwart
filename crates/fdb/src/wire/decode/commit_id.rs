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
    wire::{CommitID, Dialect, Reply},
};

fn a<'a>(t: Table<'a>) -> Result<CommitID<'a>, DecodeError> {
    Ok(CommitID {
        version: t.i64(0)?,
        conflicting_key_ranges: t.optional(4)?.map(|v| v.scalar_vector::<4>()).transpose()?,
    })
}

impl<'a> CommitID<'a> {
    pub const FILE_IDENTIFIER: u32 = 47809359;

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
