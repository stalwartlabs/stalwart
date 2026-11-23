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
    wire::{DecodeTable, Dialect, GetValueReply, Reply},
};

fn a<'a>(t: Table<'a>, dialect: Dialect) -> Result<GetValueReply<'a>, DecodeError> {
    Ok(GetValueReply {
        penalty: t.f64(0)?,
        error: t
            .optional_table(1)?
            .map(|t1| DecodeTable::decode(t1, dialect))
            .transpose()?,
        value: t.optional_bytes(3)?,
    })
}

impl<'a> GetValueReply<'a> {
    pub const FILE_IDENTIFIER: u32 = 34933361;

    pub fn decode(dialect: Dialect, buf: &'a [u8]) -> Result<Reply<Self>, DecodeError> {
        let t = match read::reply(buf, Self::FILE_IDENTIFIER)? {
            read::Reply::Value(value) => value.table()?,
            read::Reply::Error(code) => return Ok(Reply::Error(code)),
        };
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => {
                a(t, dialect)
            }
        }
        .map(Reply::Value)
    }
}
