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
    wire::{ClientDBInfo, Dialect, List, Reply},
};

fn a<'a>(t: Table<'a>, dialect: Dialect) -> Result<ClientDBInfo<'a>, DecodeError> {
    Ok(ClientDBInfo {
        grv_proxies: List::new(t.vector(0)?, dialect, ClientDBInfo::MAX_GRV_PROXIES)?,
        commit_proxies: List::new(t.vector(1)?, dialect, ClientDBInfo::MAX_COMMIT_PROXIES)?,
        id: t.uid(2)?,
        forward: t.optional_bytes(3)?,
    })
}

impl<'a> ClientDBInfo<'a> {
    pub const FILE_IDENTIFIER: u32 = 38909512;

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
