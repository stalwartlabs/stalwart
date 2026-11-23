/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, read::Table},
    wire::{DecodeTable, Dialect, NetworkAddress},
};

fn a(t: Table<'_>, dialect: Dialect) -> Result<NetworkAddress, DecodeError> {
    Ok(NetworkAddress {
        ip: DecodeTable::decode(t.table(0)?.unwrap_or(Table::EMPTY), dialect)?,
        port: t.u16(1)?,
        flags: t.u16(2)?,
        from_hostname: t.bool(3)?,
    })
}

impl<'a> DecodeTable<'a> for NetworkAddress {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => {
                a(t, dialect)
            }
        }
    }
}
