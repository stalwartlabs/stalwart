/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, read::Table},
    wire::{DecodeTable, Dialect, List, ShardLocations},
};

fn a<'a>(t: Table<'a>, dialect: Dialect) -> Result<ShardLocations<'a>, DecodeError> {
    Ok(ShardLocations {
        range: DecodeTable::decode(t.table(0)?.unwrap_or(Table::EMPTY), dialect)?,
        servers: List::new(t.vector(1)?, dialect, ShardLocations::MAX_SERVERS)?,
    })
}

impl<'a> DecodeTable<'a> for ShardLocations<'a> {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => {
                a(t, dialect)
            }
        }
    }
}
