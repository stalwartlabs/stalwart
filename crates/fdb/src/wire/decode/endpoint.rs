/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, read::Table},
    wire::{DecodeTable, Dialect, Endpoint},
};

fn a(t: Table<'_>, dialect: Dialect) -> Result<Endpoint, DecodeError> {
    Ok(Endpoint {
        addresses: DecodeTable::decode(t.table(0)?.unwrap_or(Table::EMPTY), dialect)?,
        token: t.uid(1)?,
    })
}

impl<'a> DecodeTable<'a> for Endpoint {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => {
                a(t, dialect)
            }
        }
    }
}
