/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, read::Table},
    wire::{DecodeTable, Dialect, GrvProxyInterface},
};

fn a(t: Table<'_>, dialect: Dialect) -> Result<GrvProxyInterface, DecodeError> {
    Ok(GrvProxyInterface {
        provisional: t.bool(2)?,
        get_consistent_read_version: DecodeTable::decode(
            t.table(3)?.unwrap_or(Table::EMPTY),
            dialect,
        )?,
    })
}

impl<'a> DecodeTable<'a> for GrvProxyInterface {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => {
                a(t, dialect)
            }
        }
    }
}
