/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, Uid, read::Table},
    wire::{DecodeTable, Dialect, StorageServerInterface},
};

fn a<'a>(t: Table<'a>, dialect: Dialect) -> Result<StorageServerInterface<'a>, DecodeError> {
    Ok(StorageServerInterface {
        id: t.uid(0)?,
        locality: DecodeTable::decode(t.table(1)?.unwrap_or(Table::EMPTY), dialect)?,
        get_value: DecodeTable::decode(t.table(2)?.unwrap_or(Table::EMPTY), dialect)?,
        tss_pair_id: t.optional_scalar::<16>(3)?.map(Uid::from_le_bytes),
        accepting_requests: t.bool(5)?,
    })
}

impl<'a> DecodeTable<'a> for StorageServerInterface<'a> {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => {
                a(t, dialect)
            }
        }
    }
}
