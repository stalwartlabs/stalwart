/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, read::Table},
    wire::{DecodeTable, Dialect, LocalityEntry},
};

fn a<'a>(t: Table<'a>) -> Result<LocalityEntry<'a>, DecodeError> {
    Ok(LocalityEntry {
        key: t.bytes(0)?,
        value: t.optional_bytes(1)?,
    })
}

impl<'a> DecodeTable<'a> for LocalityEntry<'a> {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => a(t),
        }
    }
}
