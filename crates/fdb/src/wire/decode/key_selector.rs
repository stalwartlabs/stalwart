/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, read::Table},
    wire::{DecodeTable, Dialect, KeySelector},
};

fn a<'a>(t: Table<'a>) -> Result<KeySelector<'a>, DecodeError> {
    Ok(KeySelector {
        key: t.bytes(0)?,
        or_equal: t.bool(1)?,
        offset: t.i32(2)?,
    })
}

impl<'a> DecodeTable<'a> for KeySelector<'a> {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => a(t),
        }
    }
}
