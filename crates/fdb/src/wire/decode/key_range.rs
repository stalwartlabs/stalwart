/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, read::Table, transform},
    wire::{DecodeTable, Dialect, KeyRange},
};

fn a<'a>(t: Table<'a>) -> Result<KeyRange<'a>, DecodeError> {
    Ok({
        let (begin, end) = transform::single_key_range_decode(t.bytes(0)?, t.bytes(1)?)?;
        KeyRange { begin, end }
    })
}

impl<'a> DecodeTable<'a> for KeyRange<'a> {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => a(t),
        }
    }
}
