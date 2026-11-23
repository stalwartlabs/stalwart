/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, read::Table},
    wire::{DecodeTable, Dialect, List, Locality},
};

fn a<'a>(t: Table<'a>, dialect: Dialect) -> Result<Locality<'a>, DecodeError> {
    Ok(Locality {
        entries: List::new(t.vector(0)?, dialect, Locality::MAX_ENTRIES)?,
    })
}

impl<'a> DecodeTable<'a> for Locality<'a> {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => {
                a(t, dialect)
            }
        }
    }
}
