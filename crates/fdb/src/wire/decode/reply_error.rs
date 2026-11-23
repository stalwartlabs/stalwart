/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{DecodeError, read::Table},
    wire::{DecodeTable, Dialect, ReplyError},
};

fn a(t: Table<'_>) -> Result<ReplyError, DecodeError> {
    Ok(ReplyError {
        code: match t.u16(0)? {
            0 => return Err(DecodeError::ErrorCode),
            code => code,
        },
    })
}

impl<'a> DecodeTable<'a> for ReplyError {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => a(t),
        }
    }
}
