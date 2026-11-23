/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{
        DecodeError,
        read::{self, Table},
    },
    wire::{DecodeTable, Dialect, IpAddress, IpAddressValue},
};

fn a(t: Table<'_>) -> Result<IpAddress, DecodeError> {
    Ok(IpAddress {
        addr: match t.union(0)? {
            read::Union {
                tag: 1,
                value: Some(t1),
            } => IpAddressValue::V4(u32::from_le_bytes(t1.scalar::<4>()?)),
            read::Union {
                tag: 2,
                value: Some(t1),
            } => IpAddressValue::V6(
                <[u8; 16]>::try_from(t1.scalar_vector::<1>()?.as_flattened())
                    .map_err(|_| DecodeError::Length)?,
            ),
            read::Union { tag, .. } => return Err(DecodeError::UnionTag(tag)),
        },
    })
}

impl<'a> DecodeTable<'a> for IpAddress {
    fn decode(t: Table<'a>, dialect: Dialect) -> Result<Self, DecodeError> {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => a(t),
        }
    }
}
