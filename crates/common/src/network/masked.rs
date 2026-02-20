/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::write::now;
use utils::snowflake::SnowflakeIdGenerator;

pub struct MaskedAddress;

impl MaskedAddress {
    pub fn parse(local_part: &str) -> Option<u64> {
        let mut parts = local_part.split('.');
        let _prefix = parts.next().filter(|v| !v.is_empty())?;
        let ids = parts.next().filter(|v| !v.is_empty())?;
        if parts.next().is_some() {
            return None;
        }
        // Format: <address_id (64)>.<expires (32)>.<checksum (32)> encoded as base36
        let ids = u128::from_str_radix(ids, 36).ok()?;
        let address_id = (ids >> 64) as u64;
        let expires = (ids >> 32) as u32;
        let checksum = ids as u32;

        if checksum == ((address_id as u32) ^ (address_id >> 32) as u32 ^ expires)
            && (expires == 0
                || (SnowflakeIdGenerator::to_timestamp(address_id) + expires as u64 > now()))
        {
            Some(address_id)
        } else {
            None
        }
    }
}
