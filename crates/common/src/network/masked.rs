/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::write::now;
use utils::snowflake::SnowflakeIdGenerator;

pub struct MaskedAddress;

const U32_MAX: u128 = u32::MAX as u128;

impl MaskedAddress {
    pub fn generate(address_id: u64, expires: Option<u32>, prefix: &str, domain: &str) -> String {
        let expires = expires.unwrap_or(0) as u128 & U32_MAX;
        let address_id = address_id as u128;
        let ids = (address_id << 64)
            | (expires << 32)
            | ((address_id & U32_MAX) ^ (address_id >> 32) ^ expires);

        let mut address = String::with_capacity(prefix.len() + domain.len() + 30);
        address.push_str(prefix);
        address.push('.');
        address.push_str(&base36_encode(ids));
        address.push('@');
        address.push_str(domain);
        address
    }

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

fn base36_encode(mut n: u128) -> String {
    const CHARS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    let mut buf = Vec::with_capacity(25);
    while n > 0 {
        buf.push(CHARS[(n % 36) as usize]);
        n /= 36;
    }

    buf.reverse();
    String::from_utf8(buf).unwrap()
}
