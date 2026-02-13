/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::write::now;

pub struct MaskedAddress {
    pub account_id: u32,
    pub address_id: u32,
    pub has_expired: bool,
}

const DEFAULT_EPOCH: u64 = 1632280000; // 52 years after UNIX_EPOCH

impl MaskedAddress {
    pub fn parse(local_part: &str) -> Option<Self> {
        let mut parts = local_part.split('.');
        let _prefix = parts.next().filter(|v| !v.is_empty())?;
        let ids = parts.next().filter(|v| !v.is_empty())?;
        if parts.next().is_some() {
            return None;
        }
        // Format: <account_id (32)>.<address_id (32)>.<expires (32)>.<checksum (32)> encoded as base36
        let ids = u128::from_str_radix(ids, 36).ok()?;
        let account_id = (ids >> 96) as u32;
        let address_id = (ids >> 64) as u32;
        let expires = (ids >> 32) as u32;
        let checksum = ids as u32;

        if checksum == (account_id ^ address_id ^ expires) {
            Some(Self {
                account_id,
                address_id,
                has_expired: (now().saturating_sub(DEFAULT_EPOCH) / 60) > expires as u64,
            })
        } else {
            None
        }
    }
}
