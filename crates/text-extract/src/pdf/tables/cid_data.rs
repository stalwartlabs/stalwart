/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(super) const EXTRA_SENTINEL: u16 = 0xD800;

pub(super) static JAPAN1: &[u8] = include_bytes!("cid_japan1.bin");
pub(super) const JAPAN1_RAW_LEN: usize = 70992;
#[cfg(test)]
pub(super) const JAPAN1_CHECKSUM: u64 = 0xE2311E4E34FE602D;
pub(super) static GB1: &[u8] = include_bytes!("cid_gb1.bin");
pub(super) const GB1_RAW_LEN: usize = 60616;
#[cfg(test)]
pub(super) const GB1_CHECKSUM: u64 = 0x5D8285994CF43CD6;
pub(super) static CNS1: &[u8] = include_bytes!("cid_cns1.bin");
pub(super) const CNS1_RAW_LEN: usize = 50439;
#[cfg(test)]
pub(super) const CNS1_CHECKSUM: u64 = 0x1FCAE917FBE43122;
pub(super) static KOREA1: &[u8] = include_bytes!("cid_korea1.bin");
pub(super) const KOREA1_RAW_LEN: usize = 40936;
#[cfg(test)]
pub(super) const KOREA1_CHECKSUM: u64 = 0x5077AF3F128E992C;
