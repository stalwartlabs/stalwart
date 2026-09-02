/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::SwapPart;

const MAGIC: u32 = 0x5357_4131;
const VERSION: u16 = 1;

pub const HEADER_LEN: usize = 32;

pub struct SwapFrame<'x> {
    part: SwapPart,
    change_id: u64,
    count: u32,
    payload: &'x [u8],
}

impl<'x> SwapFrame<'x> {
    pub fn reserve_header() -> Vec<u8> {
        vec![0u8; HEADER_LEN]
    }

    pub fn seal(out: &mut [u8], part: SwapPart, change_id: u64, count: u32) {
        let Some(payload_len) = out.len().checked_sub(HEADER_LEN) else {
            return;
        };
        let checksum = xxhash_rust::xxh3::xxh3_64(&out[HEADER_LEN..]);
        let header = &mut out[..HEADER_LEN];

        header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..6].copy_from_slice(&VERSION.to_le_bytes());
        header[6] = part.code();
        header[7] = 0;
        header[8..16].copy_from_slice(&change_id.to_le_bytes());
        header[16..20].copy_from_slice(&count.to_le_bytes());
        header[20..24].copy_from_slice(&(payload_len as u32).to_le_bytes());
        header[24..32].copy_from_slice(&checksum.to_le_bytes());
    }

    pub fn parse(buf: &'x [u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN
            || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MAGIC
            || u16::from_le_bytes(buf[4..6].try_into().ok()?) != VERSION
        {
            return None;
        }

        let payload_len = u32::from_le_bytes(buf[20..24].try_into().ok()?) as usize;
        let checksum = u64::from_le_bytes(buf[24..32].try_into().ok()?);
        let payload = buf.get(HEADER_LEN..HEADER_LEN.checked_add(payload_len)?)?;

        if xxhash_rust::xxh3::xxh3_64(payload) != checksum {
            return None;
        }

        Some(SwapFrame {
            part: SwapPart::from_code(buf[6])?,
            change_id: u64::from_le_bytes(buf[8..16].try_into().ok()?),
            count: u32::from_le_bytes(buf[16..20].try_into().ok()?),
            payload,
        })
    }

    pub fn part(&self) -> SwapPart {
        self.part
    }

    pub fn change_id(&self) -> u64 {
        self.change_id
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn payload(&self) -> &'x [u8] {
        self.payload
    }
}
