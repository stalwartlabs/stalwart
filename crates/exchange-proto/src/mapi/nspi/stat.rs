/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{error::NspiDecodeError, minid::MinimalId};
use crate::common::LeReader;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stat {
    pub sort_type: u32,
    pub container_id: u32,
    pub current_rec: u32,
    pub delta: i32,
    pub num_pos: u32,
    pub total_recs: u32,
    pub code_page: u32,
    pub template_locale: u32,
    pub sort_locale: u32,
}

impl Stat {
    pub const LEN: usize = 36;
    pub const SORT_DISPLAY_NAME: u32 = 0;
    pub const SORT_PHONETIC_DISPLAY_NAME: u32 = 3;
    pub const SORT_DISPLAY_NAME_RO: u32 = 0x3E8;
    pub const SORT_DISPLAY_NAME_W: u32 = 0x3E9;
    pub const CP_WINUNICODE: u32 = 0x4B0;

    pub fn decode(r: &mut LeReader<'_>) -> Result<Self, NspiDecodeError> {
        let fields: [u8; Self::LEN] = r.array()?;
        let mut r = LeReader::new(&fields);
        Ok(Stat {
            sort_type: r.u32()?,
            container_id: r.u32()?,
            current_rec: r.u32()?,
            delta: r.i32()?,
            num_pos: r.u32()?,
            total_recs: r.u32()?,
            code_page: r.u32()?,
            template_locale: r.u32()?,
            sort_locale: r.u32()?,
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(Self::LEN);
        for field in [
            self.sort_type,
            self.container_id,
            self.current_rec,
            u32::from_le_bytes(self.delta.to_le_bytes()),
            self.num_pos,
            self.total_recs,
            self.code_page,
            self.template_locale,
            self.sort_locale,
        ] {
            out.extend_from_slice(&field.to_le_bytes());
        }
    }

    pub fn current(&self) -> MinimalId {
        MinimalId(self.current_rec)
    }
}
