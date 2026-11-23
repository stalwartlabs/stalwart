/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod cursor;
pub(crate) mod emit;
pub(crate) mod header_id;
pub(crate) mod ops;
pub(crate) mod rec;
pub(crate) mod verify;
pub mod view;

use crate::LoadError;

pub(crate) const MAGIC: u32 = 0x5645_4953;
pub(crate) const FORMAT_VERSION: u16 = 1;
pub(crate) const HEADER_LEN: usize = 40;
pub(crate) const REC_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corrupt;

pub(crate) type Decoded<T> = Result<T, Corrupt>;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Sections {
    pub num_vars: u16,
    pub num_match_vars: u16,
    pub code: (usize, usize),
    pub records: (usize, usize),
    pub blob: (usize, usize),
    pub header_names: (usize, usize),
    pub globs: (usize, usize),
    pub num_regexes: u32,
}

impl Sections {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Sections, LoadError> {
        let head = bytes
            .first_chunk::<HEADER_LEN>()
            .ok_or(LoadError::Truncated)?;
        let u16_at = |at: usize| u16::from_le_bytes([head[at], head[at + 1]]);
        let u32_at =
            |at: usize| u32::from_le_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]);
        if u32_at(0) != MAGIC {
            return Err(LoadError::Corrupted);
        }
        let version = u16_at(4);
        if version != FORMAT_VERSION {
            return Err(LoadError::UnsupportedVersion(version));
        }
        let mut start = HEADER_LEN;
        let mut section = |len: u32| -> Result<(usize, usize), LoadError> {
            let len = len as usize;
            let end = start.checked_add(len).ok_or(LoadError::Corrupted)?;
            if end > bytes.len() {
                return Err(LoadError::Truncated);
            }
            let range = (start, end);
            start = end;
            Ok(range)
        };
        let code = section(u32_at(12))?;
        let records = section(u32_at(16))?;
        let blob = section(u32_at(20))?;
        let header_names = section(u32_at(24))?;
        let globs = section(u32_at(28))?;
        let num_records = records.1 - records.0;
        let num_regexes = u32_at(32);
        if num_records % REC_LEN != 0 || num_regexes as usize > num_records / REC_LEN {
            return Err(LoadError::Corrupted);
        }
        Ok(Sections {
            num_vars: u16_at(8),
            num_match_vars: u16_at(10),
            code,
            records,
            blob,
            header_names,
            globs,
            num_regexes,
        })
    }

    pub(crate) fn write_header(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.num_vars.to_le_bytes());
        out.extend_from_slice(&self.num_match_vars.to_le_bytes());
        for (start, end) in [
            self.code,
            self.records,
            self.blob,
            self.header_names,
            self.globs,
        ] {
            out.extend_from_slice(&((end - start) as u32).to_le_bytes());
        }
        out.extend_from_slice(&self.num_regexes.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
    }
}
