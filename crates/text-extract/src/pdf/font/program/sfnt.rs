/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::read::ReadBytes;

const COLLECTION_TAG: &[u8; 4] = b"ttcf";
const COLLECTION_FIRST_OFFSET: usize = 12;
const NUM_TABLES_OFFSET: usize = 4;
const RECORDS_OFFSET: usize = 12;
const RECORD_LEN: usize = 16;
const RECORD_OFFSET_FIELD: usize = 8;
const RECORD_LENGTH_FIELD: usize = 12;
const VERSION_TRUETYPE: u32 = 0x0001_0000;
const VERSION_OPEN_TYPE: &[u8; 4] = b"OTTO";
const VERSION_APPLE: &[u8; 4] = b"true";

#[derive(Debug, Clone, Copy)]
pub(crate) struct Sfnt<'x> {
    data: &'x [u8],
    records: &'x [[u8; RECORD_LEN]],
}

impl<'x> Sfnt<'x> {
    pub(crate) fn parse(data: &'x [u8]) -> Option<Self> {
        let offset = if data.first_chunk::<4>() == Some(COLLECTION_TAG) {
            usize::try_from(data.be_u32(COLLECTION_FIRST_OFFSET)?).ok()?
        } else {
            0
        };
        let header = data.get(offset..)?;
        let version = header.first_chunk::<4>()?;
        if u32::from_be_bytes(*version) != VERSION_TRUETYPE
            && version != VERSION_OPEN_TYPE
            && version != VERSION_APPLE
        {
            return None;
        }
        let num_tables = usize::from(header.be_u16(NUM_TABLES_OFFSET)?);
        let (records, _) = header.get(RECORDS_OFFSET..)?.as_chunks::<RECORD_LEN>();
        let records = records.get(..num_tables).unwrap_or(records);
        Some(Self { data, records })
    }

    pub(crate) fn table(&self, tag: &[u8; 4]) -> Option<&'x [u8]> {
        let record = self
            .records
            .iter()
            .find(|record| record.first_chunk::<4>() == Some(tag))?;
        let offset = usize::try_from(record.be_u32(RECORD_OFFSET_FIELD)?).ok()?;
        let len = usize::try_from(record.be_u32(RECORD_LENGTH_FIELD)?).ok()?;
        let table = self.data.get(offset..)?;
        Some(table.get(..len).unwrap_or(table))
    }
}
