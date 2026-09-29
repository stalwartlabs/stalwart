/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedMessageMetadata, MessageMetadata, build::NewMetadata};
use std::borrow::Cow;
use store::{
    Deserialize, Serialize, U32_LEN,
    write::{
        Archive, ArchiveBytes, Archiver, Compression, Dictionary,
        compress::{compress, compress_watermark, decompress_into},
    },
};

const TRAILER_LEN: usize = U32_LEN + 1;
const ROW_MARKER: u8 = 0x80;
const HEADERS_COMPRESSED: u8 = 0x01;
const HEADERS_DICTIONARY: Option<Dictionary> = Some(Dictionary::Email);

pub struct MetadataStructure(Archive<ArchiveBytes>);

pub struct MetadataRow {
    sections: Archive<ArchiveBytes>,
    headers_len: usize,
    headers_compressed: bool,
}

#[derive(Debug, Clone, Copy)]
struct RowLayout {
    structure_len: usize,
    headers_end: usize,
    headers_compressed: bool,
}

impl RowLayout {
    fn parse(bytes: &[u8]) -> trc::Result<Self> {
        let (payload, trailer) = bytes
            .split_last_chunk::<TRAILER_LEN>()
            .ok_or_else(RowLayout::corrupted)?;
        let [a0, a1, a2, a3, flags] = *trailer;
        let structure_len = u32::from_le_bytes([a0, a1, a2, a3]) as usize;
        if flags & ROW_MARKER == 0
            || flags & !(ROW_MARKER | HEADERS_COMPRESSED) != 0
            || structure_len > payload.len()
        {
            return Err(RowLayout::corrupted());
        }
        Ok(RowLayout {
            structure_len,
            headers_end: payload.len(),
            headers_compressed: flags & HEADERS_COMPRESSED != 0,
        })
    }

    fn structure(self, bytes: &[u8]) -> trc::Result<&[u8]> {
        bytes
            .get(..self.structure_len)
            .ok_or_else(RowLayout::corrupted)
    }

    fn headers(self, bytes: &[u8]) -> &[u8] {
        bytes
            .get(self.structure_len..self.headers_end)
            .unwrap_or_default()
    }

    fn corrupted() -> trc::Error {
        trc::StoreEvent::DataCorruption
            .into_err()
            .details("Invalid message metadata row")
            .caused_by(trc::location!())
    }
}

impl Deserialize for MetadataStructure {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        RowLayout::parse(bytes)?
            .structure(bytes)
            .and_then(<Archive<ArchiveBytes> as Deserialize>::deserialize)
            .map(MetadataStructure)
    }
}

impl Deserialize for MetadataRow {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let layout = RowLayout::parse(bytes)?;
        let headers = layout.headers(bytes);
        Ok(MetadataRow {
            sections: Archive::<ArchiveBytes>::deserialize_with_prefix(
                headers,
                layout.structure(bytes)?,
            )?,
            headers_len: headers.len(),
            headers_compressed: layout.headers_compressed,
        })
    }
}

impl MetadataStructure {
    pub fn unarchive(&self) -> trc::Result<&ArchivedMessageMetadata> {
        self.0.unarchive::<MessageMetadata>()
    }

    pub fn archive(&self) -> &Archive<ArchiveBytes> {
        &self.0
    }
}

impl MetadataRow {
    pub fn encode(metadata: MessageMetadata, raw_headers: &[u8]) -> trc::Result<Vec<u8>> {
        let mut row = Archiver::with_compression(metadata, Compression::None).serialize()?;
        let structure_len = u32::try_from(row.len()).map_err(|_| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Message metadata too large")
                .caused_by(trc::location!())
        })?;
        let compressed = if raw_headers.len() >= compress_watermark(HEADERS_DICTIONARY) {
            compress(HEADERS_DICTIONARY, raw_headers, 0).map_err(|err| {
                trc::StoreEvent::UnexpectedError
                    .caused_by(trc::location!())
                    .reason(err)
            })?
        } else {
            Vec::new()
        };
        let (section, flags) = if !compressed.is_empty() && compressed.len() < raw_headers.len() {
            (compressed.as_slice(), ROW_MARKER | HEADERS_COMPRESSED)
        } else {
            (raw_headers, ROW_MARKER)
        };
        row.reserve_exact(section.len() + TRAILER_LEN);
        row.extend_from_slice(section);
        row.extend_from_slice(&structure_len.to_le_bytes());
        row.push(flags);
        Ok(row)
    }

    pub fn unarchive(&self) -> trc::Result<&ArchivedMessageMetadata> {
        self.sections.unarchive::<MessageMetadata>()
    }

    pub fn headers_compressed(&self) -> bool {
        self.headers_compressed
    }

    pub fn raw_headers(&self) -> trc::Result<Cow<'_, [u8]>> {
        let stored = self
            .sections
            .inner
            .get(..self.headers_len)
            .unwrap_or_default();
        if self.headers_compressed {
            let expected = self.unarchive()?.headers_len();
            let mut inflated = Vec::new();
            decompress_into(stored, &mut inflated, expected).map_err(|err| {
                trc::StoreEvent::DecompressError
                    .caused_by(trc::location!())
                    .reason(err)
            })?;
            if inflated.len() == expected {
                Ok(Cow::Owned(inflated))
            } else {
                Err(RowLayout::corrupted())
            }
        } else {
            Ok(Cow::Borrowed(stored))
        }
    }
}

impl NewMetadata {
    pub fn encode(self) -> trc::Result<Vec<u8>> {
        MetadataRow::encode(self.metadata, &self.raw_headers)
    }
}
