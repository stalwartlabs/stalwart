/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use smallvec::SmallVec;

use super::token::{EAS_CHANGE_ID_MAX, ObjectKind, TokenReader, TokenWriter, kind};
use crate::common::token::TokenBuf;

const GROUPS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EasSyncKey {
    pub nonce: u32,
    pub generation: u32,
    pub change_id: u64,
    pub page: Option<u32>,
}

impl EasSyncKey {
    pub fn encode(&self) -> Option<TokenBuf> {
        if self.change_id > EAS_CHANGE_ID_MAX {
            return None;
        }
        let mut writer = TokenWriter::new(kind::EAS_SYNC_KEY);
        writer
            .u32(self.nonce)
            .u32(self.generation)
            .u64(self.change_id)
            .flag(self.page.is_some());
        if let Some(page) = self.page {
            writer.u32(page);
        }
        writer.finish_eas()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (kind::EAS_SYNC_KEY, mut reader) = TokenReader::decode_eas(text, &mut scratch)? else {
            return None;
        };
        let key = EasSyncKey {
            nonce: reader.u32()?,
            generation: reader.u32()?,
            change_id: reader.change_id()?,
            page: if reader.flag()? {
                Some(reader.u32()?)
            } else {
                None
            },
        };
        reader.end().then_some(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EasHierarchyKey {
    pub nonce: u32,
    pub generation: u32,
    pub groups: [u64; GROUPS],
}

impl EasHierarchyKey {
    pub fn encode(&self) -> Option<TokenBuf> {
        if self.groups.iter().any(|group| *group > EAS_CHANGE_ID_MAX) {
            return None;
        }
        let mut writer = TokenWriter::new(kind::EAS_HIERARCHY_KEY);
        writer.u32(self.nonce).u32(self.generation);
        for group in &self.groups {
            writer.u64(*group);
        }
        writer.finish_eas()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (kind::EAS_HIERARCHY_KEY, mut reader) = TokenReader::decode_eas(text, &mut scratch)?
        else {
            return None;
        };
        let key = EasHierarchyKey {
            nonce: reader.u32()?,
            generation: reader.u32()?,
            groups: [
                reader.change_id()?,
                reader.change_id()?,
                reader.change_id()?,
                reader.change_id()?,
            ],
        };
        reader.end().then_some(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EasServerId {
    pub container: u32,
    pub id: u32,
}

impl EasServerId {
    pub fn encode(&self) -> TokenBuf {
        let mut writer = TokenWriter::new(kind::EAS_SERVER_ID);
        writer.u32(self.container).u32(self.id);
        writer.finish_eas().unwrap_or_default()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (kind::EAS_SERVER_ID, mut reader) = TokenReader::decode_eas(text, &mut scratch)? else {
            return None;
        };
        let id = EasServerId {
            container: reader.u32()?,
            id: reader.u32()?,
        };
        reader.end().then_some(id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EasCollectionId {
    pub kind: ObjectKind,
    pub id: u32,
}

impl EasCollectionId {
    pub fn encode(&self) -> TokenBuf {
        let mut writer = TokenWriter::new(kind::EAS_COLLECTION_ID);
        writer.object_kind(self.kind).u32(self.id);
        writer.finish_eas().unwrap_or_default()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (kind::EAS_COLLECTION_ID, mut reader) = TokenReader::decode_eas(text, &mut scratch)?
        else {
            return None;
        };
        let id = EasCollectionId {
            kind: reader.object_kind()?,
            id: reader.u32()?,
        };
        reader.end().then_some(id)
    }
}
