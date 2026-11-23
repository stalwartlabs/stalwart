/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use arrayvec::ArrayVec;
use encodify::base64::STANDARD;
use roaring::RoaringBitmap;
use smallvec::SmallVec;

use super::token::{EAS_CHANGE_ID_MAX, ObjectKind, TokenReader, TokenWriter, kind};
use crate::common::token::TokenBuf;

pub const ATTACHMENT_PATH_MAX: usize = 8;
pub const MAX_ITEMS_STATE_LEN: usize = 16 * 1024 * 1024;
const GROUPS: usize = 4;
const RULE_ID_TEXT_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttachmentPath(ArrayVec<u16, ATTACHMENT_PATH_MAX>);

impl AttachmentPath {
    pub fn new(index: u16) -> Self {
        let mut path = ArrayVec::new();
        path.push(index);
        AttachmentPath(path)
    }

    pub fn try_push(&mut self, index: u16) -> Option<()> {
        self.0.try_push(index).ok()
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EwsObjectId {
    Folder {
        account: u32,
        kind: ObjectKind,
        id: u32,
    },
    Item {
        account: u32,
        kind: ObjectKind,
        container: u32,
        id: u32,
    },
    Occurrence {
        account: u32,
        container: u32,
        id: u32,
        instance: u64,
    },
    Attachment {
        account: u32,
        kind: ObjectKind,
        container: u32,
        id: u32,
        fingerprint: u32,
        path: AttachmentPath,
    },
    Associated {
        account: u32,
        folder_kind: ObjectKind,
        folder: u32,
        id: u32,
    },
}

impl EwsObjectId {
    pub fn encode(&self) -> TokenBuf {
        let writer = match self {
            EwsObjectId::Folder { account, kind, id } => {
                let mut writer = TokenWriter::new(kind::EWS_FOLDER);
                writer.u32(*account).object_kind(*kind).u32(*id);
                writer
            }
            EwsObjectId::Item {
                account,
                kind,
                container,
                id,
            } => {
                let mut writer = TokenWriter::new(kind::EWS_ITEM);
                writer
                    .u32(*account)
                    .object_kind(*kind)
                    .u32(*container)
                    .u32(*id);
                writer
            }
            EwsObjectId::Occurrence {
                account,
                container,
                id,
                instance,
            } => {
                let mut writer = TokenWriter::new(kind::EWS_OCCURRENCE);
                writer.u32(*account).u32(*container).u32(*id).u64(*instance);
                writer
            }
            EwsObjectId::Attachment {
                account,
                kind,
                container,
                id,
                fingerprint,
                path,
            } => {
                let mut writer = TokenWriter::new(kind::EWS_ATTACHMENT);
                writer
                    .u32(*account)
                    .object_kind(*kind)
                    .u32(*container)
                    .u32(*id)
                    .u32(*fingerprint)
                    .u64(path.0.len() as u64);
                for index in path.as_slice() {
                    writer.u32(u32::from(*index));
                }
                writer
            }
            EwsObjectId::Associated {
                account,
                folder_kind,
                folder,
                id,
            } => {
                let mut writer = TokenWriter::new(kind::EWS_ASSOCIATED);
                writer
                    .u32(*account)
                    .object_kind(*folder_kind)
                    .u32(*folder)
                    .u32(*id);
                writer
            }
        };
        writer.finish_base64().unwrap_or_default()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (token_kind, mut reader) = TokenReader::decode_base64(text, &mut scratch)?;
        let id = match token_kind {
            kind::EWS_FOLDER => EwsObjectId::Folder {
                account: reader.u32()?,
                kind: reader.object_kind()?,
                id: reader.u32()?,
            },
            kind::EWS_ITEM => EwsObjectId::Item {
                account: reader.u32()?,
                kind: reader.object_kind()?,
                container: reader.u32()?,
                id: reader.u32()?,
            },
            kind::EWS_OCCURRENCE => EwsObjectId::Occurrence {
                account: reader.u32()?,
                container: reader.u32()?,
                id: reader.u32()?,
                instance: reader.u64()?,
            },
            kind::EWS_ATTACHMENT => {
                let account = reader.u32()?;
                let kind = reader.object_kind()?;
                let container = reader.u32()?;
                let id = reader.u32()?;
                let fingerprint = reader.u32()?;
                let len = usize::try_from(reader.u64()?).ok()?;
                if !(1..=ATTACHMENT_PATH_MAX).contains(&len) {
                    return None;
                }
                let mut path = ArrayVec::new();
                for _ in 0..len {
                    path.push(u16::try_from(reader.u64()?).ok()?);
                }
                EwsObjectId::Attachment {
                    account,
                    kind,
                    container,
                    id,
                    fingerprint,
                    path: AttachmentPath(path),
                }
            }
            kind::EWS_ASSOCIATED => EwsObjectId::Associated {
                account: reader.u32()?,
                folder_kind: reader.object_kind()?,
                folder: reader.u32()?,
                id: reader.u32()?,
            },
            _ => return None,
        };
        reader.end().then_some(id)
    }

    pub fn account(&self) -> u32 {
        match self {
            EwsObjectId::Folder { account, .. }
            | EwsObjectId::Item { account, .. }
            | EwsObjectId::Occurrence { account, .. }
            | EwsObjectId::Attachment { account, .. }
            | EwsObjectId::Associated { account, .. } => *account,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EwsConversationId {
    pub account: u32,
    pub thread: u32,
}

impl EwsConversationId {
    pub fn encode(&self) -> TokenBuf {
        let mut writer = TokenWriter::new(kind::EWS_CONVERSATION);
        writer.u32(self.account).u32(self.thread);
        writer.finish_base64().unwrap_or_default()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (kind::EWS_CONVERSATION, mut reader) = TokenReader::decode_base64(text, &mut scratch)?
        else {
            return None;
        };
        let id = EwsConversationId {
            account: reader.u32()?,
            thread: reader.u32()?,
        };
        reader.end().then_some(id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EwsRuleId(pub u64);

impl EwsRuleId {
    pub fn encode(&self) -> String {
        STANDARD.encode(self.0.to_le_bytes())
    }

    pub fn decode(text: &str) -> Option<Self> {
        if text.len() != RULE_ID_TEXT_LEN {
            return None;
        }
        let bytes = STANDARD.decode(text).ok()?;
        let bytes = <[u8; 8]>::try_from(bytes.as_slice()).ok()?;
        Some(EwsRuleId(u64::from_le_bytes(bytes)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EwsPersonaId {
    Contact {
        account: u32,
        container: u32,
        id: u32,
    },
    Directory {
        principal: u32,
    },
}

impl EwsPersonaId {
    pub fn encode(&self) -> TokenBuf {
        let writer = match *self {
            EwsPersonaId::Contact {
                account,
                container,
                id,
            } => {
                let mut writer = TokenWriter::new(kind::EWS_PERSONA_CONTACT);
                writer.u32(account).u32(container).u32(id);
                writer
            }
            EwsPersonaId::Directory { principal } => {
                let mut writer = TokenWriter::new(kind::EWS_PERSONA_DIRECTORY);
                writer.u32(principal);
                writer
            }
        };
        writer.finish_base64().unwrap_or_default()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (token_kind, mut reader) = TokenReader::decode_base64(text, &mut scratch)?;
        let id = match token_kind {
            kind::EWS_PERSONA_CONTACT => EwsPersonaId::Contact {
                account: reader.u32()?,
                container: reader.u32()?,
                id: reader.u32()?,
            },
            kind::EWS_PERSONA_DIRECTORY => EwsPersonaId::Directory {
                principal: reader.u32()?,
            },
            _ => return None,
        };
        reader.end().then_some(id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EwsChangeKey {
    pub kind: ObjectKind,
    pub change_id: u64,
}

impl EwsChangeKey {
    pub fn encode(&self) -> TokenBuf {
        let mut writer = TokenWriter::new(kind::EWS_CHANGE_KEY);
        writer.object_kind(self.kind).u64(self.change_id);
        writer.finish_base64().unwrap_or_default()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (kind::EWS_CHANGE_KEY, mut reader) = TokenReader::decode_base64(text, &mut scratch)?
        else {
            return None;
        };
        let key = EwsChangeKey {
            kind: reader.object_kind()?,
            change_id: reader.u64()?,
        };
        reader.end().then_some(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EwsSubscriptionKind {
    Pull,
    Streaming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EwsSubscriptionId {
    pub kind: EwsSubscriptionKind,
    pub account: u32,
    pub id: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EwsWatermark {
    pub account: u32,
    pub subscription: u128,
    pub seq: u64,
}

impl EwsSubscriptionId {
    pub fn encode(&self) -> TokenBuf {
        let mut writer = TokenWriter::new(kind::EWS_SUBSCRIPTION);
        writer
            .flag(self.kind == EwsSubscriptionKind::Streaming)
            .u32(self.account);
        write_u128(&mut writer, self.id);
        writer.finish_base64().unwrap_or_default()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (kind::EWS_SUBSCRIPTION, mut reader) = TokenReader::decode_base64(text, &mut scratch)?
        else {
            return None;
        };
        let id = EwsSubscriptionId {
            kind: if reader.flag()? {
                EwsSubscriptionKind::Streaming
            } else {
                EwsSubscriptionKind::Pull
            },
            account: reader.u32()?,
            id: read_u128(&mut reader)?,
        };
        reader.end().then_some(id)
    }
}

impl EwsWatermark {
    pub fn encode(&self) -> TokenBuf {
        let mut writer = TokenWriter::new(kind::EWS_WATERMARK);
        writer.u32(self.account);
        write_u128(&mut writer, self.subscription);
        writer.u64(self.seq);
        writer.finish_base64().unwrap_or_default()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (kind::EWS_WATERMARK, mut reader) = TokenReader::decode_base64(text, &mut scratch)?
        else {
            return None;
        };
        let watermark = EwsWatermark {
            account: reader.u32()?,
            subscription: read_u128(&mut reader)?,
            seq: reader.u64()?,
        };
        reader.end().then_some(watermark)
    }
}

fn write_u128(writer: &mut TokenWriter, value: u128) {
    let low = u64::try_from(value & u128::from(u64::MAX)).unwrap_or_default();
    writer.u64((value >> 64) as u64).u64(low);
}

fn read_u128(reader: &mut TokenReader<'_>) -> Option<u128> {
    Some((u128::from(reader.u64()?) << 64) | u128::from(reader.u64()?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HierarchyPage {
    pub snapshot: [u64; GROUPS],
    pub synthetic: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EwsSyncState {
    Hierarchy {
        root: Option<u32>,
        groups: [u64; GROUPS],
        synthetic: u32,
        page: Option<HierarchyPage>,
        visible: Option<u32>,
    },
}

impl EwsSyncState {
    pub fn encode(&self) -> Option<TokenBuf> {
        let writer = match self {
            EwsSyncState::Hierarchy {
                root,
                groups,
                synthetic,
                page,
                visible,
            } => {
                if groups
                    .iter()
                    .chain(page.iter().flat_map(|page| page.snapshot.iter()))
                    .any(|change_id| *change_id > EAS_CHANGE_ID_MAX)
                {
                    return None;
                }
                let mut writer = TokenWriter::new(kind::EWS_HIERARCHY_SYNC);
                writer.flag(root.is_some());
                if let Some(root) = root {
                    writer.u32(*root);
                }
                for group in groups {
                    writer.u64(*group);
                }
                writer.u32(*synthetic);
                writer.flag(page.is_some());
                if let Some(page) = page {
                    for group in &page.snapshot {
                        writer.u64(*group);
                    }
                    writer.u32(page.synthetic).u32(page.offset);
                }
                writer.flag(visible.is_some());
                if let Some(visible) = visible {
                    writer.u32(*visible);
                }
                writer
            }
        };
        writer.finish_base64()
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut scratch = SmallVec::new();
        let (token_kind, mut reader) = TokenReader::decode_base64(text, &mut scratch)?;
        let state = match token_kind {
            kind::EWS_HIERARCHY_SYNC => {
                let root = if reader.flag()? {
                    Some(reader.u32()?)
                } else {
                    None
                };
                let groups = read_groups(&mut reader)?;
                let synthetic = reader.u32()?;
                let page = if reader.flag()? {
                    Some(HierarchyPage {
                        snapshot: read_groups(&mut reader)?,
                        synthetic: reader.u32()?,
                        offset: reader.u32()?,
                    })
                } else {
                    None
                };
                let visible = if reader.flag()? {
                    Some(reader.u32()?)
                } else {
                    None
                };
                EwsSyncState::Hierarchy {
                    root,
                    groups,
                    synthetic,
                    page,
                    visible,
                }
            }
            _ => return None,
        };
        reader.end().then_some(state)
    }
}

const fn logs_changes(kind: ObjectKind) -> bool {
    matches!(kind, ObjectKind::AddressBook | ObjectKind::Calendar)
}

#[derive(Debug, Clone, PartialEq)]
pub struct EwsItemsState {
    pub container: u32,
    pub kind: ObjectKind,
    pub change_id: u64,
    pub after: u32,
    pub pinned: u64,
    pub held: RoaringBitmap,
}

impl EwsItemsState {
    pub fn encode(&self) -> Option<String> {
        let mut writer = TokenWriter::new(kind::EWS_ITEMS_SYNC);
        writer
            .u32(self.container)
            .object_kind(self.kind)
            .u64(self.change_id)
            .u32(self.after);
        if logs_changes(self.kind) {
            writer.u64(self.pinned);
        }
        let header = writer.as_bytes();
        let mut bytes =
            Vec::with_capacity(header.len().saturating_add(self.held.serialized_size()));
        bytes.extend_from_slice(header);
        self.held.serialize_into(&mut bytes).ok()?;
        Some(STANDARD.encode(bytes))
    }

    pub fn decode(text: &str) -> Option<Self> {
        if text.len() > MAX_ITEMS_STATE_LEN {
            return None;
        }
        let bytes = STANDARD.decode(text).ok()?;
        let (kind::EWS_ITEMS_SYNC, mut reader) = TokenReader::from_bytes(&bytes)? else {
            return None;
        };
        let container = reader.u32()?;
        let kind = reader.object_kind()?;
        let change_id = reader.u64()?;
        let after = reader.u32()?;
        let pinned = if logs_changes(kind) { reader.u64()? } else { 0 };
        let mut rest = reader.into_rest();
        let held = RoaringBitmap::deserialize_from(&mut rest).ok()?;
        rest.is_empty().then_some(EwsItemsState {
            container,
            kind,
            change_id,
            after,
            pinned,
            held,
        })
    }
}

fn read_groups(reader: &mut TokenReader<'_>) -> Option<[u64; GROUPS]> {
    Some([
        reader.change_id()?,
        reader.change_id()?,
        reader.change_id()?,
        reader.change_id()?,
    ])
}
