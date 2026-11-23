/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{Children, CommandError, MAX_ID_LEN, SyncKeyStr, read_id, read_str, read_u8, required};
use crate::eas::status::FolderStatus;
use crate::eas::tokens::{ProtocolVersion, Tag, tag::folder_hierarchy as fh};
use crate::eas::types::FolderType;
use crate::eas::wbxml::{Decoder, Encoder};

pub const MAX_DISPLAY_NAME_CHARS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSyncRequest<'a> {
    pub sync_key: SyncKeyStr<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderCreateRequest<'a> {
    pub sync_key: SyncKeyStr<'a>,
    pub parent_id: Cow<'a, str>,
    pub display_name: Cow<'a, str>,
    pub folder_type: FolderType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderUpdateRequest<'a> {
    pub sync_key: SyncKeyStr<'a>,
    pub server_id: Cow<'a, str>,
    pub parent_id: Cow<'a, str>,
    pub display_name: Cow<'a, str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderDeleteRequest<'a> {
    pub sync_key: SyncKeyStr<'a>,
    pub server_id: Cow<'a, str>,
}

#[derive(Default)]
struct Fields<'a> {
    sync_key: Option<SyncKeyStr<'a>>,
    server_id: Option<Cow<'a, str>>,
    parent_id: Option<Cow<'a, str>>,
    display_name: Option<Cow<'a, str>>,
    folder_type: Option<FolderType>,
}

impl<'a> Fields<'a> {
    fn parse(dec: &mut Decoder<'a>, root: Tag) -> Result<Self, CommandError> {
        let mut fields = Fields::default();
        let mut children = Children::root(dec, root)?;
        while let Some(tag) = children.next(dec)? {
            match tag {
                fh::SYNC_KEY => fields.sync_key = Some(SyncKeyStr(read_id(dec, tag, MAX_ID_LEN)?)),
                fh::SERVER_ID => fields.server_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                fh::PARENT_ID => fields.parent_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                fh::DISPLAY_NAME => {
                    let name = read_str(dec, tag)?;
                    if name.is_empty() || name.chars().nth(MAX_DISPLAY_NAME_CHARS).is_some() {
                        return Err(CommandError::InvalidValue { tag });
                    }
                    fields.display_name = Some(name);
                }
                fh::TYPE => fields.folder_type = Some(FolderType(read_u8(dec, tag)?)),
                _ => {}
            }
        }
        Ok(fields)
    }

    fn sync_key(&mut self) -> Result<SyncKeyStr<'a>, CommandError> {
        required(self.sync_key.take(), fh::SYNC_KEY)
    }
}

impl<'a> FolderSyncRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut fields = Fields::parse(dec, fh::FOLDER_SYNC)?;
        Ok(FolderSyncRequest {
            sync_key: fields.sync_key()?,
        })
    }
}

impl<'a> FolderCreateRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut fields = Fields::parse(dec, fh::FOLDER_CREATE)?;
        Ok(FolderCreateRequest {
            sync_key: fields.sync_key()?,
            parent_id: required(fields.parent_id, fh::PARENT_ID)?,
            display_name: required(fields.display_name, fh::DISPLAY_NAME)?,
            folder_type: required(fields.folder_type, fh::TYPE)?,
        })
    }
}

impl<'a> FolderUpdateRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut fields = Fields::parse(dec, fh::FOLDER_UPDATE)?;
        Ok(FolderUpdateRequest {
            sync_key: fields.sync_key()?,
            server_id: required(fields.server_id, fh::SERVER_ID)?,
            parent_id: required(fields.parent_id, fh::PARENT_ID)?,
            display_name: required(fields.display_name, fh::DISPLAY_NAME)?,
        })
    }
}

impl<'a> FolderDeleteRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut fields = Fields::parse(dec, fh::FOLDER_DELETE)?;
        Ok(FolderDeleteRequest {
            sync_key: fields.sync_key()?,
            server_id: required(fields.server_id, fh::SERVER_ID)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderEntry<'x> {
    pub server_id: &'x str,
    pub parent_id: &'x str,
    pub display_name: &'x str,
    pub folder_type: FolderType,
}

impl FolderEntry<'_> {
    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.start(tag)
            .text_str(fh::SERVER_ID, self.server_id)
            .text_str(fh::PARENT_ID, self.parent_id)
            .text_str(fh::DISPLAY_NAME, self.display_name)
            .text_u64(fh::TYPE, u64::from(self.folder_type.0))
            .end();
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderChanges<'x> {
    pub updates: Vec<FolderEntry<'x>>,
    pub deletes: Vec<&'x str>,
    pub adds: Vec<FolderEntry<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSyncResponse<'x> {
    pub status: FolderStatus,
    pub sync_key: Option<&'x str>,
    pub changes: Option<FolderChanges<'x>>,
}

impl FolderSyncResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(fh::FOLDER_SYNC)
            .text_u64(fh::STATUS, u64::from(self.status.0));
        if let Some(sync_key) = self.sync_key {
            enc.text_str(fh::SYNC_KEY, sync_key);
        }
        if let Some(changes) = &self.changes {
            let count = changes
                .updates
                .len()
                .saturating_add(changes.deletes.len())
                .saturating_add(changes.adds.len());
            enc.start(fh::CHANGES)
                .text_u64(fh::COUNT, u64::try_from(count).unwrap_or(u64::MAX));
            for entry in &changes.updates {
                entry.encode(enc, fh::UPDATE);
            }
            for server_id in &changes.deletes {
                enc.start(fh::DELETE)
                    .text_str(fh::SERVER_ID, server_id)
                    .end();
            }
            for entry in &changes.adds {
                entry.encode(enc, fh::ADD);
            }
            enc.end();
        }
        enc.end();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderCreateResponse<'x> {
    pub status: FolderStatus,
    pub sync_key: Option<&'x str>,
    pub server_id: Option<&'x str>,
}

impl FolderCreateResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(fh::FOLDER_CREATE)
            .text_u64(fh::STATUS, u64::from(self.status.0));
        if let Some(sync_key) = self.sync_key {
            enc.text_str(fh::SYNC_KEY, sync_key);
        }
        if let Some(server_id) = self.server_id {
            enc.text_str(fh::SERVER_ID, server_id);
        }
        enc.end();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderUpdateResponse<'x> {
    pub status: FolderStatus,
    pub sync_key: Option<&'x str>,
}

impl FolderUpdateResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        encode_status_key(enc, fh::FOLDER_UPDATE, self.status, self.sync_key);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderDeleteResponse<'x> {
    pub status: FolderStatus,
    pub sync_key: Option<&'x str>,
}

impl FolderDeleteResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        encode_status_key(enc, fh::FOLDER_DELETE, self.status, self.sync_key);
    }
}

fn encode_status_key(enc: &mut Encoder, root: Tag, status: FolderStatus, sync_key: Option<&str>) {
    enc.start(root).text_u64(fh::STATUS, u64::from(status.0));
    if let Some(sync_key) = sync_key {
        enc.text_str(fh::SYNC_KEY, sync_key);
    }
    enc.end();
}
