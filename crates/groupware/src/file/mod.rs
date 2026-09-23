/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod content;
pub mod index;
pub mod storage;
pub mod symlink;

use common::storage::dav::{FILE_KIND_DIRECTORY, FILE_KIND_FILE, FILE_KIND_SYMLINK};
use std::{fmt::Display, str::FromStr};
use types::{acl::AclGrant, blob_hash::BlobHash, dead_property::DeadProperty};

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct FileNode {
    pub parent_id: u32,
    pub name: String,
    pub display_name: Option<String>,
    pub content: FileNodeContent,
    pub role: Option<FileNodeRole>,
    pub created: i64,
    pub modified: i64,
    pub accessed: i64,
    pub changed: i64,
    pub unsubscribed: Vec<u32>,
    pub dead_properties: DeadProperty,
    pub acls: Vec<AclGrant>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub enum FileNodeContent {
    #[default]
    Directory,
    File(FileProperties),
    Symlink(String),
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct FileProperties {
    pub blob_hash: BlobHash,
    pub size: u32,
    pub media_type: Option<String>,
    pub executable: bool,
}

#[derive(
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(derive(Debug, Clone, Copy, PartialEq, Eq))]
#[repr(u8)]
pub enum FileNodeRole {
    Root = 1,
    Home = 2,
    Temp = 3,
    Trash = 4,
    Documents = 5,
    Downloads = 6,
    Music = 7,
    Pictures = 8,
    Videos = 9,
}

impl FileNode {
    #[inline(always)]
    pub fn file(&self) -> Option<&FileProperties> {
        match &self.content {
            FileNodeContent::File(file) => Some(file),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn file_mut(&mut self) -> Option<&mut FileProperties> {
        match &mut self.content {
            FileNodeContent::File(file) => Some(file),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn is_directory(&self) -> bool {
        matches!(self.content, FileNodeContent::Directory)
    }

    #[inline(always)]
    pub fn symlink_target(&self) -> Option<&str> {
        match &self.content {
            FileNodeContent::Symlink(target) => Some(target),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn kind_id(&self) -> u8 {
        self.content.kind_id()
    }

    pub fn is_subscribed(&self, account_id: u32) -> bool {
        !self.unsubscribed.contains(&account_id)
    }

    pub fn set_subscribed(&mut self, account_id: u32, subscribed: bool) {
        if subscribed {
            self.unsubscribed.retain(|id| *id != account_id);
        } else if !self.unsubscribed.contains(&account_id) {
            self.unsubscribed.push(account_id);
        }
    }
}

impl FileNodeContent {
    #[inline(always)]
    pub fn kind_id(&self) -> u8 {
        match self {
            FileNodeContent::Directory => FILE_KIND_DIRECTORY,
            FileNodeContent::File(_) => FILE_KIND_FILE,
            FileNodeContent::Symlink(_) => FILE_KIND_SYMLINK,
        }
    }
}

impl ArchivedFileNode {
    #[inline(always)]
    pub fn file(&self) -> Option<&ArchivedFileProperties> {
        match &self.content {
            ArchivedFileNodeContent::File(file) => Some(file),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn is_directory(&self) -> bool {
        matches!(self.content, ArchivedFileNodeContent::Directory)
    }

    #[inline(always)]
    pub fn symlink_target(&self) -> Option<&str> {
        match &self.content {
            ArchivedFileNodeContent::Symlink(target) => Some(target.as_str()),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn kind_id(&self) -> u8 {
        match &self.content {
            ArchivedFileNodeContent::Directory => FILE_KIND_DIRECTORY,
            ArchivedFileNodeContent::File(_) => FILE_KIND_FILE,
            ArchivedFileNodeContent::Symlink(_) => FILE_KIND_SYMLINK,
        }
    }

    #[inline(always)]
    pub fn role(&self) -> Option<FileNodeRole> {
        self.role.as_ref().map(FileNodeRole::from)
    }

    pub fn is_subscribed(&self, account_id: u32) -> bool {
        !self
            .unsubscribed
            .iter()
            .any(|id| id.to_native() == account_id)
    }
}

impl FileNodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileNodeRole::Root => "root",
            FileNodeRole::Home => "home",
            FileNodeRole::Temp => "temp",
            FileNodeRole::Trash => "trash",
            FileNodeRole::Documents => "documents",
            FileNodeRole::Downloads => "downloads",
            FileNodeRole::Music => "music",
            FileNodeRole::Pictures => "pictures",
            FileNodeRole::Videos => "videos",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        hashify::map!(value.as_bytes(), FileNodeRole,
            b"root" => FileNodeRole::Root,
            b"home" => FileNodeRole::Home,
            b"temp" => FileNodeRole::Temp,
            b"trash" => FileNodeRole::Trash,
            b"documents" => FileNodeRole::Documents,
            b"downloads" => FileNodeRole::Downloads,
            b"music" => FileNodeRole::Music,
            b"pictures" => FileNodeRole::Pictures,
            b"videos" => FileNodeRole::Videos,
        )
        .copied()
    }

    #[inline(always)]
    pub fn id(self) -> u8 {
        self as u8
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(FileNodeRole::Root),
            2 => Some(FileNodeRole::Home),
            3 => Some(FileNodeRole::Temp),
            4 => Some(FileNodeRole::Trash),
            5 => Some(FileNodeRole::Documents),
            6 => Some(FileNodeRole::Downloads),
            7 => Some(FileNodeRole::Music),
            8 => Some(FileNodeRole::Pictures),
            9 => Some(FileNodeRole::Videos),
            _ => None,
        }
    }
}

impl From<&ArchivedFileNodeRole> for FileNodeRole {
    fn from(value: &ArchivedFileNodeRole) -> Self {
        match value {
            ArchivedFileNodeRole::Root => FileNodeRole::Root,
            ArchivedFileNodeRole::Home => FileNodeRole::Home,
            ArchivedFileNodeRole::Temp => FileNodeRole::Temp,
            ArchivedFileNodeRole::Trash => FileNodeRole::Trash,
            ArchivedFileNodeRole::Documents => FileNodeRole::Documents,
            ArchivedFileNodeRole::Downloads => FileNodeRole::Downloads,
            ArchivedFileNodeRole::Music => FileNodeRole::Music,
            ArchivedFileNodeRole::Pictures => FileNodeRole::Pictures,
            ArchivedFileNodeRole::Videos => FileNodeRole::Videos,
        }
    }
}

impl FromStr for FileNodeRole {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FileNodeRole::parse(s).ok_or(())
    }
}

impl Display for FileNodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
