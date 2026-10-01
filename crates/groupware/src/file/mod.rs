/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod content;
pub mod index;
pub mod storage;
pub mod symlink;

use crate::MetaHasher;
use common::storage::dav::{FILE_KIND_DIRECTORY, FILE_KIND_FILE, FILE_KIND_SYMLINK, FilePresence};
use std::{fmt::Display, str::FromStr};
use types::{acl::AclGrant, blob_hash::BlobHash, metadata::MetadataKinds};

const ROLE_SHIFT: u32 = 3;
const ROLE_MASK: u16 = 0xF << ROLE_SHIFT;

const _: () = assert!(FilePresence::from_bits(u16::MAX).bits() & ROLE_MASK == 0);

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct FileNode {
    pub parent_id: u32,
    pub name: String,
    pub content: FileNodeContent,
    pub flags: u16,
    pub etag: u32,
    pub created: i64,
    pub modified: i64,
    pub accessed: i64,
    pub changed: i64,
    pub unsubscribed: Vec<u32>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    pub fn presence(&self) -> FilePresence {
        FilePresence::from_bits(self.flags)
    }

    pub fn set_presence(&mut self, presence: FilePresence) {
        self.flags = presence.apply(self.flags);
    }

    pub fn role(&self) -> Option<FileNodeRole> {
        Self::role_of(self.flags)
    }

    pub fn set_role(&mut self, role: Option<FileNodeRole>) {
        self.flags =
            (self.flags & !ROLE_MASK) | (u16::from(role.map_or(0, FileNodeRole::id)) << ROLE_SHIFT);
    }

    fn role_of(flags: u16) -> Option<FileNodeRole> {
        FileNodeRole::from_id(((flags & ROLE_MASK) >> ROLE_SHIFT) as u8)
    }

    pub fn metadata_kinds(&self) -> MetadataKinds {
        self.presence().kinds()
    }

    pub fn compute_etag(&self) -> u32 {
        let mut hasher = MetaHasher::new();
        hasher
            .u8(self.kind_id())
            .u32(self.parent_id)
            .str(&self.name);
        match &self.content {
            FileNodeContent::Directory => {}
            FileNodeContent::File(file) => {
                hasher
                    .bytes(file.blob_hash.as_slice())
                    .u32(file.size)
                    .opt_str(file.media_type.as_deref())
                    .u8(u8::from(file.executable));
            }
            FileNodeContent::Symlink(target) => {
                hasher.str(target);
            }
        }
        hasher.u8(self.role().map_or(0, FileNodeRole::id)).finish()
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
        FileNode::role_of(self.flags.to_native())
    }

    pub fn is_subscribed(&self, account_id: u32) -> bool {
        !self
            .unsubscribed
            .iter()
            .any(|id| id.to_native() == account_id)
    }

    pub fn presence(&self) -> FilePresence {
        FilePresence::from_bits(self.flags.to_native())
    }

    pub fn metadata_kinds(&self) -> MetadataKinds {
        self.presence().kinds()
    }

    pub fn compute_etag(&self) -> u32 {
        let mut hasher = MetaHasher::new();
        hasher
            .u8(self.kind_id())
            .u32(self.parent_id.to_native())
            .str(&self.name);
        match &self.content {
            ArchivedFileNodeContent::Directory => {}
            ArchivedFileNodeContent::File(file) => {
                hasher
                    .bytes(file.blob_hash.0.as_slice())
                    .u32(file.size.to_native())
                    .opt_str(file.media_type.as_deref())
                    .u8(u8::from(file.executable));
            }
            ArchivedFileNodeContent::Symlink(target) => {
                hasher.str(target);
            }
        }
        hasher.u8(self.role().map_or(0, FileNodeRole::id)).finish()
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

#[cfg(test)]
mod tests {
    use super::*;
    use rkyv::rancor::Error;

    const ROLES: [Option<FileNodeRole>; 10] = [
        None,
        Some(FileNodeRole::Root),
        Some(FileNodeRole::Home),
        Some(FileNodeRole::Temp),
        Some(FileNodeRole::Trash),
        Some(FileNodeRole::Documents),
        Some(FileNodeRole::Downloads),
        Some(FileNodeRole::Music),
        Some(FileNodeRole::Pictures),
        Some(FileNodeRole::Videos),
    ];

    fn presence_mask() -> u16 {
        FilePresence::from_bits(u16::MAX).bits()
    }

    fn all_presences() -> impl Iterator<Item = FilePresence> {
        (0..=presence_mask()).map(FilePresence::from_bits)
    }

    fn archived(node: &FileNode) -> (Option<FileNodeRole>, FilePresence) {
        let bytes = rkyv::to_bytes::<Error>(node).expect("the node archives");
        let archived =
            rkyv::access::<ArchivedFileNode, Error>(&bytes).expect("the archive validates");
        (archived.role(), archived.presence())
    }

    #[test]
    fn every_role_round_trips_with_every_presence_pattern() {
        assert_eq!(all_presences().count(), 8);
        assert_eq!(FileNode::default().role(), None);

        for (id, role) in ROLES.into_iter().enumerate() {
            assert_eq!(usize::from(role.map_or(0, FileNodeRole::id)), id);
            for presence in all_presences() {
                let mut node = FileNode::default();
                node.set_role(role);
                node.set_presence(presence);
                assert_eq!((node.role(), node.presence()), (role, presence));
                assert_eq!(archived(&node), (role, presence));

                let mut reversed = FileNode::default();
                reversed.set_presence(presence);
                reversed.set_role(role);
                assert_eq!(reversed.flags, node.flags);
            }
        }
    }

    #[test]
    fn role_and_presence_setters_do_not_clobber_each_other() {
        for start in [0, u16::MAX, 0x5A5A, 0xA5A5] {
            let mut node = FileNode {
                flags: start,
                ..Default::default()
            };
            for role in ROLES {
                let before = node.flags;
                node.set_role(role);
                assert_eq!(node.role(), role);
                assert_eq!(node.flags & !ROLE_MASK, before & !ROLE_MASK);
            }
            for presence in all_presences() {
                let before = node.flags;
                node.set_presence(presence);
                assert_eq!(node.presence(), presence);
                assert_eq!(node.flags & !presence_mask(), before & !presence_mask());
            }
        }
    }

    #[test]
    fn unknown_role_bits_read_as_no_role() {
        for id in ROLES.len() as u16..=ROLE_MASK >> ROLE_SHIFT {
            let node = FileNode {
                flags: (id << ROLE_SHIFT) | presence_mask(),
                ..Default::default()
            };
            assert_eq!(node.role(), None);
            assert_eq!(
                archived(&node),
                (None, FilePresence::from_bits(presence_mask()))
            );
            assert_eq!(node.compute_etag(), FileNode::default().compute_etag());
        }
    }

    #[test]
    fn archived_file_node_size_is_pinned() {
        assert_eq!(size_of::<ArchivedFileNode>(), 113);
    }
}
