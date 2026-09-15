/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResourceChunkBuilder;
use crate::{ArenaRef, FileFlags, GroupwareResourceMetadata, GroupwareResourceRef, ResourceChunk};
use types::media_type::MediaTypeId;

const KIND_MASK: u32 = 0b11;
pub const FILE_KIND_DIRECTORY: u8 = 0;
pub const FILE_KIND_FILE: u8 = 1;
pub const FILE_KIND_SYMLINK: u8 = 2;
const EXECUTABLE: u32 = 1 << 2;
const ROLE_SHIFT: u32 = 3;
const ROLE_MASK: u32 = 0xF;
const MEDIA_SHIFT: u32 = 7;
const MEDIA_MASK: u32 = (1 << MediaTypeId::BITS) - 1;
const EXTRA_SHIFT: u32 = 19;
const EXTRA_MASK: u32 = 0xFF;
const RESERVED_SHIFT: u32 = EXTRA_SHIFT + 8;

pub const MAX_FILE_EXTRA_LEN: usize = EXTRA_MASK as usize;
pub const FILE_DEFAULT_MEDIA_TYPE: &str = "application/octet-stream";

impl FileFlags {
    pub fn new(
        kind: u8,
        executable: bool,
        role: u8,
        media_type: MediaTypeId,
        extra_len: u16,
    ) -> Self {
        FileFlags(
            (kind as u32 & KIND_MASK)
                | if executable { EXECUTABLE } else { 0 }
                | (role as u32 & ROLE_MASK) << ROLE_SHIFT
                | (media_type.raw() as u32 & MEDIA_MASK) << MEDIA_SHIFT
                | (extra_len as u32 & EXTRA_MASK) << EXTRA_SHIFT,
        )
    }

    #[inline(always)]
    pub fn kind(self) -> u8 {
        (self.0 & KIND_MASK) as u8
    }

    #[inline(always)]
    pub fn is_directory(self) -> bool {
        self.kind() == FILE_KIND_DIRECTORY
    }

    #[inline(always)]
    pub fn is_executable(self) -> bool {
        self.0 & EXECUTABLE != 0
    }

    #[inline(always)]
    pub fn role(self) -> u8 {
        ((self.0 >> ROLE_SHIFT) & ROLE_MASK) as u8
    }

    #[inline(always)]
    pub fn media_type_id(self) -> MediaTypeId {
        MediaTypeId::from_raw(((self.0 >> MEDIA_SHIFT) & MEDIA_MASK) as u16)
    }

    #[inline(always)]
    pub fn extra_len(self) -> usize {
        ((self.0 >> EXTRA_SHIFT) & EXTRA_MASK) as usize
    }

    pub fn is_valid(self) -> bool {
        self.kind() <= FILE_KIND_SYMLINK
            && self.0 >> RESERVED_SHIFT == 0
            && (self.extra_len() == 0 || self.media_type_id().is_uncatalogued())
    }
}

impl ResourceChunkBuilder {
    pub fn push_file_name(
        &mut self,
        name: &str,
        media_type: Option<&str>,
    ) -> (ArenaRef, MediaTypeId, u16) {
        let media_id = media_type.map_or(MediaTypeId::NONE, MediaTypeId::lookup);
        let name_ref = self.push_str(name);
        if !media_id.is_uncatalogued() {
            return (name_ref, media_id, 0);
        }
        match media_type.filter(|media_type| media_type.len() <= MAX_FILE_EXTRA_LEN) {
            Some(media_type) => {
                self.bytes.extend_from_slice(media_type.as_bytes());
                (name_ref, media_id, media_type.len() as u16)
            }
            None => (name_ref, MediaTypeId::NONE, 0),
        }
    }

    pub(super) fn push_file_bytes(
        &mut self,
        chunk: &ResourceChunk,
        name: ArenaRef,
        flags: FileFlags,
    ) -> ArenaRef {
        let off = self.bytes.len() as u32;
        if let Some(bytes) = chunk
            .bytes
            .get(name.off as usize..(name.off as usize + name.len as usize + flags.extra_len()))
        {
            self.bytes.extend_from_slice(bytes);
        }
        ArenaRef { off, len: name.len }
    }
}

impl<'x> GroupwareResourceRef<'x> {
    #[inline(always)]
    pub fn file_flags(&self) -> Option<FileFlags> {
        match &self.resource.data {
            GroupwareResourceMetadata::File { flags, .. } => Some(*flags),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn file_kind(&self) -> Option<u8> {
        self.file_flags().map(FileFlags::kind)
    }

    #[inline(always)]
    pub fn is_executable(&self) -> bool {
        self.file_flags().is_some_and(FileFlags::is_executable)
    }

    #[inline(always)]
    pub fn file_role(&self) -> u8 {
        self.file_flags().map_or(0, FileFlags::role)
    }

    pub fn media_type(&self) -> Option<&'x str> {
        let flags = self.file_flags()?;
        let id = flags.media_type_id();
        if id.is_uncatalogued() {
            self.file_extra_bytes(flags)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
        } else {
            id.as_str()
        }
        .or((flags.kind() == FILE_KIND_FILE).then_some(FILE_DEFAULT_MEDIA_TYPE))
    }

    fn file_extra_bytes(&self, flags: FileFlags) -> Option<&'x [u8]> {
        match &self.resource.data {
            GroupwareResourceMetadata::File { name, .. } if flags.extra_len() > 0 => {
                let start = name.off as usize + name.len as usize;
                self.chunk.bytes.get(start..start + flags.extra_len())
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GroupwareResource, NO_ID};

    const TRASH: u8 = 4;
    const VIDEOS: u8 = 9;

    fn push(
        builder: &mut ResourceChunkBuilder,
        document_id: u32,
        name: &str,
        media_type: Option<&str>,
    ) {
        let (name, media_id, extra_len) = builder.push_file_name(name, media_type);
        let acls = builder.push_acls(&[]);
        builder.records.push(GroupwareResource {
            document_id,
            data: GroupwareResourceMetadata::File {
                name,
                size: 10,
                parent_id: NO_ID,
                acls,
                etag: 0,
                modified: 0,
                created_delta: 0,
                flags: FileFlags::new(FILE_KIND_FILE, true, TRASH, media_id, extra_len),
            },
        });
    }

    #[test]
    fn resource_record_does_not_grow() {
        assert_eq!(std::mem::size_of::<GroupwareResourceMetadata>(), 48);
        assert_eq!(std::mem::size_of::<GroupwareResource>(), 56);
    }

    #[test]
    fn flags_round_trip() {
        let flags = FileFlags::new(
            FILE_KIND_SYMLINK,
            true,
            VIDEOS,
            MediaTypeId::UNCATALOGUED,
            MAX_FILE_EXTRA_LEN as u16,
        );
        assert_eq!(flags.kind(), FILE_KIND_SYMLINK);
        assert!(flags.is_executable());
        assert_eq!(flags.role(), VIDEOS);
        assert_eq!(flags.media_type_id(), MediaTypeId::UNCATALOGUED);
        assert_eq!(flags.extra_len(), MAX_FILE_EXTRA_LEN);
        assert_eq!(flags.0 >> 31, 0);
        assert!(flags.is_valid());
        assert!(!FileFlags(flags.0 | 1 << RESERVED_SHIFT).is_valid());
        assert!(!FileFlags(KIND_MASK).is_valid());
        assert!(!FileFlags::new(FILE_KIND_FILE, false, 0, MediaTypeId::NONE, 4).is_valid());

        let flags = FileFlags::new(FILE_KIND_DIRECTORY, false, 0, MediaTypeId::NONE, 0);
        assert!(flags.is_directory());
        assert!(!flags.is_executable());
        assert_eq!(flags.role(), 0);
        assert!(flags.media_type_id().is_none());
        assert_eq!(flags.extra_len(), 0);
    }

    #[test]
    fn extras_are_read_back() {
        let mut builder = ResourceChunkBuilder::with_capacity(5);
        push(&mut builder, 0, "a.txt", Some("text/plain"));
        push(&mut builder, 1, "b.bin", Some("application/x-stalwart"));
        push(&mut builder, 2, "c d.txt", Some("application/x-stalwart"));
        push(&mut builder, 3, "e(1).txt", None);
        push(&mut builder, 4, "f.txt", Some(&"x".repeat(300)));
        let chunk = builder.finish();
        let resources = chunk
            .records
            .iter()
            .map(|resource| GroupwareResourceRef {
                chunk: &chunk,
                resource,
            })
            .collect::<Vec<_>>();
        let refs = resources
            .iter()
            .map(|r| {
                (
                    r.container_name(),
                    r.media_type(),
                    r.file_role(),
                    r.is_executable(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            refs,
            vec![
                (Some("a.txt"), Some("text/plain"), TRASH, true),
                (Some("b.bin"), Some("application/x-stalwart"), TRASH, true),
                (Some("c d.txt"), Some("application/x-stalwart"), TRASH, true),
                (Some("e(1).txt"), Some(FILE_DEFAULT_MEDIA_TYPE), TRASH, true),
                (Some("f.txt"), Some(FILE_DEFAULT_MEDIA_TYPE), TRASH, true),
            ]
        );

        let mut copy = ResourceChunkBuilder::with_capacity(5);
        for resource in chunk.records.iter() {
            copy.push_from(&GroupwareResourceRef {
                chunk: &chunk,
                resource,
            });
        }
        let copy = copy.finish();
        for (a, b) in chunk.records.iter().zip(copy.records.iter()) {
            let a = GroupwareResourceRef {
                chunk: &chunk,
                resource: a,
            };
            let b = GroupwareResourceRef {
                chunk: &copy,
                resource: b,
            };
            assert_eq!(a.container_name(), b.container_name());
            assert_eq!(a.media_type(), b.media_type());
        }
    }
}
