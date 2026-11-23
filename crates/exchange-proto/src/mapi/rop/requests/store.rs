/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::super::views::EidArray;
use super::super::views::MapiString;
use super::read_long_term_id;
use crate::common::LeReader;
use crate::ids::Eid;
use crate::ids::LongTermId;
use crate::mapi::restriction::RestrictionBytes;
use crate::mapi::rop::{buffer::DecodeContext, error::RopDecodeError};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OpenFolder {
    pub output_handle_index: u8,
    pub folder_id: Eid,
    pub open_mode_flags: u8,
}

impl OpenFolder {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let folder_id = Eid::from_wire(r.array()?);
        let open_mode_flags = r.u8()?;
        Ok(OpenFolder {
            output_handle_index,
            folder_id,
            open_mode_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CreateFolder<'a> {
    pub output_handle_index: u8,
    pub folder_type: u8,
    pub open_existing: bool,
    pub display_name: MapiString<'a>,
    pub comment: MapiString<'a>,
}

impl<'a> CreateFolder<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let folder_type = r.u8()?;
        let use_unicode_strings = r.u8()? != 0;
        let open_existing = r.u8()? != 0;
        let _ = r.u8()?;
        let display_name = MapiString::decode(r, use_unicode_strings)?;
        let comment = MapiString::decode(r, use_unicode_strings)?;
        Ok(CreateFolder {
            output_handle_index,
            folder_type,
            open_existing,
            display_name,
            comment,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeleteFolder {
    pub delete_folder_flags: u8,
    pub folder_id: Eid,
}

impl DeleteFolder {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let delete_folder_flags = r.u8()?;
        let folder_id = Eid::from_wire(r.array()?);
        Ok(DeleteFolder {
            delete_folder_flags,
            folder_id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeleteMessages<'a> {
    pub want_asynchronous: bool,
    pub notify_non_read: bool,
    pub message_ids: EidArray<'a>,
}

impl<'a> DeleteMessages<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let want_asynchronous = r.u8()? != 0;
        let notify_non_read = r.u8()? != 0;
        let message_id_count = r.u16()?;
        let message_ids = EidArray::decode(r, usize::from(message_id_count))?;
        Ok(DeleteMessages {
            want_asynchronous,
            notify_non_read,
            message_ids,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetReceiveFolder<'a> {
    pub folder_id: Eid,
    pub message_class: &'a [u8],
}

impl<'a> SetReceiveFolder<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let folder_id = Eid::from_wire(r.array()?);
        let message_class = r.ascii_z()?;
        Ok(SetReceiveFolder {
            folder_id,
            message_class,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetReceiveFolder<'a> {
    pub message_class: &'a [u8],
}

impl<'a> GetReceiveFolder<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let message_class = r.ascii_z()?;
        Ok(GetReceiveFolder { message_class })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetSearchCriteria<'a> {
    pub restriction_data: RestrictionBytes<'a>,
    pub folder_ids: EidArray<'a>,
    pub search_flags: u32,
}

impl<'a> SetSearchCriteria<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let restriction_data_size = r.u16()?;
        let restriction_data = RestrictionBytes(r.bytes(usize::from(restriction_data_size))?);
        let folder_id_count = r.u16()?;
        let folder_ids = EidArray::decode(r, usize::from(folder_id_count))?;
        let search_flags = r.u32()?;
        Ok(SetSearchCriteria {
            restriction_data,
            folder_ids,
            search_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetSearchCriteria {
    pub use_unicode: bool,
    pub include_restriction: bool,
    pub include_folders: bool,
}

impl GetSearchCriteria {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let use_unicode = r.u8()? != 0;
        let include_restriction = r.u8()? != 0;
        let include_folders = r.u8()? != 0;
        Ok(GetSearchCriteria {
            use_unicode,
            include_restriction,
            include_folders,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MoveCopyMessages<'a> {
    pub dest_handle_index: u8,
    pub message_ids: EidArray<'a>,
    pub want_asynchronous: bool,
    pub want_copy: bool,
}

impl<'a> MoveCopyMessages<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let dest_handle_index = r.u8()?;
        let message_id_count = r.u16()?;
        let message_ids = EidArray::decode(r, usize::from(message_id_count))?;
        let want_asynchronous = r.u8()? != 0;
        let want_copy = r.u8()? != 0;
        Ok(MoveCopyMessages {
            dest_handle_index,
            message_ids,
            want_asynchronous,
            want_copy,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MoveFolder<'a> {
    pub dest_handle_index: u8,
    pub want_asynchronous: bool,
    pub folder_id: Eid,
    pub new_folder_name: MapiString<'a>,
}

impl<'a> MoveFolder<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let dest_handle_index = r.u8()?;
        let want_asynchronous = r.u8()? != 0;
        let use_unicode = r.u8()? != 0;
        let folder_id = Eid::from_wire(r.array()?);
        let new_folder_name = MapiString::decode(r, use_unicode)?;
        Ok(MoveFolder {
            dest_handle_index,
            want_asynchronous,
            folder_id,
            new_folder_name,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CopyFolder<'a> {
    pub dest_handle_index: u8,
    pub want_asynchronous: bool,
    pub want_recursive: bool,
    pub folder_id: Eid,
    pub new_folder_name: MapiString<'a>,
}

impl<'a> CopyFolder<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let dest_handle_index = r.u8()?;
        let want_asynchronous = r.u8()? != 0;
        let want_recursive = r.u8()? != 0;
        let use_unicode = r.u8()? != 0;
        let folder_id = Eid::from_wire(r.array()?);
        let new_folder_name = MapiString::decode(r, use_unicode)?;
        Ok(CopyFolder {
            dest_handle_index,
            want_asynchronous,
            want_recursive,
            folder_id,
            new_folder_name,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LongTermIdFromId {
    pub object_id: Eid,
}

impl LongTermIdFromId {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let object_id = Eid::from_wire(r.array()?);
        Ok(LongTermIdFromId { object_id })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IdFromLongTermId {
    pub long_term_id: LongTermId,
}

impl IdFromLongTermId {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let long_term_id = read_long_term_id(r)?;
        Ok(IdFromLongTermId { long_term_id })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicFolderIsGhosted {
    pub folder_id: Eid,
}

impl PublicFolderIsGhosted {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let folder_id = Eid::from_wire(r.array()?);
        Ok(PublicFolderIsGhosted { folder_id })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EmptyFolder {
    pub want_asynchronous: bool,
    pub want_delete_associated: bool,
}

impl EmptyFolder {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let want_asynchronous = r.u8()? != 0;
        let want_delete_associated = r.u8()? != 0;
        Ok(EmptyFolder {
            want_asynchronous,
            want_delete_associated,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HardDeleteMessages<'a> {
    pub want_asynchronous: bool,
    pub notify_non_read: bool,
    pub message_ids: EidArray<'a>,
}

impl<'a> HardDeleteMessages<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let want_asynchronous = r.u8()? != 0;
        let notify_non_read = r.u8()? != 0;
        let message_id_count = r.u16()?;
        let message_ids = EidArray::decode(r, usize::from(message_id_count))?;
        Ok(HardDeleteMessages {
            want_asynchronous,
            notify_non_read,
            message_ids,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HardDeleteMessagesAndSubfolders {
    pub want_asynchronous: bool,
    pub want_delete_associated: bool,
}

impl HardDeleteMessagesAndSubfolders {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let want_asynchronous = r.u8()? != 0;
        let want_delete_associated = r.u8()? != 0;
        Ok(HardDeleteMessagesAndSubfolders {
            want_asynchronous,
            want_delete_associated,
        })
    }
}
