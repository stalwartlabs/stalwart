/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::super::views::EidArray;
use super::super::views::ModifyRecipientRows;
use super::super::views::PropTagArrayView;
use crate::common::LeReader;
use crate::ids::Eid;
use crate::mapi::restriction::RestrictionBytes;
use crate::mapi::rop::{buffer::DecodeContext, error::RopDecodeError};
use crate::mapi::sort::SortOrderSet;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OpenMessage {
    pub output_handle_index: u8,
    pub code_page_id: u16,
    pub folder_id: Eid,
    pub open_mode_flags: u8,
    pub message_id: Eid,
}

impl OpenMessage {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let code_page_id = r.u16()?;
        let folder_id = Eid::from_wire(r.array()?);
        let open_mode_flags = r.u8()?;
        let message_id = Eid::from_wire(r.array()?);
        Ok(OpenMessage {
            output_handle_index,
            code_page_id,
            folder_id,
            open_mode_flags,
            message_id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetHierarchyTable {
    pub output_handle_index: u8,
    pub table_flags: u8,
}

impl GetHierarchyTable {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let table_flags = r.u8()?;
        Ok(GetHierarchyTable {
            output_handle_index,
            table_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetContentsTable {
    pub output_handle_index: u8,
    pub table_flags: u8,
}

impl GetContentsTable {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let table_flags = r.u8()?;
        Ok(GetContentsTable {
            output_handle_index,
            table_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CreateMessage {
    pub output_handle_index: u8,
    pub code_page_id: u16,
    pub folder_id: Eid,
    pub associated_flag: bool,
}

impl CreateMessage {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let code_page_id = r.u16()?;
        let folder_id = Eid::from_wire(r.array()?);
        let associated_flag = r.u8()? != 0;
        Ok(CreateMessage {
            output_handle_index,
            code_page_id,
            folder_id,
            associated_flag,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SaveChangesMessage {
    pub input_handle_index: u8,
    pub save_flags: u8,
}

impl SaveChangesMessage {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let input_handle_index = r.u8()?;
        let save_flags = r.u8()?;
        Ok(SaveChangesMessage {
            input_handle_index,
            save_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RemoveAllRecipients {
    pub reserved: u32,
}

impl RemoveAllRecipients {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let reserved = r.u32()?;
        Ok(RemoveAllRecipients { reserved })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModifyRecipients<'a> {
    pub recipient_columns: PropTagArrayView<'a>,
    pub recipient_rows: ModifyRecipientRows<'a>,
}

impl<'a> ModifyRecipients<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let column_count = r.u16()?;
        let recipient_columns = PropTagArrayView::decode(r, usize::from(column_count))?;
        let row_count = r.u16()?;
        let recipient_rows =
            ModifyRecipientRows::decode(r, usize::from(row_count), recipient_columns, ctx.limits)?;
        Ok(ModifyRecipients {
            recipient_columns,
            recipient_rows,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadRecipients {
    pub row_id: u32,
}

impl ReadRecipients {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let row_id = r.u32()?;
        let _ = r.u16()?;
        Ok(ReadRecipients { row_id })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetColumns<'a> {
    pub set_columns_flags: u8,
    pub property_tags: PropTagArrayView<'a>,
}

impl<'a> SetColumns<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let set_columns_flags = r.u8()?;
        let property_tag_count = r.u16()?;
        let property_tags = PropTagArrayView::decode(r, usize::from(property_tag_count))?;
        Ok(SetColumns {
            set_columns_flags,
            property_tags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SortTable<'a> {
    pub sort_table_flags: u8,
    pub sort_orders: SortOrderSet<'a>,
}

impl<'a> SortTable<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let sort_table_flags = r.u8()?;
        let sort_orders = SortOrderSet::decode(r)?;
        Ok(SortTable {
            sort_table_flags,
            sort_orders,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Restrict<'a> {
    pub restrict_flags: u8,
    pub restriction_data: RestrictionBytes<'a>,
}

impl<'a> Restrict<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let restrict_flags = r.u8()?;
        let restriction_data_size = r.u16()?;
        let restriction_data = RestrictionBytes(r.bytes(usize::from(restriction_data_size))?);
        Ok(Restrict {
            restrict_flags,
            restriction_data,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QueryRows {
    pub query_rows_flags: u8,
    pub forward_read: bool,
    pub row_count: u16,
}

impl QueryRows {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let query_rows_flags = r.u8()?;
        let forward_read = r.u8()? != 0;
        let row_count = r.u16()?;
        Ok(QueryRows {
            query_rows_flags,
            forward_read,
            row_count,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeekRow {
    pub origin: u8,
    pub row_count: i32,
    pub want_row_moved_count: bool,
}

impl SeekRow {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let origin = r.u8()?;
        let row_count = r.i32()?;
        let want_row_moved_count = r.u8()? != 0;
        Ok(SeekRow {
            origin,
            row_count,
            want_row_moved_count,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeekRowBookmark<'a> {
    pub bookmark: &'a [u8],
    pub row_count: i32,
    pub want_row_moved_count: bool,
}

impl<'a> SeekRowBookmark<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let bookmark_size = r.u16()?;
        let bookmark = r.bytes(usize::from(bookmark_size))?;
        let row_count = r.i32()?;
        let want_row_moved_count = r.u8()? != 0;
        Ok(SeekRowBookmark {
            bookmark,
            row_count,
            want_row_moved_count,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeekRowFractional {
    pub numerator: u32,
    pub denominator: u32,
}

impl SeekRowFractional {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let numerator = r.u32()?;
        let denominator = r.u32()?;
        Ok(SeekRowFractional {
            numerator,
            denominator,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetMessageStatus {
    pub message_id: Eid,
}

impl GetMessageStatus {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let message_id = Eid::from_wire(r.array()?);
        Ok(GetMessageStatus { message_id })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetMessageStatus {
    pub message_id: Eid,
    pub message_status_flags: u32,
    pub message_status_mask: u32,
}

impl SetMessageStatus {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let message_id = Eid::from_wire(r.array()?);
        let message_status_flags = r.u32()?;
        let message_status_mask = r.u32()?;
        Ok(SetMessageStatus {
            message_id,
            message_status_flags,
            message_status_mask,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OpenAttachment {
    pub output_handle_index: u8,
    pub open_attachment_flags: u8,
    pub attachment_id: u32,
}

impl OpenAttachment {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let open_attachment_flags = r.u8()?;
        let attachment_id = r.u32()?;
        Ok(OpenAttachment {
            output_handle_index,
            open_attachment_flags,
            attachment_id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CreateAttachment {
    pub output_handle_index: u8,
}

impl CreateAttachment {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        Ok(CreateAttachment {
            output_handle_index,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeleteAttachment {
    pub attachment_id: u32,
}

impl DeleteAttachment {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let attachment_id = r.u32()?;
        Ok(DeleteAttachment { attachment_id })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SaveChangesAttachment {
    pub input_handle_index: u8,
    pub save_flags: u8,
}

impl SaveChangesAttachment {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let input_handle_index = r.u8()?;
        let save_flags = r.u8()?;
        Ok(SaveChangesAttachment {
            input_handle_index,
            save_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OpenEmbeddedMessage {
    pub output_handle_index: u8,
    pub code_page_id: u16,
    pub open_mode_flags: u8,
}

impl OpenEmbeddedMessage {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let code_page_id = r.u16()?;
        let open_mode_flags = r.u8()?;
        Ok(OpenEmbeddedMessage {
            output_handle_index,
            code_page_id,
            open_mode_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FindRow<'a> {
    pub find_row_flags: u8,
    pub restriction_data: RestrictionBytes<'a>,
    pub origin: u8,
    pub bookmark: &'a [u8],
}

impl<'a> FindRow<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let find_row_flags = r.u8()?;
        let restriction_data_size = r.u16()?;
        let restriction_data = RestrictionBytes(r.bytes(usize::from(restriction_data_size))?);
        let origin = r.u8()?;
        let bookmark_size = r.u16()?;
        let bookmark = r.bytes(usize::from(bookmark_size))?;
        Ok(FindRow {
            find_row_flags,
            restriction_data,
            origin,
            bookmark,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExpandRow {
    pub max_row_count: u16,
    pub category_id: u64,
}

impl ExpandRow {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let max_row_count = r.u16()?;
        let category_id = r.u64()?;
        Ok(ExpandRow {
            max_row_count,
            category_id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CollapseRow {
    pub category_id: u64,
}

impl CollapseRow {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let category_id = r.u64()?;
        Ok(CollapseRow { category_id })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetReadFlags<'a> {
    pub want_asynchronous: bool,
    pub read_flags: u8,
    pub message_ids: EidArray<'a>,
}

impl<'a> SetReadFlags<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let want_asynchronous = r.u8()? != 0;
        let read_flags = r.u8()?;
        let message_id_count = r.u16()?;
        let message_ids = EidArray::decode(r, usize::from(message_id_count))?;
        Ok(SetReadFlags {
            want_asynchronous,
            read_flags,
            message_ids,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetCollapseState {
    pub row_id: u64,
    pub row_instance_number: u32,
}

impl GetCollapseState {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let row_id = r.u64()?;
        let row_instance_number = r.u32()?;
        Ok(GetCollapseState {
            row_id,
            row_instance_number,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetCollapseState<'a> {
    pub collapse_state: &'a [u8],
}

impl<'a> SetCollapseState<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let collapse_state_size = r.u16()?;
        let collapse_state = r.bytes(usize::from(collapse_state_size))?;
        Ok(SetCollapseState { collapse_state })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FreeBookmark<'a> {
    pub bookmark: &'a [u8],
}

impl<'a> FreeBookmark<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let bookmark_size = r.u16()?;
        let bookmark = r.bytes(usize::from(bookmark_size))?;
        Ok(FreeBookmark { bookmark })
    }
}
