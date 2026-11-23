/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::LeWriter;
use crate::ids::Eid;
use crate::mapi::rop::writer::RopResponse;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetHierarchyTableResponse {
    pub row_count: u32,
}

impl RopResponse for GetHierarchyTableResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.row_count);
    }

    fn encoded_len_hint(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetContentsTableResponse {
    pub row_count: u32,
}

impl RopResponse for GetContentsTableResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.row_count);
    }

    fn encoded_len_hint(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CreateMessageResponse {
    pub message_id: Option<Eid>,
}

impl RopResponse for CreateMessageResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.message_id.is_some()));
        if let Some(v) = self.message_id {
            out.extend_from_slice(&v.to_wire());
        }
    }

    fn encoded_len_hint(&self) -> usize {
        9
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SaveChangesMessageResponse {
    pub input_handle_index: u8,
    pub message_id: Eid,
}

impl RopResponse for SaveChangesMessageResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.input_handle_index);
        out.extend_from_slice(&self.message_id.to_wire());
    }

    fn encoded_len_hint(&self) -> usize {
        9
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetColumnsResponse {
    pub table_status: u8,
}

impl RopResponse for SetColumnsResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.table_status);
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SortTableResponse {
    pub table_status: u8,
}

impl RopResponse for SortTableResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.table_status);
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RestrictResponse {
    pub table_status: u8,
}

impl RopResponse for RestrictResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.table_status);
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QueryPositionResponse {
    pub numerator: u32,
    pub denominator: u32,
}

impl RopResponse for QueryPositionResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.numerator);
        out.put_u32(self.denominator);
    }

    fn encoded_len_hint(&self) -> usize {
        8
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeekRowResponse {
    pub has_sought_less: bool,
    pub rows_sought: i32,
}

impl RopResponse for SeekRowResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.has_sought_less));
        out.put_i32(self.rows_sought);
    }

    fn encoded_len_hint(&self) -> usize {
        5
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeekRowBookmarkResponse {
    pub row_no_longer_visible: bool,
    pub has_sought_less: bool,
    pub rows_sought: u32,
}

impl RopResponse for SeekRowBookmarkResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.row_no_longer_visible));
        out.put_u8(u8::from(self.has_sought_less));
        out.put_u32(self.rows_sought);
    }

    fn encoded_len_hint(&self) -> usize {
        6
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CreateBookmarkResponse<'x> {
    pub bookmark: &'x [u8],
}

impl RopResponse for CreateBookmarkResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let bookmark_len = u16::try_from(self.bookmark.len()).unwrap_or(u16::MAX);
        out.put_u16(bookmark_len);
        out.extend_from_slice(
            self.bookmark
                .get(..usize::from(bookmark_len))
                .unwrap_or(self.bookmark),
        );
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.bookmark.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetMessageStatusResponse {
    pub message_status_flags: u32,
}

impl RopResponse for GetMessageStatusResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.message_status_flags);
    }

    fn encoded_len_hint(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetMessageStatusResponse {
    pub message_status_flags: u32,
}

impl RopResponse for SetMessageStatusResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.message_status_flags);
    }

    fn encoded_len_hint(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CreateAttachmentResponse {
    pub attachment_id: u32,
}

impl RopResponse for CreateAttachmentResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.attachment_id);
    }

    fn encoded_len_hint(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CollapseRowResponse {
    pub collapsed_row_count: u32,
}

impl RopResponse for CollapseRowResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.collapsed_row_count);
    }

    fn encoded_len_hint(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetReadFlagsResponse {
    pub partial_completion: bool,
}

impl RopResponse for SetReadFlagsResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.partial_completion));
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetCollapseStateResponse<'x> {
    pub collapse_state: &'x [u8],
}

impl RopResponse for GetCollapseStateResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let collapse_state_len = u16::try_from(self.collapse_state.len()).unwrap_or(u16::MAX);
        out.put_u16(collapse_state_len);
        out.extend_from_slice(
            self.collapse_state
                .get(..usize::from(collapse_state_len))
                .unwrap_or(self.collapse_state),
        );
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.collapse_state.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetCollapseStateResponse<'x> {
    pub bookmark: &'x [u8],
}

impl RopResponse for SetCollapseStateResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let bookmark_len = u16::try_from(self.bookmark.len()).unwrap_or(u16::MAX);
        out.put_u16(bookmark_len);
        out.extend_from_slice(
            self.bookmark
                .get(..usize::from(bookmark_len))
                .unwrap_or(self.bookmark),
        );
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.bookmark.len())
    }
}
