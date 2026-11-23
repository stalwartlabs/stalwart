/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::LeWriter;
use crate::ids::Eid;
use crate::ids::LongTermId;
use crate::mapi::rop::writer::RopResponse;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeleteFolderResponse {
    pub partial_completion: bool,
}

impl RopResponse for DeleteFolderResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.partial_completion));
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeleteMessagesResponse {
    pub partial_completion: bool,
}

impl RopResponse for DeleteMessagesResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.partial_completion));
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetReceiveFolderResponse<'x> {
    pub folder_id: Eid,
    pub explicit_message_class: &'x [u8],
}

impl RopResponse for GetReceiveFolderResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.folder_id.to_wire());
        out.put_ascii_z(self.explicit_message_class);
    }

    fn encoded_len_hint(&self) -> usize {
        8_usize.saturating_add(self.explicit_message_class.len().saturating_add(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NotGhostedResponse;

impl RopResponse for NotGhostedResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(0);
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetSearchCriteriaResponse<'x> {
    pub restriction_data: &'x [u8],
    pub logon_id: u8,
    pub folder_ids: &'x [Eid],
    pub search_flags: u32,
}

impl RopResponse for GetSearchCriteriaResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let restriction_data_len = u16::try_from(self.restriction_data.len()).unwrap_or(u16::MAX);
        out.put_u16(restriction_data_len);
        out.extend_from_slice(
            self.restriction_data
                .get(..usize::from(restriction_data_len))
                .unwrap_or(self.restriction_data),
        );
        out.put_u8(self.logon_id);
        let folder_ids_len = u16::try_from(self.folder_ids.len()).unwrap_or(u16::MAX);
        out.put_u16(folder_ids_len);
        for item in self.folder_ids.iter().take(usize::from(folder_ids_len)) {
            out.extend_from_slice(&item.to_wire());
        }
        out.put_u32(self.search_flags);
    }

    fn encoded_len_hint(&self) -> usize {
        9_usize
            .saturating_add(self.restriction_data.len())
            .saturating_add(self.folder_ids.len().saturating_mul(8))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MoveCopyMessagesResponse {
    pub partial_completion: bool,
}

impl RopResponse for MoveCopyMessagesResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.partial_completion));
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MoveFolderResponse {
    pub partial_completion: bool,
}

impl RopResponse for MoveFolderResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.partial_completion));
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CopyFolderResponse {
    pub partial_completion: bool,
}

impl RopResponse for CopyFolderResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.partial_completion));
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LongTermIdFromIdResponse {
    pub long_term_id: LongTermId,
}

impl RopResponse for LongTermIdFromIdResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.long_term_id.to_wire());
    }

    fn encoded_len_hint(&self) -> usize {
        24
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IdFromLongTermIdResponse {
    pub object_id: Eid,
}

impl RopResponse for IdFromLongTermIdResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.object_id.to_wire());
    }

    fn encoded_len_hint(&self) -> usize {
        8
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EmptyFolderResponse {
    pub partial_completion: bool,
}

impl RopResponse for EmptyFolderResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.partial_completion));
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HardDeleteMessagesResponse {
    pub partial_completion: bool,
}

impl RopResponse for HardDeleteMessagesResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.partial_completion));
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HardDeleteMessagesAndSubfoldersResponse {
    pub partial_completion: bool,
}

impl RopResponse for HardDeleteMessagesAndSubfoldersResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.partial_completion));
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}
