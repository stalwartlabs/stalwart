/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::Guid;
use crate::common::LeWriter;
use crate::ics::flags::TransferStatus;
use crate::ids::Globcnt;
use crate::mapi::rop::writer::RopResponse;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FastTransferDestinationPutBufferResponse {
    pub transfer_status: TransferStatus,
    pub in_progress_count: u16,
    pub total_step_count: u16,
    pub buffer_used_size: u16,
}

impl RopResponse for FastTransferDestinationPutBufferResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.transfer_status as u16);
        out.put_u16(self.in_progress_count);
        out.put_u16(self.total_step_count);
        out.put_u8(0x00);
        out.put_u16(self.buffer_used_size);
    }

    fn encoded_len_hint(&self) -> usize {
        9
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FastTransferDestinationPutBufferExtendedResponse {
    pub transfer_status: TransferStatus,
    pub in_progress_count: u32,
    pub total_step_count: u32,
    pub buffer_used_size: u16,
}

impl RopResponse for FastTransferDestinationPutBufferExtendedResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.transfer_status as u16);
        out.put_u32(self.in_progress_count);
        out.put_u32(self.total_step_count);
        out.put_u8(0x00);
        out.put_u16(self.buffer_used_size);
    }

    fn encoded_len_hint(&self) -> usize {
        13
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynchronizationImportMessageChangeResponse;

impl RopResponse for SynchronizationImportMessageChangeResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u64(0);
    }

    fn encoded_len_hint(&self) -> usize {
        8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynchronizationImportHierarchyChangeResponse;

impl RopResponse for SynchronizationImportHierarchyChangeResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u64(0);
    }

    fn encoded_len_hint(&self) -> usize {
        8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynchronizationImportMessageMoveResponse;

impl RopResponse for SynchronizationImportMessageMoveResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u64(0);
    }

    fn encoded_len_hint(&self) -> usize {
        8
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetLocalReplicaIdsResponse {
    pub repl_guid: Guid,
    pub global_count: Globcnt,
}

impl RopResponse for GetLocalReplicaIdsResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_guid(&self.repl_guid);
        out.extend_from_slice(&self.global_count.to_wire());
    }

    fn encoded_len_hint(&self) -> usize {
        22
    }
}
