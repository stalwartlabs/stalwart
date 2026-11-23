/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use smallvec::SmallVec;

use super::{
    buffer::HandleTableIn,
    header::{ResponseHeader, RopId},
};
use crate::{
    common::LeWriter,
    mapi::{
        emsmdb::{ExecuteResponseMark, MapiLimits},
        notify::NotificationData,
        prop::row::{RowOptions, RowSetLayout, RowSetWriter},
        rpc_ext::RpcHeaderExt,
    },
};

const ROP_SIZE_LEN: usize = 2;
const HANDLE_LEN: usize = 4;
const UNASSIGNED: u32 = u32::MAX;
pub const BUFFER_TOO_SMALL_LEN: usize = 3;
pub const PENDING_LEN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark(usize);

pub trait RopResponse {
    fn encode(&self, out: &mut Vec<u8>);
    fn encoded_len_hint(&self) -> usize;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureBody {
    HeaderOnly,
    LogonRedirect {
        logon_flags: u8,
        server: Vec<u8>,
    },
    NullDestination(u32),
    NullDestinationPartial {
        dest_handle: u32,
        partial_completion: bool,
    },
    NullDestinationStream(u32),
    PartialCompletion(bool),
    Transfer,
    Zeroed(u8),
}

const TRANSFER_FAILURE_LEN: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadMark {
    out_len: usize,
    size_at: usize,
    limit: usize,
    capacity: usize,
    ended: bool,
    response: ExecuteResponseMark,
}

fn payload_budget(room: usize, handles: usize) -> usize {
    room.min(usize::try_from(MapiLimits::DEFAULT.output_budget_max).unwrap_or(0))
        .saturating_sub(ROP_SIZE_LEN)
        .saturating_sub(handles.saturating_mul(HANDLE_LEN))
}

#[derive(Debug)]
pub struct RopWriter<'o> {
    pub(crate) out: &'o mut Vec<u8>,
    size_at: usize,
    pub(crate) limit: usize,
    capacity: usize,
    handles: SmallVec<[u32; 16]>,
    ended: bool,
}

impl<'o> RopWriter<'o> {
    pub fn new(out: &'o mut Vec<u8>, max_rop_out: u32, input_handles: &HandleTableIn<'_>) -> Self {
        let size_at = out.len();
        out.put_u16(0);
        let budget = payload_budget(
            usize::try_from(max_rop_out)
                .unwrap_or(0)
                .saturating_sub(RpcHeaderExt::LEN),
            input_handles.len(),
        );
        let handles: SmallVec<[u32; 16]> = input_handles.iter().collect();
        out.reserve(budget.saturating_add(handles.len().saturating_mul(HANDLE_LEN)));
        let capacity = out.len().saturating_add(budget);
        RopWriter {
            limit: capacity,
            capacity,
            out,
            size_at,
            handles,
            ended: false,
        }
    }

    pub fn mark(&self) -> Mark {
        Mark(self.out.len())
    }

    pub fn rollback(&mut self, mark: Mark) {
        self.out
            .truncate(mark.0.max(self.size_at.saturating_add(ROP_SIZE_LEN)));
    }

    pub fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.out.len())
    }

    pub fn reserve_tail(&mut self, bytes: usize) {
        self.limit = self.capacity.saturating_sub(bytes);
    }

    pub fn reset_handle(&mut self, index: u8, handle: u32) {
        if let Some(slot) = self.handles.get_mut(usize::from(index)) {
            *slot = handle;
        }
    }

    pub fn set_handle(&mut self, index: u8, handle: u32) -> bool {
        match self.handles.get_mut(usize::from(index)) {
            Some(slot) if handle != UNASSIGNED => {
                *slot = handle;
                true
            }
            _ => false,
        }
    }

    fn commit(&mut self, mark: usize) -> Result<(), Overflow> {
        if self.ended || self.out.len() > self.limit {
            self.out.truncate(mark);
            Err(Overflow)
        } else {
            Ok(())
        }
    }

    pub fn response<R: RopResponse>(
        &mut self,
        header: ResponseHeader,
        body: &R,
    ) -> Result<(), Overflow> {
        let mark = self.out.len();
        self.out
            .reserve(ResponseHeader::LEN.saturating_add(body.encoded_len_hint()));
        header.write(self.out);
        body.encode(self.out);
        self.commit(mark)
    }

    pub fn failure(
        &mut self,
        header: ResponseHeader,
        failure: &FailureBody,
    ) -> Result<(), Overflow> {
        let mark = self.out.len();
        header.write(self.out);
        match failure {
            FailureBody::HeaderOnly => {}
            FailureBody::LogonRedirect {
                logon_flags,
                server,
            } => {
                let server = server
                    .get(..memchr::memchr(0, server).unwrap_or(server.len()))
                    .unwrap_or_default();
                let server = server.get(..usize::from(u8::MAX - 1)).unwrap_or(server);
                self.out.put_u8(*logon_flags);
                self.out
                    .put_u8(u8::try_from(server.len().saturating_add(1)).unwrap_or(u8::MAX));
                self.out.put_ascii_z(server);
            }
            FailureBody::NullDestination(dest) => self.out.put_u32(*dest),
            FailureBody::NullDestinationPartial {
                dest_handle,
                partial_completion,
            } => {
                self.out.put_u32(*dest_handle);
                self.out.put_u8(u8::from(*partial_completion));
            }
            FailureBody::NullDestinationStream(dest) => {
                self.out.put_u32(*dest);
                self.out.put_u64(0);
                self.out.put_u64(0);
            }
            FailureBody::PartialCompletion(partial) => self.out.put_u8(u8::from(*partial)),
            FailureBody::Transfer => self.out.extend_from_slice(&[0; TRANSFER_FAILURE_LEN]),
            FailureBody::Zeroed(len) => self
                .out
                .resize(self.out.len().saturating_add(usize::from(*len)), 0),
        }
        self.commit(mark)
    }

    pub fn row_writer(
        &mut self,
        header: ResponseHeader,
        layout: RowSetLayout,
        options: RowOptions,
    ) -> Result<RowSetWriter<'_, 'o>, Overflow> {
        let mark = self.out.len();
        header.write(self.out);
        self.commit(mark)?;
        RowSetWriter::begin(self, mark, layout, options)
    }

    pub fn buffer_too_small(
        &mut self,
        size_needed: u16,
        unprocessed: &[u8],
    ) -> Result<(), Overflow> {
        let len = BUFFER_TOO_SMALL_LEN.saturating_add(unprocessed.len());
        if self.ended || self.out.len().saturating_add(len) > self.capacity {
            return Err(Overflow);
        }
        self.out.put_u8(RopId::BUFFER_TOO_SMALL.0);
        self.out.put_u16(size_needed);
        self.out.extend_from_slice(unprocessed);
        self.ended = true;
        Ok(())
    }

    pub fn notify(
        &mut self,
        handle: u32,
        logon_id: u8,
        data: &NotificationData<'_>,
    ) -> Result<(), Overflow> {
        let mark = self.out.len();
        self.out.put_u8(RopId::NOTIFY.0);
        self.out.put_u32(handle);
        self.out.put_u8(logon_id);
        data.encode(self.out);
        self.commit(mark)
    }

    pub fn backoff(
        &mut self,
        logon_id: u8,
        duration: u32,
        rops: &[(RopId, u32)],
        additional: &[u8],
    ) -> Result<(), Overflow> {
        let mark = self.out.len();
        self.out.put_u8(RopId::BACKOFF.0);
        self.out.put_u8(logon_id);
        self.out.put_u32(duration);
        let count = u8::try_from(rops.len()).unwrap_or(u8::MAX);
        self.out.put_u8(count);
        for (id, duration) in rops.iter().take(usize::from(count)) {
            self.out.put_u8(id.0);
            self.out.put_u32(*duration);
        }
        let additional = additional
            .get(..usize::from(u16::MAX))
            .unwrap_or(additional);
        self.out
            .put_u16(u16::try_from(additional.len()).unwrap_or(u16::MAX));
        self.out.extend_from_slice(additional);
        self.commit(mark)
    }

    pub fn pending(&mut self, session_index: u16) -> Result<(), Overflow> {
        let mark = self.out.len();
        self.out.put_u8(RopId::PENDING.0);
        self.out.put_u16(session_index);
        self.commit(mark)
    }

    pub fn next_payload(
        &mut self,
        response: &mut ExecuteResponseMark,
        max_rop_out: u32,
        min_residual: usize,
    ) -> Option<PayloadMark> {
        let handles = self.handles.len();
        let sealed_end = self
            .out
            .len()
            .saturating_add(handles.saturating_mul(HANDLE_LEN));
        let residual = response
            .residual(sealed_end, max_rop_out)
            .filter(|residual| *residual >= min_residual)?;
        let saved = PayloadMark {
            out_len: self.out.len(),
            size_at: self.size_at,
            limit: self.limit,
            capacity: self.capacity,
            ended: self.ended,
            response: *response,
        };
        self.seal();
        if !response.next_buffer(self.out) {
            self.drop_payload(response, saved);
            return None;
        }
        let budget = payload_budget(residual.saturating_sub(RpcHeaderExt::LEN), handles);
        self.size_at = self.out.len();
        self.out.put_u16(0);
        self.out
            .reserve(budget.saturating_add(handles.saturating_mul(HANDLE_LEN)));
        self.capacity = self.out.len().saturating_add(budget);
        self.limit = self.capacity;
        self.ended = false;
        Some(saved)
    }

    pub fn drop_payload(&mut self, response: &mut ExecuteResponseMark, saved: PayloadMark) {
        self.out.truncate(saved.out_len);
        self.size_at = saved.size_at;
        self.limit = saved.limit;
        self.capacity = saved.capacity;
        self.ended = saved.ended;
        *response = saved.response;
    }

    fn seal(&mut self) {
        let len = self.out.len().saturating_sub(self.size_at);
        self.out
            .patch_u16(self.size_at, u16::try_from(len).unwrap_or(u16::MAX));
        for handle in &self.handles {
            self.out.put_u32(*handle);
        }
    }

    pub fn finish(mut self) -> usize {
        self.seal();
        self.out.len().saturating_sub(self.size_at)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/rop/writer/tests.rs"]
mod tests;
