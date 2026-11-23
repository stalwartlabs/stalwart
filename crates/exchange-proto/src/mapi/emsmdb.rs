/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    aux_buffer::{AuxIn, AuxOut},
    ec::{ErrorCode, StatusCode},
    error::BodyError,
    rpc_ext::{self, RpcHeaderExt},
};
use crate::common::{LeReader, LeWriter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapiLimits {
    pub rop_buffer_max: u32,
    pub max_rop_out_min: u32,
    pub max_rop_out_max: u32,
    pub output_budget_max: u32,
    pub aux_min: u32,
    pub aux_max: u32,
    pub handles_max: u16,
    pub decompressed_max: u16,
    pub restriction_depth: u8,
    pub named_name_max_units: u16,
    pub mv_count_max: u32,
}

impl MapiLimits {
    pub const DEFAULT: Self = MapiLimits {
        rop_buffer_max: 0x40000,
        max_rop_out_min: 8,
        max_rop_out_max: 0x40000,
        output_budget_max: 0x8000,
        aux_min: 8,
        aux_max: 0x1008,
        handles_max: 255,
        decompressed_max: 0x8000,
        restriction_depth: 32,
        named_name_max_units: 255,
        mv_count_max: 0x8000,
    };
}

impl Default for MapiLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecuteFlags(u32);

impl ExecuteFlags {
    pub const NO_COMPRESSION: u32 = 0x0000_0001;
    pub const NO_XOR_MAGIC: u32 = 0x0000_0002;
    pub const CHAIN: u32 = 0x0000_0004;

    pub fn new(bits: u32) -> Self {
        ExecuteFlags(bits)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn contains(self, flag: u32) -> bool {
        self.0 & flag == flag
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectRequest<'a> {
    pub user_dn: &'a [u8],
    pub flags: u32,
    pub code_page: u32,
    pub lcid_sort: u32,
    pub lcid_string: u32,
    pub aux: AuxIn<'a>,
}

impl ConnectRequest<'_> {
    pub const FLAG_ADMIN: u32 = 0x0000_0001;
    pub const FLAG_IGNORE_NO_PUBLIC_FOLDERS: u32 = 0x0000_8000;
}

#[derive(Debug, Clone, Copy)]
pub struct ConnectResponse<'x> {
    pub error: ErrorCode,
    pub polls_max: u32,
    pub retry_count: u32,
    pub retry_delay: u32,
    pub dn_prefix: &'x [u8],
    pub display_name: &'x str,
    pub aux: &'x AuxOut,
}

impl ConnectResponse<'_> {
    pub const POLLS_MAX_MS: u32 = 60_000;
    pub const RETRY_COUNT: u32 = 6;
    pub const RETRY_DELAY_MS: u32 = 10_000;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecuteRequest<'a> {
    pub flags: ExecuteFlags,
    pub rop_buffer: &'a [u8],
    pub max_rop_out: u32,
    pub aux: AuxIn<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectRequest<'a> {
    pub aux: AuxIn<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationWaitRequest<'a> {
    pub flags: u32,
    pub aux: AuxIn<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecuteResponseMark {
    start: usize,
    rop_buffer: usize,
    last_buffer: usize,
    payloads: u8,
}

impl ExecuteResponseMark {
    pub const PAYLOADS_MAX: u8 = 96;

    pub(crate) fn residual(&self, end: usize, max_rop_out: u32) -> Option<usize> {
        let used = end.checked_sub(self.rop_buffer)?;
        usize::try_from(max_rop_out).ok()?.checked_sub(used)
    }

    pub(crate) fn next_buffer(&mut self, out: &mut Vec<u8>) -> bool {
        if self.payloads >= Self::PAYLOADS_MAX
            || !rpc_ext::patch_buffer_header(out, self.last_buffer, false)
        {
            return false;
        }
        self.last_buffer = rpc_ext::write_buffer_header(out);
        self.payloads = self.payloads.saturating_add(1);
        true
    }
}

const EXECUTE_FIXED_LEN: usize = 16;
const ERROR_CODE_AT: usize = 4;
const ROP_BUFFER_SIZE_AT: usize = 12;

fn read_aux<'a>(r: &mut LeReader<'a>, limits: &MapiLimits) -> Result<AuxIn<'a>, BodyError> {
    let size = r.u32()?;
    if size == 0 {
        return Ok(AuxIn::default());
    }
    if size < limits.aux_min {
        return Err(BodyError::AuxTooShort);
    }
    if size > limits.aux_max {
        return Err(BodyError::AuxTooLarge);
    }
    let len = usize::try_from(size).map_err(|_| BodyError::AuxTooLarge)?;
    Ok(AuxIn::new(r.bytes(len)?))
}

fn finish_body<T>(r: &LeReader<'_>, value: T) -> Result<T, BodyError> {
    if r.is_empty() {
        Ok(value)
    } else {
        Err(BodyError::TrailingData {
            offset: u32::try_from(r.offset()).unwrap_or(u32::MAX),
        })
    }
}

pub fn parse_connect(body: &[u8]) -> Result<ConnectRequest<'_>, BodyError> {
    let mut r = LeReader::new(body);
    let user_dn = r.ascii_z()?;
    let flags = r.u32()?;
    let code_page = r.u32()?;
    let lcid_sort = r.u32()?;
    let lcid_string = r.u32()?;
    let aux = read_aux(&mut r, &MapiLimits::DEFAULT)?;
    finish_body(
        &r,
        ConnectRequest {
            user_dn,
            flags,
            code_page,
            lcid_sort,
            lcid_string,
            aux,
        },
    )
}

pub fn parse_execute<'a>(
    body: &'a [u8],
    limits: &MapiLimits,
) -> Result<ExecuteRequest<'a>, BodyError> {
    let mut r = LeReader::new(body);
    let flags = ExecuteFlags(r.u32()?);
    let rop_buffer_size = r.u32()?;
    if rop_buffer_size > limits.rop_buffer_max {
        return Err(BodyError::RopBufferTooLarge);
    }
    if usize::try_from(rop_buffer_size).is_ok_and(|size| size != 0 && size < RpcHeaderExt::LEN) {
        return Err(BodyError::RopBufferTooShort);
    }
    let rop_buffer =
        r.bytes(usize::try_from(rop_buffer_size).map_err(|_| BodyError::RopBufferTooLarge)?)?;
    let max_rop_out = r.u32()?;
    if max_rop_out < limits.max_rop_out_min {
        return Err(BodyError::MaxRopOutTooSmall);
    }
    if max_rop_out > limits.max_rop_out_max {
        return Err(BodyError::MaxRopOutTooLarge);
    }
    let aux = read_aux(&mut r, limits)?;
    finish_body(
        &r,
        ExecuteRequest {
            flags,
            rop_buffer,
            max_rop_out,
            aux,
        },
    )
}

pub fn parse_disconnect(body: &[u8]) -> Result<DisconnectRequest<'_>, BodyError> {
    let mut r = LeReader::new(body);
    let aux = read_aux(&mut r, &MapiLimits::DEFAULT)?;
    finish_body(&r, DisconnectRequest { aux })
}

pub fn parse_notification_wait(body: &[u8]) -> Result<NotificationWaitRequest<'_>, BodyError> {
    let mut r = LeReader::new(body);
    let flags = r.u32()?;
    let aux = read_aux(&mut r, &MapiLimits::DEFAULT)?;
    finish_body(&r, NotificationWaitRequest { flags, aux })
}

pub fn write_connect_response(out: &mut Vec<u8>, r: &ConnectResponse<'_>) {
    out.put_u32(StatusCode::OK.0);
    out.put_u32(r.error.0);
    if r.error == ErrorCode::SUCCESS {
        out.reserve(
            r.dn_prefix
                .len()
                .saturating_add(r.display_name.len().saturating_mul(2))
                .saturating_add(r.aux.as_bytes().len())
                .saturating_add(24),
        );
        out.put_u32(r.polls_max);
        out.put_u32(r.retry_count);
        out.put_u32(r.retry_delay);
        out.put_ascii_z(r.dn_prefix);
        out.put_utf16_z(r.display_name);
        out.put_u32(r.aux.len_u32());
        out.extend_from_slice(r.aux.as_bytes());
    } else {
        out.extend_from_slice(&[0; 12]);
        out.put_u8(0);
        out.put_u16(0);
        out.put_u32(0);
    }
}

pub fn begin_execute_response(out: &mut Vec<u8>) -> ExecuteResponseMark {
    let start = out.len();
    out.extend_from_slice(&[0; EXECUTE_FIXED_LEN]);
    let rop_buffer = rpc_ext::write_buffer_header(out);
    ExecuteResponseMark {
        start,
        rop_buffer,
        last_buffer: rop_buffer,
        payloads: 1,
    }
}

pub fn finish_execute_response(out: &mut Vec<u8>, mark: ExecuteResponseMark, error: ErrorCode) {
    let rop_buffer_size = (error == ErrorCode::SUCCESS)
        .then(|| {
            let size = u32::try_from(out.len().checked_sub(mark.rop_buffer)?).ok()?;
            rpc_ext::patch_buffer_header(out, mark.last_buffer, true).then_some(size)
        })
        .flatten();
    let error = match rop_buffer_size {
        Some(_) => error,
        None if error == ErrorCode::SUCCESS => ErrorCode::RPC_FAILED,
        None => error,
    };
    if rop_buffer_size.is_none() {
        out.truncate(mark.start.saturating_add(EXECUTE_FIXED_LEN));
    }
    out.patch_u32(mark.start.saturating_add(ERROR_CODE_AT), error.0);
    out.patch_u32(
        mark.start.saturating_add(ROP_BUFFER_SIZE_AT),
        rop_buffer_size.unwrap_or(0),
    );
    out.put_u32(0);
}

pub fn write_disconnect_response(out: &mut Vec<u8>, error: ErrorCode) {
    out.put_u32(StatusCode::OK.0);
    out.put_u32(error.0);
    out.put_u32(0);
}

pub fn write_notification_wait_response(out: &mut Vec<u8>, error: ErrorCode, event_pending: bool) {
    out.put_u32(StatusCode::OK.0);
    out.put_u32(error.0);
    out.put_u32(u32::from(event_pending && error == ErrorCode::SUCCESS));
    out.put_u32(0);
}

pub fn write_failure_body(out: &mut Vec<u8>, status: StatusCode) {
    out.put_u32(status.0);
    out.put_u32(0);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/emsmdb/tests.rs"]
mod tests;
