/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::LeReader,
    ids::Eid,
    mapi::rop::{
        buffer::{DecodeContext, LogonKind},
        error::RopDecodeError,
        header::RopHeader,
    },
};

const BABE: u16 = 0xBABE;
const NOTIFY_EXTENDED: u16 = 0x0400;
const CLIENT_DATA_LEN: usize = 24;
const LONG_TERM_ID_LEN: usize = 24;
const GUID_LEN: usize = 16;

fn logon_private(ctx: &DecodeContext<'_>) -> bool {
    ctx.logon != Some(LogonKind::Public)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Logon<'a> {
    pub output_handle_index: u8,
    pub logon_flags: u8,
    pub open_flags: u32,
    pub store_state: u32,
    pub essdn: &'a [u8],
}

impl<'a> Logon<'a> {
    pub const FLAG_PRIVATE: u8 = 0x01;

    pub(crate) fn decode(
        header: &RopHeader,
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let logon_flags = r.u8()?;
        let open_flags = r.u32()?;
        let store_state = r.u32()?;
        let size = usize::from(r.u16()?);
        let essdn = r.bytes(size)?;
        let essdn = essdn
            .get(..memchr::memchr(0, essdn).unwrap_or(essdn.len()))
            .unwrap_or_default();
        Ok(Logon {
            output_handle_index: header.handle_index,
            logon_flags,
            open_flags,
            store_state,
            essdn,
        })
    }

    pub fn kind(&self) -> LogonKind {
        if self.logon_flags & Self::FLAG_PRIVATE != 0 {
            LogonKind::Private
        } else {
            LogonKind::Public
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetMessageReadFlag {
    pub input_handle_index: u8,
    pub read_flags: u8,
    pub client_data: Option<[u8; CLIENT_DATA_LEN]>,
}

impl SetMessageReadFlag {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let input_handle_index = r.u8()?;
        let read_flags = r.u8()?;
        let client_data = if logon_private(ctx) {
            None
        } else {
            Some(r.array()?)
        };
        Ok(SetMessageReadFlag {
            input_handle_index,
            read_flags,
            client_data,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadStream {
    pub byte_count: u16,
    pub maximum_byte_count: Option<u32>,
}

impl ReadStream {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let byte_count = r.u16()?;
        let maximum_byte_count = if byte_count == BABE {
            Some(r.u32()?)
        } else {
            None
        };
        Ok(ReadStream {
            byte_count,
            maximum_byte_count,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastTransferSourceGetBuffer {
    pub buffer_size: u16,
    pub maximum_buffer_size: Option<u16>,
}

impl FastTransferSourceGetBuffer {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let buffer_size = r.u16()?;
        let maximum_buffer_size = if buffer_size == BABE {
            Some(r.u16()?)
        } else {
            None
        };
        Ok(FastTransferSourceGetBuffer {
            buffer_size,
            maximum_buffer_size,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterNotification {
    pub output_handle_index: u8,
    pub notification_types: u16,
    pub want_whole_store: bool,
    pub folder_id: Option<Eid>,
    pub message_id: Option<Eid>,
}

impl RegisterNotification {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let notification_types = r.u16()?;
        if notification_types & NOTIFY_EXTENDED != 0 {
            r.u8()?;
        }
        let want_whole_store = r.u8()? != 0;
        let (folder_id, message_id) = if want_whole_store {
            (None, None)
        } else {
            (
                Some(Eid::from_wire(r.array()?)),
                Some(Eid::from_wire(r.array()?)),
            )
        };
        Ok(RegisterNotification {
            output_handle_index,
            notification_types,
            want_whole_store,
            folder_id,
            message_id,
        })
    }
}

pub(super) fn skip_write_per_user_information(
    r: &mut LeReader<'_>,
    ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(LONG_TERM_ID_LEN)?;
    r.u8()?;
    let data_offset = r.u32()?;
    let data_size = usize::from(r.u16()?);
    r.skip(data_size)?;
    if data_offset == 0 && logon_private(ctx) {
        r.skip(GUID_LEN)?;
    }
    Ok(())
}
