/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    error::RopDecodeError,
    header::{RopHeader, RopId},
    requests::{RopRequest, decode_request},
};
use crate::{common::LeReader, mapi::emsmdb::MapiLimits};

const HANDLE_LEN: usize = 4;
const ROP_SIZE_LEN: usize = 2;

#[derive(Debug, Clone, Copy)]
pub struct RopBuffer<'a> {
    pub rops: &'a [u8],
    pub handles: HandleTableIn<'a>,
    limits: MapiLimits,
}

impl<'a> RopBuffer<'a> {
    pub fn parse(payload: &'a [u8], limits: &MapiLimits) -> Result<Self, RopDecodeError> {
        if payload.is_empty() {
            return Ok(RopBuffer {
                rops: payload,
                handles: HandleTableIn::EMPTY,
                limits: *limits,
            });
        }
        let (size, _) = payload
            .split_first_chunk::<ROP_SIZE_LEN>()
            .ok_or(RopDecodeError::RopSize)?;
        let size = usize::from(u16::from_le_bytes(*size));
        if size < ROP_SIZE_LEN {
            return Err(RopDecodeError::RopSize);
        }
        let (head, handles) = payload
            .split_at_checked(size)
            .ok_or(RopDecodeError::RopSize)?;
        let rops = head.get(ROP_SIZE_LEN..).unwrap_or_default();
        if !handles.len().is_multiple_of(HANDLE_LEN)
            || handles.len() / HANDLE_LEN > usize::from(limits.handles_max)
        {
            return Err(RopDecodeError::HandleTable);
        }
        Ok(RopBuffer {
            rops,
            handles: HandleTableIn(handles),
            limits: *limits,
        })
    }

    pub fn rops(&self) -> RopIter<'a> {
        RopIter {
            rest: self.rops,
            limits: self.limits,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleTableIn<'a>(&'a [u8]);

impl<'a> HandleTableIn<'a> {
    pub const EMPTY: HandleTableIn<'static> = HandleTableIn(&[]);

    pub fn len(&self) -> usize {
        self.0.len() / HANDLE_LEN
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: u8) -> Option<u32> {
        self.0
            .as_chunks::<HANDLE_LEN>()
            .0
            .get(usize::from(index))
            .map(|h| u32::from_le_bytes(*h))
    }

    pub fn iter(&self) -> impl Iterator<Item = u32> + 'a {
        self.0
            .as_chunks::<HANDLE_LEN>()
            .0
            .iter()
            .map(|h| u32::from_le_bytes(*h))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonKind {
    Private,
    Public,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogonKinds {
    active: [u64; 4],
    private: [u64; 4],
}

impl LogonKinds {
    fn slot(logon_id: u8) -> (usize, u64) {
        (usize::from(logon_id >> 6), 1u64 << (logon_id & 63))
    }

    pub fn set(&mut self, logon_id: u8, kind: Option<LogonKind>) {
        let (word, bit) = Self::slot(logon_id);
        if let (Some(active), Some(private)) =
            (self.active.get_mut(word), self.private.get_mut(word))
        {
            match kind {
                Some(LogonKind::Private) => {
                    *active |= bit;
                    *private |= bit;
                }
                Some(LogonKind::Public) => {
                    *active |= bit;
                    *private &= !bit;
                }
                None => {
                    *active &= !bit;
                    *private &= !bit;
                }
            }
        }
    }

    pub fn get(&self, logon_id: u8) -> Option<LogonKind> {
        let (word, bit) = Self::slot(logon_id);
        let active = self.active.get(word)?;
        let private = self.private.get(word)?;
        (active & bit != 0).then_some(if private & bit != 0 {
            LogonKind::Private
        } else {
            LogonKind::Public
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DecodeContext<'c> {
    pub logon: Option<LogonKind>,
    pub limits: &'c MapiLimits,
}

#[derive(Debug, Clone)]
pub struct RopIter<'a> {
    rest: &'a [u8],
    limits: MapiLimits,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedRop<'a> {
    pub header: RopHeader,
    pub request: RopRequest<'a>,
    pub raw_from_here: &'a [u8],
}

impl<'a> RopIter<'a> {
    pub fn remaining_len(&self) -> usize {
        self.rest.len()
    }

    pub fn next_rop(
        &mut self,
        logons: &LogonKinds,
    ) -> Option<Result<DecodedRop<'a>, RopDecodeError>> {
        if self.rest.is_empty() {
            return None;
        }
        let raw_from_here = self.rest;
        let result = self.decode_one(raw_from_here, logons);
        match &result {
            Ok(_) => {}
            Err(_) => self.rest = &[],
        }
        Some(result)
    }

    fn decode_one(
        &mut self,
        raw_from_here: &'a [u8],
        logons: &LogonKinds,
    ) -> Result<DecodedRop<'a>, RopDecodeError> {
        let mut r = LeReader::new(raw_from_here);
        let id = RopId(r.u8()?);
        if id.is_reserved() {
            return Err(RopDecodeError::UnknownRop(id.0));
        }
        let logon_id = r.u8()?;
        let handle_index = r.u8()?;
        let mut header = RopHeader {
            id,
            logon_id,
            handle_index,
            input_handle: handle_index,
        };
        let ctx = DecodeContext {
            logon: logons.get(logon_id),
            limits: &self.limits,
        };
        let request = decode_request(&header, &mut r, &ctx)?;
        if let Some(input_handle) = request.separate_input_handle() {
            header.input_handle = input_handle;
        }
        self.rest = r.remaining();
        Ok(DecodedRop {
            header,
            request,
            raw_from_here,
        })
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/rop/buffer/tests.rs"]
mod tests;
