/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod dispatch;
mod ics;
mod manual;
mod props;
mod store;
mod stubs;
mod tables;

pub use dispatch::RopRequest;
pub(crate) use dispatch::decode_request;
pub use ics::*;
pub use manual::*;
pub use props::*;
pub use store::*;
pub use tables::*;

use super::{buffer::DecodeContext, error::RopDecodeError, header::RopId};
use crate::{common::LeReader, ids::LongTermId};

impl RopRequest<'_> {
    pub(crate) fn separate_input_handle(&self) -> Option<u8> {
        match self {
            RopRequest::SaveChangesMessage(request) => Some(request.input_handle_index),
            RopRequest::SaveChangesAttachment(request) => Some(request.input_handle_index),
            RopRequest::SetMessageReadFlag(request) => Some(request.input_handle_index),
            _ => None,
        }
    }
}

#[cold]
#[inline(never)]
fn too_many(r: &LeReader<'_>) -> RopDecodeError {
    RopDecodeError::TooMany {
        offset: RopDecodeError::at(r.offset()),
    }
}

fn framed(r: &LeReader<'_>, start: usize, size: usize) -> Result<(), RopDecodeError> {
    if r.offset().checked_sub(start) == Some(size) {
        Ok(())
    } else {
        Err(frame_size(start))
    }
}

#[cold]
#[inline(never)]
fn frame_size(start: usize) -> RopDecodeError {
    RopDecodeError::FrameSize {
        offset: RopDecodeError::at(start),
    }
}

fn read_long_term_id(r: &mut LeReader<'_>) -> Result<LongTermId, RopDecodeError> {
    let offset = r.offset();
    let bytes = r.bytes(LongTermId::LEN)?;
    LongTermId::from_wire(bytes).ok_or(RopDecodeError::BadValue {
        offset: RopDecodeError::at(offset),
    })
}

type Walker = fn(&mut LeReader<'_>, &DecodeContext<'_>) -> Result<(), RopDecodeError>;

fn stub<'a>(
    id: RopId,
    r: &mut LeReader<'a>,
    ctx: &DecodeContext<'_>,
    walker: Walker,
) -> Result<RopRequest<'a>, RopDecodeError> {
    let body = r.remaining();
    let before = r.offset();
    walker(r, ctx)?;
    let len = r.offset().saturating_sub(before);
    Ok(RopRequest::Stub(id, body.get(..len).unwrap_or_default()))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/rop/requests/tests.rs"]
mod tests;
