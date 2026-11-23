/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{Children, CommandError, Counter, MAX_ID_LEN, MAX_MOVE_ITEMS, read_id, required};
use crate::eas::status::MoveItemsStatus;
use crate::eas::tokens::{ProtocolVersion, tag::move_items as mv};
use crate::eas::wbxml::{Decoder, Encoder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveItem<'a> {
    pub src_msg_id: Cow<'a, str>,
    pub src_fld_id: Cow<'a, str>,
    pub dst_fld_id: Cow<'a, str>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MoveItemsRequest<'a> {
    pub moves: Vec<MoveItem<'a>>,
}

impl<'a> MoveItemsRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = MoveItemsRequest::default();
        let mut counter = Counter::new(MAX_MOVE_ITEMS);
        let mut children = Children::root(dec, mv::MOVE_ITEMS)?;
        while let Some(tag) = children.next(dec)? {
            if tag == mv::MOVE {
                counter.bump(tag)?;
                request.moves.push(MoveItem::parse(dec)?);
            }
        }
        if request.moves.is_empty() {
            return Err(CommandError::Missing { tag: mv::MOVE });
        }
        Ok(request)
    }
}

impl<'a> MoveItem<'a> {
    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut src_msg_id = None;
        let mut src_fld_id = None;
        let mut dst_fld_id = None;
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                mv::SRC_MSG_ID => src_msg_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                mv::SRC_FLD_ID => src_fld_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                mv::DST_FLD_ID => dst_fld_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                _ => {}
            }
        }
        Ok(MoveItem {
            src_msg_id: required(src_msg_id, mv::SRC_MSG_ID)?,
            src_fld_id: required(src_fld_id, mv::SRC_FLD_ID)?,
            dst_fld_id: required(dst_fld_id, mv::DST_FLD_ID)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveItemsResult<'x> {
    pub src_msg_id: &'x str,
    pub status: MoveItemsStatus,
    pub dst_msg_id: Option<&'x str>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MoveItemsResponse<'x> {
    pub status: Option<MoveItemsStatus>,
    pub responses: Vec<MoveItemsResult<'x>>,
}

impl MoveItemsResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(mv::MOVE_ITEMS);
        if let Some(status) = self.status {
            enc.text_u64(mv::STATUS, u64::from(status.0));
        }
        for response in &self.responses {
            enc.start(mv::RESPONSE)
                .text_str(mv::SRC_MSG_ID, response.src_msg_id)
                .text_u64(mv::STATUS, u64::from(response.status.0));
            if let Some(dst_msg_id) = response.dst_msg_id {
                enc.text_str(mv::DST_MSG_ID, dst_msg_id);
            }
            enc.end();
        }
        enc.end();
    }
}
