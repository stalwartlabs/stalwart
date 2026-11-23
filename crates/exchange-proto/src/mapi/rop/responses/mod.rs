/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod ics;
pub mod manual;
pub mod props;
pub mod store;
pub mod tables;

pub use ics::*;
pub use manual::*;
pub use props::*;
pub use store::*;
pub use tables::*;

use crate::{
    common::LeWriter,
    mapi::{
        ec::ErrorCode,
        prop::{CountWidth, PropTag, PropValue, encode_value},
        rop::writer::RopResponse,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyResponse;

impl RopResponse for EmptyResponse {
    fn encode(&self, _out: &mut Vec<u8>) {}

    fn encoded_len_hint(&self) -> usize {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyProblem {
    pub index: u16,
    pub tag: PropTag,
    pub error: ErrorCode,
}

impl PropertyProblem {
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.index);
        out.put_u32(self.tag.0);
        out.put_u32(self.error.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TaggedValue<'x> {
    pub tag: PropTag,
    pub value: PropValue<'x>,
}

impl TaggedValue<'_> {
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.tag.0);
        encode_value(out, &self.value, CountWidth::Rop);
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/rop/responses/tests.rs"]
mod tests;
