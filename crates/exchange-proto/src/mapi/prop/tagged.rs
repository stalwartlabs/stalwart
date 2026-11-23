/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    codec::{ValueMode, decode_value_in, encode_value_in, wire_type},
    tag::PropTag,
    value::{CountWidth, PropValue},
};
use crate::{
    common::LeReader,
    mapi::{emsmdb::MapiLimits, rop::RopDecodeError},
};

const VALIDATED: MapiLimits = MapiLimits {
    mv_count_max: u32::MAX,
    restriction_depth: u8::MAX,
    ..MapiLimits::DEFAULT
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggedValues<'a> {
    bytes: &'a [u8],
    count: u32,
    mode: ValueMode,
}

impl<'a> TaggedValues<'a> {
    pub fn decode(
        r: &mut LeReader<'a>,
        count: u32,
        width: CountWidth,
        limits: &MapiLimits,
    ) -> Result<Self, RopDecodeError> {
        Self::decode_in(r, count, width.into(), limits, limits.restriction_depth)
    }

    pub(crate) fn decode_in(
        r: &mut LeReader<'a>,
        count: u32,
        mode: ValueMode,
        limits: &MapiLimits,
        depth: u8,
    ) -> Result<Self, RopDecodeError> {
        let start = r.remaining();
        let before = r.offset();
        for _ in 0..count {
            let tag = PropTag(r.u32()?);
            decode_value_in(r, wire_type(tag.type_code()), mode, limits, depth)?;
        }
        let len = r.offset().saturating_sub(before);
        Ok(TaggedValues {
            bytes: start.get(..len).unwrap_or_default(),
            count,
            mode,
        })
    }

    pub fn len(&self) -> u32 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn iter(&self) -> TaggedIter<'a> {
        TaggedIter {
            reader: LeReader::new(self.bytes),
            remaining: self.count,
            mode: self.mode,
        }
    }

    pub(crate) fn encode_in(&self, out: &mut Vec<u8>, mode: ValueMode) {
        if mode == self.mode {
            out.extend_from_slice(self.bytes);
        } else {
            for (tag, value) in self.iter() {
                out.extend_from_slice(&tag.0.to_le_bytes());
                encode_value_in(out, &value, mode);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaggedIter<'a> {
    reader: LeReader<'a>,
    remaining: u32,
    mode: ValueMode,
}

impl<'a> Iterator for TaggedIter<'a> {
    type Item = (PropTag, PropValue<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        let tag = PropTag(self.reader.u32().ok()?);
        let value = decode_value_in(
            &mut self.reader,
            wire_type(tag.type_code()),
            self.mode,
            &VALIDATED,
            u8::MAX,
        )
        .ok()?;
        Some((tag, value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, usize::try_from(self.remaining).ok())
    }
}
