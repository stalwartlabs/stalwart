/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use smallvec::SmallVec;

use super::error::RopDecodeError;
use crate::{
    common::{LeReader, Utf16Le},
    ids::{Eid, LongTermId},
    mapi::{
        emsmdb::MapiLimits,
        prop::{CountWidth, PropId, PropTag, PropertyName, TaggedValues},
        recipient::RecipientRow,
    },
};

const LONG_TERM_ID_RANGE_LEN: usize = LongTermId::LEN * 2;

fn too_many(r: &LeReader<'_>) -> RopDecodeError {
    RopDecodeError::TooMany {
        offset: RopDecodeError::at(r.offset()),
    }
}

fn fixed<'a>(r: &mut LeReader<'a>, count: usize, size: usize) -> Result<&'a [u8], RopDecodeError> {
    let len = count.checked_mul(size).ok_or_else(|| too_many(r))?;
    Ok(r.bytes(len)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropTagArrayView<'a>(&'a [u8]);

impl<'a> PropTagArrayView<'a> {
    pub fn decode(r: &mut LeReader<'a>, count: usize) -> Result<Self, RopDecodeError> {
        fixed(r, count, 4).map(PropTagArrayView)
    }

    pub fn len(&self) -> usize {
        self.0.len() / 4
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<PropTag> {
        self.0
            .as_chunks::<4>()
            .0
            .get(index)
            .map(|t| PropTag(u32::from_le_bytes(*t)))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = PropTag> + 'a {
        self.0
            .as_chunks::<4>()
            .0
            .iter()
            .map(|t| PropTag(u32::from_le_bytes(*t)))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EidArray<'a>(&'a [u8]);

impl<'a> EidArray<'a> {
    pub fn decode(r: &mut LeReader<'a>, count: usize) -> Result<Self, RopDecodeError> {
        fixed(r, count, 8).map(EidArray)
    }

    pub fn len(&self) -> usize {
        self.0.len() / 8
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Eid> + 'a {
        self.0.as_chunks::<8>().0.iter().map(|e| Eid::from_wire(*e))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropIdArray<'a>(&'a [u8]);

impl<'a> PropIdArray<'a> {
    pub fn decode(r: &mut LeReader<'a>, count: usize) -> Result<Self, RopDecodeError> {
        fixed(r, count, 2).map(PropIdArray)
    }

    pub fn len(&self) -> usize {
        self.0.len() / 2
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = PropId> + 'a {
        self.0
            .as_chunks::<2>()
            .0
            .iter()
            .map(|id| PropId(u16::from_le_bytes(*id)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongTermIdRanges<'a>(&'a [u8]);

impl<'a> LongTermIdRanges<'a> {
    pub fn decode(
        r: &mut LeReader<'a>,
        count: usize,
        _limits: &MapiLimits,
    ) -> Result<Self, RopDecodeError> {
        fixed(r, count, LONG_TERM_ID_RANGE_LEN).map(LongTermIdRanges)
    }

    pub fn len(&self) -> usize {
        self.0.len() / LONG_TERM_ID_RANGE_LEN
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Option<LongTermId>, Option<LongTermId>)> + 'a {
        self.0
            .as_chunks::<LONG_TERM_ID_RANGE_LEN>()
            .0
            .iter()
            .map(|range| {
                let (min, max) = range.split_at(LongTermId::LEN);
                (LongTermId::from_wire(min), LongTermId::from_wire(max))
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapiString<'a> {
    Unicode(Utf16Le<'a>),
    String8(&'a [u8]),
}

impl<'a> MapiString<'a> {
    pub fn decode(r: &mut LeReader<'a>, unicode: bool) -> Result<Self, RopDecodeError> {
        Ok(if unicode {
            MapiString::Unicode(r.utf16_z()?)
        } else {
            MapiString::String8(r.ascii_z()?)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyNameList<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> PropertyNameList<'a> {
    pub fn decode(
        r: &mut LeReader<'a>,
        count: usize,
        _limits: &MapiLimits,
    ) -> Result<Self, RopDecodeError> {
        let start = r.remaining();
        let before = r.offset();
        for _ in 0..count {
            PropertyName::decode(r)?;
        }
        let len = r.offset().saturating_sub(before);
        Ok(PropertyNameList {
            bytes: start.get(..len).unwrap_or_default(),
            count,
        })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = PropertyName<'a>> + 'a {
        let mut r = LeReader::new(self.bytes);
        (0..self.count).map_while(move |_| PropertyName::decode(&mut r).ok())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageReadState<'a> {
    pub message_id: &'a [u8],
    pub mark_as_read: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageReadStates<'a>(&'a [u8]);

impl<'a> MessageReadStates<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, RopDecodeError> {
        let mut r = LeReader::new(bytes);
        while !r.is_empty() {
            read_state(&mut r)?;
        }
        Ok(MessageReadStates(bytes))
    }

    pub fn iter(&self) -> impl Iterator<Item = MessageReadState<'a>> + 'a {
        let mut r = LeReader::new(self.0);
        std::iter::from_fn(move || read_state(&mut r).ok())
    }
}

fn read_state<'a>(r: &mut LeReader<'a>) -> Result<MessageReadState<'a>, RopDecodeError> {
    let len = usize::from(r.u16()?);
    Ok(MessageReadState {
        message_id: r.bytes(len)?,
        mark_as_read: r.u8()? != 0,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlaggedValues<'a> {
    pub flags: u8,
    pub values: TaggedValues<'a>,
}

fn read_flagged<'a>(
    r: &mut LeReader<'a>,
    limits: &MapiLimits,
) -> Result<FlaggedValues<'a>, RopDecodeError> {
    let flags = r.u8()?;
    let count = r.u16()?;
    let values = TaggedValues::decode(r, u32::from(count), CountWidth::Rop, limits)?;
    Ok(FlaggedValues { flags, values })
}

const VALIDATED: MapiLimits = MapiLimits {
    mv_count_max: u32::MAX,
    restriction_depth: u8::MAX,
    ..MapiLimits::DEFAULT
};

macro_rules! flagged_list {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name<'a> {
            bytes: &'a [u8],
            count: usize,
        }

        impl<'a> $name<'a> {
            pub fn decode(
                r: &mut LeReader<'a>,
                count: usize,
                limits: &MapiLimits,
            ) -> Result<Self, RopDecodeError> {
                let start = r.remaining();
                let before = r.offset();
                for _ in 0..count {
                    read_flagged(r, limits)?;
                }
                let len = r.offset().saturating_sub(before);
                Ok($name {
                    bytes: start.get(..len).unwrap_or_default(),
                    count,
                })
            }

            pub fn len(&self) -> usize {
                self.count
            }

            pub fn is_empty(&self) -> bool {
                self.count == 0
            }

            pub fn iter(&self) -> impl Iterator<Item = FlaggedValues<'a>> + 'a {
                let mut r = LeReader::new(self.bytes);
                (0..self.count).map_while(move |_| read_flagged(&mut r, &VALIDATED).ok())
            }
        }
    };
}

flagged_list!(PermissionDataList);
flagged_list!(RuleDataList);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModifyRecipientRow<'a> {
    pub row_id: u32,
    pub recipient_type: u8,
    pub row: &'a [u8],
}

impl<'a> ModifyRecipientRow<'a> {
    pub fn recipient(
        &self,
        columns: &[PropTag],
    ) -> Result<Option<RecipientRow<'a>>, RopDecodeError> {
        if self.row.is_empty() {
            return Ok(None);
        }
        let mut r = LeReader::new(self.row);
        RecipientRow::decode_with(&mut r, columns, &VALIDATED).map(Some)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModifyRecipientRows<'a> {
    bytes: &'a [u8],
    count: usize,
}

fn read_modify_row<'a>(r: &mut LeReader<'a>) -> Result<ModifyRecipientRow<'a>, RopDecodeError> {
    let row_id = r.u32()?;
    let recipient_type = r.u8()?;
    let size = usize::from(r.u16()?);
    Ok(ModifyRecipientRow {
        row_id,
        recipient_type,
        row: r.bytes(size)?,
    })
}

impl<'a> ModifyRecipientRows<'a> {
    pub fn decode(
        r: &mut LeReader<'a>,
        count: usize,
        columns: PropTagArrayView<'_>,
        limits: &MapiLimits,
    ) -> Result<Self, RopDecodeError> {
        let columns: SmallVec<[PropTag; 32]> = columns.iter().collect();
        let start = r.remaining();
        let before = r.offset();
        for _ in 0..count {
            let row = read_modify_row(r)?;
            if !row.row.is_empty() {
                let mut inner = LeReader::new(row.row);
                RecipientRow::decode_with(&mut inner, &columns, limits)?;
                if !inner.is_empty() {
                    return Err(RopDecodeError::TrailingData {
                        offset: RopDecodeError::at(r.offset()),
                    });
                }
            }
        }
        let len = r.offset().saturating_sub(before);
        Ok(ModifyRecipientRows {
            bytes: start.get(..len).unwrap_or_default(),
            count,
        })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = ModifyRecipientRow<'a>> + 'a {
        let mut r = LeReader::new(self.bytes);
        (0..self.count).map_while(move |_| read_modify_row(&mut r).ok())
    }
}
