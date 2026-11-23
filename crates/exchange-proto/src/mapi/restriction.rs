/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use smallvec::SmallVec;

use super::{
    emsmdb::MapiLimits,
    prop::{
        CountWidth, PropTag, PropValue,
        codec::{ValueMode, decode_value_in, encode_value_in, read_count, wire_type, write_count},
        tagged::TaggedValues,
    },
    rop::RopDecodeError,
};
use crate::common::LeReader;

pub(crate) const AND: u8 = 0x00;
pub(crate) const OR: u8 = 0x01;
pub(crate) const NOT: u8 = 0x02;
pub(crate) const CONTENT: u8 = 0x03;
pub(crate) const PROPERTY: u8 = 0x04;
const COMPARE_PROPS: u8 = 0x05;
pub(crate) const BITMASK: u8 = 0x06;
const SIZE: u8 = 0x07;
pub(crate) const EXIST: u8 = 0x08;
pub(crate) const SUB: u8 = 0x09;
pub(crate) const COMMENT: u8 = 0x0A;
const COUNT: u8 = 0x0B;
const PRESENT: u8 = 0xFF;
const ABSENT: u8 = 0x00;
const MAX_NODES: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    Re,
    MemberOfDl,
}

impl RelOp {
    pub const fn from_wire(v: u8) -> Option<Self> {
        match v {
            0 => Some(RelOp::Lt),
            1 => Some(RelOp::Le),
            2 => Some(RelOp::Gt),
            3 => Some(RelOp::Ge),
            4 => Some(RelOp::Eq),
            5 => Some(RelOp::Ne),
            6 => Some(RelOp::Re),
            0x64 => Some(RelOp::MemberOfDl),
            _ => None,
        }
    }

    pub const fn to_wire(self) -> u8 {
        match self {
            RelOp::Lt => 0,
            RelOp::Le => 1,
            RelOp::Gt => 2,
            RelOp::Ge => 3,
            RelOp::Eq => 4,
            RelOp::Ne => 5,
            RelOp::Re => 6,
            RelOp::MemberOfDl => 0x64,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RestrictionNode<'a> {
    And(Range<u16>),
    Or(Range<u16>),
    Not(u16),
    Content {
        fuzzy: u32,
        tag: PropTag,
        value: PropValue<'a>,
    },
    Property {
        op: RelOp,
        tag: PropTag,
        value: PropValue<'a>,
    },
    CompareProps {
        op: RelOp,
        a: PropTag,
        b: PropTag,
    },
    Bitmask {
        all_set: bool,
        tag: PropTag,
        mask: u32,
    },
    Size {
        op: RelOp,
        tag: PropTag,
        size: u32,
    },
    Exist(PropTag),
    Sub {
        tag: PropTag,
        child: u16,
    },
    Comment {
        values: TaggedValues<'a>,
        child: Option<u16>,
    },
    Count {
        count: u32,
        child: u16,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Restriction<'a> {
    pub nodes: Vec<RestrictionNode<'a>>,
    pub children: Vec<u16>,
    pub root: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestrictionBytes<'a>(pub &'a [u8]);

impl<'a> RestrictionBytes<'a> {
    pub fn decode(
        &self,
        width: CountWidth,
        abk: bool,
        max_depth: u8,
    ) -> Result<Option<Restriction<'a>>, RopDecodeError> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let mode = mode_for(width, abk);
        let limits = MapiLimits {
            restriction_depth: max_depth,
            ..MapiLimits::DEFAULT
        };
        let mut builder = Builder {
            r: LeReader::new(self.0),
            mode,
            limits: &limits,
            nodes: Vec::new(),
            children: Vec::new(),
        };
        let root = builder.node(max_depth)?;
        if !builder.r.is_empty() {
            return Err(RopDecodeError::TrailingData {
                offset: RopDecodeError::at(builder.r.offset()),
            });
        }
        Ok(Some(Restriction {
            nodes: builder.nodes,
            children: builder.children,
            root,
        }))
    }
}

fn mode_for(width: CountWidth, abk: bool) -> ValueMode {
    if abk {
        ValueMode::AddressBook
    } else {
        width.into()
    }
}

struct Builder<'a, 'l> {
    r: LeReader<'a>,
    mode: ValueMode,
    limits: &'l MapiLimits,
    nodes: Vec<RestrictionNode<'a>>,
    children: Vec<u16>,
}

impl<'a> Builder<'a, '_> {
    fn push(&mut self, node: RestrictionNode<'a>) -> Result<u16, RopDecodeError> {
        let index = u16::try_from(self.nodes.len()).map_err(|_| RopDecodeError::TooMany {
            offset: RopDecodeError::at(self.r.offset()),
        })?;
        if self.nodes.len() >= MAX_NODES {
            return Err(RopDecodeError::TooMany {
                offset: RopDecodeError::at(self.r.offset()),
            });
        }
        self.nodes.push(node);
        Ok(index)
    }

    fn node(&mut self, depth: u8) -> Result<u16, RopDecodeError> {
        let child_depth = depth.checked_sub(1).ok_or(RopDecodeError::TooDeep)?;
        let offset = self.r.offset();
        let kind = self.r.u8()?;
        let node = match kind {
            AND | OR => {
                let count = read_count(&mut self.r, self.mode.width())?;
                if count > self.r.remaining().len() {
                    return Err(RopDecodeError::TooMany {
                        offset: RopDecodeError::at(offset),
                    });
                }
                let mut list: SmallVec<[u16; 8]> = SmallVec::new();
                for _ in 0..count {
                    list.push(self.node(child_depth)?);
                }
                let range = self.children_range(&list, offset)?;
                if kind == AND {
                    RestrictionNode::And(range)
                } else {
                    RestrictionNode::Or(range)
                }
            }
            NOT => RestrictionNode::Not(self.node(child_depth)?),
            CONTENT => {
                let fuzzy = self.r.u32()?;
                let tag = PropTag(self.r.u32()?);
                let value = self.tagged_value(child_depth)?;
                RestrictionNode::Content { fuzzy, tag, value }
            }
            PROPERTY => {
                let op = self.relop(offset)?;
                let tag = PropTag(self.r.u32()?);
                let value = self.tagged_value(child_depth)?;
                RestrictionNode::Property { op, tag, value }
            }
            COMPARE_PROPS => RestrictionNode::CompareProps {
                op: self.relop(offset)?,
                a: PropTag(self.r.u32()?),
                b: PropTag(self.r.u32()?),
            },
            BITMASK => {
                let all_set = match self.r.u8()? {
                    0 => false,
                    1 => true,
                    _ => {
                        return Err(RopDecodeError::BadValue {
                            offset: RopDecodeError::at(offset),
                        });
                    }
                };
                RestrictionNode::Bitmask {
                    all_set,
                    tag: PropTag(self.r.u32()?),
                    mask: self.r.u32()?,
                }
            }
            SIZE => RestrictionNode::Size {
                op: self.relop(offset)?,
                tag: PropTag(self.r.u32()?),
                size: self.r.u32()?,
            },
            EXIST => RestrictionNode::Exist(PropTag(self.r.u32()?)),
            SUB => {
                let tag = PropTag(self.r.u32()?);
                RestrictionNode::Sub {
                    tag,
                    child: self.node(child_depth)?,
                }
            }
            COMMENT => {
                let count = self.r.u8()?;
                let values = TaggedValues::decode_in(
                    &mut self.r,
                    u32::from(count),
                    self.mode,
                    self.limits,
                    child_depth,
                )?;
                let child = match self.r.u8()? {
                    0 => None,
                    _ => Some(self.node(child_depth)?),
                };
                RestrictionNode::Comment { values, child }
            }
            COUNT => {
                let count = self.r.u32()?;
                RestrictionNode::Count {
                    count,
                    child: self.node(child_depth)?,
                }
            }
            other => {
                return Err(RopDecodeError::BadKind {
                    offset: RopDecodeError::at(offset),
                    kind: other,
                });
            }
        };
        self.push(node)
    }

    fn children_range(
        &mut self,
        list: &[u16],
        offset: usize,
    ) -> Result<Range<u16>, RopDecodeError> {
        let too_many = || RopDecodeError::TooMany {
            offset: RopDecodeError::at(offset),
        };
        let start = u16::try_from(self.children.len()).map_err(|_| too_many())?;
        self.children.extend_from_slice(list);
        let end = u16::try_from(self.children.len()).map_err(|_| too_many())?;
        Ok(start..end)
    }

    fn relop(&mut self, offset: usize) -> Result<RelOp, RopDecodeError> {
        RelOp::from_wire(self.r.u8()?).ok_or(RopDecodeError::BadValue {
            offset: RopDecodeError::at(offset),
        })
    }

    fn tagged_value(&mut self, depth: u8) -> Result<PropValue<'a>, RopDecodeError> {
        if self.mode == ValueMode::AddressBook {
            let offset = self.r.offset();
            match self.r.u8()? {
                PRESENT => {}
                ABSENT => return Ok(PropValue::Null),
                _ => {
                    return Err(RopDecodeError::BadValue {
                        offset: RopDecodeError::at(offset),
                    });
                }
            }
        }
        let tag = PropTag(self.r.u32()?);
        decode_value_in(
            &mut self.r,
            wire_type(tag.type_code()),
            self.mode,
            self.limits,
            depth,
        )
    }
}

pub(crate) fn skip_restriction(
    r: &mut LeReader<'_>,
    mode: ValueMode,
    limits: &MapiLimits,
    depth: u8,
) -> Result<(), RopDecodeError> {
    let mut nodes = 0usize;
    skip_node(r, mode, limits, depth, &mut nodes)
}

fn skip_node(
    r: &mut LeReader<'_>,
    mode: ValueMode,
    limits: &MapiLimits,
    depth: u8,
    nodes: &mut usize,
) -> Result<(), RopDecodeError> {
    let child_depth = depth.checked_sub(1).ok_or(RopDecodeError::TooDeep)?;
    let offset = r.offset();
    let bad_value = || RopDecodeError::BadValue {
        offset: RopDecodeError::at(offset),
    };
    match r.u8()? {
        AND | OR => {
            let count = read_count(r, mode.width())?;
            if count > r.remaining().len() {
                return Err(RopDecodeError::TooMany {
                    offset: RopDecodeError::at(offset),
                });
            }
            for _ in 0..count {
                skip_node(r, mode, limits, child_depth, nodes)?;
            }
        }
        NOT => skip_node(r, mode, limits, child_depth, nodes)?,
        kind @ (CONTENT | PROPERTY) => {
            if kind == CONTENT {
                r.skip(4)?;
            } else {
                RelOp::from_wire(r.u8()?).ok_or_else(bad_value)?;
            }
            r.skip(4)?;
            let present = match mode {
                ValueMode::AddressBook => {
                    let at = r.offset();
                    match r.u8()? {
                        PRESENT => true,
                        ABSENT => false,
                        _ => {
                            return Err(RopDecodeError::BadValue {
                                offset: RopDecodeError::at(at),
                            });
                        }
                    }
                }
                ValueMode::Rop | ValueMode::Wide => true,
            };
            if present {
                let tag = PropTag(r.u32()?);
                decode_value_in(r, wire_type(tag.type_code()), mode, limits, child_depth)?;
            }
        }
        COMPARE_PROPS | SIZE => {
            RelOp::from_wire(r.u8()?).ok_or_else(bad_value)?;
            r.skip(8)?;
        }
        BITMASK => {
            if r.u8()? > 1 {
                return Err(bad_value());
            }
            r.skip(8)?;
        }
        EXIST => r.skip(4)?,
        SUB | COUNT => {
            r.skip(4)?;
            skip_node(r, mode, limits, child_depth, nodes)?;
        }
        COMMENT => {
            let count = r.u8()?;
            TaggedValues::decode_in(r, u32::from(count), mode, limits, child_depth)?;
            if r.u8()? != 0 {
                skip_node(r, mode, limits, child_depth, nodes)?;
            }
        }
        other => {
            return Err(RopDecodeError::BadKind {
                offset: RopDecodeError::at(offset),
                kind: other,
            });
        }
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_NODES {
        return Err(RopDecodeError::TooMany {
            offset: RopDecodeError::at(offset),
        });
    }
    Ok(())
}

impl Restriction<'_> {
    pub fn encode(&self, out: &mut Vec<u8>, width: CountWidth) {
        self.encode_node(out, self.root, mode_for(width, false), u8::MAX);
    }

    pub fn encode_abk(&self, out: &mut Vec<u8>) {
        self.encode_node(out, self.root, ValueMode::AddressBook, u8::MAX);
    }

    fn encode_node(&self, out: &mut Vec<u8>, index: u16, mode: ValueMode, depth: u8) {
        let (Some(node), Some(child_depth)) =
            (self.nodes.get(usize::from(index)), depth.checked_sub(1))
        else {
            return;
        };
        match node {
            RestrictionNode::And(range) | RestrictionNode::Or(range) => {
                out.push(if matches!(node, RestrictionNode::And(_)) {
                    AND
                } else {
                    OR
                });
                let list = self
                    .children
                    .get(usize::from(range.start)..usize::from(range.end))
                    .unwrap_or_default();
                write_count(out, list.len(), mode.width());
                for child in list {
                    self.encode_node(out, *child, mode, child_depth);
                }
            }
            RestrictionNode::Not(child) => {
                out.push(NOT);
                self.encode_node(out, *child, mode, child_depth);
            }
            RestrictionNode::Content { fuzzy, tag, value } => {
                out.push(CONTENT);
                out.extend_from_slice(&fuzzy.to_le_bytes());
                out.extend_from_slice(&tag.0.to_le_bytes());
                write_tagged(out, *tag, value, mode);
            }
            RestrictionNode::Property { op, tag, value } => {
                out.push(PROPERTY);
                out.push(op.to_wire());
                out.extend_from_slice(&tag.0.to_le_bytes());
                write_tagged(out, *tag, value, mode);
            }
            RestrictionNode::CompareProps { op, a, b } => {
                out.push(COMPARE_PROPS);
                out.push(op.to_wire());
                out.extend_from_slice(&a.0.to_le_bytes());
                out.extend_from_slice(&b.0.to_le_bytes());
            }
            RestrictionNode::Bitmask { all_set, tag, mask } => {
                out.push(BITMASK);
                out.push(u8::from(*all_set));
                out.extend_from_slice(&tag.0.to_le_bytes());
                out.extend_from_slice(&mask.to_le_bytes());
            }
            RestrictionNode::Size { op, tag, size } => {
                out.push(SIZE);
                out.push(op.to_wire());
                out.extend_from_slice(&tag.0.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
            }
            RestrictionNode::Exist(tag) => {
                out.push(EXIST);
                out.extend_from_slice(&tag.0.to_le_bytes());
            }
            RestrictionNode::Sub { tag, child } => {
                out.push(SUB);
                out.extend_from_slice(&tag.0.to_le_bytes());
                self.encode_node(out, *child, mode, child_depth);
            }
            RestrictionNode::Comment { values, child } => {
                out.push(COMMENT);
                out.push(u8::try_from(values.len()).unwrap_or(u8::MAX));
                values.encode_in(out, mode);
                match child {
                    Some(child) => {
                        out.push(1);
                        self.encode_node(out, *child, mode, child_depth);
                    }
                    None => out.push(0),
                }
            }
            RestrictionNode::Count { count, child } => {
                out.push(COUNT);
                out.extend_from_slice(&count.to_le_bytes());
                self.encode_node(out, *child, mode, child_depth);
            }
        }
    }
}

fn write_tagged(out: &mut Vec<u8>, tag: PropTag, value: &PropValue<'_>, mode: ValueMode) {
    if mode == ValueMode::AddressBook {
        if matches!(value, PropValue::Null) {
            out.push(ABSENT);
            return;
        }
        out.push(PRESENT);
    }
    out.extend_from_slice(&tag.with_type(value.ptype()).0.to_le_bytes());
    encode_value_in(out, value, mode);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/restriction/tests.rs"]
mod tests;
