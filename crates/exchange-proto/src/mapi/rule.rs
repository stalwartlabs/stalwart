/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MapiLimits,
    prop::{CountWidth, PropTag, TaggedValues, codec::write_str_utf16, tags},
    rop::RopDecodeError,
};
use crate::common::LeReader;
use std::borrow::Cow;

pub const SMTP_ADDRESS_TYPE: &str = "SMTP";
const RECIPIENT_RESERVED: u8 = 0x00;
const RECIPIENT_TO: i32 = 1;
const SMTP_RECIPIENT_PROPS: u16 = 5;
const BLOCK_HEADER: usize = 9;
const SERVER_EID_OURS: u8 = 0x01;
const SERVER_EID_LEN: u16 = 21;
const STORE_EID_PLACEHOLDER: [u8; 1] = [0];
const STORE_EID_PLACEHOLDER_LEN: u16 = 1;
const SERVER_EID_UNUSED: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    Move,
    Copy,
    Reply,
    OofReply,
    DeferAction,
    Bounce,
    Forward,
    Delegate,
    Tag,
    Delete,
    MarkAsRead,
}

impl ActionType {
    pub const fn from_wire(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => ActionType::Move,
            0x02 => ActionType::Copy,
            0x03 => ActionType::Reply,
            0x04 => ActionType::OofReply,
            0x05 => ActionType::DeferAction,
            0x06 => ActionType::Bounce,
            0x07 => ActionType::Forward,
            0x08 => ActionType::Delegate,
            0x09 => ActionType::Tag,
            0x0A => ActionType::Delete,
            0x0B => ActionType::MarkAsRead,
            _ => return None,
        })
    }

    pub const fn to_wire(self) -> u8 {
        match self {
            ActionType::Move => 0x01,
            ActionType::Copy => 0x02,
            ActionType::Reply => 0x03,
            ActionType::OofReply => 0x04,
            ActionType::DeferAction => 0x05,
            ActionType::Bounce => 0x06,
            ActionType::Forward => 0x07,
            ActionType::Delegate => 0x08,
            ActionType::Tag => 0x09,
            ActionType::Delete => 0x0A,
            ActionType::MarkAsRead => 0x0B,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForwardFlavor(pub u32);

impl ForwardFlavor {
    pub const PRESERVE_SENDER: u32 = 0x01;
    pub const DO_NOT_MUNGE: u32 = 0x02;
    pub const AS_ATTACHMENT: u32 = 0x04;
    pub const TEXT_MESSAGE: u32 = 0x08;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleActions<'a> {
    blocks: &'a [u8],
    count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionBlock<'a> {
    pub kind: Option<ActionType>,
    pub flavor: u32,
    pub flags: u32,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientBlocks<'a> {
    bytes: &'a [u8],
    count: u16,
    limits: MapiLimits,
}

impl<'a> RuleActions<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, RopDecodeError> {
        let mut r = LeReader::new(bytes);
        let count = r.u16()?;
        let blocks = r.remaining();
        for _ in 0..count {
            let offset = r.offset();
            let len = usize::from(r.u16()?);
            if len < BLOCK_HEADER {
                return Err(RopDecodeError::BadValue {
                    offset: RopDecodeError::at(offset),
                });
            }
            r.skip(len)?;
        }
        if !r.is_empty() {
            return Err(RopDecodeError::TrailingData {
                offset: RopDecodeError::at(r.offset()),
            });
        }
        Ok(RuleActions { blocks, count })
    }

    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = ActionBlock<'a>> + 'a {
        let mut rest = self.blocks;
        (0..self.count).map_while(move |_| {
            let (len, tail) = rest.split_first_chunk::<2>()?;
            let (block, tail) = tail.split_at_checked(usize::from(u16::from_le_bytes(*len)))?;
            rest = tail;
            let (&kind, block) = block.split_first()?;
            let (flavor, block) = block.split_first_chunk::<4>()?;
            let (flags, data) = block.split_first_chunk::<4>()?;
            Some(ActionBlock {
                kind: ActionType::from_wire(kind),
                flavor: u32::from_le_bytes(*flavor),
                flags: u32::from_le_bytes(*flags),
                data,
            })
        })
    }
}

impl<'a> ActionBlock<'a> {
    pub fn folder_id(&self) -> Option<u64> {
        if !matches!(self.kind, Some(ActionType::Move | ActionType::Copy)) {
            return None;
        }
        let mut r = LeReader::new(self.data);
        let in_store = r.u8().ok()? != 0;
        let store_len = usize::from(r.u16().ok()?);
        r.skip(store_len).ok()?;
        let folder_len = usize::from(r.u16().ok()?);
        let folder = r.bytes(folder_len).ok()?;
        if !in_store || !r.is_empty() {
            return None;
        }
        let [SERVER_EID_OURS, rest @ ..] = folder else {
            return None;
        };
        let (fid, unused) = rest.split_first_chunk::<8>()?;
        (unused.len() == SERVER_EID_UNUSED).then(|| u64::from_le_bytes(*fid))
    }

    pub fn recipients(&self, limits: &MapiLimits) -> Result<RecipientBlocks<'a>, RopDecodeError> {
        let mut r = LeReader::new(self.data);
        let count = r.u16()?;
        let bytes = r.remaining();
        for _ in 0..count {
            r.u8()?;
            let properties = r.u16()?;
            TaggedValues::decode(&mut r, u32::from(properties), CountWidth::Rop, limits)?;
        }
        if !r.is_empty() {
            return Err(RopDecodeError::TrailingData {
                offset: RopDecodeError::at(r.offset()),
            });
        }
        Ok(RecipientBlocks {
            bytes,
            count,
            limits: *limits,
        })
    }
}

impl<'a> RecipientBlocks<'a> {
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = TaggedValues<'a>> + 'a {
        let mut r = LeReader::new(self.bytes);
        let limits = self.limits;
        (0..self.count).map_while(move |_| {
            r.u8().ok()?;
            let properties = r.u16().ok()?;
            TaggedValues::decode(&mut r, u32::from(properties), CountWidth::Rop, &limits).ok()
        })
    }
}

#[derive(Debug)]
pub struct RuleActionsWriter {
    out: Vec<u8>,
    count: u16,
    overflow: bool,
}

impl Default for RuleActionsWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleActionsWriter {
    pub fn new() -> Self {
        RuleActionsWriter {
            out: vec![0, 0],
            count: 0,
            overflow: false,
        }
    }

    pub fn move_to(&mut self, kind: ActionType, folder_id: u64) {
        self.block(kind, 0, |out| {
            out.push(1);
            out.extend_from_slice(&STORE_EID_PLACEHOLDER_LEN.to_le_bytes());
            out.extend_from_slice(&STORE_EID_PLACEHOLDER);
            out.extend_from_slice(&SERVER_EID_LEN.to_le_bytes());
            out.push(SERVER_EID_OURS);
            out.extend_from_slice(&folder_id.to_le_bytes());
            out.extend_from_slice(&[0; SERVER_EID_UNUSED]);
        });
    }

    pub fn simple(&mut self, kind: ActionType) {
        self.block(kind, 0, |_| {});
    }

    pub fn tag_i32(&mut self, tag: PropTag, value: i32) {
        self.block(ActionType::Tag, 0, |out| {
            out.extend_from_slice(&tag.0.to_le_bytes());
            out.extend_from_slice(&value.to_le_bytes());
        });
    }

    pub fn tag_strings<'x>(
        &mut self,
        tag: PropTag,
        values: impl ExactSizeIterator<Item = Cow<'x, str>>,
    ) {
        let Ok(count) = u32::try_from(values.len()) else {
            self.overflow = true;
            return;
        };
        self.block(ActionType::Tag, 0, |out| {
            out.extend_from_slice(&tag.0.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
            for value in values {
                write_str_utf16(out, &value);
            }
        });
    }

    pub fn forward_smtp<'a>(
        &mut self,
        kind: ActionType,
        flavor: ForwardFlavor,
        addresses: impl ExactSizeIterator<Item = &'a str>,
    ) {
        let Ok(count) = u16::try_from(addresses.len()) else {
            self.overflow = true;
            return;
        };
        self.block(kind, flavor.0, |out| {
            out.extend_from_slice(&count.to_le_bytes());
            for address in addresses {
                out.push(RECIPIENT_RESERVED);
                out.extend_from_slice(&SMTP_RECIPIENT_PROPS.to_le_bytes());
                for tag in [tags::DISPLAY_NAME, tags::EMAIL_ADDRESS] {
                    out.extend_from_slice(&tag.0.to_le_bytes());
                    write_str_utf16(out, address);
                }
                out.extend_from_slice(&tags::ADDRESS_TYPE.0.to_le_bytes());
                write_str_utf16(out, SMTP_ADDRESS_TYPE);
                out.extend_from_slice(&tags::RECIPIENT_TYPE.0.to_le_bytes());
                out.extend_from_slice(&RECIPIENT_TO.to_le_bytes());
                out.extend_from_slice(&tags::SMTP_ADDRESS.0.to_le_bytes());
                write_str_utf16(out, address);
            }
        });
    }

    fn block(&mut self, kind: ActionType, flavor: u32, data: impl FnOnce(&mut Vec<u8>)) {
        let start = self.out.len();
        self.out.extend_from_slice(&[0, 0, kind.to_wire()]);
        self.out.extend_from_slice(&flavor.to_le_bytes());
        self.out.extend_from_slice(&0u32.to_le_bytes());
        data(&mut self.out);
        let body = start.saturating_add(2);
        match (
            u16::try_from(self.out.len().saturating_sub(body)),
            self.count.checked_add(1),
        ) {
            (Ok(len), Some(count)) => {
                if let Some(prefix) = self.out.get_mut(start..body) {
                    prefix.copy_from_slice(&len.to_le_bytes());
                }
                self.count = count;
            }
            _ => {
                self.out.truncate(start);
                self.overflow = true;
            }
        }
    }

    pub fn finish(mut self) -> Option<Vec<u8>> {
        if self.overflow {
            return None;
        }
        if let Some(prefix) = self.out.get_mut(..2) {
            prefix.copy_from_slice(&self.count.to_le_bytes());
        }
        Some(self.out)
    }
}
