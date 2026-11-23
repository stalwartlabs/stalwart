/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{common::LeWriter, mapi::ec::ErrorCode};

macro_rules! rop_ids {
    ($($name:ident = $id:literal, $text:literal, $tier:ident, $handles:ident, $failure:ident;)*) => {
        impl RopId {
            $(pub const $name: Self = RopId($id);)*

            pub const fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($id => Some($text),)*
                    _ => None,
                }
            }

            pub const fn tier(self) -> Option<Tier> {
                match self.0 {
                    $($id => Some(Tier::$tier),)*
                    _ => None,
                }
            }

            pub const fn handles(self) -> Option<HandleRole> {
                match self.0 {
                    $($id => Some(HandleRole::$handles),)*
                    _ => None,
                }
            }

            pub const fn failure(self) -> Option<FailurePolicy> {
                match self.0 {
                    $($id => Some(FailurePolicy::$failure),)*
                    _ => None,
                }
            }
        }
    };
}

pub(crate) use rop_ids;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RopId(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    A,
    AIcs,
    B,
    C,
    D,
    ServerOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleRole {
    Input,
    Output,
    Release,
    ServerOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    HeaderOnly,
    SameBody,
    NoResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RopHeader {
    pub id: RopId,
    pub logon_id: u8,
    pub handle_index: u8,
    pub input_handle: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    pub id: RopId,
    pub handle_index: u8,
    pub return_value: ErrorCode,
}

impl ResponseHeader {
    pub const LEN: usize = 6;

    pub fn new(id: RopId, handle_index: u8, return_value: ErrorCode) -> Self {
        ResponseHeader {
            id,
            handle_index,
            return_value,
        }
    }

    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.put_u8(self.id.response_id().0);
        out.put_u8(self.handle_index);
        out.put_u32(self.return_value.0);
    }
}

impl RopId {
    pub const fn response_id(self) -> RopId {
        if self.0 == RopId::GET_MESSAGE_STATUS.0 {
            RopId::SET_MESSAGE_STATUS
        } else {
            self
        }
    }

    pub const fn is_reserved(self) -> bool {
        self.name().is_none()
    }
}
