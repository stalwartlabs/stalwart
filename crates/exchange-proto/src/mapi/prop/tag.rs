/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::codec::wire_type;
use super::value::MvType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PropId(pub u16);

impl PropId {
    pub const fn is_named(self) -> bool {
        self.0 >= 0x8000
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropType {
    Unspecified,
    Null,
    I16,
    I32,
    F32,
    F64,
    Currency,
    AppTime,
    Error,
    Bool,
    Object,
    I64,
    String8,
    Unicode,
    Time,
    Guid,
    ServerId,
    Restriction,
    RuleAction,
    Binary,
    MvI16,
    MvI32,
    MvF32,
    MvF64,
    MvCurrency,
    MvAppTime,
    MvI64,
    MvString8,
    MvUnicode,
    MvTime,
    MvGuid,
    MvBinary,
    CodePageString(u16),
    Unknown(u16),
}

const CODE_PAGE_FLAG: u16 = 0x8000;

impl PropType {
    pub const fn code(self) -> u16 {
        match self {
            PropType::Unspecified => 0x0000,
            PropType::Null => 0x0001,
            PropType::I16 => 0x0002,
            PropType::I32 => 0x0003,
            PropType::F32 => 0x0004,
            PropType::F64 => 0x0005,
            PropType::Currency => 0x0006,
            PropType::AppTime => 0x0007,
            PropType::Error => 0x000A,
            PropType::Bool => 0x000B,
            PropType::Object => 0x000D,
            PropType::I64 => 0x0014,
            PropType::String8 => 0x001E,
            PropType::Unicode => 0x001F,
            PropType::Time => 0x0040,
            PropType::Guid => 0x0048,
            PropType::ServerId => 0x00FB,
            PropType::Restriction => 0x00FD,
            PropType::RuleAction => 0x00FE,
            PropType::Binary => 0x0102,
            PropType::MvI16 => 0x1002,
            PropType::MvI32 => 0x1003,
            PropType::MvF32 => 0x1004,
            PropType::MvF64 => 0x1005,
            PropType::MvCurrency => 0x1006,
            PropType::MvAppTime => 0x1007,
            PropType::MvI64 => 0x1014,
            PropType::MvString8 => 0x101E,
            PropType::MvUnicode => 0x101F,
            PropType::MvTime => 0x1040,
            PropType::MvGuid => 0x1048,
            PropType::MvBinary => 0x1102,
            PropType::CodePageString(code_page) => CODE_PAGE_FLAG | (code_page & !CODE_PAGE_FLAG),
            PropType::Unknown(code) => code,
        }
    }

    pub const fn from_code(code: u16) -> Self {
        match code {
            0x0000 => PropType::Unspecified,
            0x0001 => PropType::Null,
            0x0002 => PropType::I16,
            0x0003 => PropType::I32,
            0x0004 => PropType::F32,
            0x0005 => PropType::F64,
            0x0006 => PropType::Currency,
            0x0007 => PropType::AppTime,
            0x000A => PropType::Error,
            0x000B => PropType::Bool,
            0x000D => PropType::Object,
            0x0014 => PropType::I64,
            0x001E => PropType::String8,
            0x001F => PropType::Unicode,
            0x0040 => PropType::Time,
            0x0048 => PropType::Guid,
            0x00FB => PropType::ServerId,
            0x00FD => PropType::Restriction,
            0x00FE => PropType::RuleAction,
            0x0102 => PropType::Binary,
            0x1002 => PropType::MvI16,
            0x1003 => PropType::MvI32,
            0x1004 => PropType::MvF32,
            0x1005 => PropType::MvF64,
            0x1006 => PropType::MvCurrency,
            0x1007 => PropType::MvAppTime,
            0x1014 => PropType::MvI64,
            0x101E => PropType::MvString8,
            0x101F => PropType::MvUnicode,
            0x1040 => PropType::MvTime,
            0x1048 => PropType::MvGuid,
            0x1102 => PropType::MvBinary,
            code if code & CODE_PAGE_FLAG != 0 => PropType::CodePageString(code & !CODE_PAGE_FLAG),
            code => PropType::Unknown(code),
        }
    }

    pub const fn mv_type(self) -> Option<MvType> {
        Some(match self {
            PropType::MvI16 => MvType::I16,
            PropType::MvI32 => MvType::I32,
            PropType::MvF32 => MvType::F32,
            PropType::MvF64 => MvType::F64,
            PropType::MvCurrency => MvType::Currency,
            PropType::MvAppTime => MvType::AppTime,
            PropType::MvI64 => MvType::I64,
            PropType::MvString8 => MvType::String8,
            PropType::MvUnicode => MvType::Unicode,
            PropType::MvTime => MvType::Time,
            PropType::MvGuid => MvType::Guid,
            PropType::MvBinary => MvType::Binary,
            _ => return None,
        })
    }

    pub const fn is_multi(self) -> bool {
        self.mv_type().is_some()
    }

    pub const fn base(self) -> Self {
        match self.mv_type() {
            Some(mv_type) => mv_type.element_type(),
            None => self,
        }
    }

    pub const fn fixed_size(self) -> Option<u8> {
        match self {
            PropType::Bool => Some(1),
            PropType::I16 => Some(2),
            PropType::I32 | PropType::F32 | PropType::Error => Some(4),
            PropType::F64
            | PropType::Currency
            | PropType::AppTime
            | PropType::I64
            | PropType::Time => Some(8),
            PropType::Guid => Some(16),
            _ => None,
        }
    }

    pub const fn storage_class(self) -> Self {
        match self {
            PropType::String8 | PropType::CodePageString(_) => PropType::Unicode,
            PropType::MvString8 => PropType::MvUnicode,
            other => other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PropTag(pub u32);

impl PropTag {
    pub const fn new(id: PropId, ptype: PropType) -> Self {
        let [id_lo, id_hi] = id.0.to_le_bytes();
        let [type_lo, type_hi] = ptype.code().to_le_bytes();
        PropTag(u32::from_le_bytes([type_lo, type_hi, id_lo, id_hi]))
    }

    pub const fn id(self) -> PropId {
        let [_, _, id_lo, id_hi] = self.0.to_le_bytes();
        PropId(u16::from_le_bytes([id_lo, id_hi]))
    }

    pub const fn type_code(self) -> u16 {
        let [type_lo, type_hi, _, _] = self.0.to_le_bytes();
        u16::from_le_bytes([type_lo, type_hi])
    }

    pub const fn ptype(self) -> PropType {
        PropType::from_code(self.type_code())
    }

    pub const fn is_multi(self) -> bool {
        self.ptype().is_multi()
    }

    pub fn has_known_type(self) -> bool {
        !matches!(wire_type(self.type_code()), PropType::Unknown(_))
    }

    pub const fn is_named(self) -> bool {
        self.id().is_named()
    }

    pub const fn with_type(self, ptype: PropType) -> Self {
        PropTag::new(self.id(), ptype)
    }
}
