/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;

use super::tag::PropType;
use crate::{
    common::{FileTime, Guid},
    mapi::ec::ErrorCode,
};

#[derive(Debug, Clone, PartialEq)]
pub enum OwnedPropValue {
    Null,
    I16(i16),
    I32(i32),
    F32(f32),
    F64(f64),
    Currency(i64),
    AppTime(f64),
    Error(ErrorCode),
    Bool(bool),
    I64(i64),
    Time(FileTime),
    Guid(Guid),
    String8(Box<[u8]>),
    Unicode(Box<str>),
    Binary(Bytes),
    ServerId(Box<[u8]>),
    Restriction(Box<[u8]>),
    RuleAction(Box<[u8]>),
    Object,
    MvI16(Box<[i16]>),
    MvI32(Box<[i32]>),
    MvF32(Box<[f32]>),
    MvF64(Box<[f64]>),
    MvCurrency(Box<[i64]>),
    MvAppTime(Box<[f64]>),
    MvI64(Box<[i64]>),
    MvTime(Box<[FileTime]>),
    MvGuid(Box<[Guid]>),
    MvString8(Box<[Box<[u8]>]>),
    MvUnicode(Box<[Box<str>]>),
    MvBinary(Box<[Bytes]>),
}

impl OwnedPropValue {
    pub fn ptype(&self) -> PropType {
        match self {
            OwnedPropValue::Null => PropType::Null,
            OwnedPropValue::I16(_) => PropType::I16,
            OwnedPropValue::I32(_) => PropType::I32,
            OwnedPropValue::F32(_) => PropType::F32,
            OwnedPropValue::F64(_) => PropType::F64,
            OwnedPropValue::Currency(_) => PropType::Currency,
            OwnedPropValue::AppTime(_) => PropType::AppTime,
            OwnedPropValue::Error(_) => PropType::Error,
            OwnedPropValue::Bool(_) => PropType::Bool,
            OwnedPropValue::I64(_) => PropType::I64,
            OwnedPropValue::Time(_) => PropType::Time,
            OwnedPropValue::Guid(_) => PropType::Guid,
            OwnedPropValue::String8(_) => PropType::String8,
            OwnedPropValue::Unicode(_) => PropType::Unicode,
            OwnedPropValue::Binary(_) => PropType::Binary,
            OwnedPropValue::ServerId(_) => PropType::ServerId,
            OwnedPropValue::Restriction(_) => PropType::Restriction,
            OwnedPropValue::RuleAction(_) => PropType::RuleAction,
            OwnedPropValue::Object => PropType::Object,
            OwnedPropValue::MvI16(_) => PropType::MvI16,
            OwnedPropValue::MvI32(_) => PropType::MvI32,
            OwnedPropValue::MvF32(_) => PropType::MvF32,
            OwnedPropValue::MvF64(_) => PropType::MvF64,
            OwnedPropValue::MvCurrency(_) => PropType::MvCurrency,
            OwnedPropValue::MvAppTime(_) => PropType::MvAppTime,
            OwnedPropValue::MvI64(_) => PropType::MvI64,
            OwnedPropValue::MvTime(_) => PropType::MvTime,
            OwnedPropValue::MvGuid(_) => PropType::MvGuid,
            OwnedPropValue::MvString8(_) => PropType::MvString8,
            OwnedPropValue::MvUnicode(_) => PropType::MvUnicode,
            OwnedPropValue::MvBinary(_) => PropType::MvBinary,
        }
    }

    pub fn content_len(&self) -> usize {
        match self {
            OwnedPropValue::MvString8(items) => {
                items_len(items.iter().map(|item| item.len()), size_of::<u8>())
            }
            OwnedPropValue::MvUnicode(items) => {
                items_len(items.iter().map(|item| item.len()), size_of::<u16>())
            }
            OwnedPropValue::MvBinary(items) => {
                items_len(items.iter().map(|item| item.len()), size_of::<u32>())
            }
            _ => self.heap_size(),
        }
    }

    pub fn heap_size(&self) -> usize {
        match self {
            OwnedPropValue::String8(bytes)
            | OwnedPropValue::ServerId(bytes)
            | OwnedPropValue::Restriction(bytes)
            | OwnedPropValue::RuleAction(bytes) => bytes.len(),
            OwnedPropValue::Unicode(text) => text.len(),
            OwnedPropValue::Binary(bytes) => bytes.len(),
            OwnedPropValue::MvI16(items) => size_of_val::<[i16]>(items),
            OwnedPropValue::MvI32(items) => size_of_val::<[i32]>(items),
            OwnedPropValue::MvF32(items) => size_of_val::<[f32]>(items),
            OwnedPropValue::MvF64(items) | OwnedPropValue::MvAppTime(items) => {
                size_of_val::<[f64]>(items)
            }
            OwnedPropValue::MvCurrency(items) | OwnedPropValue::MvI64(items) => {
                size_of_val::<[i64]>(items)
            }
            OwnedPropValue::MvTime(items) => size_of_val::<[FileTime]>(items),
            OwnedPropValue::MvGuid(items) => size_of_val::<[Guid]>(items),
            OwnedPropValue::MvString8(items) => items
                .iter()
                .fold(size_of_val::<[Box<[u8]>]>(items), |total, item| {
                    total.saturating_add(item.len())
                }),
            OwnedPropValue::MvUnicode(items) => items
                .iter()
                .fold(size_of_val::<[Box<str>]>(items), |total, item| {
                    total.saturating_add(item.len())
                }),
            OwnedPropValue::MvBinary(items) => items
                .iter()
                .fold(size_of_val::<[Bytes]>(items), |total, item| {
                    total.saturating_add(item.len())
                }),
            _ => 0,
        }
    }
}

fn items_len(lengths: impl Iterator<Item = usize>, overhead: usize) -> usize {
    lengths.fold(0, |total, len| {
        total.saturating_add(len).saturating_add(overhead)
    })
}
