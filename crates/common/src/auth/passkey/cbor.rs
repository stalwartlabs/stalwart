/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::PasskeyError;

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const MAX_DEPTH: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CborKey<'x> {
    Int(i64),
    Text(&'x str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CborValue<'x> {
    Int(i64),
    Bytes(&'x [u8]),
    Text(&'x str),
    Other,
}

pub(super) struct CborReader<'x> {
    bytes: &'x [u8],
}

impl<'x> CborReader<'x> {
    pub(super) fn new(bytes: &'x [u8]) -> Self {
        CborReader { bytes }
    }

    pub(super) fn remaining(&self) -> &'x [u8] {
        self.bytes
    }

    fn header(&mut self) -> Result<(u8, u64), PasskeyError> {
        let (&initial, rest) = self.bytes.split_first().ok_or(PasskeyError::Cbor)?;
        let major = initial >> 5;
        let (argument, rest) = match initial & 0x1f {
            info @ 0..=23 => (u64::from(info), rest),
            24 => {
                let (&value, rest) = rest.split_first().ok_or(PasskeyError::Cbor)?;
                (u64::from(value), rest)
            }
            25 => {
                let (value, rest) = rest.split_first_chunk::<2>().ok_or(PasskeyError::Cbor)?;
                (u64::from(u16::from_be_bytes(*value)), rest)
            }
            26 => {
                let (value, rest) = rest.split_first_chunk::<4>().ok_or(PasskeyError::Cbor)?;
                (u64::from(u32::from_be_bytes(*value)), rest)
            }
            27 => {
                let (value, rest) = rest.split_first_chunk::<8>().ok_or(PasskeyError::Cbor)?;
                (u64::from_be_bytes(*value), rest)
            }
            _ => return Err(PasskeyError::Cbor),
        };
        self.bytes = rest;
        Ok((major, argument))
    }

    fn take(&mut self, len: u64) -> Result<&'x [u8], PasskeyError> {
        let len = usize::try_from(len).map_err(|_| PasskeyError::Cbor)?;
        let (value, rest) = self.bytes.split_at_checked(len).ok_or(PasskeyError::Cbor)?;
        self.bytes = rest;
        Ok(value)
    }

    fn container_len(&self, len: u64, min_item_len: usize) -> Result<usize, PasskeyError> {
        usize::try_from(len)
            .ok()
            .filter(|&len| len.saturating_mul(min_item_len) <= self.bytes.len())
            .ok_or(PasskeyError::Cbor)
    }

    pub(super) fn map(&mut self) -> Result<usize, PasskeyError> {
        match self.header()? {
            (MAJOR_MAP, len) => self.container_len(len, 2),
            _ => Err(PasskeyError::Cbor),
        }
    }

    pub(super) fn bytes(&mut self) -> Result<&'x [u8], PasskeyError> {
        match self.header()? {
            (MAJOR_BYTES, len) => self.take(len),
            _ => Err(PasskeyError::Cbor),
        }
    }

    pub(super) fn text(&mut self) -> Result<&'x str, PasskeyError> {
        match self.header()? {
            (MAJOR_TEXT, len) => {
                std::str::from_utf8(self.take(len)?).map_err(|_| PasskeyError::Cbor)
            }
            _ => Err(PasskeyError::Cbor),
        }
    }

    pub(super) fn int(&mut self) -> Result<i64, PasskeyError> {
        match self.header()? {
            (MAJOR_UNSIGNED, value) => i64::try_from(value).map_err(|_| PasskeyError::Cbor),
            (MAJOR_NEGATIVE, value) => i64::try_from(value)
                .map(|value| -1 - value)
                .map_err(|_| PasskeyError::Cbor),
            _ => Err(PasskeyError::Cbor),
        }
    }

    pub(super) fn key(&mut self) -> Result<CborKey<'x>, PasskeyError> {
        match self.value()? {
            CborValue::Int(value) => Ok(CborKey::Int(value)),
            CborValue::Text(value) => Ok(CborKey::Text(value)),
            CborValue::Bytes(_) | CborValue::Other => Err(PasskeyError::Cbor),
        }
    }

    pub(super) fn value(&mut self) -> Result<CborValue<'x>, PasskeyError> {
        match self.header()? {
            (MAJOR_UNSIGNED, value) => i64::try_from(value)
                .map(CborValue::Int)
                .map_err(|_| PasskeyError::Cbor),
            (MAJOR_NEGATIVE, value) => i64::try_from(value)
                .map(|value| CborValue::Int(-1 - value))
                .map_err(|_| PasskeyError::Cbor),
            (MAJOR_BYTES, len) => self.take(len).map(CborValue::Bytes),
            (MAJOR_TEXT, len) => std::str::from_utf8(self.take(len)?)
                .map(CborValue::Text)
                .map_err(|_| PasskeyError::Cbor),
            (major, argument) => self
                .skip_contents(major, argument, 0)
                .map(|_| CborValue::Other),
        }
    }

    pub(super) fn skip(&mut self) -> Result<&'x [u8], PasskeyError> {
        let start = self.bytes;
        self.skip_item(0)?;
        start
            .get(..start.len() - self.bytes.len())
            .ok_or(PasskeyError::Cbor)
    }

    fn skip_item(&mut self, depth: u32) -> Result<(), PasskeyError> {
        let (major, argument) = self.header()?;
        self.skip_contents(major, argument, depth)
    }

    fn skip_contents(&mut self, major: u8, argument: u64, depth: u32) -> Result<(), PasskeyError> {
        if depth > MAX_DEPTH {
            return Err(PasskeyError::Cbor);
        }
        match major {
            MAJOR_UNSIGNED | MAJOR_NEGATIVE | MAJOR_SIMPLE => Ok(()),
            MAJOR_BYTES | MAJOR_TEXT => self.take(argument).map(|_| ()),
            MAJOR_ARRAY => {
                for _ in 0..self.container_len(argument, 1)? {
                    self.skip_item(depth + 1)?;
                }
                Ok(())
            }
            MAJOR_MAP => {
                for _ in 0..self.container_len(argument, 2)? {
                    self.skip_item(depth + 1)?;
                    self.skip_item(depth + 1)?;
                }
                Ok(())
            }
            MAJOR_TAG => self.skip_item(depth + 1),
            _ => Err(PasskeyError::Cbor),
        }
    }
}
