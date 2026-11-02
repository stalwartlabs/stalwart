/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod oid;
pub(crate) mod reader;
pub(crate) mod writer;

pub(crate) mod tag {
    pub(crate) const BOOLEAN: u8 = 0x01;
    pub(crate) const INTEGER: u8 = 0x02;
    pub(crate) const BIT_STRING: u8 = 0x03;
    pub(crate) const OCTET_STRING: u8 = 0x04;
    pub(crate) const NULL: u8 = 0x05;
    pub(crate) const OID: u8 = 0x06;
    pub(crate) const UTF8_STRING: u8 = 0x0C;
    pub(crate) const UTC_TIME: u8 = 0x17;
    pub(crate) const GENERALIZED_TIME: u8 = 0x18;
    pub(crate) const SEQUENCE: u8 = 0x30;
    pub(crate) const SET: u8 = 0x31;
    pub(crate) const CONSTRUCTED: u8 = 0x20;
    pub(crate) const CONTEXT: u8 = 0x80;

    pub(crate) const fn context(number: u8) -> u8 {
        CONTEXT | number
    }

    pub(crate) const fn context_constructed(number: u8) -> u8 {
        CONTEXT | CONSTRUCTED | number
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
    Truncated,
    UnexpectedTag,
    InvalidLength,
    UnsupportedTag,
    TooDeep,
    TrailingData,
    InvalidValue,
}
