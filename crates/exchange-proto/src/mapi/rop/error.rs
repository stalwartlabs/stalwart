/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::Truncated,
    mapi::{ec::ErrorCode, prop::MvError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RopDecodeError {
    Truncated { offset: u32 },
    RopSize,
    HandleTable,
    UnknownRop(u8),
    HandleIndex(u8),
    BadType { offset: u32, ptype: u16 },
    BadValue { offset: u32 },
    BadUtf16 { offset: u32 },
    TooMany { offset: u32 },
    TooDeep,
    NameTooLong,
    BadKind { offset: u32, kind: u8 },
    TrailingData { offset: u32 },
    FrameSize { offset: u32 },
}

const _: () = assert!(size_of::<RopDecodeError>() <= 8);

impl RopDecodeError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            RopDecodeError::TooDeep | RopDecodeError::TooMany { .. } => ErrorCode::TOO_COMPLEX,
            RopDecodeError::NameTooLong => ErrorCode::INVALID_PARAM,
            _ => ErrorCode::RPC_FORMAT,
        }
    }

    pub(crate) fn at(offset: usize) -> u32 {
        u32::try_from(offset).unwrap_or(u32::MAX)
    }

    pub(crate) fn from_mv(err: MvError, offset: usize) -> Self {
        let offset = Self::at(offset);
        match err {
            MvError::Truncated => RopDecodeError::Truncated { offset },
            MvError::TooMany => RopDecodeError::TooMany { offset },
            MvError::BadHasValue => RopDecodeError::BadValue { offset },
            MvError::Utf16 => RopDecodeError::BadUtf16 { offset },
        }
    }
}

impl From<Truncated> for RopDecodeError {
    fn from(err: Truncated) -> Self {
        RopDecodeError::Truncated {
            offset: Self::at(err.offset),
        }
    }
}
