/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::Truncated;

use super::{
    ec::{ErrorCode, StatusCode},
    http::ResponseCode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    RequestType,
    RequestId,
    ClientInfo,
    ClientApplication,
    ContentType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    Missing(HeaderKind),
    Invalid(HeaderKind),
    UnknownRequestType,
}

impl HeaderError {
    pub fn response_code(&self) -> ResponseCode {
        match self {
            HeaderError::Missing(_) => ResponseCode::MissingHeader,
            HeaderError::Invalid(_) => ResponseCode::InvalidHeader,
            HeaderError::UnknownRequestType => ResponseCode::InvalidRequestType,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    Truncated { offset: u32 },
    TrailingData { offset: u32 },
    RopBufferTooLarge,
    RopBufferTooShort,
    MaxRopOutTooSmall,
    MaxRopOutTooLarge,
    AuxTooShort,
    AuxTooLarge,
    BadExtHeader,
    NotLastBuffer,
    SizeMismatch,
    DecompressedTooLarge,
    Lz77Corrupt,
    BadAuxBlock { offset: u32 },
    BadMetaStream,
}

impl BodyError {
    pub fn response_code(&self) -> ResponseCode {
        match self {
            BodyError::Truncated { .. }
            | BodyError::TrailingData { .. }
            | BodyError::BadMetaStream => ResponseCode::InvalidRequestBody,
            _ => ResponseCode::Success,
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            BodyError::RopBufferTooLarge
            | BodyError::MaxRopOutTooLarge
            | BodyError::AuxTooLarge => StatusCode::BAD_STUB_DATA,
            _ => StatusCode::OK,
        }
    }

    pub fn error_code(&self) -> ErrorCode {
        match self {
            BodyError::RopBufferTooShort
            | BodyError::MaxRopOutTooSmall
            | BodyError::AuxTooShort => ErrorCode::RPC_FAILED,
            _ => ErrorCode::RPC_FORMAT,
        }
    }
}

impl From<Truncated> for BodyError {
    fn from(err: Truncated) -> Self {
        BodyError::Truncated {
            offset: u32::try_from(err.offset).unwrap_or(u32::MAX),
        }
    }
}

const _: () = assert!(size_of::<BodyError>() <= 8);
