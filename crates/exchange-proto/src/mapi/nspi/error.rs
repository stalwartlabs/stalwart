/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::Truncated,
    mapi::{emsmdb::MapiLimits, http::ResponseCode, rop::RopDecodeError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NspiStatus(pub u32);

macro_rules! nspi_status {
    ($($name:ident = $value:literal, $text:literal;)*) => {
        impl NspiStatus {
            $(pub const $name: Self = NspiStatus($value);)*

            pub fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($value => Some($text),)*
                    _ => None,
                }
            }
        }
    };
}

nspi_status! {
    SUCCESS = 0x0000_0000, "Success";
    UNBIND_SUCCESS = 0x0000_0001, "UnbindSuccess";
    UNBIND_FAILURE = 0x0000_0002, "UnbindFailure";
    ERRORS_RETURNED = 0x0004_0380, "ErrorsReturned";
    GENERAL_FAILURE = 0x8000_4005, "GeneralFailure";
    NOT_SUPPORTED = 0x8004_0102, "NotSupported";
    INVALID_OBJECT = 0x8004_0108, "InvalidObject";
    OUT_OF_RESOURCES = 0x8004_010E, "OutOfResources";
    NOT_FOUND = 0x8004_010F, "NotFound";
    LOGON_FAILED = 0x8004_0111, "LogonFailed";
    TOO_COMPLEX = 0x8004_0117, "TooComplex";
    INVALID_CODEPAGE = 0x8004_011E, "InvalidCodepage";
    INVALID_LOCALE = 0x8004_011F, "InvalidLocale";
    TABLE_TOO_BIG = 0x8004_0403, "TableTooBig";
    INVALID_BOOKMARK = 0x8004_0405, "InvalidBookmark";
    ACCESS_DENIED = 0x8007_0005, "AccessDenied";
    NOT_ENOUGH_MEMORY = 0x8007_000E, "NotEnoughMemory";
    INVALID_PARAMETER = 0x8007_0057, "InvalidParameter";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NspiLimits {
    pub array_max: u32,
    pub restriction_depth: u8,
    pub mv_count_max: u32,
    pub aux_min: u32,
    pub aux_max: u32,
}

impl NspiLimits {
    pub const DEFAULT: Self = NspiLimits {
        array_max: 100_000,
        restriction_depth: MapiLimits::DEFAULT.restriction_depth,
        mv_count_max: 100_000,
        aux_min: MapiLimits::DEFAULT.aux_min,
        aux_max: MapiLimits::DEFAULT.aux_max,
    };

    pub(crate) const fn value_limits(&self) -> MapiLimits {
        MapiLimits {
            restriction_depth: self.restriction_depth,
            mv_count_max: self.mv_count_max,
            ..MapiLimits::DEFAULT
        }
    }
}

impl Default for NspiLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NspiDecodeError {
    NotNspi,
    Truncated { offset: u32 },
    BadAux,
    TooMany { offset: u32 },
    BadString { offset: u32 },
    Value(RopDecodeError),
}

const _: () = assert!(size_of::<NspiDecodeError>() <= 12);

impl NspiDecodeError {
    pub fn response_code(&self) -> ResponseCode {
        match self {
            NspiDecodeError::NotNspi => ResponseCode::InvalidRequestType,
            NspiDecodeError::Truncated { .. } | NspiDecodeError::BadAux => {
                ResponseCode::InvalidRequestBody
            }
            _ => ResponseCode::Success,
        }
    }

    pub fn status(&self) -> NspiStatus {
        match self {
            NspiDecodeError::Value(RopDecodeError::TooDeep | RopDecodeError::TooMany { .. }) => {
                NspiStatus::TOO_COMPLEX
            }
            NspiDecodeError::TooMany { .. } => NspiStatus::TABLE_TOO_BIG,
            _ => NspiStatus::INVALID_PARAMETER,
        }
    }

    pub(crate) fn at(offset: usize) -> u32 {
        u32::try_from(offset).unwrap_or(u32::MAX)
    }
}

impl From<Truncated> for NspiDecodeError {
    fn from(err: Truncated) -> Self {
        NspiDecodeError::Truncated {
            offset: Self::at(err.offset),
        }
    }
}

impl From<RopDecodeError> for NspiDecodeError {
    fn from(err: RopDecodeError) -> Self {
        match err {
            RopDecodeError::Truncated { offset } => NspiDecodeError::Truncated { offset },
            other => NspiDecodeError::Value(other),
        }
    }
}
