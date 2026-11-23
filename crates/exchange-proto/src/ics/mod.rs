/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

pub mod flags;
pub mod fx;
pub mod globset;
pub mod idset;
pub mod pcl;
pub mod state;

use crate::mapi::ec::ErrorCode;

pub use globset::{GlobSet, GlobsetError};
pub use idset::{IdSet, IdSetForm, ReplKey};
pub use pcl::{Pcl, PclOrder};
pub use state::{DeltaSummary, IcsState, InvariantViolation, StateUpload, SyncKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcsLimits {
    pub max_value_len: u32,
    pub max_mv_fixed_bytes: u32,
    pub max_mv_count: u32,
    pub max_depth: u8,
    pub max_embed_depth: u8,
    pub max_name_units: u16,
    pub max_state_len: u32,
    pub max_ranges: u32,
}

impl IcsLimits {
    pub const DEFAULT: Self = IcsLimits {
        max_value_len: 64 * 1024 * 1024,
        max_mv_fixed_bytes: 64 * 1024,
        max_mv_count: 65_536,
        max_depth: 16,
        max_embed_depth: 8,
        max_name_units: 255,
        max_state_len: 16 * 1024 * 1024,
        max_ranges: 1_000_000,
    };
}

impl Default for IcsLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FxError {
    Truncated { offset: u32 },
    Grammar { offset: u32 },
    TooLarge { offset: u32 },
    TooDeep { offset: u32 },
    BadValue { offset: u32 },
    BadName { offset: u32 },
    UnsupportedType { offset: u32 },
    Globset(GlobsetError),
    StateProperty,
    StateSequence,
    ValueOpen,
    ValueLength,
    Pcl,
}

const _: () = assert!(size_of::<FxError>() <= 8);

impl FxError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            FxError::TooLarge { .. } => ErrorCode::TOO_BIG,
            FxError::UnsupportedType { .. } => ErrorCode::NOT_SUPPORTED,
            FxError::StateProperty | FxError::StateSequence => ErrorCode::INVALID_PARAM,
            FxError::ValueOpen | FxError::ValueLength => ErrorCode::ERROR,
            FxError::Truncated { .. }
            | FxError::Grammar { .. }
            | FxError::TooDeep { .. }
            | FxError::BadValue { .. }
            | FxError::BadName { .. }
            | FxError::Globset(_)
            | FxError::Pcl => ErrorCode::RPC_FORMAT,
        }
    }
}

impl From<GlobsetError> for FxError {
    fn from(err: GlobsetError) -> Self {
        FxError::Globset(err)
    }
}

impl GlobsetError {
    pub fn error_code(&self) -> ErrorCode {
        ErrorCode::RPC_FORMAT
    }
}
