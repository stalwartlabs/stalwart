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

pub mod aux_buffer;
pub mod ec;
pub mod emsmdb;
pub mod error;
pub mod http;
#[cfg(feature = "convert")]
pub mod junk_rule;
pub mod lzxpress;
pub mod notify;
pub mod nspi;
pub mod prop;
pub mod recipient;
pub mod restriction;
pub mod rop;
pub mod rpc_ext;
pub mod rule;
pub mod rule_logic;
pub mod sort;
pub mod stream;

pub use ec::{ErrorCode, StatusCode};
pub use emsmdb::MapiLimits;
pub use error::{BodyError, HeaderError, HeaderKind};
pub use http::{Endpoint, RequestType, ResponseCode};
