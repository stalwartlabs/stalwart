/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod abk;
pub mod arrays;
pub mod error;
pub mod minid;
pub mod stat;
pub mod tags;
pub mod verbs;

pub use abk::{AbkCell, AbkListWriter, AbkRowWriter};
pub use arrays::{AsciiStrings, BinaryArray, MidArray, PropTagList, WideStrings};
pub use error::{NspiDecodeError, NspiLimits, NspiStatus};
pub use minid::MinimalId;
pub use stat::Stat;
pub use verbs::{NspiBody, NspiRequest, parse_nspi, write_nspi_success};

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/nspi/tests.rs"]
mod tests;
