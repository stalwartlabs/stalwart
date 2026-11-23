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

pub mod base64;
pub mod guid;
pub mod reader;
pub mod time;
pub mod token;
pub mod utf16;
pub mod writer;
pub mod xml;

pub use base64::{Base64Encoder, Base64Error, Base64Mode, Base64Text};
pub use guid::{Braces, Guid, HexCase};
pub use reader::{LeReader, Truncated};
pub use time::{
    EasDateForm, FileTime, LocalDateTime, Precision, SystemTime, UtcSeconds, XsDateTime,
    XsDuration, XsForm, XsZone,
};
pub use token::{TOKEN_MAX, TokenBuf};
pub use utf16::Utf16Le;
pub use writer::LeWriter;

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/common/tests.rs"]
mod tests;
