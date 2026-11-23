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

mod encode;
mod lzfu;
mod text;

pub use encode::{RtfSource, rtf_compress, rtf_encapsulate};
pub(crate) use lzfu::crc32_update;
pub use lzfu::{RtfKind, rtf_decompress};
pub use text::{Deencapsulated, rtf_deencapsulate, rtf_to_plain};

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/rtf/tests.rs"]
mod tests;
