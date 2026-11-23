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

pub mod decoder;
pub mod dom;
pub mod encoder;
pub mod segments;

pub use decoder::{DecodeError, Decoder, Event, WbxmlLimits};
pub use encoder::{Encoder, NulPolicy};
pub use segments::{Part, Segments};

pub(crate) const WBXML_VERSION: u8 = 0x03;
pub(crate) const PUBLIC_ID_UNKNOWN: u8 = 0x01;
pub(crate) const CHARSET_UTF8: u32 = 106;
pub(crate) const SWITCH_PAGE: u8 = 0x00;
pub(crate) const END: u8 = 0x01;
pub(crate) const STR_I: u8 = 0x03;
pub(crate) const LITERAL: u8 = 0x04;
pub(crate) const OPAQUE: u8 = 0xC3;
pub(crate) const TAG_ID: u8 = 0x3F;
pub(crate) const TAG_CONTENT: u8 = 0x40;
pub(crate) const TAG_ATTRIBUTES: u8 = 0x80;
pub(crate) const HEADER: [u8; 4] = [WBXML_VERSION, PUBLIC_ID_UNKNOWN, 0x6A, 0x00];

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/eas/wbxml/tests.rs"]
mod tests;
