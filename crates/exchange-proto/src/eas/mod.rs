/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod commands;
pub mod http;
pub mod multipart;
pub mod status;
pub mod tokens;
pub mod types;
pub mod wbxml;

#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/eas/test_support.rs"]
pub mod test_support;

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/eas/tests.rs"]
mod tests;
