/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod kv;
pub mod read;
pub mod transform;
mod uid;
pub mod write;

pub use read::DecodeError;
pub use uid::Uid;

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/codec/tests.rs"]
mod tests;
