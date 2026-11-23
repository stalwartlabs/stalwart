/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod config;
pub mod database;
pub mod error;
pub mod page;
pub mod range;
pub mod read;
pub mod transaction;
pub mod version;

pub const MAX_KEY_SIZE: usize = 10_000;
pub const MAX_VALUE_SIZE: usize = 100_000;
pub const MAX_TRANSACTION_SIZE: usize = 10_000_000;
pub const KEYSPACE_END: &[u8] = b"\xff";
