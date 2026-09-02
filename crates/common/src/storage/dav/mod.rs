/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod paths;
pub mod resource;
pub mod store;

pub use store::ResourceChunkBuilder;

pub(crate) const SCHEDULE_INBOX_ID: u32 = u32::MAX - 1;
pub const CONTAINER_FLAG: u32 = 1 << 31;
