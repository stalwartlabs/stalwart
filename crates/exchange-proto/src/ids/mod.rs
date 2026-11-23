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

pub mod eas;
pub mod eid;
pub mod entryid;
pub mod essdn;
pub mod ews;
pub mod mid;
pub mod token;
pub mod xid;

pub use eid::{Cn, Eid, Fid, Gid, Globcnt, LongTermId, Mid, ReplGuid, ReplId};
pub use xid::Xid;

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ids/tests.rs"]
mod tests;
