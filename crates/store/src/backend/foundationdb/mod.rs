/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use fdb::{ClusterConfig, Database};
use std::time::Duration;

mod assembly;
pub mod blob;
mod known;
pub mod main;
mod preread;
#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/foundationdb/probe.rs"]
pub mod probe;
pub mod read;
mod window;
pub mod write;

pub(crate) const MAX_VALUE_SIZE: usize = fdb::MAX_VALUE_SIZE;
pub(crate) const FDB_VALUE_TOO_LARGE: i32 = fdb::ErrorCode::VALUE_TOO_LARGE.get() as i32;
const MAX_THROTTLED_TIME: Duration = Duration::from_secs(15 * 60);

pub struct FdbStore {
    db: Database,
    cluster: ClusterConfig,
    windows: window::WindowLoad,
}

#[inline(always)]
fn into_error(error: fdb::Error) -> trc::Error {
    trc::StoreEvent::FoundationdbError
        .reason(error.message())
        .ctx(trc::Key::Code, error.code())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/foundationdb/tests.rs"]
mod tests;
