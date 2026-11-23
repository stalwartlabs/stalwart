/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::codec::Uid;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct EndpointHealth {
    token: Uid,
    state: AtomicU64,
}

impl EndpointHealth {
    pub const fn new(token: Uid) -> Self {
        Self {
            token,
            state: AtomicU64::new(0),
        }
    }

    pub const fn token(&self) -> Uid {
        self.token
    }

    pub(crate) fn get(&self, generation: u64) -> Option<bool> {
        let packed = self.state.load(Ordering::Relaxed);
        (packed >> 1 == generation).then_some(packed & 1 == 1)
    }

    pub(crate) fn set(&self, generation: u64, failed: bool) {
        self.state
            .fetch_max(generation << 1 | u64::from(failed), Ordering::Relaxed);
    }
}
