/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{EphemeralState, EphemeralStore};
use crate::Store;
use ahash::AHashMap;
use parking_lot::RwLock;
use std::sync::Arc;

impl EphemeralStore {
    pub fn open() -> Store {
        Store::Ephemeral(Arc::new(EphemeralStore {
            state: RwLock::new(EphemeralState {
                subspaces: AHashMap::new(),
            }),
        }))
    }
}
