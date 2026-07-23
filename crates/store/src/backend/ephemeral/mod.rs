/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod blob;
pub mod main;
pub mod read;
pub mod write;

use ahash::AHashMap;
use parking_lot::RwLock;
use std::collections::BTreeMap;

pub struct EphemeralStore {
    pub(crate) state: RwLock<EphemeralState>,
}

pub(crate) struct EphemeralState {
    pub(crate) subspaces: AHashMap<u8, BTreeMap<Vec<u8>, Vec<u8>>>,
}
