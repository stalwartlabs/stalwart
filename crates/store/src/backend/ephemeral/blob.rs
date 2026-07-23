/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::EphemeralStore;
use crate::SUBSPACE_BLOBS;
use std::ops::Range;

impl EphemeralStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let state = self.state.read();
        Ok(state
            .subspaces
            .get(&SUBSPACE_BLOBS)
            .and_then(|m| m.get(key))
            .map(|bytes| {
                if range.start == 0 && range.end == usize::MAX {
                    bytes.clone()
                } else {
                    bytes
                        .get(range.start..std::cmp::min(bytes.len(), range.end))
                        .unwrap_or_default()
                        .to_vec()
                }
            }))
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        let mut state = self.state.write();
        state
            .subspaces
            .entry(SUBSPACE_BLOBS)
            .or_default()
            .insert(key.to_vec(), data.to_vec());
        Ok(())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        let mut state = self.state.write();
        if let Some(map) = state.subspaces.get_mut(&SUBSPACE_BLOBS) {
            map.remove(key);
        }
        Ok(true)
    }
}
