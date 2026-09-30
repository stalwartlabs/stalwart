/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, storage::metadata::StoredEntries};
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, assert::AssertValue, metadata::MetadataClass},
};
use trc::AddContext;
use types::collection::Collection;

#[derive(Debug, Default)]
pub struct FlaggedContainers {
    tenant_id: Option<u32>,
    entries: StoredEntries,
}

impl FlaggedContainers {
    pub async fn load(
        server: &Server,
        account_id: u32,
        collection: Collection,
        flagged: &RoaringBitmap,
    ) -> trc::Result<Self> {
        if flagged.is_empty() {
            return Ok(FlaggedContainers::default());
        }
        let entries = server
            .stored_metadata_entries(account_id, collection, flagged)
            .await
            .caused_by(trc::location!())?;
        let tenant_id = if entries.is_empty() {
            None
        } else {
            server
                .account(account_id)
                .await
                .caused_by(trc::location!())?
                .tenant_id()
        };
        Ok(FlaggedContainers { tenant_id, entries })
    }

    pub fn remove(&self, batch: &mut BatchBuilder, document_id: u32) {
        match self.entries.get(document_id) {
            Some(entry) => entry.release(batch, self.tenant_id),
            None => {
                batch
                    .with_document(document_id)
                    .assert_value(MetadataClass::Shared, AssertValue::None);
            }
        }
    }
}

#[cfg(test)]
mod tests;
