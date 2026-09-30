/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::StoredContainer;
use crate::{Server, auth::AccountCache};
use store::write::metadata::{METADATA_COMPRESS_WATERMARK, StoredMetadata};
use trc::{EventType, LimitEvent};
use types::metadata::{EncodedMetadata, MetadataEdit, STORAGE_TRAILER_CAPACITY};

impl Server {
    pub async fn has_metadata_quota(
        &self,
        account: &AccountCache,
        edit: MetadataEdit,
        previous: Option<&StoredContainer>,
        next: &EncodedMetadata,
    ) -> trc::Result<bool> {
        has_room_for(edit, previous, next, move |growth| {
            self.has_quota_for_growth(account, growth)
        })
        .await
    }

    async fn has_quota_for_growth(&self, account: &AccountCache, growth: u64) -> trc::Result<bool> {
        quota_outcome(self.has_available_quota(account, growth).await)
    }
}

async fn has_room_for<F, Fut>(
    edit: MetadataEdit,
    previous: Option<&StoredContainer>,
    next: &EncodedMetadata,
    mut has_quota: F,
) -> trc::Result<bool>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = trc::Result<bool>>,
{
    if edit == MetadataEdit::RemovalOnly && previous.is_some() {
        return Ok(true);
    }
    let previous = previous.map_or(0, |previous| u64::from(previous.size));
    let bound = (next.len() + STORAGE_TRAILER_CAPACITY) as u64;
    if bound <= previous || has_quota(bound - previous).await? {
        Ok(true)
    } else if next.len() >= METADATA_COMPRESS_WATERMARK {
        let stored = StoredMetadata::new(next.clone())?.len() as u64;
        Ok(stored <= previous || has_quota(stored - previous).await?)
    } else {
        Ok(false)
    }
}

fn quota_outcome(result: trc::Result<()>) -> trc::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(err)
            if err.matches(EventType::Limit(LimitEvent::Quota))
                || err.matches(EventType::Limit(LimitEvent::TenantQuota)) =>
        {
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests;
