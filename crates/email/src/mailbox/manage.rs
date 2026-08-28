/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::cache::MessageCacheFetch;
use common::{Server, storage::index::ObjectIndexBuilder};
use registry::schema::enums::StorageQuota;
use std::future::Future;
use store::write::BatchBuilder;
use trc::AddContext;
use types::collection::Collection;

pub trait MailboxFnc: Sync + Send {
    fn create_system_folders(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn mailbox_create_path(
        &self,
        account_id: u32,
        path: &str,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;
}

impl MailboxFnc for Server {
    async fn create_system_folders(&self, account_id: u32) -> trc::Result<()> {
        #[cfg(feature = "test_mode")]
        if account_id == 0 {
            return Ok(());
        }

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox);

        // Create mailboxes
        let mut last_document_id = ARCHIVE_ID;
        for folder in &self.core.email.default_folders {
            let document_id = match folder.special_use {
                SpecialUse::Inbox => INBOX_ID,
                SpecialUse::Trash => TRASH_ID,
                SpecialUse::Junk => JUNK_ID,
                SpecialUse::Drafts => DRAFTS_ID,
                SpecialUse::Sent => SENT_ID,
                SpecialUse::Archive => ARCHIVE_ID,
                SpecialUse::None
                | SpecialUse::Important
                | SpecialUse::Memos
                | SpecialUse::Scheduled
                | SpecialUse::Snoozed => {
                    last_document_id += 1;
                    last_document_id
                }
                SpecialUse::Shared => unreachable!(),
            };

            let mut object = Mailbox::new(folder.name.clone()).with_role(folder.special_use);
            if folder.subscribe {
                object.add_subscriber(account_id);
            }
            batch
                .with_document(document_id)
                .custom(ObjectIndexBuilder::<(), _>::new().with_changes(object))
                .caused_by(trc::location!())?;
        }

        batch.reserve_document_ids(account_id, Collection::Mailbox, last_document_id + 1);

        self.core
            .storage
            .data
            .write_batch(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    async fn mailbox_create_path(&self, account_id: u32, path: &str) -> trc::Result<Option<u32>> {
        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;

        let mut next_parent_id = 0;
        let mut create_paths = Vec::with_capacity(2);

        let mut path = path.split('/').map(|v| v.trim());
        let mut found_path = String::with_capacity(16);
        {
            while let Some(name) = path.next() {
                if !found_path.is_empty() {
                    found_path.push('/');
                }

                for ch in name.chars() {
                    for ch in ch.to_lowercase() {
                        found_path.push(ch);
                    }
                }

                if let Some(item) = cache
                    .mailboxes
                    .items
                    .iter()
                    .find(|item| item.path.to_lowercase() == found_path)
                {
                    next_parent_id = item.document_id + 1;
                } else {
                    create_paths.push(name.to_string());
                    create_paths.extend(path.map(|v| v.to_string()));
                    break;
                }
            }
        }

        // Create missing folders
        if !create_paths.is_empty() {
            if create_paths
                .iter()
                .any(|name| name.len() > self.core.email.mailbox_name_max_len)
            {
                return Ok(None);
            }

            let account = self.account(account_id).await.caused_by(trc::location!())?;
            if cache.mailboxes.items.len() + create_paths.len()
                > self.object_quota(account.object_quotas(), StorageQuota::MaxMailboxes) as usize
            {
                return Ok(None);
            }

            let mut batch = BatchBuilder::new();
            let first_slot = batch.reserve_document_ids(
                account_id,
                Collection::Mailbox,
                create_paths.len() as u32,
            );
            let last_slot = first_slot.offset(create_paths.len() - 1);
            let mut parent_slot = None;

            for (offset, name) in create_paths.into_iter().enumerate() {
                let slot = first_slot.offset(offset);
                let mut mailbox = Mailbox::new(name);
                if parent_slot.is_none() {
                    mailbox.parent_id = next_parent_id;
                }
                let builder = ObjectIndexBuilder::<(), _>::new().with_changes(mailbox);

                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Mailbox)
                    .create_document(slot)
                    .custom(match parent_slot {
                        Some(parent_slot) => builder.with_pending_id(parent_slot),
                        None => builder,
                    })
                    .caused_by(trc::location!())?;
                parent_slot = Some(slot);
            }

            let assigned_ids = self.commit_batch(batch).await.caused_by(trc::location!())?;

            return Ok(Some(assigned_ids.slot(last_slot)));
        }

        Ok(Some(next_parent_id - 1))
    }
}
