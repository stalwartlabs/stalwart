/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::metadata::MessageData;
use common::{KV_LOCK_PURGE_ACCOUNT, Server, storage::index::ObjectIndexBuilder};
use directory::backend::internal::manage::ManageDirectory;
use groupware::calendar::storage::ItipAutoExpunge;
use std::future::Future;
use store::rand::prelude::SliceRandom;
use store::write::key::DeserializeBigEndian;
use store::write::{IndexPropertyClass, SearchIndex, TaskEpoch, TaskQueueClass, now};
use store::{IterateParams, SerializeInfallible, U32_LEN, U64_LEN, ValueKey};
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::collection::{Collection, VanishedCollection};
use types::field::{EmailField, EmailSubmissionField};

pub trait EmailDeletion: Sync + Send {
    fn emails_delete(
        &self,
        account_id: u32,
        tenant_id: Option<u32>,
        batch: &mut BatchBuilder,
        document_ids: RoaringBitmap,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

    fn purge_accounts(&self, use_roles: bool) -> impl Future<Output = ()> + Send;

    fn purge_account(&self, account_id: u32) -> impl Future<Output = ()> + Send;

    fn purge_email_submissions(
        &self,
        account_id: u32,
        hold_period: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn emails_auto_expunge(
        &self,
        account_id: u32,
        hold_period: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl EmailDeletion for Server {
    async fn emails_delete(
        &self,
        account_id: u32,
        tenant_id: Option<u32>,
        batch: &mut BatchBuilder,
        document_ids: RoaringBitmap,
    ) -> trc::Result<RoaringBitmap> {
        let mut deleted_ids = RoaringBitmap::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email);
        self.archives(
            account_id,
            Collection::Email,
            &document_ids,
            |document_id, data_| {
                // Add changes to batch
                let metadata = data_
                    .to_unarchived::<MessageData>()
                    .caused_by(trc::location!())?;
                for mailbox in metadata.inner.mailboxes.iter() {
                    batch.log_vanished_item(
                        VanishedCollection::Email,
                        (mailbox.mailbox_id.to_native(), mailbox.uid.to_native()),
                    );
                }
                batch
                    .with_document(document_id)
                    .custom(
                        ObjectIndexBuilder::<_, ()>::new()
                            .with_tenant_id(tenant_id)
                            .with_current(metadata),
                    )
                    .caused_by(trc::location!())?
                    .set(
                        ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                            index: SearchIndex::Email,
                            due: TaskEpoch::now(),
                            is_insert: false,
                        }),
                        0u64.serialize(),
                    )
                    .commit_point();

                deleted_ids.insert(document_id);

                Ok(true)
            },
        )
        .await?;

        let not_destroyed = if document_ids.len() == deleted_ids.len() {
            RoaringBitmap::new()
        } else {
            deleted_ids ^= document_ids;
            deleted_ids
        };

        Ok(not_destroyed)
    }

    async fn purge_accounts(&self, use_roles: bool) {
        if let Ok(account_ids) = self.store().principal_ids(None, None).await {
            let mut account_ids: Vec<u32> = account_ids
                .into_iter()
                .filter(|id| {
                    !use_roles
                        || self
                            .core
                            .network
                            .roles
                            .purge_accounts
                            .is_enabled_for_integer(*id)
                })
                .collect();

            // Shuffle account ids
            account_ids.shuffle(&mut store::rand::rng());

            for account_id in account_ids {
                self.purge_account(account_id).await;
            }
        }
    }

    async fn purge_account(&self, account_id: u32) {
        // Lock account
        match self
            .core
            .storage
            .lookup
            .try_lock(KV_LOCK_PURGE_ACCOUNT, &account_id.to_be_bytes(), 3600)
            .await
        {
            Ok(true) => (),
            Ok(false) => {
                trc::event!(Purge(trc::PurgeEvent::InProgress), AccountId = account_id,);
                return;
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to lock account.")
                        .account_id(account_id)
                );
                return;
            }
        }

        // Auto-expunge deleted and junk messages
        if let Some(hold_period) = self.core.jmap.mail_autoexpunge_after
            && let Err(err) = self.emails_auto_expunge(account_id, hold_period).await
        {
            trc::error!(
                err.details("Failed to auto-expunge e-mail messages.")
                    .account_id(account_id)
            );
        }

        // Auto-expunge iMIP messages
        if let Some(hold_period) = self.core.groupware.itip_inbox_auto_expunge
            && let Err(err) = self.itip_auto_expunge(account_id, hold_period).await
        {
            trc::error!(
                err.details("Failed to auto-expunge iTIP messages.")
                    .account_id(account_id)
            );
        }

        // Delete old e-mail submissions
        if let Some(hold_period) = self.core.jmap.email_submission_autoexpunge_after
            && let Err(err) = self.purge_email_submissions(account_id, hold_period).await
        {
            trc::error!(
                err.details("Failed to auto-expunge e-mail submissions.")
                    .account_id(account_id)
            );
        }

        // Purge changelogs
        if let Err(err) = self
            .delete_changes(
                account_id,
                self.core.jmap.changes_max_history,
                self.core.jmap.share_notification_max_history,
            )
            .await
        {
            trc::error!(
                err.details("Failed to purge changes.")
                    .account_id(account_id)
            );
        }

        // Delete lock
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_PURGE_ACCOUNT, &account_id.to_be_bytes())
            .await
        {
            trc::error!(err.details("Failed to delete lock.").account_id(account_id));
        }
    }

    async fn emails_auto_expunge(&self, account_id: u32, hold_period: u64) -> trc::Result<()> {
        // Filter messages by received date
        let mut destroy_ids = RoaringBitmap::new();
        let cutoff = now().saturating_sub(hold_period);
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: 0,
                        class: ValueClass::Property(EmailField::DeletedAt.into()),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: u32::MAX,
                        class: ValueClass::Property(EmailField::DeletedAt.into()),
                    },
                )
                .ascending(),
                |key, value| {
                    let deleted_at = value.deserialize_be_u64(0)?;
                    if deleted_at <= cutoff {
                        destroy_ids.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if destroy_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Purge(trc::PurgeEvent::AutoExpunge),
            Collection = Collection::Email.as_str(),
            AccountId = account_id,
            Total = destroy_ids.len(),
        );

        // Delete messages
        let mut batch = BatchBuilder::new();
        let tenant_id = self
            .store()
            .get_principal(account_id)
            .await
            .caused_by(trc::location!())?
            .and_then(|p| p.tenant());
        self.emails_delete(account_id, tenant_id, &mut batch, destroy_ids)
            .await?;
        self.commit_batch(batch).await?;
        self.notify_task_queue();

        Ok(())
    }

    async fn purge_email_submissions(&self, account_id: u32, hold_period: u64) -> trc::Result<()> {
        // Filter messages by received date
        let mut destroy_ids = Vec::new();
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::EmailSubmission.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: EmailSubmissionField::Metadata.into(),
                            value: 0,
                        }),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: u32::MAX,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: EmailSubmissionField::Metadata.into(),
                            value: now().saturating_sub(hold_period),
                        }),
                    },
                )
                .ascending()
                .no_values(),
                |key, _| {
                    destroy_ids.push((
                        key.deserialize_be_u32(key.len() - U32_LEN)?,
                        key.deserialize_be_u64(key.len() - U32_LEN - U64_LEN)?,
                    ));

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if destroy_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Purge(trc::PurgeEvent::AutoExpunge),
            Collection = Collection::EmailSubmission.as_str(),
            AccountId = account_id,
            Total = destroy_ids.len(),
        );

        // Delete messages
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::EmailSubmission);

        for (document_id, send_at) in destroy_ids {
            batch
                .with_document(document_id)
                .clear(EmailSubmissionField::Metadata)
                .clear(ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: EmailSubmissionField::Metadata.into(),
                    value: send_at,
                }))
                .commit_point();
        }

        self.commit_batch(batch).await?;

        Ok(())
    }
}
