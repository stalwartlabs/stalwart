/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod cleanup;
mod stage;

use crate::task_manager::outcome::Outcome;
use cleanup::{GranteeCleanup, Purge};
use common::Server;
use email::mailbox::Mailbox;
use groupware::{calendar::Calendar, contact::AddressBook, file::FileNode};
use registry::schema::structs::TaskShareRevokeCleanup;
use std::iter;
use store::{
    ValueKey,
    query::acl::AclQuery,
    rkyv::vec::ArchivedVec,
    write::{Archive, ArchiveBytes, assert::AssertValue},
};
use trc::{AddContext, EventType, StoreEvent};
use types::{acl::ArchivedAclGrant, collection::Collection, id::Id};

pub(crate) trait GranteeCleanupTask: Sync + Send {
    fn remove_grantee_references(
        &self,
        grantee_id: u32,
        member_group_ids: &[Id],
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn share_revoke_cleanup(
        &self,
        task: &TaskShareRevokeCleanup,
    ) -> impl Future<Output = Outcome> + Send;

    fn revoke_cleanup(
        &self,
        task: &TaskShareRevokeCleanup,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl GranteeCleanupTask for Server {
    async fn remove_grantee_references(
        &self,
        grantee_id: u32,
        member_group_ids: &[Id],
    ) -> trc::Result<()> {
        let mut items = Vec::new();
        for account_id in iter::once(grantee_id).chain(
            member_group_ids
                .iter()
                .map(|id| id.document_id())
                .filter(|group_id| *group_id != grantee_id),
        ) {
            items.extend(
                self.store()
                    .acl_query(AclQuery::HasAccess {
                        grant_account_id: account_id,
                    })
                    .await
                    .caused_by(trc::location!())?
                    .into_iter()
                    .filter(|item| item.to_account_id != grantee_id)
                    .map(|item| (item.to_account_id, item.to_collection, item.to_document_id)),
            );
        }
        if !member_group_ids.is_empty() {
            items.sort_unstable_by_key(|(owner_id, collection, document_id)| {
                (*owner_id, *collection as u8, *document_id)
            });
            items.dedup();
        }

        for owner_items in items.chunk_by(|a, b| a.0 == b.0) {
            let Some(owner_id) = owner_items.first().map(|item| item.0) else {
                continue;
            };

            let result = match self.try_account(owner_id).await {
                Ok(Some(owner)) => {
                    GranteeCleanup::new(
                        self,
                        owner_id,
                        owner.changed_by(),
                        Purge::Grantee(grantee_id),
                    )
                    .run(
                        owner_items
                            .iter()
                            .map(|(_, collection, document_id)| (*collection, *document_id)),
                    )
                    .await
                }
                Ok(None) => Ok(()),
                Err(err) => Err(err),
            };

            if let Err(err) = result {
                skip_unless_transient(err.account_id(owner_id).caused_by(trc::location!()))?;
            }
        }

        Ok(())
    }

    async fn share_revoke_cleanup(&self, task: &TaskShareRevokeCleanup) -> Outcome {
        match self.revoke_cleanup(task).await {
            Ok(()) => Outcome::done(),
            Err(err) => {
                let outcome = if is_transient(&err) {
                    Outcome::error(&err)
                } else {
                    Outcome::fatal(err.to_string())
                };
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .caused_by(trc::location!())
                        .details("Failed to clean up revoked share")
                );
                outcome
            }
        }
    }

    async fn revoke_cleanup(&self, task: &TaskShareRevokeCleanup) -> trc::Result<()> {
        let owner_id = task.account_id.document_id();
        let document_id = task.document_id.document_id();
        let collection = task.object_type.collection();
        let Some(owner) = self
            .try_account(owner_id)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        let Some(archive) = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                owner_id,
                collection,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        GranteeCleanup::new(self, owner_id, owner.changed_by(), Purge::LostAccess)
            .with_guard(
                collection,
                document_id,
                AssertValue::Archive(archive.version),
            )
            .run(iter::once((collection, document_id)))
            .await
            .add_context(|err| err.account_id(owner_id).document_id(document_id))
    }
}

pub(crate) fn shared_acls(
    collection: Collection,
    archive: &Archive<ArchiveBytes>,
) -> trc::Result<Option<&ArchivedVec<ArchivedAclGrant>>> {
    Ok(match collection {
        Collection::Mailbox => Some(&archive.unarchive::<Mailbox>()?.acls),
        Collection::Calendar => Some(&archive.unarchive::<Calendar>()?.acls),
        Collection::AddressBook => Some(&archive.unarchive::<AddressBook>()?.acls),
        Collection::FileNode => Some(&archive.unarchive::<FileNode>()?.acls),
        _ => None,
    })
}

fn skip_unless_transient(err: trc::Error) -> trc::Result<()> {
    if is_transient(&err) {
        Err(err)
    } else {
        trc::error!(err.ctx(trc::Key::Reason, "Skipped during grantee reference cleanup"));
        Ok(())
    }
}

fn is_transient(err: &trc::Error) -> bool {
    matches!(
        err.event_type(),
        EventType::Store(
            StoreEvent::AssertValueFailed
                | StoreEvent::FoundationdbError
                | StoreEvent::MysqlError
                | StoreEvent::PostgresqlError
                | StoreEvent::RocksdbError
                | StoreEvent::SqliteError
                | StoreEvent::RedisError
                | StoreEvent::KeepError
                | StoreEvent::S3Error
                | StoreEvent::AzureError
                | StoreEvent::FilesystemError
                | StoreEvent::PoolError
                | StoreEvent::DataWrite
                | StoreEvent::DataIterate
                | StoreEvent::BlobRead
                | StoreEvent::BlobWrite
                | StoreEvent::BlobDelete
                | StoreEvent::SqlQuery
                | StoreEvent::NotConfigured
        )
    )
}
