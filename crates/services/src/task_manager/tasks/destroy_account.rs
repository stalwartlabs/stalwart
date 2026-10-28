/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::{outcome::Outcome, tasks::grantee_cleanup::GranteeCleanupTask};
use common::{Server, cache::invalidate::CacheInvalidationBuilder, ipc::CacheInvalidation};
use email::{message::metadata::MetadataStructure, sieve::SieveScript};
use groupware::file::FileNode;
use registry::{
    schema::{
        enums::TaskAccountMaintenanceType,
        prelude::{ObjectType, Property},
        structs::{Task, TaskAccountMaintenance, TaskDestroyAccount, TaskStatus},
    },
    types::{EnumImpl, id::ObjectId},
};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use registry::schema::structs::ArchivedItem;
#[cfg(feature = "enterprise")]
use store::{Deserialize, IterateParams, U64_LEN};
// SPDX-SnippetEnd
use store::{
    SerializeInfallible, ValueKey,
    registry::{
        RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    search::SearchQuery,
    write::{
        Archive, ArchiveBytes, BatchBuilder, BlobLink, BlobOp, RegistryClass, SearchIndex,
        ValueClass,
    },
};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    collection::Collection,
    field::{EmailField, Field},
    id::Id,
};

const DESTROY_WINDOW: usize = 5_000;

pub(crate) trait DestroyAccountTask: Sync + Send {
    fn destroy_account(&self, task: &TaskDestroyAccount) -> impl Future<Output = Outcome> + Send;
}

impl DestroyAccountTask for Server {
    async fn destroy_account(&self, task: &TaskDestroyAccount) -> Outcome {
        match destroy_account(self, task).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let result = Outcome::error(&err);
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .details("Failed to destroy account")
                );
                result
            }
        }
    }
}

async fn destroy_account(server: &Server, task: &TaskDestroyAccount) -> trc::Result<Outcome> {
    let account_id = task.account_id.document_id();

    if server
        .store()
        .key_exists(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::Account.to_id(),
            item_id: account_id as u64,
        })))
        .await
        .caused_by(trc::location!())?
    {
        return Ok(Outcome::Done(vec![Task::AccountMaintenance(
            TaskAccountMaintenance {
                account_id: task.account_id,
                maintenance_type: TaskAccountMaintenanceType::RebuildShares,
                status: TaskStatus::now(),
            },
        )]));
    }

    server
        .remove_grantee_references(account_id, task.member_group_ids.as_slice())
        .await
        .caused_by(trc::location!())?;

    // Destroy public keys, masked emails and OAuth grants
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let objects = [
        ObjectType::PublicKey,
        ObjectType::MaskedEmail,
        ObjectType::OAuthGrant,
    ];
    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    let objects = [ObjectType::PublicKey, ObjectType::OAuthGrant];
    for object in objects {
        let mut batch = BatchBuilder::new();
        let ids = server
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(object).with_account(account_id))
            .await?;
        let object_id = object.to_id();

        for id in ids {
            if object == ObjectType::OAuthGrant {
                match server
                    .registry()
                    .write(RegistryWrite::delete(ObjectId::new(object, id)))
                    .await
                {
                    Ok(RegistryWriteResult::Success(_)) => continue,
                    Ok(_) => {}
                    Err(err) => {
                        trc::error!(
                            err.caused_by(trc::location!())
                                .account_id(account_id)
                                .id(id.id())
                                .details(
                                    "Failed to delete OAuth grant, clearing its account index only"
                                )
                        );
                    }
                }
            }
            batch
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id: id.id(),
                }))
                .clear(ValueClass::Registry(RegistryClass::IndexId {
                    object_id,
                    item_id: id.id(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId as u16,
                    object_id,
                    item_id: id.id(),
                    key: (account_id as u64).serialize(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Reference {
                    to_object_id: ObjectType::Account as u16,
                    to_item_id: account_id as u64,
                    from_object_id: object_id,
                    from_item_id: id.id(),
                }))
                .bulk_commit_point();
        }

        if !batch.is_empty() {
            server.store().write_batch(&mut batch).await?;
        }
    }

    // Remove archived items
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    {
        let object_id = ObjectType::ArchivedItem.to_id();
        let ids = server
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::ArchivedItem).with_account(account_id))
            .await?;
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        let account_key = (account_id as u64).serialize();
        server
            .store()
            .iterate_many(
                ids.iter()
                    .map(|id| {
                        let key = ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                            object_id,
                            item_id: id.id(),
                        }));
                        IterateParams::new(key.clone(), key)
                    })
                    .collect(),
                |key, value| {
                    let item_id = key
                        .last_chunk::<U64_LEN>()
                        .map(|item_id| u64::from_be_bytes(*item_id))
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                    let item = ArchivedItem::deserialize(value)?;
                    let until = item.archived_until().timestamp() as u64;

                    batch
                        .clear(BlobOp::Link {
                            hash: item.into_blob_id().hash,
                            to: BlobLink::Temporary { until },
                        })
                        .clear(ValueClass::Registry(RegistryClass::Index {
                            index_id: Property::AccountId.to_id(),
                            object_id,
                            item_id,
                            key: account_key.clone(),
                        }))
                        .clear(ValueClass::Registry(RegistryClass::Item {
                            object_id,
                            item_id,
                        }))
                        .bulk_commit_point();
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
        if !batch.is_empty() {
            server.store().write_batch(&mut batch).await?;
        }
    }
    // SPDX-SnippetEnd

    // Remove search index
    for index in [
        SearchIndex::Email,
        SearchIndex::Contacts,
        SearchIndex::Calendar,
        SearchIndex::File,
    ] {
        if let Some(store) = server.search_store().internal_fts() {
            store.unindex_account(index, account_id).await?;
        } else {
            server
                .search_store()
                .unindex(SearchQuery::new(index).with_account_id(account_id))
                .await?;
        }

        server
            .store()
            .clear_search_index_queue(index, account_id)
            .await?;
    }

    // Unlink all accounts's blobs
    destroy_account_blobs(server, account_id).await?;

    server
        .destroy_viewer_metadata(account_id)
        .await
        .caused_by(trc::location!())?;
    server
        .destroy_owner_metadata(account_id)
        .await
        .caused_by(trc::location!())?;

    // Drop the resident caches and the writer's pending state on every node
    server
        .invalidate_caches(
            CacheInvalidationBuilder::from(CacheInvalidation::MessageCache(account_id))
                .with_invalidation(CacheInvalidation::GroupwareResources(account_id))
                .with_invalidation(CacheInvalidation::PrivateMetadata(account_id)),
        )
        .await?;
    server.inner.cache.swap.forget(account_id);

    // Remove persisted cache snapshots
    server.inner.cache.swap.remove_account(account_id).await;

    // Destroy account data
    server
        .store()
        .danger_destroy_account(account_id)
        .await
        .caused_by(trc::location!())?;

    Ok(Outcome::done())
}

pub async fn destroy_account_blobs(server: &Server, account_id: u32) -> trc::Result<()> {
    let window = server.store().is_postgresql().then_some(DESTROY_WINDOW);
    let mut links = Vec::new();
    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id);

    let class = ValueClass::Immutable(EmailField::Metadata.into());
    let mut next = Some(0);
    while let Some(from_document_id) = next {
        next = server
            .values_window(
                account_id,
                Collection::Email,
                &class,
                from_document_id,
                window,
                |document_id, structure: MetadataStructure| {
                    links.push((document_id, structure.unarchive()?.blob_hash()));
                    Ok(())
                },
            )
            .await
            .caused_by(trc::location!())?;
        clear_links(
            server,
            account_id,
            Collection::Email,
            &mut links,
            &mut batch,
        )
        .await?;
    }

    let class = ValueClass::Property(Field::ARCHIVE.into());
    for collection in [Collection::FileNode, Collection::SieveScript] {
        let mut next = Some(0);
        while let Some(from_document_id) = next {
            next = server
                .values_window(
                    account_id,
                    collection,
                    &class,
                    from_document_id,
                    window,
                    |document_id, archive: Archive<ArchiveBytes>| {
                        let blob_hash = match collection {
                            Collection::FileNode => archive
                                .unarchive::<FileNode>()?
                                .file()
                                .map(|file| BlobHash::from(&file.blob_hash)),
                            _ => Some(BlobHash::from(
                                &archive.unarchive::<SieveScript>()?.blob_hash,
                            )),
                        };
                        if let Some(blob_hash) = blob_hash {
                            links.push((document_id, blob_hash));
                        }
                        Ok(())
                    },
                )
                .await
                .caused_by(trc::location!())?;
            clear_links(server, account_id, collection, &mut links, &mut batch).await?;
        }
    }

    if !batch.is_empty() {
        server
            .store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}

async fn clear_links(
    server: &Server,
    account_id: u32,
    collection: Collection,
    links: &mut Vec<(u32, BlobHash)>,
    batch: &mut BatchBuilder,
) -> trc::Result<()> {
    for (document_id, hash) in links.drain(..) {
        if batch.is_large_bulk_batch() {
            server
                .store()
                .write_batch(batch)
                .await
                .caused_by(trc::location!())?;
            *batch = BatchBuilder::new();
            batch.with_account_id(account_id);
        }
        batch
            .with_collection(collection)
            .with_document(document_id)
            .clear(ValueClass::Blob(BlobOp::Link {
                hash,
                to: BlobLink::Document,
            }));
    }
    Ok(())
}
