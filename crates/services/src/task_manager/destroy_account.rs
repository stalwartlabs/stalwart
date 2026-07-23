/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::TaskResult;
use common::Server;
use email::{message::metadata::MessageMetadata, sieve::SieveScript};
use groupware::file::FileNode;
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{ArchivedItem, TaskDestroyAccount},
    },
    types::EnumImpl,
};
use store::{
    SerializeInfallible, ValueKey,
    registry::RegistryQuery,
    search::SearchQuery,
    write::{BatchBuilder, BlobLink, BlobOp, RegistryClass, SearchIndex, ValueClass},
};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    collection::Collection,
    field::{EmailField, Field},
    id::Id,
};

pub(crate) trait DestroyAccountTask: Sync + Send {
    fn destroy_account(&self, task: &TaskDestroyAccount)
    -> impl Future<Output = TaskResult> + Send;
}

impl DestroyAccountTask for Server {
    async fn destroy_account(&self, task: &TaskDestroyAccount) -> TaskResult {
        match destroy_account(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .details("Failed to destroy account")
                );
                result
            }
        }
    }
}

async fn destroy_account(server: &Server, task: &TaskDestroyAccount) -> trc::Result<TaskResult> {
    let account_id = task.account_id.document_id();

    // Destroy public keys and masked emails
    for object in [ObjectType::PublicKey, ObjectType::MaskedEmail] {
        let mut batch = BatchBuilder::new();
        let ids = server
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(object).with_account(account_id))
            .await?;
        let object_id = object.to_id();

        for id in ids {
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
                }));
        }

        if !batch.is_empty() {
            server.store().write(batch.build_all()).await?;
        }
    }

    // Remove archived items
    let mut batch = BatchBuilder::new();
    let ids = server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::ArchivedItem).with_account(account_id))
        .await?;
    for id in ids {
        let object_id = ObjectType::ArchivedItem.to_id();
        let item_id = id.id();

        if let Some(item) = server
            .store()
            .get_value::<ArchivedItem>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id,
            })))
            .await?
        {
            let until = item.archived_until().timestamp() as u64;
            let blob_hash = item.into_blob_id().hash;

            batch
                .with_account_id(account_id)
                .clear(BlobOp::Link {
                    hash: blob_hash,
                    to: BlobLink::Temporary { until },
                })
                .clear(ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId.to_id(),
                    object_id,
                    item_id,
                    key: (account_id as u64).serialize(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id,
                }));
        }
    }
    if !batch.is_empty() {
        server.store().write(batch.build_all()).await?;
    }

    // Remove search index
    for index in [
        SearchIndex::Email,
        SearchIndex::Contacts,
        SearchIndex::Calendar,
    ] {
        server
            .search_store()
            .unindex(SearchQuery::new(index).with_account_id(account_id))
            .await?;
    }

    // Unlink all accounts's blobs
    destroy_account_blobs(server, account_id).await?;

    // Destroy account data
    server
        .store()
        .danger_destroy_account(account_id)
        .await
        .caused_by(trc::location!())?;

    Ok(TaskResult::Success(vec![]))
}

pub async fn destroy_account_blobs(server: &Server, account_id: u32) -> trc::Result<()> {
    let mut delete_keys = Vec::new();
    for (collection, field) in [
        (Collection::Email, u8::from(EmailField::Metadata)),
        (Collection::FileNode, u8::from(Field::ARCHIVE)),
        (Collection::SieveScript, u8::from(Field::ARCHIVE)),
    ] {
        server
            .all_archives(account_id, collection, field, |document_id, archive| {
                match collection {
                    Collection::Email => {
                        let message = archive.unarchive::<MessageMetadata>()?;
                        delete_keys.push((
                            collection,
                            document_id,
                            BlobHash::from(&message.blob_hash),
                        ));
                    }
                    Collection::FileNode => {
                        if let Some(file) = archive.unarchive::<FileNode>()?.file.as_ref() {
                            delete_keys.push((
                                collection,
                                document_id,
                                BlobHash::from(&file.blob_hash),
                            ));
                        }
                    }
                    Collection::SieveScript => {
                        let sieve = archive.unarchive::<SieveScript>()?;
                        delete_keys.push((
                            collection,
                            document_id,
                            BlobHash::from(&sieve.blob_hash),
                        ));
                    }
                    _ => {}
                }
                Ok(())
            })
            .await
            .caused_by(trc::location!())?;
    }

    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id);

    for (collection, document_id, hash) in delete_keys {
        if batch.is_large_batch() {
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
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

    if !batch.is_empty() {
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}
