/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::destroy::destroy_subspace;
use common::{Server, manager::SPAM_TRAINER_KEY};
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{ArchivedEmail, ArchivedItem},
    },
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId},
};
use spam_filter::modules::classifier::SpamTrainer;
use store::{
    Deserialize, IterateParams, SUBSPACE_BLOB_LINK, SUBSPACE_DIRECTORY, SUBSPACE_QUOTA,
    SUBSPACE_REPORT_IN, SUBSPACE_REPORT_OUT, SUBSPACE_TASK_QUEUE, SUBSPACE_TELEMETRY_METRIC,
    SUBSPACE_TELEMETRY_SPAN, Serialize, SerializeInfallible, U32_LEN, U64_LEN,
    search::{SearchField, SearchFilter, SearchQuery},
    write::{
        AlignedBytes, AnyClass, AnyKey, Archive, Archiver, BatchBuilder, RegistryClass,
        SearchIndex, ValueClass, key::DeserializeBigEndian, now,
    },
};
use trc::AddContext;
use types::{blob::BlobId, blob_hash::BLOB_HASH_LEN};

const LEGACY_SUBSPACE_BLOB_EXTRA: u8 = b'j'; // Now SUBSPACE_DELETED_ITEMS
const LEGACY_SUBSPACE_BITMAP_ID: u8 = b'b'; // Now SUBSPACE_REGISTRY_IDX
const LEGACY_SUBSPACE_SETTINGS: u8 = b's'; // Now SUBSPACE_REGISTRY
const LEGACY_SUBSPACE_FTS_INDEX: u8 = b'g'; // Now SUBSPACE_REGISTRY_PK
const LEGACY_SUBSPACE_TELEMETRY_INDEX: u8 = b'w'; // Now SUBSPACE_SPAM_SAMPLES

pub async fn migrate_v0_16(server: &Server) -> trc::Result<()> {
    // Delete tracing index
    server
        .search_store()
        .unindex(
            SearchQuery::new(SearchIndex::Tracing)
                .with_filter(SearchFilter::lt(SearchField::Id, u64::MAX)),
        )
        .await
        .caused_by(trc::location!())?;

    // Delete old quotas
    server
        .store()
        .delete_range(
            AnyKey {
                subspace: SUBSPACE_QUOTA,
                key: vec![0x04],
            },
            AnyKey {
                subspace: SUBSPACE_QUOTA,
                key: vec![0x05],
            },
        )
        .await
        .caused_by(trc::location!())?;

    // Destroy old and incompatible subspaces
    for namespace in [
        LEGACY_SUBSPACE_BLOB_EXTRA,
        LEGACY_SUBSPACE_TELEMETRY_INDEX,
        LEGACY_SUBSPACE_SETTINGS,
        LEGACY_SUBSPACE_BITMAP_ID,
        LEGACY_SUBSPACE_FTS_INDEX,
        SUBSPACE_REPORT_IN,
        SUBSPACE_REPORT_OUT,
        SUBSPACE_DIRECTORY,
        SUBSPACE_TELEMETRY_METRIC,
        SUBSPACE_TELEMETRY_SPAN,
        SUBSPACE_TASK_QUEUE,
    ] {
        destroy_subspace(server.store(), namespace)
            .await
            .caused_by(trc::location!())?;
    }

    // Migrate blob links
    migrate_blob_links(server).await?;

    // Migrate spam model
    migrate_spam_model(server).await?;

    Ok(())
}

async fn migrate_spam_model(server: &Server) -> trc::Result<()> {
    let Some(mut trainer) = server
        .blob_store()
        .get_blob(SPAM_TRAINER_KEY, 0..usize::MAX)
        .await
        .and_then(|archive| match archive {
            Some(archive) => <Archive<AlignedBytes> as Deserialize>::deserialize(&archive)
                .and_then(|archive| archive.deserialize_untrusted::<SpamTrainer>())
                .map(Some),
            None => Ok(None),
        })
        .caused_by(trc::location!())?
    else {
        return Ok(());
    };

    if trainer.last_id == 0 {
        return Ok(());
    }

    if let Some(config) = &server.core.spam.classifier {
        trainer.reservoir.ham.total_seen = std::cmp::min(
            config.min_ham_samples + config.reservoir_capacity as u64,
            trainer.reservoir.ham.total_seen,
        );
        trainer.reservoir.spam.total_seen = std::cmp::min(
            config.min_spam_samples + config.reservoir_capacity as u64,
            trainer.reservoir.spam.total_seen,
        );
    } else {
        trainer.reservoir.ham.total_seen = std::cmp::min(
            trainer.reservoir.ham.buffer.len() as u64,
            trainer.reservoir.ham.total_seen,
        );
        trainer.reservoir.spam.total_seen = std::cmp::min(
            trainer.reservoir.spam.buffer.len() as u64,
            trainer.reservoir.spam.total_seen,
        );
    }

    trainer.reservoir.ham.buffer.clear();
    trainer.reservoir.spam.buffer.clear();
    trainer.last_id = 0;

    server
        .blob_store()
        .put_blob(
            SPAM_TRAINER_KEY,
            &Archiver::new(trainer)
                .serialize()
                .caused_by(trc::location!())?,
            server.core.email.compression,
        )
        .await
        .caused_by(trc::location!())?;

    Ok(())
}

async fn migrate_blob_links(server: &Server) -> trc::Result<()> {
    let mut delete_keys = Vec::new();
    let mut archived_items = Vec::new();
    let now = now();

    server
        .store()
        .iterate(
            IterateParams::new(
                AnyKey {
                    subspace: SUBSPACE_BLOB_LINK,
                    key: vec![0u8],
                },
                AnyKey {
                    subspace: SUBSPACE_BLOB_LINK,
                    key: vec![u8::MAX; 32],
                },
            ),
            |key, value| {
                const TEMP_LINK: usize = BLOB_HASH_LEN + U32_LEN + U64_LEN;

                const QUOTA_LINK: u8 = 0;
                const UNDELETE_LINK: u8 = 1;
                const SPAM_SAMPLE_LINK: u8 = 2;

                if key.len() == TEMP_LINK && value.len() == 1 {
                    let until = key.deserialize_be_u64(BLOB_HASH_LEN + U32_LEN)?;
                    if until > now {
                        let account_id = key.deserialize_be_u32(BLOB_HASH_LEN)?;
                        let hash = types::blob_hash::BlobHash::try_from_hash_slice(
                            key.get(0..BLOB_HASH_LEN).ok_or_else(|| {
                                trc::Error::corrupted_key(key, None, trc::location!())
                            })?,
                        )
                        .unwrap();

                        match value.first().copied() {
                            Some(UNDELETE_LINK) => {
                                archived_items.push((key.to_vec(), account_id, hash, until));
                            }
                            Some(SPAM_SAMPLE_LINK | QUOTA_LINK) => {
                                delete_keys.push(key.to_vec());
                            }
                            _ => {}
                        }
                    }
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    // Delete spam samples and quota links
    let mut batch = BatchBuilder::new();
    for key in delete_keys {
        batch.clear(ValueClass::Any(AnyClass {
            subspace: SUBSPACE_BLOB_LINK,
            key,
        }));

        if batch.is_large_batch() {
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
        }
    }
    if !batch.is_empty() {
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    // Migrate spam samples
    let mut batch = BatchBuilder::new();
    let id_gen = &server.inner.data.registry_id_gen;
    let mut last_id = 0;
    for (key, account_id, blob_hash, until) in archived_items {
        let item = ArchivedItem::Email(ArchivedEmail {
            account_id: account_id.into(),
            blob_id: BlobId::new(blob_hash.clone(), Default::default()),
            archived_until: UTCDateTime::from_timestamp(until as i64),
            archived_at: UTCDateTime::now(),
            from: "Unavailable".to_string(),
            received_at: UTCDateTime::now(),
            subject: "...".to_string(),
            size: 0,
        })
        .to_pickled_vec();
        let object_id = ObjectType::ArchivedItem.to_id();

        loop {
            let new_id = id_gen.generate();
            if new_id != last_id {
                last_id = new_id;
                break;
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        let item_id = last_id;

        batch
            .set(
                ValueClass::Any(AnyClass {
                    subspace: SUBSPACE_BLOB_LINK,
                    key,
                }),
                ObjectId::new(ObjectType::ArchivedItem, item_id.into()).serialize(),
            )
            .set(
                ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId.to_id(),
                    object_id,
                    item_id,
                    key: (account_id as u64).serialize(),
                }),
                vec![],
            )
            .set(
                ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                item,
            );

        if batch.is_large_batch() {
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
        }
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
