/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use store::{
    IterateParams, SUBSPACE_BLOB_LINK, Serialize, SerializeInfallible, U32_LEN, U64_LEN, ValueKey,
    write::{
        AnyClass, Archiver, BatchBuilder, BlobLink, BlobOp, ValueClass, key::DeserializeBigEndian,
        now,
    },
};
use trc::AddContext;
use types::blob_hash::{BLOB_HASH_LEN, BlobHash};

const SUBSPACE_BLOB_RESERVE: u8 = b'j';

pub(crate) async fn migrate_blobs_v014(server: &Server) -> trc::Result<()> {
    let mut num_blobs = 0;
    for byte in 0..=u8::MAX {
        // Validate linked blobs
        let mut from_hash = BlobHash::default();
        let mut to_hash = BlobHash::new_max();
        from_hash.0[0] = byte;
        to_hash.0[0] = byte;
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Commit { hash: from_hash }),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::Blob(BlobOp::Link {
                hash: to_hash,
                to: BlobLink::Document,
            }),
        };

        let mut keys = Vec::new();
        server
            .store()
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, value| {
                    if key.len() == BLOB_HASH_LEN + U64_LEN + 1 {
                        let hash =
                            BlobHash::try_from_hash_slice(key.get(0..BLOB_HASH_LEN).ok_or_else(
                                || trc::Error::corrupted_key(key, value.into(), trc::location!()),
                            )?)
                            .unwrap();
                        let account_id = key.deserialize_be_u32(BLOB_HASH_LEN)?;
                        let document_id = key.deserialize_be_u32(BLOB_HASH_LEN + U32_LEN + 1)?;
                        let collection = key[BLOB_HASH_LEN + U32_LEN];

                        if account_id == u32::MAX && document_id == u32::MAX && collection == 0 {
                            keys.push((key.to_vec(), BlobOp::Commit { hash }));
                        } else if collection == u8::MAX {
                            keys.push((
                                key.to_vec(),
                                BlobOp::Link {
                                    hash,
                                    to: BlobLink::Id {
                                        id: ((account_id as u64) << 32) | document_id as u64,
                                    },
                                },
                            ));
                        }
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let mut batch = BatchBuilder::new();
        num_blobs += keys.len();
        for (key, op) in keys {
            batch
                .clear(ValueClass::Any(AnyClass {
                    subspace: SUBSPACE_BLOB_LINK,
                    key,
                }))
                .set(op, vec![]);

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
    }

    trc::event!(
        Server(trc::ServerEvent::Startup),
        Details = format!("Migrated {num_blobs} blob links")
    );

    enum OldType {
        Quota { size: u32 },
        Undelete { deleted_at: u64, size: u32 },
        Temp,
        None,
    }

    struct OldBlobEntry {
        account_id: u32,
        until: u64,
        hash: BlobHash,
        blob_type: OldType,
        old_key: Vec<u8>,
    }

    let mut entries = Vec::new();
    let now = now();
    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::Any(AnyClass {
                    subspace: SUBSPACE_BLOB_RESERVE,
                    key: vec![0u8],
                })),
                ValueKey::from(ValueClass::Any(AnyClass {
                    subspace: SUBSPACE_BLOB_RESERVE,
                    key: vec![u8::MAX; 32],
                })),
            )
            .ascending(),
            |key, value| {
                if key.len() == BLOB_HASH_LEN + U64_LEN + U32_LEN {
                    let account_id = key.deserialize_be_u32(0)?;
                    let hash = BlobHash::try_from_hash_slice(
                        key.get(U32_LEN..BLOB_HASH_LEN + U32_LEN).ok_or_else(|| {
                            trc::Error::corrupted_key(key, value.into(), trc::location!())
                        })?,
                    )
                    .unwrap();
                    let until = key.deserialize_be_u64(BLOB_HASH_LEN + U32_LEN)?;

                    let blob_type = if until > now {
                        if value.len() == U32_LEN {
                            let size = value.deserialize_be_u32(0)?;
                            if size != 0 {
                                OldType::Quota { size }
                            } else {
                                OldType::Temp
                            }
                        } else if value.len() == U64_LEN + U32_LEN + 1 {
                            let size = value.deserialize_be_u32(0)?;
                            let deleted_at = value.deserialize_be_u64(U32_LEN)?;
                            OldType::Undelete { deleted_at, size }
                        } else {
                            OldType::Temp
                        }
                    } else {
                        OldType::None
                    };

                    entries.push(OldBlobEntry {
                        account_id,
                        until,
                        hash,
                        blob_type,
                        old_key: key.to_vec(),
                    });
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let mut batch = BatchBuilder::new();
    let num_entries = entries.len();
    for entry in entries {
        batch
            .clear(ValueClass::Any(AnyClass {
                subspace: SUBSPACE_BLOB_RESERVE,
                key: entry.old_key,
            }))
            .with_account_id(entry.account_id);

        match entry.blob_type {
            OldType::Quota { size } => {
                batch
                    .set(
                        BlobOp::Link {
                            hash: entry.hash.clone(),
                            to: BlobLink::Temporary { until: entry.until },
                        },
                        vec![BlobLink::QUOTA_LINK],
                    )
                    .set(
                        BlobOp::Quota {
                            hash: entry.hash,
                            until: entry.until,
                        },
                        size.serialize(),
                    );
            }
            OldType::Undelete { deleted_at, size } => {
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                #[cfg(feature = "enterprise")]
                {
                    batch
                        .set(
                            BlobOp::Link {
                                hash: entry.hash.clone(),
                                to: BlobLink::Temporary { until: entry.until },
                            },
                            vec![BlobLink::UNDELETE_LINK],
                        )
                        .set(
                            BlobOp::Undelete {
                                hash: entry.hash,
                                until: entry.until,
                            },
                            Archiver::new(common::enterprise::undelete::DeletedItem {
                                typ: common::enterprise::undelete::DeletedItemType::Email {
                                    from: "unknown".into(),
                                    subject: "unknown".into(),
                                    received_at: deleted_at,
                                },
                                size,
                                deleted_at,
                            })
                            .serialize()
                            .caused_by(trc::location!())?,
                        );
                }

                // SPDX-SnippetEnd
            }
            OldType::Temp => {
                batch.set(
                    BlobOp::Link {
                        hash: entry.hash,
                        to: BlobLink::Temporary { until: entry.until },
                    },
                    vec![],
                );
            }
            OldType::None => (),
        }

        if batch.is_large_batch() {
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
        }
    }

    trc::event!(
        Server(trc::ServerEvent::Startup),
        Details = format!("Migrated {num_entries} temporary blob links")
    );

    if !batch.is_empty() {
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}
