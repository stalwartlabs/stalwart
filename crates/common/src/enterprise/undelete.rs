/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::Core;
use store::{
    Deserialize, IterateParams, U32_LEN, U64_LEN, ValueKey,
    write::{AlignedBytes, Archive, BlobOp, ValueClass, key::DeserializeBigEndian, now},
};
use trc::AddContext;
use types::blob_hash::{BLOB_HASH_LEN, BlobHash};

pub struct DeletedBlob {
    pub hash: BlobHash,
    pub expires_at: u64,
    pub item: DeletedItem,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DeletedItem {
    pub typ: DeletedItemType,
    pub size: u32,
    pub deleted_at: u64,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum DeletedItemType {
    Email {
        from: Box<str>,
        subject: Box<str>,
        received_at: u64,
    },
    FileNode {
        name: Box<str>,
    },
    CalendarEvent {
        title: Box<str>,
        start_time: u64,
    },
    ContactCard {
        name: Box<str>,
    },
    SieveScript {
        name: Box<str>,
    },
}

impl Core {
    pub async fn list_deleted(&self, account_id: u32) -> trc::Result<Vec<DeletedBlob>> {
        let from_key = ValueKey {
            account_id,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Undelete {
                hash: BlobHash::default(),
                until: 0,
            }),
        };
        let to_key = ValueKey {
            account_id,
            collection: 0,
            document_id: u32::MAX,
            class: ValueClass::Blob(BlobOp::Undelete {
                hash: BlobHash::new_max(),
                until: u64::MAX,
            }),
        };

        let now = now();
        let mut results = Vec::new();

        self.storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let expires_at = key.deserialize_be_u64(key.len() - U64_LEN)?;
                    if expires_at > now {
                        let item = <Archive<AlignedBytes> as Deserialize>::deserialize(value)
                            .and_then(|bytes| bytes.deserialize::<DeletedItem>())
                            .add_context(|ctx| ctx.ctx(trc::Key::Key, key))?;

                        results.push(DeletedBlob {
                            hash: BlobHash::try_from_hash_slice(
                                key.get(U32_LEN + 1..U32_LEN + 1 + BLOB_HASH_LEN)
                                    .ok_or_else(|| {
                                        trc::Error::corrupted_key(
                                            key,
                                            value.into(),
                                            trc::location!(),
                                        )
                                    })?,
                            )
                            .unwrap(),
                            expires_at,
                            item,
                        });
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        Ok(results)
    }
}
