/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use super::{BlobOp, Operation, ValueClass, ValueOp, key::DeserializeBigEndian, now};
use crate::{
    BlobStore, IterateParams, Store, U32_LEN, U64_LEN, ValueKey,
    write::{BatchBuilder, BlobLink},
};
use trc::{AddContext, PurgeEvent};
use types::{
    blob::BlobClass,
    blob_hash::{BLOB_HASH_LEN, BlobHash},
};

#[derive(Debug, PartialEq, Eq)]
pub struct BlobQuota {
    pub bytes: usize,
    pub count: usize,
}

impl Store {
    pub async fn blob_exists(&self, hash: impl AsRef<BlobHash> + Sync + Send) -> trc::Result<bool> {
        self.get_value::<()>(ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Commit {
                hash: hash.as_ref().clone(),
            }),
        })
        .await
        .map(|v| v.is_some())
        .caused_by(trc::location!())
    }

    pub async fn blob_quota(&self, account_id: u32) -> trc::Result<BlobQuota> {
        let from_key = ValueKey {
            account_id,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Quota {
                hash: BlobHash::default(),
                until: 0,
            }),
        };
        let to_key = ValueKey {
            account_id: account_id + 1,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Quota {
                hash: BlobHash::default(),
                until: u64::MAX,
            }),
        };

        let now = now();
        let mut quota = BlobQuota { bytes: 0, count: 0 };

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let until = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if until > now {
                    let bytes = value.deserialize_be_u32(0)?;
                    if bytes > 0 {
                        quota.bytes += bytes as usize;
                        quota.count += 1;
                    }
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(quota)
    }

    pub async fn blob_has_access(
        &self,
        hash: impl AsRef<BlobHash> + Sync + Send,
        class: impl AsRef<BlobClass> + Sync + Send,
    ) -> trc::Result<bool> {
        let key = match class.as_ref() {
            BlobClass::Reserved {
                account_id,
                expires,
            } if *expires > now() => ValueKey {
                account_id: *account_id,
                collection: 0,
                document_id: 0,
                class: ValueClass::Blob(BlobOp::Link {
                    hash: hash.as_ref().clone(),
                    to: BlobLink::Temporary { until: *expires },
                }),
            },
            BlobClass::Linked {
                account_id,
                collection,
                document_id,
            } => ValueKey {
                account_id: *account_id,
                collection: *collection,
                document_id: *document_id,
                class: ValueClass::Blob(BlobOp::Link {
                    hash: hash.as_ref().clone(),
                    to: BlobLink::Document,
                }),
            },
            _ => return Ok(false),
        };

        self.get_value::<()>(key).await.map(|v| v.is_some())
    }

    pub async fn purge_blobs(&self, blob_store: BlobStore) -> trc::Result<()> {
        let mut total_active = 0;
        let mut total_deleted = 0;
        let started = Instant::now();

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

            let mut state = BlobPurgeState::new();
            self.iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let hash =
                        BlobHash::try_from_hash_slice(key.get(0..BLOB_HASH_LEN).ok_or_else(
                            || trc::Error::corrupted_key(key, value.into(), trc::location!()),
                        )?)
                        .unwrap();

                    state.update_hash(hash);
                    state.process_key(key, value)?;

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

            state.finalize(BlobHash::default());

            // Delete expired or unlinked blobs
            for (_, op) in &state.delete_keys {
                if let BlobOp::Commit { hash } = op {
                    blob_store
                        .delete_blob(hash.as_ref())
                        .await
                        .caused_by(trc::location!())?;
                }
            }

            // Delete hashes
            let mut batch = BatchBuilder::new();
            for (account_id, op) in state.delete_keys {
                if batch.is_large_batch() {
                    self.write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                    batch = BatchBuilder::new();
                }

                if let Some(account_id) = account_id {
                    batch.with_account_id(account_id);
                }

                batch.any_op(Operation::Value {
                    class: ValueClass::Blob(op),
                    op: ValueOp::Clear,
                });
            }
            if !batch.is_empty() {
                self.write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }

            total_active += state.total_active - 1; // Exclude default hash
            total_deleted += state.total_deleted;
        }

        trc::event!(
            Purge(PurgeEvent::BlobCleanup),
            Expires = total_deleted,
            Total = total_active,
            Elapsed = started.elapsed()
        );

        Ok(())
    }
}

struct BlobPurgeState {
    last_hash: BlobHash,
    last_hash_is_linked: bool,
    delete_keys: Vec<(Option<u32>, BlobOp)>,
    spam_train_samples: Vec<(u32, u64)>,
    now: u64,
    total_deleted: u64,
    total_active: u64,
}

impl BlobPurgeState {
    fn new() -> Self {
        Self {
            last_hash: BlobHash::default(),
            last_hash_is_linked: true, // Avoid deleting non-existing last_hash on first iteration
            delete_keys: Vec::new(),
            spam_train_samples: Vec::new(),
            now: now(),
            total_deleted: 0,
            total_active: 0,
        }
    }

    pub fn update_hash(&mut self, hash: BlobHash) {
        if self.last_hash != hash {
            self.finalize(hash);
            self.last_hash_is_linked = false;
        }
    }

    pub fn finalize(&mut self, new_hash: BlobHash) {
        if !self.last_hash_is_linked {
            self.total_deleted += 1;
            self.delete_keys.push((
                None,
                BlobOp::Commit {
                    hash: std::mem::replace(&mut self.last_hash, new_hash),
                },
            ));
        } else {
            self.total_active += 1;
            if !self.spam_train_samples.is_empty() {
                if self.spam_train_samples.len() > 1 {
                    // Sort by account_id ascending, then until descending
                    self.spam_train_samples
                        .sort_unstable_by(|(a_id, a_until), (b_id, b_until)| {
                            a_id.cmp(b_id).then_with(|| b_until.cmp(a_until))
                        });
                    let mut samples = self.spam_train_samples.iter().peekable();
                    while let Some((account_id, _)) = samples.next() {
                        // Keep only the latest sample per account
                        while let Some((next_account_id, next_until)) = samples.peek() {
                            if next_account_id == account_id {
                                self.delete_keys.push((
                                    Some(*account_id),
                                    BlobOp::SpamSample {
                                        hash: self.last_hash.clone(),
                                        until: *next_until,
                                    },
                                ));
                                self.delete_keys.push((
                                    Some(*account_id),
                                    BlobOp::Link {
                                        hash: self.last_hash.clone(),
                                        to: BlobLink::Temporary { until: *next_until },
                                    },
                                ));
                                samples.next();
                            } else {
                                break;
                            }
                        }
                    }
                }

                self.spam_train_samples.clear();
            }
            self.last_hash = new_hash;
        }
    }

    pub fn process_key(&mut self, key: &[u8], value: &[u8]) -> trc::Result<()> {
        const TEMP_LINK: usize = BLOB_HASH_LEN + U32_LEN + U64_LEN;
        const DOC_LINK: usize = BLOB_HASH_LEN + U64_LEN + 1;
        const ID_LINK: usize = BLOB_HASH_LEN + U64_LEN;

        match key.len() {
            BLOB_HASH_LEN => {
                // Main blob entry
                Ok(())
            }
            TEMP_LINK => {
                // Temporary link
                let until = key.deserialize_be_u64(BLOB_HASH_LEN + U32_LEN)?;
                if until <= self.now {
                    let account_id = key.deserialize_be_u32(BLOB_HASH_LEN)?;
                    self.delete_keys.push((
                        Some(account_id),
                        BlobOp::Link {
                            hash: self.last_hash.clone(),
                            to: BlobLink::Temporary { until },
                        },
                    ));
                    match value.first().copied() {
                        Some(BlobLink::QUOTA_LINK) => {
                            self.delete_keys.push((
                                Some(account_id),
                                BlobOp::Quota {
                                    hash: self.last_hash.clone(),
                                    until,
                                },
                            ));
                        }
                        Some(BlobLink::UNDELETE_LINK) => {
                            self.delete_keys.push((
                                Some(account_id),
                                BlobOp::Undelete {
                                    hash: self.last_hash.clone(),
                                    until,
                                },
                            ));
                        }
                        Some(BlobLink::SPAM_SAMPLE_LINK) => {
                            self.delete_keys.push((
                                Some(account_id),
                                BlobOp::SpamSample {
                                    hash: self.last_hash.clone(),
                                    until,
                                },
                            ));
                        }
                        _ => {}
                    }
                } else {
                    // Delete attempts to train the same message multiple times
                    if matches!(value.first(), Some(&BlobLink::SPAM_SAMPLE_LINK)) {
                        let account_id = key.deserialize_be_u32(BLOB_HASH_LEN)?;
                        self.spam_train_samples.push((account_id, until));
                    }

                    self.last_hash_is_linked = true;
                }
                Ok(())
            }
            DOC_LINK | ID_LINK => {
                // Document/Id link
                self.last_hash_is_linked = true;
                Ok(())
            }
            _ => Err(trc::Error::corrupted_key(
                key,
                value.into(),
                trc::location!(),
            )),
        }
    }
}
