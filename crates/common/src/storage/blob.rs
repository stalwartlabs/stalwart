/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{KV_QUOTA_BLOB, Server};
use mail_parser::Encoding;
use std::{borrow::Cow, ops::Range};
use store::{
    U32_LEN, U64_LEN,
    dispatch::lookup::KeyValue,
    write::{BatchBuilder, BlobLink, BlobOp, now},
};
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId, BlobSection},
    blob_hash::BlobHash,
};

const COUNT_BYTES: u32 = 20;
const COUNT_SHIFT: u32 = 64 - COUNT_BYTES;
const SIZE_MASK: u64 = (1u64 << COUNT_SHIFT) - 1;

pub struct BlobQuotaStatus {
    pub allowed: bool,
    pub expires_in: u64,
}

pub trait SectionDecode {
    fn fetch_range(&self) -> Range<usize>;

    fn decode_fetched(&self, fetched: Vec<u8>) -> Option<Vec<u8>>;
}

impl SectionDecode for BlobSection {
    fn fetch_range(&self) -> Range<usize> {
        self.outermost().range()
    }

    fn decode_fetched(&self, fetched: Vec<u8>) -> Option<Vec<u8>> {
        let Some((outermost, containers)) = self.containers().split_first() else {
            return Some(
                match Encoding::from(self.part().encoding).decode(&fetched) {
                    Cow::Owned(decoded) => decoded,
                    Cow::Borrowed(decoded) if decoded.len() != fetched.len() => decoded.to_vec(),
                    Cow::Borrowed(_) => fetched,
                },
            );
        };
        let mut buffer = Vec::new();
        Encoding::from(outermost.encoding).decode_append(&fetched, &mut buffer);
        drop(fetched);
        for container in containers {
            let mut decoded = Vec::new();
            Encoding::from(container.encoding)
                .decode_append(buffer.get(container.range())?, &mut decoded);
            buffer = decoded;
        }
        let part = self.part();
        Some(
            Encoding::from(part.encoding)
                .decode(buffer.get(part.range())?)
                .into_owned(),
        )
    }
}

impl Server {
    pub async fn blob_has_quota(
        &self,
        account_id: u32,
        bytes: usize,
    ) -> trc::Result<BlobQuotaStatus> {
        if self.core.jmap.upload_tmp_quota_size > 0 || self.core.jmap.upload_tmp_quota_amount > 0 {
            let now = now();
            let range_start = now / self.core.jmap.upload_tmp_ttl;
            let range_end =
                (range_start * self.core.jmap.upload_tmp_ttl) + self.core.jmap.upload_tmp_ttl;
            let expires_in = range_end - now;

            let mut bucket = Vec::with_capacity(U32_LEN + U64_LEN + 1);
            bucket.push(KV_QUOTA_BLOB);
            bucket.extend_from_slice(account_id.to_be_bytes().as_slice());
            bucket.extend_from_slice(range_start.to_be_bytes().as_slice());

            self.in_memory_store()
                .counter_incr(
                    KeyValue::new(bucket, 1i64 << COUNT_SHIFT | bytes as i64).expires(expires_in),
                    true,
                )
                .await
                .caused_by(trc::location!())
                .map(|v| {
                    let v = v as u64;
                    let count = v >> COUNT_SHIFT;
                    let size = v & SIZE_MASK;

                    let allowed = (self.core.jmap.upload_tmp_quota_amount == 0
                        || count <= self.core.jmap.upload_tmp_quota_amount as u64)
                        && (self.core.jmap.upload_tmp_quota_size == 0
                            || size <= self.core.jmap.upload_tmp_quota_size as u64);

                    BlobQuotaStatus {
                        allowed,
                        expires_in,
                    }
                })
        } else {
            Ok(BlobQuotaStatus {
                allowed: true,
                expires_in: 0,
            })
        }
    }

    #[allow(clippy::blocks_in_conditions)]
    pub async fn put_jmap_blob(&self, account_id: u32, data: &[u8]) -> trc::Result<BlobId> {
        // First reserve the hash
        let hash = BlobHash::generate(data);
        let mut batch = BatchBuilder::new();
        let until = now() + self.core.jmap.upload_tmp_ttl;

        batch.with_account_id(account_id).set(
            BlobOp::Link {
                hash: hash.clone(),
                to: BlobLink::Temporary { until },
            },
            (data.len() as u64).to_be_bytes().to_vec(),
        );

        self.core
            .storage
            .data
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;

        if !self
            .core
            .storage
            .data
            .blob_exists(&hash)
            .await
            .caused_by(trc::location!())?
        {
            // Upload blob to store
            self.core
                .storage
                .blob
                .put_blob(hash.as_ref(), data, self.core.email.compression)
                .await
                .caused_by(trc::location!())?;

            // Commit blob
            let mut batch = BatchBuilder::new();
            batch.set(BlobOp::Commit { hash: hash.clone() }, Vec::new());
            self.core
                .storage
                .data
                .write_batch(&mut batch)
                .await
                .caused_by(trc::location!())?;
        }

        Ok(BlobId {
            hash,
            class: BlobClass::Reserved {
                account_id,
                expires: until,
            },
            section: None,
        })
    }

    pub async fn put_temporary_blob(
        &self,
        account_id: u32,
        data: &[u8],
        hold_for: u64,
    ) -> trc::Result<(BlobHash, BlobOp)> {
        // First reserve the hash
        let hash = BlobHash::generate(data);
        let mut batch = BatchBuilder::new();
        let until = now() + hold_for;

        batch.with_account_id(account_id).set(
            BlobOp::Link {
                hash: hash.clone(),
                to: BlobLink::Temporary { until },
            },
            vec![],
        );

        self.core
            .storage
            .data
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;

        if !self
            .core
            .storage
            .data
            .blob_exists(&hash)
            .await
            .caused_by(trc::location!())?
        {
            // Upload blob to store
            self.core
                .storage
                .blob
                .put_blob(hash.as_ref(), data, self.core.email.compression)
                .await
                .caused_by(trc::location!())?;

            // Commit blob
            let mut batch = BatchBuilder::new();
            batch.set(BlobOp::Commit { hash: hash.clone() }, Vec::new());
            self.core
                .storage
                .data
                .write_batch(&mut batch)
                .await
                .caused_by(trc::location!())?;
        }

        Ok((
            hash.clone(),
            BlobOp::Link {
                hash,
                to: BlobLink::Temporary { until },
            },
        ))
    }

    pub async fn get_blob_section(
        &self,
        hash: &BlobHash,
        section: &BlobSection,
    ) -> trc::Result<Option<Vec<u8>>> {
        Ok(self
            .blob_store()
            .get_blob(hash.as_slice(), section.fetch_range())
            .await?
            .and_then(|bytes| section.decode_fetched(bytes)))
    }
}
