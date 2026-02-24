/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{KV_QUOTA_BLOB, Server};
use mail_parser::{
    Encoding,
    decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode},
};
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

impl Server {
    pub async fn blob_has_quota(&self, account_id: u32, bytes: usize) -> trc::Result<bool> {
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

                    (self.core.jmap.upload_tmp_quota_amount == 0
                        || count <= self.core.jmap.upload_tmp_quota_amount as u64)
                        && (self.core.jmap.upload_tmp_quota_size == 0
                            || size <= self.core.jmap.upload_tmp_quota_size as u64)
                })
        } else {
            Ok(true)
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
            vec![],
        );

        self.core
            .storage
            .data
            .write(batch.build_all())
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
                .write(batch.build_all())
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
            .write(batch.build_all())
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
                .write(batch.build_all())
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
            .get_blob(
                hash.as_slice(),
                (section.offset_start)..(section.offset_start.saturating_add(section.size)),
            )
            .await?
            .and_then(|bytes| match Encoding::from(section.encoding) {
                Encoding::None => Some(bytes),
                Encoding::Base64 => base64_decode(&bytes),
                Encoding::QuotedPrintable => quoted_printable_decode(&bytes),
            }))
    }
}
