/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    KV_QUOTA_BLOB, Server,
    network::memory::{MEMORY_STEP, MemoryClass, MemoryReservation},
};
use bytes::Bytes;
use mail_parser::Encoding;
use std::{borrow::Cow, ops::Deref, ops::Range};
use store::{
    U32_LEN, U64_LEN,
    dispatch::lookup::KeyValue,
    write::{BatchBuilder, BlobLink, BlobOp, blob::BlobLinkValue, blob_codec::BlobOpts, now},
};
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId, BlobSection},
    blob_hash::BlobHash,
};

const COUNT_BYTES: u32 = 20;
const COUNT_SHIFT: u32 = 64 - COUNT_BYTES;
const SIZE_MASK: u64 = (1u64 << COUNT_SHIFT) - 1;

const READ_COPY_FACTOR: u64 = 2;

pub struct FetchedBlob {
    bytes: Vec<u8>,
    reservation: MemoryReservation,
}

impl FetchedBlob {
    fn fit(mut bytes: Vec<u8>, mut reservation: MemoryReservation) -> trc::Result<Self> {
        if bytes.capacity() - bytes.len() > MEMORY_STEP as usize {
            bytes.shrink_to_fit();
        }
        let capacity = bytes.capacity() as u64;
        reservation
            .try_reserve_to(capacity)
            .caused_by(trc::location!())?;
        reservation.shrink_to(capacity);
        Ok(FetchedBlob { bytes, reservation })
    }

    pub fn try_reserve_extra(&mut self, extra: usize) -> trc::Result<()> {
        self.reservation
            .try_reserve_to(self.bytes.capacity().saturating_add(extra) as u64)
            .caused_by(trc::location!())
    }

    pub fn replace_prefix(&mut self, prefix_len: usize, replacement: &[u8]) -> trc::Result<()> {
        let len = replacement.len() + self.bytes.len().saturating_sub(prefix_len);
        self.try_reserve_extra(len)?;
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(replacement);
        bytes.extend_from_slice(self.bytes.get(prefix_len..).unwrap_or_default());
        self.bytes = bytes;
        self.reservation.shrink_to(self.bytes.capacity() as u64);
        Ok(())
    }

    pub fn into_parts(self) -> (Vec<u8>, MemoryReservation) {
        (self.bytes, self.reservation)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Deref for FetchedBlob {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<FetchedBlob> for Bytes {
    fn from(blob: FetchedBlob) -> Self {
        Bytes::from_owner(blob)
    }
}

impl AsRef<[u8]> for FetchedBlob {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct BlobQuotaStatus {
    pub allowed: bool,
    pub expires_in: u64,
}

pub struct BlobHold {
    hash: BlobHash,
    account_id: u32,
    until: u64,
    uploaded: bool,
}

impl BlobHold {
    pub fn release(self, batch: &mut BatchBuilder) -> &mut BatchBuilder {
        batch.with_account_id(self.account_id).clear(BlobOp::Link {
            hash: self.hash.clone(),
            to: BlobLink::Temporary { until: self.until },
        });
        self.commit(batch)
    }

    pub fn commit(self, batch: &mut BatchBuilder) -> &mut BatchBuilder {
        if self.uploaded {
            batch.set(BlobOp::Commit { hash: self.hash }, Vec::new())
        } else {
            batch
        }
    }
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
                .key_incr(
                    KeyValue::new(bucket, 1i64 << COUNT_SHIFT | bytes as i64).expires(expires_in),
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
            BlobLinkValue::new(data.len()),
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
                .put_blob(hash.as_ref(), data, &self.core.blob.email)
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
        opts: &BlobOpts,
    ) -> trc::Result<(BlobHash, BlobOp)> {
        let (hash, hold) = self
            .hold_blob(account_id, BlobHash::generate(data), data, hold_for, opts)
            .await?;
        let link = BlobOp::Link {
            hash: hash.clone(),
            to: BlobLink::Temporary { until: hold.until },
        };
        let mut batch = BatchBuilder::new();
        hold.commit(&mut batch);
        if !batch.is_empty() {
            self.core
                .storage
                .data
                .write_batch(&mut batch)
                .await
                .caused_by(trc::location!())?;
        }

        Ok((hash, link))
    }

    pub async fn hold_blob(
        &self,
        account_id: u32,
        hash: BlobHash,
        data: &[u8],
        hold_for: u64,
        opts: &BlobOpts,
    ) -> trc::Result<(BlobHash, BlobHold)> {
        // First reserve the hash
        let mut batch = BatchBuilder::new();
        let until = now() + hold_for;

        batch.with_account_id(account_id).set(
            BlobOp::Link {
                hash: hash.clone(),
                to: BlobLink::Temporary { until },
            },
            BlobLinkValue::new(data.len()),
        );

        self.core
            .storage
            .data
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;

        let uploaded = !self
            .core
            .storage
            .data
            .blob_exists(&hash)
            .await
            .caused_by(trc::location!())?;
        if uploaded {
            self.core
                .storage
                .blob
                .put_blob(hash.as_ref(), data, opts)
                .await
                .caused_by(trc::location!())?;
        }

        Ok((
            hash.clone(),
            BlobHold {
                hash,
                account_id,
                until,
                uploaded,
            },
        ))
    }

    pub fn memory_reservation(&self, class: MemoryClass) -> MemoryReservation {
        self.inner
            .data
            .memory_budget
            .reservation(class, self.core.network.max_buffered_memory)
    }

    pub fn is_memory_available(&self, class: MemoryClass) -> bool {
        self.inner
            .data
            .memory_budget
            .is_accepting(class, self.core.network.max_buffered_memory)
    }

    pub async fn fetch_blob(
        &self,
        hash: &BlobHash,
        range: Range<usize>,
        size_hint: Option<u64>,
    ) -> trc::Result<Option<FetchedBlob>> {
        let factor = if range.start == 0 && self.core.blob.is_uncompressed() {
            1
        } else {
            READ_COPY_FACTOR
        };
        let reservation = self.read_reservation(size_hint, factor)?;
        match self
            .get_blob(hash.as_slice(), range)
            .await
            .caused_by(trc::location!())?
        {
            Some(bytes) => FetchedBlob::fit(bytes, reservation).map(Some),
            None => Ok(None),
        }
    }

    pub async fn fetch_blob_section(
        &self,
        hash: &BlobHash,
        section: &BlobSection,
        size_hint: Option<u64>,
    ) -> trc::Result<Option<FetchedBlob>> {
        let reservation = self.read_reservation(size_hint, READ_COPY_FACTOR)?;
        match self
            .get_blob(hash.as_slice(), section.fetch_range())
            .await
            .caused_by(trc::location!())?
            .and_then(|bytes| section.decode_fetched(bytes))
        {
            Some(bytes) => FetchedBlob::fit(bytes, reservation).map(Some),
            None => Ok(None),
        }
    }

    pub fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> impl Future<Output = trc::Result<Option<Vec<u8>>>> {
        self.blob_store().get_blob(key, range, &self.core.blob.keys)
    }

    pub fn account_blob(&self, bytes: Vec<u8>) -> trc::Result<FetchedBlob> {
        FetchedBlob::fit(bytes, self.memory_reservation(MemoryClass::Read))
    }

    fn read_reservation(
        &self,
        size_hint: Option<u64>,
        factor: u64,
    ) -> trc::Result<MemoryReservation> {
        let mut reservation = self.memory_reservation(MemoryClass::Read);
        if let Some(size) = size_hint {
            reservation
                .try_reserve_to(size.saturating_mul(factor))
                .caused_by(trc::location!())?;
        }
        Ok(reservation)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/storage/blob/tests.rs"]
mod tests;
