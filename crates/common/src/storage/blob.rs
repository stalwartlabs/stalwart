/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use mail_parser::{
    Encoding,
    decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode},
};
use store::{
    SerializeInfallible,
    write::{BatchBuilder, BlobLink, BlobOp, now},
};
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId, BlobSection},
    blob_hash::BlobHash,
};

impl Server {
    #[allow(clippy::blocks_in_conditions)]
    pub async fn put_jmap_blob(&self, account_id: u32, data: &[u8]) -> trc::Result<BlobId> {
        // First reserve the hash
        let hash = BlobHash::generate(data);
        let mut batch = BatchBuilder::new();
        let until = now() + self.core.jmap.upload_tmp_ttl;

        batch
            .with_account_id(account_id)
            .set(
                BlobOp::Link {
                    hash: hash.clone(),
                    to: BlobLink::Temporary { until },
                },
                vec![BlobLink::QUOTA_LINK],
            )
            .set(
                BlobOp::Quota {
                    hash: hash.clone(),
                    until,
                },
                (data.len() as u32).serialize(),
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
                .put_blob(hash.as_ref(), data, self.core.storage.compression)
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
                .put_blob(hash.as_ref(), data, self.core.storage.compression)
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
