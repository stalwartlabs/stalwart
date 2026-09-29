/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::{IndexMessage, PendingMessageData},
    metadata::{ArchivedMessageMetadata, ExtraHeaders, MessageMetadata},
    sortkeys::MessageSortKeys,
};
use common::storage::index::ObjectIndexBuilder;
use store::{
    write::{BatchBuilder, BlobLink, BlobOp, IndexPropertyClass, ValueClass},
    xxhash_rust::xxh3::xxh3_128,
};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    field::EmailField,
    keyword::{HASATTACHMENT, HASNOATTACHMENT},
};
use utils::hash128::Hash128;

impl ArchivedMessageMetadata {
    pub fn index_verbatim(&self, batch: &mut BatchBuilder, metadata: Vec<u8>, sort_keys: Vec<u8>) {
        batch
            .set(
                BlobOp::Link {
                    hash: self.blob_hash(),
                    to: BlobLink::Document,
                },
                Vec::new(),
            )
            .set(EmailField::SortKeys, sort_keys)
            .set(EmailField::Metadata, metadata);
    }

    pub fn unindex(&self, batch: &mut BatchBuilder, thread_name: &str) {
        batch
            .clear(EmailField::Metadata)
            .clear(EmailField::SortKeys)
            .clear(ValueClass::IndexProperty(IndexPropertyClass::Hash {
                property: EmailField::Threading.into(),
                hash: Hash128::from(xxh3_128(
                    if !thread_name.is_empty() {
                        thread_name
                    } else {
                        "!"
                    }
                    .as_bytes(),
                )),
            }))
            .clear(BlobOp::Link {
                hash: self.blob_hash(),
                to: BlobLink::Document,
            });
    }
}

impl IndexMessage for BatchBuilder {
    fn index_message(
        &mut self,
        tenant_id: Option<u32>,
        message: &mail_parser::Message<'_>,
        extra_headers: &ExtraHeaders,
        blob_hash: BlobHash,
        mut data: PendingMessageData,
    ) -> trc::Result<&mut Self> {
        let built = MessageMetadata::build(message, extra_headers, blob_hash.clone());
        if built.has_attachments {
            data.data.keywords |= 1 << HASATTACHMENT;
        } else {
            data.data.keywords |= 1 << HASNOATTACHMENT;
        }

        self.set(
            BlobOp::Link {
                hash: blob_hash,
                to: BlobLink::Document,
            },
            Vec::new(),
        )
        .custom(
            ObjectIndexBuilder::<(), _>::new()
                .with_tenant_id(tenant_id)
                .with_changes(data),
        )
        .caused_by(trc::location!())?
        .set(
            EmailField::SortKeys,
            MessageSortKeys::from_message(message).serialize(),
        )
        .set(
            EmailField::Metadata,
            built.encode().caused_by(trc::location!())?,
        );

        Ok(self)
    }
}
