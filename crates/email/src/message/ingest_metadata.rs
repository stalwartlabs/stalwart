/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::metadata::{
    MetadataLog, MetadataWrite, PrivateMetadataCommit, PrivateMetadataWrite,
};
use store::write::{BatchBuilder, PendingId};
use types::{collection::Collection, metadata::EncodedMetadata};

#[derive(Debug, Default)]
pub struct IngestMetadata {
    pub shared: Option<EncodedMetadata>,
    pub private: Option<PrivateMetadataWrite>,
}

impl IngestMetadata {
    pub fn new(
        shared: Option<EncodedMetadata>,
        private: Option<PrivateMetadataWrite>,
    ) -> Option<Box<Self>> {
        (shared.is_some() || private.is_some())
            .then(|| Box::new(IngestMetadata { shared, private }))
    }

    pub(crate) fn build(
        self,
        batch: &mut BatchBuilder,
        account_id: u32,
        tenant_id: Option<u32>,
        document_id: PendingId,
        commit: &mut PrivateMetadataCommit,
    ) -> trc::Result<()> {
        if let Some(container) = self.shared {
            MetadataWrite {
                account_id,
                tenant_id,
                collection: Collection::Email,
                document_id,
                previous: None,
                next: Some(container),
                log: MetadataLog::None,
            }
            .build(batch)?;
        }
        if let Some(write) = self.private {
            write.build(document_id, batch, commit)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::IngestMetadata;
    use common::storage::metadata::{MetadataLog, PrivateMetadataCommit, PrivateMetadataWrite};
    use std::borrow::Cow;
    use store::write::{
        BatchBuilder, Operation, PendingId, ValueClass, ValueOp, metadata::MetadataClass,
    };
    use types::{
        collection::Collection,
        metadata::{EncodedMetadata, MetadataBuilder},
    };

    const OWNER: u32 = 7;
    const VIEWER: u32 = 9;

    fn container() -> EncodedMetadata {
        let mut builder = MetadataBuilder::new();
        builder.set_imap(Cow::Borrowed("/comment"), b"value");
        builder.encode().expect("non-empty")
    }

    fn private_write() -> PrivateMetadataWrite {
        PrivateMetadataWrite {
            owner_id: OWNER,
            viewer_id: VIEWER,
            viewer_tenant_id: None,
            collection: Collection::Email,
            previous: None,
            next: Some(container()),
            log: MetadataLog::None,
        }
    }

    fn written(batch: &BatchBuilder) -> Vec<(Option<u32>, Option<PendingId>, MetadataClass)> {
        let mut account_id = None;
        let mut document_id = None;
        let mut written = Vec::new();
        for op in batch.ops() {
            match op {
                Operation::AccountId { account_id: id } => account_id = Some(*id),
                Operation::DocumentId { document_id: id } => document_id = Some(*id),
                Operation::Value {
                    class: ValueClass::Metadata(class),
                    op: ValueOp::Set(_),
                } => written.push((account_id, document_id, *class)),
                _ => {}
            }
        }
        written
    }

    #[test]
    fn empty_metadata_is_not_allocated() {
        assert!(IngestMetadata::new(None, None).is_none());
        assert!(IngestMetadata::new(Some(container()), None).is_some());
        assert!(IngestMetadata::new(None, Some(private_write())).is_some());
    }

    #[test]
    fn containers_are_written_to_the_new_document() {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(OWNER)
            .with_collection(Collection::Email);
        let slot = batch.reserve_document_id(OWNER, Collection::Email);
        let document_id = PendingId::Slot(slot);
        batch.create_document(slot);

        let mut commit = PrivateMetadataCommit::default();
        IngestMetadata {
            shared: Some(container()),
            private: Some(private_write()),
        }
        .build(&mut batch, OWNER, None, document_id, &mut commit)
        .expect("valid containers");

        assert_eq!(
            written(&batch),
            [
                (Some(OWNER), Some(document_id), MetadataClass::Shared),
                (
                    Some(OWNER),
                    Some(document_id),
                    MetadataClass::Private { viewer: VIEWER }
                ),
            ]
        );
        assert!(!commit.is_empty());
        assert_eq!(batch.last_account_id(), Some(OWNER));
        assert_eq!(batch.last_collection(), Some(Collection::Email));
        assert_eq!(batch.last_document_id(), Some(document_id));
    }
}
