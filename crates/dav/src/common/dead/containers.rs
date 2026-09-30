/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::AccountCache,
    storage::metadata::{MetadataLog, MetadataWrite, StoredContainer, StoredEntry},
};
use std::sync::Arc;
use store::{
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{BatchBuilder, PendingId, metadata::MetadataBuf},
};
use trc::AddContext;
use types::{
    collection::Collection,
    metadata::{EncodedMetadata, MetadataBuilder, MetadataKinds},
};

type ContainerKey = (u32, u8, u32);

#[derive(Debug, Default)]
pub(crate) struct ContainerRequest {
    groups: AHashMap<(u32, Collection), RoaringBitmap>,
}

#[derive(Debug, Default)]
pub(crate) struct DeadContainers {
    containers: AHashMap<ContainerKey, MetadataBuf>,
}

#[derive(Debug)]
pub(crate) struct ContainerWrites {
    account_id: u32,
    collection: Collection,
    owner: Option<Arc<AccountCache>>,
    growth: u64,
}

impl ContainerRequest {
    pub fn insert(&mut self, account_id: u32, collection: Collection, document_id: u32) {
        self.groups
            .entry((account_id, collection))
            .or_default()
            .insert(document_id);
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub async fn load(self, server: &Server) -> trc::Result<DeadContainers> {
        let mut containers = AHashMap::new();
        for ((account_id, collection), documents) in self.groups {
            let collection_id = u8::from(collection);
            server
                .metadata_containers(
                    account_id,
                    collection,
                    &documents,
                    |document_id, view, stored| {
                        containers.insert(
                            (account_id, collection_id, document_id),
                            MetadataBuf::from_view(&view, stored.size, stored.hash),
                        );
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }
        Ok(DeadContainers { containers })
    }
}

impl DeadContainers {
    pub fn get(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> Option<&MetadataBuf> {
        self.containers
            .get(&(account_id, u8::from(collection), document_id))
    }

    pub fn stored_entries(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> impl Iterator<Item = StoredEntry> + '_ {
        let collection = u8::from(collection);
        self.containers
            .iter()
            .filter(
                move |((container_account_id, container_collection, _), _)| {
                    *container_account_id == account_id && *container_collection == collection
                },
            )
            .map(|((_, _, document_id), container)| stored_entry(*document_id, container))
    }
}

pub(crate) fn stored_entry(document_id: u32, container: &MetadataBuf) -> StoredEntry {
    StoredEntry {
        document_id,
        size: container.stored_len(),
        hash: Some(container.hash()),
    }
}

impl ContainerWrites {
    pub fn new(account_id: u32, collection: Collection) -> Self {
        ContainerWrites {
            account_id,
            collection,
            owner: None,
            growth: 0,
        }
    }

    pub async fn copy(
        &mut self,
        server: &Server,
        source: &MetadataBuf,
        document_id: impl Into<PendingId>,
        previous: Option<StoredContainer>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        self.growth += u64::from(source.stored_len())
            .saturating_sub(previous.map_or(0, |previous| u64::from(previous.size)));
        self.build(
            server,
            document_id.into(),
            previous,
            MetadataBuilder::from_view(&source.view()).encode(),
            batch,
        )
        .await
    }

    pub async fn clear(
        &mut self,
        server: &Server,
        document_id: impl Into<PendingId>,
        previous: StoredContainer,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        self.build(server, document_id.into(), Some(previous), None, batch)
            .await
    }

    async fn build(
        &mut self,
        server: &Server,
        document_id: PendingId,
        previous: Option<StoredContainer>,
        next: Option<EncodedMetadata>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let owner = match &self.owner {
            Some(owner) => owner,
            None => self.owner.insert(
                server
                    .account(self.account_id)
                    .await
                    .caused_by(trc::location!())?,
            ),
        };
        MetadataWrite {
            account_id: self.account_id,
            tenant_id: owner.id_tenant,
            collection: self.collection,
            document_id,
            previous,
            next,
            log: MetadataLog::None,
        }
        .build(batch)
        .caused_by(trc::location!())?;
        Ok(())
    }

    pub async fn finish(self, server: &Server) -> trc::Result<()> {
        match self.owner {
            Some(owner) if self.growth > 0 => server
                .has_available_quota(&owner, self.growth)
                .await
                .caused_by(trc::location!()),
            _ => Ok(()),
        }
    }
}

pub(crate) async fn read_container(
    server: &Server,
    account_id: u32,
    collection: Collection,
    document_id: u32,
    kinds: MetadataKinds,
) -> trc::Result<Option<MetadataBuf>> {
    if kinds.is_empty() {
        Ok(None)
    } else {
        server
            .metadata_container(account_id, collection, document_id)
            .await
    }
}

pub(crate) async fn stored_container(
    server: &Server,
    account_id: u32,
    collection: Collection,
    document_id: u32,
    kinds: MetadataKinds,
) -> trc::Result<Option<StoredContainer>> {
    if kinds.is_empty() {
        return Ok(None);
    }
    server
        .stored_metadata_entries(
            account_id,
            collection,
            &RoaringBitmap::from_iter([document_id]),
        )
        .await?
        .get(document_id)
        .map(|entry| {
            entry
                .hash
                .map(|hash| StoredContainer {
                    size: entry.size,
                    kinds,
                    hash,
                })
                .ok_or_else(|| {
                    trc::StoreEvent::DataCorruption
                        .into_err()
                        .details("Metadata container carries no trailer")
                        .account_id(account_id)
                        .document_id(document_id)
                        .caused_by(trc::location!())
                })
        })
        .transpose()
}

pub(crate) fn container_kinds(container: Option<&MetadataBuf>) -> MetadataKinds {
    container.map_or(MetadataKinds::NONE, MetadataBuf::kinds)
}
