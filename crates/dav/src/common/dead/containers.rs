/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::AccountCache,
    storage::metadata::{
        MetadataContainers, MetadataLog, MetadataWrite, StoredContainer, StoredEntry,
    },
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
    metadata::{EncodedMetadata, MetadataKinds},
};

type GroupKey = (u32, Collection);

#[derive(Debug, Default)]
pub(crate) struct ContainerRequest {
    groups: AHashMap<GroupKey, RoaringBitmap>,
}

#[derive(Debug, Default)]
pub(crate) struct DeadContainers {
    groups: Vec<(GroupKey, MetadataContainers)>,
}

#[derive(Debug)]
pub(crate) struct ContainerWrites {
    account_id: u32,
    collection: Collection,
    owner: Option<Arc<AccountCache>>,
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
        let mut groups = Vec::new();
        for (key @ (account_id, collection), documents) in self.groups {
            let containers = server
                .load_metadata_containers(account_id, collection, &documents)
                .await
                .caused_by(trc::location!())?;
            if !containers.is_empty() {
                groups.push((key, containers));
            }
        }
        Ok(DeadContainers { groups })
    }
}

impl DeadContainers {
    pub fn get(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> Option<&MetadataBuf> {
        self.group(account_id, collection)
            .and_then(|containers| containers.get(document_id))
    }

    pub fn stored_len(&self) -> u64 {
        self.groups
            .iter()
            .flat_map(|(_, containers)| containers.iter())
            .map(|(_, container)| u64::from(container.stored_len()))
            .sum()
    }

    pub fn stored_entries(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> impl Iterator<Item = StoredEntry> + '_ {
        self.group(account_id, collection)
            .into_iter()
            .flat_map(MetadataContainers::iter)
            .map(|(document_id, container)| StoredEntry::from_container(document_id, container))
    }

    fn group(&self, account_id: u32, collection: Collection) -> Option<&MetadataContainers> {
        self.groups
            .iter()
            .find(|(key, _)| *key == (account_id, collection))
            .map(|(_, containers)| containers)
    }
}

impl ContainerWrites {
    pub fn new(account_id: u32, collection: Collection) -> Self {
        ContainerWrites {
            account_id,
            collection,
            owner: None,
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
        self.build(
            server,
            document_id.into(),
            previous,
            EncodedMetadata::from_view(&source.view()),
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

    pub async fn release(
        &mut self,
        server: &Server,
        entry: StoredEntry,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let tenant_id = self.owner(server).await?.id_tenant;
        batch
            .with_account_id(self.account_id)
            .with_collection(self.collection);
        entry.release(batch, tenant_id);
        Ok(())
    }

    async fn owner(&mut self, server: &Server) -> trc::Result<&AccountCache> {
        match &mut self.owner {
            Some(owner) => Ok(owner),
            owner => Ok(owner.insert(
                server
                    .account(self.account_id)
                    .await
                    .caused_by(trc::location!())?,
            )),
        }
    }

    async fn build(
        &mut self,
        server: &Server,
        document_id: PendingId,
        previous: Option<StoredContainer>,
        next: Option<EncodedMetadata>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let tenant_id = self.owner(server).await?.id_tenant;
        MetadataWrite {
            account_id: self.account_id,
            tenant_id,
            collection: self.collection,
            previous,
            next,
            log: MetadataLog::None,
        }
        .build(document_id, batch)
        .caused_by(trc::location!())?;
        Ok(())
    }
}

pub(crate) fn copy_growth(source: &MetadataBuf, previous: Option<&StoredEntry>) -> u64 {
    u64::from(source.stored_len())
        .saturating_sub(previous.map_or(0, |previous| u64::from(previous.size)))
}

pub(crate) async fn check_growth(server: &Server, account_id: u32, growth: u64) -> trc::Result<()> {
    if growth > 0 {
        let account = server
            .account(account_id)
            .await
            .caused_by(trc::location!())?;
        server
            .has_available_quota(&account, growth)
            .await
            .caused_by(trc::location!())
    } else {
        Ok(())
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

pub(crate) async fn stored_entry_of(
    server: &Server,
    account_id: u32,
    collection: Collection,
    document_id: u32,
    kinds: MetadataKinds,
) -> trc::Result<Option<StoredEntry>> {
    if kinds.is_empty() {
        return Ok(None);
    }
    server
        .stored_metadata_entries(
            account_id,
            collection,
            &RoaringBitmap::from_iter([document_id]),
        )
        .await
        .map(|entries| entries.get(document_id).copied())
}

pub(crate) fn edited_container(
    entry: StoredEntry,
    account_id: u32,
    kinds: MetadataKinds,
) -> trc::Result<StoredContainer> {
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
                .document_id(entry.document_id)
                .caused_by(trc::location!())
        })
}

pub(crate) fn container_kinds(container: Option<&MetadataBuf>) -> MetadataKinds {
    container.map_or(MetadataKinds::NONE, MetadataBuf::kinds)
}
