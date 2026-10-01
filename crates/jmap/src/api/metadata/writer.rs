/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MetadataAccess, MetadataPatches, MetadataPreload, MetadataUpdate, ObjectMetadata,
    PreloadedContainers, PreparedMetadata, write::ContainerTarget,
};
use common::{
    Server,
    auth::AccountCache,
    storage::{
        index::RewritePresence,
        metadata::{MetadataLog, MetadataPresence, PrivateMetadataCommit},
    },
};
use email::message::ingest_metadata::IngestMetadata;
use jmap_proto::{error::set::SetError, object::metadata::MetadataProperty, request::MaybeInvalid};
use jmap_tools::{Element, Value};
use std::{mem, sync::Arc};
use store::write::{Archive, AssignedIds, BatchBuilder, PendingId};
use trc::AddContext;
use types::{id::Id, metadata::MetadataKinds};
use utils::map::vec_map::VecMap;

pub struct MetadataWriter {
    metadata: ObjectMetadata,
    account_id: u32,
    owner: Option<Arc<AccountCache>>,
    viewer: Option<Arc<AccountCache>>,
    containers: PreloadedContainers,
    commit: PrivateMetadataCommit,
}

#[derive(Debug)]
pub enum NewMetadata {
    Create(MetadataPatches),
    Copy {
        patches: Option<MetadataPatches>,
        source_id: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataTarget {
    Create,
    Update { document_id: u32 },
    UpdateInThread { document_id: u32, thread_id: u32 },
}

impl MetadataWriter {
    pub fn new(metadata: ObjectMetadata, account_id: u32) -> Self {
        MetadataWriter {
            metadata,
            account_id,
            owner: None,
            viewer: None,
            containers: PreloadedContainers::default(),
            commit: PrivateMetadataCommit::default(),
        }
    }

    pub fn with_owner(mut self, owner: Arc<AccountCache>) -> Self {
        self.owner = Some(owner);
        self
    }

    pub fn metadata(&self) -> &ObjectMetadata {
        &self.metadata
    }

    pub fn extract<P, E>(
        &self,
        patches: MetadataPatches,
        object: &mut Value<'_, P, E>,
    ) -> Result<Option<MetadataPatches>, SetError<P>>
    where
        P: MetadataProperty,
        E: Element<Property = P>,
    {
        self.metadata.extract(patches, object)
    }

    pub async fn preload(
        &mut self,
        server: &Server,
        account_id: u32,
        preload: MetadataPreload,
    ) -> trc::Result<()> {
        if !preload.is_empty() {
            self.containers = self.metadata.preload(server, account_id, preload).await?;
        }
        Ok(())
    }

    pub async fn preload_updates<P, E>(
        &mut self,
        server: &Server,
        updates: Option<&VecMap<MaybeInvalid<Id>, Value<'_, P, E>>>,
        stored: impl Fn(u32) -> Option<MetadataKinds>,
    ) -> trc::Result<()>
    where
        P: MetadataProperty,
        E: Element<Property = P>,
    {
        self.containers = self
            .metadata
            .preload_updates(server, self.account_id, updates, stored)
            .await?;
        Ok(())
    }

    pub async fn prepare_for<P: MetadataProperty>(
        &mut self,
        server: &Server,
        patches: MetadataPatches,
        access: MetadataAccess,
        target: MetadataTarget,
    ) -> trc::Result<Result<PreparedMetadata, SetError<P>>> {
        let Some(support) = self.metadata.support() else {
            return Ok(Ok(PreparedMetadata::default()));
        };
        let validated = match patches.validate(support, access) {
            Ok(validated) => validated,
            Err(err) => return Ok(Err(err)),
        };
        let (document_id, log) = match target {
            MetadataTarget::Create => (None, MetadataLog::None),
            MetadataTarget::Update { document_id } => (Some(document_id), self.metadata.log()),
            MetadataTarget::UpdateInThread {
                document_id,
                thread_id,
            } => (
                Some(document_id),
                MetadataLog::Item {
                    prefix: Some(PendingId::Assigned(thread_id)),
                },
            ),
        };
        let (shared, private) = document_id.map_or((None, None), |document_id| {
            (
                self.containers.shared.get(document_id),
                self.containers.private.get(document_id),
            )
        });
        match validated.apply(shared, private) {
            Ok(update) => self.finish_prepare(server, update, log).await,
            Err(err) => Ok(Err(err)),
        }
    }

    pub async fn prepare_ingest<P: MetadataProperty>(
        &mut self,
        server: &Server,
        metadata: NewMetadata,
        access: MetadataAccess,
    ) -> trc::Result<Result<Option<Box<IngestMetadata>>, SetError<P>>> {
        let update = match self.new_update(metadata, access) {
            Ok(update) if update.is_empty() => return Ok(Ok(None)),
            Ok(update) => update,
            Err(err) => return Ok(Err(err)),
        };
        let target = self.target(server, MetadataLog::None).await?;
        update.prepare_ingest(server, target).await
    }

    pub async fn prepare_new<P: MetadataProperty>(
        &mut self,
        server: &Server,
        metadata: Option<NewMetadata>,
        access: MetadataAccess,
    ) -> trc::Result<Result<Option<PreparedMetadata>, SetError<P>>> {
        let Some(metadata) = metadata else {
            return Ok(Ok(None));
        };
        match self.new_update(metadata, access) {
            Ok(update) => Ok(self
                .finish_prepare(server, update, MetadataLog::None)
                .await?
                .map(Some)),
            Err(err) => Ok(Err(err)),
        }
    }

    fn new_update<P: MetadataProperty>(
        &self,
        metadata: NewMetadata,
        access: MetadataAccess,
    ) -> Result<MetadataUpdate, SetError<P>> {
        let (patches, source_id) = match metadata {
            NewMetadata::Create(patches) => (Some(patches), None),
            NewMetadata::Copy { patches, source_id } => (patches, Some(source_id)),
        };
        let shared = source_id.and_then(|source_id| self.containers.shared.get(source_id));
        let Some(support) = self.metadata.support() else {
            return Ok(MetadataUpdate::copied(shared, None));
        };
        let validated = patches
            .unwrap_or_else(MetadataPatches::for_create)
            .validate(support, access)?;
        match source_id {
            Some(source_id) => validated.apply_to_copy(
                shared,
                self.containers
                    .private
                    .get(source_id)
                    .filter(|_| access.may_read),
            ),
            None => validated.apply(None, None),
        }
    }

    async fn finish_prepare<P: MetadataProperty>(
        &mut self,
        server: &Server,
        update: MetadataUpdate,
        log: MetadataLog,
    ) -> trc::Result<Result<PreparedMetadata, SetError<P>>> {
        if update.is_empty() {
            return Ok(Ok(PreparedMetadata::default()));
        }
        let target = self.target(server, log).await?;
        update.prepare(server, target).await
    }

    async fn target(
        &mut self,
        server: &Server,
        log: MetadataLog,
    ) -> trc::Result<ContainerTarget<'_>> {
        let owner = match self.owner.take() {
            Some(owner) => owner,
            None => server
                .account(self.account_id)
                .await
                .caused_by(trc::location!())?,
        };
        Ok(ContainerTarget {
            owner: self.owner.insert(owner),
            viewer_id: self.metadata.caller_id(),
            viewer: &mut self.viewer,
            collection: self.metadata.collection(),
            log,
        })
    }

    pub fn write(
        &mut self,
        prepared: PreparedMetadata,
        document_id: impl Into<PendingId>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<Option<MetadataPresence>> {
        prepared.build(document_id, batch, &mut self.commit)
    }

    pub async fn write_metadata_only<T: RewritePresence, P: MetadataProperty>(
        &mut self,
        server: &Server,
        patches: MetadataPatches,
        access: MetadataAccess,
        current: &Archive<&T::Archived>,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<Result<(), SetError<P>>> {
        let prepared = match self
            .prepare_for(
                server,
                patches,
                access,
                MetadataTarget::Update { document_id },
            )
            .await?
        {
            Ok(prepared) => prepared,
            Err(err) => return Ok(Err(err)),
        };
        if let Some(kinds) = prepared.shared_kinds() {
            T::rewrite_presence(current, kinds, self.account_id, document_id, batch)
                .caused_by(trc::location!())?;
        }
        self.write(prepared, document_id, batch)?;
        batch.commit_point();
        Ok(Ok(()))
    }

    pub async fn commit(
        &mut self,
        server: &Server,
        batch: BatchBuilder,
    ) -> trc::Result<AssignedIds> {
        server
            .commit_metadata_batch(batch, mem::take(&mut self.commit))
            .await
    }
}
