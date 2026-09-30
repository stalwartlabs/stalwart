/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ContainerTarget, MetadataAccess, MetadataPatches, MetadataPreload, MetadataUpdate,
    ObjectMetadata, PreloadedContainers, PreparedMetadata,
};
use common::{Server, storage::metadata::PrivateMetadataCommit};
use jmap_proto::{error::set::SetError, object::metadata::MetadataProperty};
use jmap_tools::{Element, Value};
use store::write::{AssignedIds, BatchBuilder, PendingId};
use trc::AddContext;

pub struct MetadataWriter {
    metadata: ObjectMetadata,
    account_id: u32,
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

impl MetadataWriter {
    pub fn new(metadata: ObjectMetadata, account_id: u32) -> Self {
        MetadataWriter {
            metadata,
            account_id,
            containers: PreloadedContainers::default(),
            commit: PrivateMetadataCommit::default(),
        }
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

    pub async fn prepare<P: MetadataProperty>(
        &self,
        server: &Server,
        patches: MetadataPatches,
        access: MetadataAccess,
        document_id: Option<u32>,
    ) -> trc::Result<Result<PreparedMetadata, SetError<P>>> {
        let Some(support) = self.metadata.support() else {
            return Ok(Err(patches.unsupported()));
        };
        let validated = match patches.validate(support, access) {
            Ok(validated) => validated,
            Err(err) => return Ok(Err(err)),
        };
        let (shared, private) = document_id.map_or((None, None), |document_id| {
            (
                self.containers.shared.get(document_id),
                self.containers.private.get(document_id),
            )
        });
        match validated.apply(shared, private) {
            Ok(update) => self.finish_prepare(server, update).await,
            Err(err) => Ok(Err(err)),
        }
    }

    pub fn copy_update<P: MetadataProperty>(
        &self,
        patches: Option<MetadataPatches>,
        source_id: u32,
        access: MetadataAccess,
    ) -> Result<MetadataUpdate, SetError<P>> {
        let shared = self.containers.shared.get(source_id);
        match (self.metadata.support(), patches) {
            (Some(support), patches) => patches
                .unwrap_or_else(MetadataPatches::for_create)
                .validate(support, access)
                .and_then(|validated| {
                    validated.apply_to_copy(
                        shared,
                        self.containers
                            .private
                            .get(source_id)
                            .filter(|_| access.may_read),
                    )
                }),
            (None, None) => Ok(MetadataUpdate::copied(shared, None)),
            (None, Some(patches)) => Err(patches.unsupported()),
        }
    }

    pub async fn prepare_copy<P: MetadataProperty>(
        &self,
        server: &Server,
        patches: Option<MetadataPatches>,
        source_id: u32,
        access: MetadataAccess,
    ) -> trc::Result<Result<PreparedMetadata, SetError<P>>> {
        match self.copy_update(patches, source_id, access) {
            Ok(update) => self.finish_prepare(server, update).await,
            Err(err) => Ok(Err(err)),
        }
    }

    pub async fn prepare_new<P: MetadataProperty>(
        &self,
        server: &Server,
        metadata: Option<NewMetadata>,
        access: MetadataAccess,
    ) -> trc::Result<Result<Option<PreparedMetadata>, SetError<P>>> {
        let result = match metadata {
            Some(NewMetadata::Create(patches)) => {
                self.prepare(server, patches, access, None).await?
            }
            Some(NewMetadata::Copy { patches, source_id }) => {
                self.prepare_copy(server, patches, source_id, access)
                    .await?
            }
            None => return Ok(Ok(None)),
        };
        Ok(result.map(Some))
    }

    async fn finish_prepare<P: MetadataProperty>(
        &self,
        server: &Server,
        update: MetadataUpdate,
    ) -> trc::Result<Result<PreparedMetadata, SetError<P>>> {
        if update.is_empty() {
            return Ok(Ok(PreparedMetadata::default()));
        }
        let owner = server
            .account(self.account_id)
            .await
            .caused_by(trc::location!())?;
        update
            .prepare(
                server,
                ContainerTarget {
                    owner: &owner,
                    viewer_id: self
                        .metadata
                        .viewer()
                        .map_or(owner.id, |viewer| viewer.account_id()),
                    collection: self.metadata.collection(),
                    log: self.metadata.log(),
                },
            )
            .await
    }

    pub fn write(
        &mut self,
        prepared: PreparedMetadata,
        document_id: impl Into<PendingId>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        prepared
            .build(document_id, batch, &mut self.commit)
            .map(|_| ())
    }

    pub async fn committed(self, server: &Server, assigned_ids: &AssignedIds) {
        server
            .private_metadata_committed(self.commit, assigned_ids)
            .await;
    }
}
