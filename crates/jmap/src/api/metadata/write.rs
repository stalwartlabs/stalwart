/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::prepared::{PreparedMetadata, SharedWrite};
use common::{
    Server,
    auth::AccountCache,
    storage::metadata::{MetadataLog, PrivateMetadataWrite, StoredContainer},
};
use jmap_proto::{error::set::SetError, object::metadata::MetadataProperty};
use types::{
    collection::Collection,
    metadata::{EncodedMetadata, MetadataEdit, MetadataKinds},
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetadataUpdate {
    shared: Option<ContainerChange>,
    private: Option<ContainerChange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerChange {
    previous: Option<StoredContainer>,
    next: Option<EncodedMetadata>,
    edit: MetadataEdit,
}

#[derive(Debug, Clone, Copy)]
pub struct ContainerTarget<'x> {
    pub owner: &'x AccountCache,
    pub viewer_id: u32,
    pub collection: Collection,
    pub log: MetadataLog,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DetachedMetadata {
    pub shared: Option<EncodedMetadata>,
    pub private: Option<PrivateMetadataWrite>,
}

impl MetadataUpdate {
    pub(super) fn new(shared: Option<ContainerChange>, private: Option<ContainerChange>) -> Self {
        MetadataUpdate { shared, private }
    }

    pub fn is_empty(&self) -> bool {
        self.shared.is_none() && self.private.is_none()
    }

    pub fn shared(&self) -> Option<&ContainerChange> {
        self.shared.as_ref()
    }

    pub fn private(&self) -> Option<&ContainerChange> {
        self.private.as_ref()
    }

    pub async fn prepare<P: MetadataProperty>(
        self,
        server: &Server,
        target: ContainerTarget<'_>,
    ) -> trc::Result<Result<PreparedMetadata, SetError<P>>> {
        let owner = target.owner;
        let shared = match self.shared {
            Some(change) => {
                if !change.has_quota(server, owner).await? {
                    return Ok(Err(SetError::over_quota()));
                }
                Some(SharedWrite {
                    account_id: owner.id,
                    tenant_id: owner.id_tenant,
                    collection: target.collection,
                    log: target.log,
                    change,
                })
            }
            None => None,
        };
        let private = match self.private {
            Some(change) => match change.into_private_write(server, target).await? {
                Ok(write) => Some(write),
                Err(err) => return Ok(Err(err)),
            },
            None => None,
        };
        Ok(Ok(PreparedMetadata { shared, private }))
    }

    pub async fn prepare_detached<P: MetadataProperty>(
        self,
        server: &Server,
        target: ContainerTarget<'_>,
    ) -> trc::Result<Result<DetachedMetadata, SetError<P>>> {
        let private = match self.private {
            Some(change) => match change.into_private_write(server, target).await? {
                Ok(write) => Some(write),
                Err(err) => return Ok(Err(err)),
            },
            None => None,
        };
        Ok(Ok(DetachedMetadata {
            shared: self.shared.and_then(ContainerChange::into_next),
            private,
        }))
    }
}

impl ContainerChange {
    pub(super) fn new(
        previous: Option<StoredContainer>,
        next: Option<EncodedMetadata>,
        edit: MetadataEdit,
    ) -> Self {
        ContainerChange {
            previous,
            next,
            edit,
        }
    }

    pub fn previous(&self) -> Option<&StoredContainer> {
        self.previous.as_ref()
    }

    pub fn next(&self) -> Option<&EncodedMetadata> {
        self.next.as_ref()
    }

    pub fn into_next(self) -> Option<EncodedMetadata> {
        self.next
    }

    pub fn edit(&self) -> MetadataEdit {
        self.edit
    }

    pub(super) fn into_parts(self) -> (Option<StoredContainer>, Option<EncodedMetadata>) {
        (self.previous, self.next)
    }

    pub fn kinds(&self) -> MetadataKinds {
        self.next
            .as_ref()
            .map_or(MetadataKinds::NONE, EncodedMetadata::kinds)
    }

    async fn has_quota(&self, server: &Server, account: &AccountCache) -> trc::Result<bool> {
        match &self.next {
            Some(next) => {
                server
                    .has_metadata_quota(account, self.edit, self.previous.as_ref(), next)
                    .await
            }
            None => Ok(true),
        }
    }

    async fn into_private_write<P: MetadataProperty>(
        self,
        server: &Server,
        target: ContainerTarget<'_>,
    ) -> trc::Result<Result<PrivateMetadataWrite, SetError<P>>> {
        let owner = target.owner;
        let viewer = if target.viewer_id == owner.id {
            None
        } else {
            Some(server.account(target.viewer_id).await?)
        };
        let viewer = viewer.as_deref().unwrap_or(owner);
        if !self.has_quota(server, viewer).await? {
            return Ok(Err(SetError::over_quota()));
        }
        let (previous, next) = self.into_parts();
        Ok(Ok(PrivateMetadataWrite {
            owner_id: owner.id,
            viewer_id: viewer.id,
            viewer_tenant_id: viewer.id_tenant,
            collection: target.collection,
            previous,
            next,
            log: target.log,
        }))
    }
}
