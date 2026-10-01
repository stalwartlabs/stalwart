/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MetadataContainers, MetadataDocuments, MetadataGet, MetadataPatches, MetadataPreload,
    MetadataQuery, MetadataSupport, MetadataType, MetadataValues, PreloadedContainers,
    PrivateCandidates, uses_metadata,
};
use crate::changes::state::{MetadataStateManager, ViewerChangeId};
use common::{
    Server,
    auth::AccessToken,
    storage::metadata::{MetadataLog, MetadataViewer},
};
use jmap_proto::{
    error::set::SetError,
    object::metadata::{MetadataFilter, MetadataProperty, MetadataSelection},
    request::{MaybeInvalid, capability::CapabilityIds},
};
use jmap_tools::{Element, Value};
use registry::schema::enums::Permission;
use std::borrow::Borrow;
use store::roaring::RoaringBitmap;
use trc::AddContext;
use types::{collection::Collection, id::Id, metadata::MetadataKinds};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, Copy)]
pub struct ObjectMetadata {
    object: MetadataType,
    support: Option<MetadataSupport>,
    caller_id: u32,
    client: MetadataClient,
}

#[derive(Debug, Clone, Copy)]
enum MetadataClient {
    Aware { viewer: Option<MetadataViewer> },
    Unaware,
}

impl ObjectMetadata {
    pub fn new(
        server: &Server,
        access_token: &AccessToken,
        using: CapabilityIds,
        object: MetadataType,
    ) -> Self {
        let viewer = server.metadata_viewer(access_token, Permission::JmapMetadataPrivate);
        let support = MetadataSupport::new(&server.core.metadata, access_token, object, viewer);
        ObjectMetadata {
            object,
            support,
            caller_id: access_token.account_id(),
            client: if uses_metadata(using) {
                MetadataClient::Aware {
                    viewer: viewer.filter(|_| support.is_some()),
                }
            } else {
                MetadataClient::Unaware
            },
        }
    }

    pub fn support(&self) -> Option<&MetadataSupport> {
        match self.client {
            MetadataClient::Aware { .. } => self.support.as_ref(),
            MetadataClient::Unaware => None,
        }
    }

    pub fn viewer(&self) -> Option<MetadataViewer> {
        match self.client {
            MetadataClient::Aware { viewer } => viewer,
            MetadataClient::Unaware => None,
        }
    }

    pub fn caller_id(&self) -> u32 {
        self.caller_id
    }

    pub fn collection(&self) -> Collection {
        self.object.collection()
    }

    pub fn log(&self) -> MetadataLog {
        match self.object {
            MetadataType::Mailbox | MetadataType::Calendar | MetadataType::AddressBook => {
                MetadataLog::Container
            }
            MetadataType::Email
            | MetadataType::SieveScript
            | MetadataType::CalendarEvent
            | MetadataType::ContactCard
            | MetadataType::FileNode => MetadataLog::Item { prefix: None },
        }
    }

    pub async fn viewer_change_id(
        &self,
        server: &Server,
        account_id: u32,
    ) -> trc::Result<ViewerChangeId> {
        server
            .viewer_change_id(self.viewer(), account_id, self.collection())
            .await
    }

    pub async fn private_candidates(
        &self,
        server: &Server,
        account_id: u32,
    ) -> trc::Result<Option<PrivateCandidates>> {
        match self.viewer() {
            Some(viewer) => viewer_candidates(server, viewer, account_id, self.collection()).await,
            None => Ok(None),
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
        if self.support().is_some() {
            patches.extract(object)
        } else {
            MetadataPatches::reject_unsupported(object).map(|_| None)
        }
    }

    pub async fn preload_updates<P, E>(
        &self,
        server: &Server,
        account_id: u32,
        updates: Option<&VecMap<MaybeInvalid<Id>, Value<'_, P, E>>>,
        stored: impl Fn(u32) -> Option<MetadataKinds>,
    ) -> trc::Result<PreloadedContainers>
    where
        P: MetadataProperty,
        E: Element<Property = P>,
    {
        if self.support().is_some() {
            self.preload(
                server,
                account_id,
                MetadataPreload::from_updates(updates, stored),
            )
            .await
        } else {
            Ok(PreloadedContainers::default())
        }
    }

    pub async fn preload(
        &self,
        server: &Server,
        account_id: u32,
        preload: MetadataPreload,
    ) -> trc::Result<PreloadedContainers> {
        let collection = self.collection();
        let shared = server
            .load_metadata_containers(account_id, collection, &preload.shared)
            .await
            .caused_by(trc::location!())?;
        let private_viewer = if preload.private.is_empty() {
            None
        } else {
            self.private_candidates(server, account_id)
                .await?
                .map(|candidates| candidates.viewer_id)
        };
        let private = match private_viewer {
            Some(viewer_id) => server
                .load_private_metadata_containers(
                    account_id,
                    viewer_id,
                    collection,
                    &preload.private,
                )
                .await
                .caused_by(trc::location!())?,
            None => MetadataContainers::default(),
        };
        Ok(PreloadedContainers { shared, private })
    }

    pub fn get(&self, selection: MetadataSelection) -> Option<MetadataGet> {
        MetadataGet::new(self.support.as_ref(), selection)
    }

    pub async fn load<P, E>(
        &self,
        server: &Server,
        account_id: u32,
        get: &MetadataGet,
        documents: &MetadataDocuments,
    ) -> trc::Result<MetadataValues<P, E>>
    where
        P: MetadataProperty + Send + Sync,
        E: Element<Property = P> + Send + Sync,
    {
        let private_viewer = if get.wants_private() && !documents.requested().is_empty() {
            match self.client {
                MetadataClient::Aware {
                    viewer: Some(viewer),
                } => viewer_candidates(server, viewer, account_id, self.collection())
                    .await?
                    .map(|candidates| candidates.viewer_id),
                MetadataClient::Aware { viewer: None } => None,
                MetadataClient::Unaware => Some(self.caller_id),
            }
        } else {
            None
        };
        get.load(server, account_id, private_viewer, documents)
            .await
    }

    pub fn query<'x>(
        &self,
        filters: impl IntoIterator<Item = &'x MetadataFilter>,
    ) -> trc::Result<MetadataQuery> {
        MetadataQuery::new(self.support(), filters)
    }

    pub async fn evaluate<B: Borrow<RoaringBitmap>>(
        &self,
        server: &Server,
        account_id: u32,
        query: &MetadataQuery,
        shared: impl FnOnce() -> B,
    ) -> trc::Result<Vec<RoaringBitmap>> {
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let shared = query.has_shared().then(shared);
        let private = if query.has_private() {
            self.private_candidates(server, account_id).await?
        } else {
            None
        };
        let empty = RoaringBitmap::new();
        query
            .evaluate(
                server,
                account_id,
                shared.as_ref().map_or(&empty, Borrow::borrow),
                private,
            )
            .await
    }
}

async fn viewer_candidates(
    server: &Server,
    viewer: MetadataViewer,
    owner_id: u32,
    collection: Collection,
) -> trc::Result<Option<PrivateCandidates>> {
    let state = server
        .metadata_viewer_state(viewer, owner_id, collection)
        .await
        .caused_by(trc::location!())?;
    Ok((state.containers > 0).then_some(PrivateCandidates {
        viewer_id: viewer.account_id(),
        containers: state.containers,
    }))
}
