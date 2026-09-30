/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{GroupwareResources, MessageStoreCache, Server, storage::metadata::MetadataViewer};
use jmap_proto::types::state::State;
use std::future::Future;
use trc::AddContext;
use types::{
    ChangeId,
    collection::{Collection, SyncCollection},
};

pub trait StateManager: Sync + Send {
    fn get_state(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> impl Future<Output = trc::Result<State>> + Send;

    fn assert_state(
        &self,
        account_id: u32,
        collection: SyncCollection,
        if_in_state: &Option<State>,
    ) -> impl Future<Output = trc::Result<State>> + Send;
}

pub trait MetadataStateManager: Sync + Send {
    fn metadata_state(
        &self,
        viewer: Option<MetadataViewer>,
        account_id: u32,
        collection: Collection,
        shared: State,
    ) -> impl Future<Output = trc::Result<State>> + Send;

    fn assert_metadata_state(
        &self,
        viewer: Option<MetadataViewer>,
        account_id: u32,
        collection: Collection,
        shared: State,
        if_in_state: &Option<State>,
    ) -> impl Future<Output = trc::Result<State>> + Send;
}

pub trait JmapCacheState: Sync + Send {
    fn get_state(&self, is_container: bool) -> State;

    fn assert_state(&self, is_container: bool, if_in_state: &Option<State>) -> trc::Result<State> {
        let old_state: State = self.get_state(is_container);
        if let Some(if_in_state) = if_in_state
            && &old_state != if_in_state
        {
            return Err(trc::JmapEvent::StateMismatch.into_err());
        }
        Ok(old_state)
    }
}

impl StateManager for Server {
    async fn get_state(&self, account_id: u32, collection: SyncCollection) -> trc::Result<State> {
        self.core
            .storage
            .data
            .get_last_change_id(account_id, collection.into())
            .await
            .caused_by(trc::location!())
            .map(State::from)
    }

    async fn assert_state(
        &self,
        account_id: u32,
        collection: SyncCollection,
        if_in_state: &Option<State>,
    ) -> trc::Result<State> {
        let old_state: State = self.get_state(account_id, collection).await?;
        if let Some(if_in_state) = if_in_state
            && &old_state != if_in_state
        {
            return Err(trc::JmapEvent::StateMismatch.into_err());
        }

        Ok(old_state)
    }
}

impl MetadataStateManager for Server {
    async fn metadata_state(
        &self,
        viewer: Option<MetadataViewer>,
        account_id: u32,
        collection: Collection,
        shared: State,
    ) -> trc::Result<State> {
        match viewer {
            Some(viewer) => self
                .metadata_viewer_state(viewer, account_id, collection)
                .await
                .caused_by(trc::location!())
                .map(|state| max_state(shared, state.change_id)),
            None => Ok(shared),
        }
    }

    async fn assert_metadata_state(
        &self,
        viewer: Option<MetadataViewer>,
        account_id: u32,
        collection: Collection,
        shared: State,
        if_in_state: &Option<State>,
    ) -> trc::Result<State> {
        let old_state = self
            .metadata_state(viewer, account_id, collection, shared)
            .await?;
        if let Some(if_in_state) = if_in_state
            && &old_state != if_in_state
        {
            return Err(trc::JmapEvent::StateMismatch.into_err());
        }
        Ok(old_state)
    }
}

pub(crate) fn max_state(state: State, change_id: ChangeId) -> State {
    match state {
        State::Initial if change_id != 0 => State::Exact(change_id),
        State::Exact(current) => State::Exact(current.max(change_id)),
        state => state,
    }
}

#[inline(always)]
fn cache_state(change_id: ChangeId) -> State {
    (change_id != 0).then_some(change_id).into()
}

impl JmapCacheState for MessageStoreCache {
    fn get_state(&self, is_container: bool) -> State {
        cache_state(if is_container {
            self.mailboxes.change_id
        } else {
            self.emails.change_id
        })
    }
}

impl JmapCacheState for GroupwareResources {
    fn get_state(&self, is_container: bool) -> State {
        cache_state(if is_container {
            self.container_change_id
        } else {
            self.item_change_id
        })
    }
}
