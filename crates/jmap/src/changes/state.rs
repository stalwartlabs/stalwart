/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{DavResources, MessageStoreCache, Server};
use jmap_proto::types::state::State;
use std::future::Future;
use trc::AddContext;
use types::collection::SyncCollection;

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

impl JmapCacheState for MessageStoreCache {
    fn get_state(&self, is_container: bool) -> State {
        if is_container {
            State::from(self.mailboxes.change_id)
        } else {
            State::from(self.emails.change_id)
        }
    }
}

impl JmapCacheState for DavResources {
    fn get_state(&self, is_container: bool) -> State {
        if is_container {
            State::from(self.container_change_id)
        } else {
            State::from(self.item_change_id)
        }
    }
}
