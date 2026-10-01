/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PropFindItem, PropFindRequestHandler};
use crate::{
    common::{
        lock::{LockData, build_lock_key},
        uri::{SyncToken, Urn},
    },
    principal::propfind::PrincipalPropFind,
};
use common::{
    GroupwareResources, Server,
    auth::{AccessToken, AccountCache},
    sharing::file::FileNodeAccess,
    storage::dav::canonical_dav_resource_uri,
};
use dav_proto::{
    parser::header::dav_base_uri,
    schema::{
        property::ActiveLock,
        request::PropFind,
        response::{Href, Response},
    },
};
use groupware::cache::GroupwareCache;
use std::{borrow::Cow, sync::Arc};
use store::{
    ahash::AHashMap,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::collection::{Collection, SyncCollection};

pub(crate) struct PropFindData {
    pub accounts: AHashMap<u32, PropFindAccountData>,
    pub principals: ExpandedPrincipals,
}

#[derive(Default)]
pub(crate) struct ExpandedPrincipals(AHashMap<u32, Option<Response>>);

#[derive(Default)]
pub(crate) struct PropFindAccountData {
    pub resources: Option<Arc<GroupwareResources>>,
    pub quota: Option<PropFindAccountQuota>,
    pub owner: Option<Href>,
    pub locks: Option<LockData>,
    pub locks_not_found: bool,
    pub file_access: Option<FileNodeAccess>,
}

#[derive(Clone, Default)]
pub(crate) struct PropFindAccountQuota {
    pub used: u64,
    pub available: Option<u64>,
}

impl PropFindData {
    pub fn new() -> Self {
        Self {
            accounts: AHashMap::with_capacity(2),
            principals: ExpandedPrincipals::default(),
        }
    }

    pub async fn quota(
        &mut self,
        server: &Server,
        account_id: u32,
    ) -> trc::Result<PropFindAccountQuota> {
        let data = self.accounts.entry(account_id).or_default();

        if let Some(quota) = &data.quota {
            Ok(quota.clone())
        } else {
            let quota = server.dav_quota(account_id).await?;
            data.quota = Some(quota.clone());
            Ok(quota)
        }
    }

    pub async fn owner(
        &mut self,
        server: &Server,
        account_info: &AccountCache,
        account_id: u32,
    ) -> trc::Result<Href> {
        let data = self.accounts.entry(account_id).or_default();

        if let Some(owner) = &data.owner {
            Ok(owner.clone())
        } else {
            let owner = server
                .owner_href(account_info, account_id)
                .await
                .caused_by(trc::location!())?;
            data.owner = Some(owner.clone());
            Ok(owner)
        }
    }

    pub async fn resources(
        &mut self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        sync_collection: SyncCollection,
        min_change_id: u64,
    ) -> trc::Result<Arc<GroupwareResources>> {
        let data = self.accounts.entry(account_id).or_default();

        if let Some(resources) = &data.resources {
            Ok(resources.clone())
        } else {
            let resources = server
                .fetch_groupware_resources_at(
                    access_token.account_id(),
                    account_id,
                    sync_collection,
                    min_change_id,
                )
                .await
                .caused_by(trc::location!())?;
            data.resources = Some(resources.clone());
            Ok(resources)
        }
    }

    pub async fn locks(
        &mut self,
        server: &Server,
        account_id: u32,
        collection_container: Collection,
        item: &PropFindItem,
    ) -> trc::Result<Option<Vec<ActiveLock>>> {
        let data = self.accounts.entry(account_id).or_default();

        if data.locks.is_none() && !data.locks_not_found {
            data.locks = server
                .in_memory_store()
                .key_get::<Archive<ArchiveBytes>>(
                    build_lock_key(account_id, collection_container).as_slice(),
                )
                .await
                .caused_by(trc::location!())?
                .map(|lock_data| lock_data.deserialize::<LockData>())
                .transpose()
                .caused_by(trc::location!())?;
            if data.locks.is_none() {
                data.locks_not_found = true;
            }
        }

        let Some(lock_data) = &data.locks else {
            return Ok(None);
        };
        let base_uri = dav_base_uri(&item.name).unwrap_or_default();
        let name = if collection_container == Collection::FileNode {
            canonical_dav_resource_uri(&item.name).unwrap_or(Cow::Borrowed(item.name.as_str()))
        } else {
            Cow::Borrowed(item.name.as_str())
        };
        let Some(path) = name
            .strip_prefix(base_uri)
            .and_then(|path| path.strip_prefix('/'))
            .map(|path| path.trim_end_matches('/'))
        else {
            return Ok(None);
        };
        Ok(Some(lock_data.active_locks(path, base_uri)))
    }
}

impl ExpandedPrincipals {
    pub async fn expand(
        &mut self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        propfind: &PropFind,
    ) -> crate::Result<Option<Response>> {
        if let Some(response) = self.0.get(&account_id) {
            return Ok(response.clone());
        }
        let response = server
            .expand_principal(access_token, account_id, propfind)
            .await?;
        self.0.insert(account_id, response.clone());
        Ok(response)
    }
}

pub(crate) trait SyncTokenUrn {
    fn sync_token(&self) -> String;
}

impl SyncTokenUrn for GroupwareResources {
    fn sync_token(&self) -> String {
        Urn::Sync(SyncToken::State(self.highest_change_id)).to_string()
    }
}
