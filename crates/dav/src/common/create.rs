/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::DavError;
use common::{
    Server,
    auth::AccessToken,
    storage::create_lock::{CREATE_LOCK_ATTEMPTS, CreateLock},
};
use dav_proto::{Condition, RequestHeaders};
use groupware::cache::GroupwareCache;
use hyper::StatusCode;
use store::{
    InMemoryStore,
    write::{AssignedIds, BatchBuilder},
};
use trc::AddContext;
use types::collection::SyncCollection;

pub(crate) trait CreateLockHandler: Sync + Send {
    fn lock_create(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: SyncCollection,
        path: &str,
        headers: &RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<CreateLock>> + Send;

    fn commit_create(
        &self,
        lock: CreateLock,
        batch: BatchBuilder,
    ) -> impl Future<Output = trc::Result<AssignedIds>> + Send;
}

impl CreateLockHandler for Server {
    async fn lock_create(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: SyncCollection,
        path: &str,
        headers: &RequestHeaders<'_>,
    ) -> crate::Result<CreateLock> {
        let lock = CreateLock::new(account_id, collection.into(), path.as_bytes());
        let min_change_id = if matches!(self.in_memory_store(), InMemoryStore::Local(_)) {
            0
        } else {
            u64::MAX
        };
        let mut attempts = 1;
        while !self.try_create_lock(&lock).await? {
            if attempts == CREATE_LOCK_ATTEMPTS {
                return Err(DavError::Code(StatusCode::SERVICE_UNAVAILABLE));
            }
            attempts += 1;
            self.create_lock_backoff().await;
            if resource_exists(
                self,
                access_token,
                account_id,
                collection,
                path,
                min_change_id,
            )
            .await?
            {
                return Err(created_concurrently(headers));
            }
        }

        match resource_exists(
            self,
            access_token,
            account_id,
            collection,
            path,
            min_change_id,
        )
        .await
        {
            Ok(false) => Ok(lock),
            Ok(true) => {
                self.release_create_lock(&lock).await;
                Err(created_concurrently(headers))
            }
            Err(err) => {
                self.release_create_lock(&lock).await;
                Err(err.into())
            }
        }
    }

    async fn commit_create(
        &self,
        lock: CreateLock,
        batch: BatchBuilder,
    ) -> trc::Result<AssignedIds> {
        let result = self.commit_batch(batch).await;
        self.release_create_lock(&lock).await;
        result
    }
}

async fn resource_exists(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    collection: SyncCollection,
    path: &str,
    min_change_id: u64,
) -> trc::Result<bool> {
    server
        .fetch_groupware_resources_at(
            access_token.account_id(),
            account_id,
            collection,
            min_change_id,
        )
        .await
        .caused_by(trc::location!())
        .map(|resources| resources.by_path(path).is_some())
}

fn created_concurrently(headers: &RequestHeaders<'_>) -> DavError {
    let requires_absent = headers.if_.iter().any(|if_| {
        if_.resource.is_none()
            && if_
                .list
                .iter()
                .any(|cond| matches!(cond, Condition::Exists { is_not: true }))
    });
    if requires_absent {
        DavError::Code(StatusCode::PRECONDITION_FAILED)
    } else {
        trc::StoreEvent::AssertValueFailed
            .into_err()
            .details("Resource was created concurrently")
            .caused_by(trc::location!())
            .into()
    }
}
