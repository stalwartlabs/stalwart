/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::DavError;
use common::{KV_LOCK_DAV, Server, auth::AccessToken};
use dav_proto::{Condition, RequestHeaders};
use groupware::cache::GroupwareCache;
use hyper::StatusCode;
use std::{ops::RangeInclusive, time::Duration};
use store::{
    InMemoryStore, U32_LEN, U64_LEN,
    rand::{self, RngExt},
    write::{AssignedIds, BatchBuilder},
    xxhash_rust::xxh3::xxh3_64,
};
use trc::AddContext;
use types::collection::SyncCollection;

const CREATE_LOCK_EXPIRY_SECS: u64 = 10;
const CREATE_LOCK_ATTEMPTS: u32 = 3;
const CREATE_LOCK_RETRY_MS: RangeInclusive<u64> = 500..=1500;
const CREATE_LOCK_KEY_LEN: usize = U32_LEN + 1 + U64_LEN;

pub(crate) struct CreateLock {
    key: [u8; CREATE_LOCK_KEY_LEN],
}

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

    fn release_create_lock(&self, lock: &CreateLock) -> impl Future<Output = ()> + Send;
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
        let lock = CreateLock::new(account_id, collection, path);
        let store = self.in_memory_store();
        let min_change_id = if matches!(store, InMemoryStore::Local(_)) {
            0
        } else {
            u64::MAX
        };
        let mut attempts = 1;
        while !store
            .try_lock(KV_LOCK_DAV, &lock.key, CREATE_LOCK_EXPIRY_SECS)
            .await
            .caused_by(trc::location!())?
        {
            if attempts == CREATE_LOCK_ATTEMPTS {
                return Err(DavError::Code(StatusCode::SERVICE_UNAVAILABLE));
            }
            attempts += 1;
            let backoff = rand::rng().random_range(CREATE_LOCK_RETRY_MS);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
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

    async fn release_create_lock(&self, lock: &CreateLock) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_DAV, &lock.key)
            .await
        {
            trc::error!(
                err.details("Failed to release resource creation lock")
                    .caused_by(trc::location!())
            );
        }
    }
}

impl CreateLock {
    fn new(account_id: u32, collection: SyncCollection, path: &str) -> Self {
        let mut key = [0u8; CREATE_LOCK_KEY_LEN];
        for (dst, src) in key.iter_mut().zip(
            account_id
                .to_be_bytes()
                .into_iter()
                .chain([u8::from(collection)])
                .chain(xxh3_64(path.as_bytes()).to_be_bytes()),
        ) {
            *dst = src;
        }
        CreateLock { key }
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
