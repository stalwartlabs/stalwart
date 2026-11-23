/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{KV_LOCK_CREATE, Server};
use std::{ops::RangeInclusive, time::Duration};
use store::{
    U32_LEN, U64_LEN,
    rand::{self, RngExt},
    xxhash_rust::xxh3::xxh3_64,
};
use trc::AddContext;

pub const CREATE_LOCK_ATTEMPTS: u32 = 3;
const CREATE_LOCK_EXPIRY_SECS: u64 = 10;
const CREATE_LOCK_RETRY_MS: RangeInclusive<u64> = 500..=1500;
const CREATE_LOCK_KEY_LEN: usize = U32_LEN + 1 + U64_LEN;

pub struct CreateLock {
    key: [u8; CREATE_LOCK_KEY_LEN],
}

impl CreateLock {
    pub fn new(account_id: u32, collection: u8, name: &[u8]) -> Self {
        let mut key = [0u8; CREATE_LOCK_KEY_LEN];
        for (dst, src) in key.iter_mut().zip(
            account_id
                .to_be_bytes()
                .into_iter()
                .chain([collection])
                .chain(xxh3_64(name).to_be_bytes()),
        ) {
            *dst = src;
        }
        CreateLock { key }
    }
}

impl Server {
    pub async fn try_create_lock(&self, lock: &CreateLock) -> trc::Result<bool> {
        self.in_memory_store()
            .try_lock(KV_LOCK_CREATE, &lock.key, CREATE_LOCK_EXPIRY_SECS)
            .await
            .caused_by(trc::location!())
    }

    pub async fn create_lock_backoff(&self) {
        let backoff = rand::rng().random_range(CREATE_LOCK_RETRY_MS);
        tokio::time::sleep(Duration::from_millis(backoff)).await;
    }

    pub async fn release_create_lock(&self, lock: &CreateLock) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_CREATE, &lock.key)
            .await
        {
            trc::error!(
                err.details("Failed to release resource creation lock")
                    .caused_by(trc::location!())
            );
        }
    }
}
