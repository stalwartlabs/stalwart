/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::FdbStore;
use crate::Store;
use foundationdb::{Database, api, options::DatabaseOption};
use registry::schema::structs;
use std::sync::Arc;

impl FdbStore {
    pub async fn open(config: structs::FoundationDbStore) -> Result<Store, String> {
        let guard = unsafe {
            api::FdbApiBuilder::default()
                .build()
                .map_err(|err| format!("Failed to boot FoundationDB: {err:?}"))?
                .boot()
                .map_err(|err| format!("Failed to boot FoundationDB: {err:?}"))?
        };

        let db = Database::new(config.cluster_file.as_deref())
            .map_err(|err| format!("Failed to create FoundationDB database: {err:?}"))?;

        if let Some(value) = config.transaction_timeout {
            db.set_option(DatabaseOption::TransactionTimeout(
                value.into_inner().as_millis() as i32,
            ))
            .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }
        if let Some(value) = config.transaction_retry_limit {
            db.set_option(DatabaseOption::TransactionRetryLimit(value as i32))
                .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }
        if let Some(value) = config.transaction_retry_delay {
            db.set_option(DatabaseOption::TransactionMaxRetryDelay(
                value.into_inner().as_millis() as i32,
            ))
            .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }
        if let Some(value) = config.machine_id {
            db.set_option(DatabaseOption::MachineId(value))
                .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }
        if let Some(value) = config.datacenter_id {
            db.set_option(DatabaseOption::DatacenterId(value))
                .map_err(|err| format!("Failed to set option: {err:?}"))?;
        }

        Ok(Store::FoundationDb(Arc::new(Self {
            guard,
            db,
            version: Default::default(),
        })))
    }
}
