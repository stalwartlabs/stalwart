/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, RegistryStoreInner, Store};
use registry::{
    schema::{
        prelude::Object,
        structs::{DataStore, LocalSettings},
    },
    types::id::ObjectId,
};
use std::path::PathBuf;
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

impl RegistryStore {
    pub async fn init(local: PathBuf) -> Result<Self, String> {
        let todo = "environment variables and reading from files";
        const ERROR_MSG: &str = "Failed to initialize registry";

        let mut inner = RegistryStoreInner::load(local).await?;
        let Some(data_store) = inner
            .local_registry
            .read()
            .get(&ObjectId::new(Object::DataStore, Id::singleton()))
            .cloned()
        else {
            return Err(format!(
                "{ERROR_MSG}: Missing \"DataStore\" object definition."
            ));
        };
        let data_store = serde_json::from_value::<DataStore>(data_store)
            .map_err(|err| format!("{ERROR_MSG}: Failed to parse \"DataStore\" object: {err}"))?;
        let Some(local_settings) = inner
            .local_registry
            .read()
            .get(&ObjectId::new(Object::LocalSettings, Id::singleton()))
            .cloned()
        else {
            return Err(format!(
                "{ERROR_MSG}: Missing \"LocalSettings\" object definition."
            ));
        };
        let local_settings =
            serde_json::from_value::<LocalSettings>(local_settings).map_err(|err| {
                format!("{ERROR_MSG}: Failed to parse \"LocalSettings\" object: {err}")
            })?;

        inner.store = Store::build(data_store).await?;
        inner.node_id = local_settings.node_id;
        if inner.node_id == 0 {
            return Err(format!(
                "{ERROR_MSG}: \"LocalSettings\" object has invalid nodeId of 0."
            ));
        }
        inner.id_generator = SnowflakeIdGenerator::with_node_id(inner.node_id);
        Ok(Self(inner.into()))
    }
}
