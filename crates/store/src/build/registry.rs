/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, RegistryStoreInner, Store};
use ahash::AHashSet;
use registry::{
    schema::{
        prelude::ObjectType,
        structs::{DataStore, LocalSettings},
    },
    types::{EnumImpl, id::ObjectId},
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
            .get(&ObjectId::new(ObjectType::DataStore, Id::singleton()))
            .cloned()
            .map(DataStore::from)
        else {
            return Err(format!(
                "{ERROR_MSG}: Missing \"DataStore\" object definition."
            ));
        };

        let Some(local_settings) = inner
            .local_registry
            .read()
            .get(&ObjectId::new(ObjectType::LocalSettings, Id::singleton()))
            .cloned()
            .map(LocalSettings::from)
        else {
            return Err(format!(
                "{ERROR_MSG}: Missing \"LocalSettings\" object definition."
            ));
        };

        // Validate local objects
        let mut local_objects =
            AHashSet::from_iter([ObjectType::DataStore, ObjectType::LocalSettings]);
        for object in local_settings.local_registry_object_types {
            if let Some(object) = ObjectType::parse(&object) {
                local_objects.insert(object);
            } else {
                return Err(format!(
                    "{ERROR_MSG}: LocalSettings/localRegistryObjectImpls contains invalid object type: {object}"
                ));
            }
        }
        for object_id in inner.local_registry.read().keys() {
            if !local_objects.contains(&object_id.object()) {
                return Err(format!(
                    "{ERROR_MSG}: Found object of type {:?} in local registry, but it is not listed in LocalSettings/localRegistryObjectImpls.",
                    object_id.object().as_str()
                ));
            }
        }

        inner.local_objects = local_objects;
        inner.store = Store::build(data_store).await?;
        inner.node_id = local_settings.node_id;
        if inner.node_id == 0 {
            return Err(format!(
                "{ERROR_MSG}: \"LocalSettings\" object has invalid nodeId of 0."
            ));
        }
        inner.id_generator = SnowflakeIdGenerator::new();
        Ok(Self(inner.into()))
    }
}
