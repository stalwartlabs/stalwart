/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, RegistryStoreInner, Store};
use ahash::AHashMap;
use parking_lot::RwLock;
use registry::{
    schema::prelude::{OBJ_SINGLETON, Object},
    types::{EnumType, id::ObjectId},
};
use serde_json::{Map, Value, map::Entry};
use std::path::PathBuf;
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

impl RegistryStoreInner {
    pub async fn load(local_path: PathBuf) -> Result<Self, String> {
        let error_msg = format!("Failed to read local registry at {}", local_path.display());
        let contents = tokio::fs::read_to_string(&local_path)
            .await
            .map_err(|err| format!("{error_msg}: {err}"))?;
        let values = serde_json::from_str::<Value>(&contents)
            .map_err(|err| format!("{error_msg}: {err}"))?;

        let Value::Object(object) = values else {
            return Err(format!("{error_msg}: Found invalid JSON structure."));
        };

        let mut local_registry = AHashMap::new();
        for (key, value) in object.into_iter() {
            let object_type = Object::parse(key.as_str())
                .ok_or_else(|| format!("{error_msg}: Unrecognized object {key:?}."))?;
            let is_singleton = object_type.flags() & OBJ_SINGLETON != 0;
            let Value::Object(object) = value else {
                return Err(format!("{error_msg}: Found invalid JSON structure."));
            };
            if !is_singleton {
                for (id, value) in object.into_iter() {
                    let id = id.parse::<u64>().map_err(|_| {
                        format!("{error_msg}: Failed to parse object id {id} for object {key:?}")
                    })?;
                    if !matches!(value, Value::Object(_)) {
                        return Err(format!(
                            "{error_msg}: Object {key:?} with id {id} is invalid."
                        ));
                    }
                    if local_registry
                        .insert(ObjectId::new(object_type, Id::new(id)), value)
                        .is_some()
                    {
                        return Err(format!(
                            "{error_msg}: Object {key:?} with id {id} defined multiple times."
                        ));
                    }
                }
            } else if local_registry
                .insert(
                    ObjectId::new(object_type, Id::singleton()),
                    Value::Object(object),
                )
                .is_some()
            {
                return Err(format!(
                    "{error_msg}: Object {key:?} defined multiple times."
                ));
            }
        }

        Ok(RegistryStoreInner {
            local_path,
            local_registry: RwLock::new(local_registry),
            local_objects: Default::default(),
            store: Store::None,
            id_generator: SnowflakeIdGenerator::new(),
            node_id: 0,
        })
    }
}

impl RegistryStore {
    pub async fn write_local_registry(&self) -> trc::Result<()> {
        let mut map = Map::new();

        for (id, value) in self.0.local_registry.read().iter() {
            let is_singleton = id.object().flags() & OBJ_SINGLETON != 0;
            match map.entry(id.object().as_str().to_string()) {
                Entry::Vacant(entry) => {
                    if is_singleton {
                        entry.insert(value.clone());
                    } else {
                        entry.insert(Map::from_iter([(id.id().to_string(), value.clone())]).into());
                    }
                }
                Entry::Occupied(mut entry) => {
                    if !is_singleton {
                        if let Value::Object(map) = entry.get_mut() {
                            map.insert(id.id().to_string(), value.clone());
                        }
                    } else {
                        debug_assert!(false, "Unexpected double singleton assignment");
                    }
                }
            }
        }

        let json_text = serde_json::to_string(&Value::Object(map)).map_err(|err| {
            trc::EventType::Registry(trc::RegistryEvent::LocalWriteError)
                .into_err()
                .caused_by(trc::location!())
                .reason(err)
        })?;
        tokio::fs::write(&self.0.local_path, json_text)
            .await
            .map_err(|err| {
                trc::EventType::Registry(trc::RegistryEvent::LocalWriteError)
                    .into_err()
                    .caused_by(trc::location!())
                    .reason(err)
            })
    }
}
