/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Deserialize, IterateParams, RegistryStore, SUBSPACE_REGISTRY, U16_LEN, U64_LEN, ValueKey,
    registry::RegistryObject,
    write::{AnyClass, RegistryClass, ValueClass, key::KeySerializer},
};
use registry::{
    pickle::PickledStream,
    types::{EnumType, ObjectType, id::ObjectId},
};
use trc::AddContext;
use types::id::Id;
use utils::codec::leb128::Leb128Reader;

impl RegistryStore {
    pub async fn object<T: ObjectType>(&self, id: Id) -> trc::Result<Option<T>> {
        let item_id = id.id();
        let object = T::object();

        if self.0.local_objects.contains(&object) {
            let Some(item) = self
                .0
                .local_registry
                .read()
                .get(&ObjectId::new(object, id))
                .cloned()
            else {
                return Ok(None);
            };
            serde_json::from_value::<T>(item).map(Some).map_err(|err| {
                trc::EventType::Registry(trc::RegistryEvent::LocalParseError)
                    .into_err()
                    .caused_by(trc::location!())
                    .id(item_id)
                    .details(object.as_str())
                    .reason(err)
            })
        } else {
            let Some(bytes) = self
                .0
                .store
                .get_value::<PickledBytes>(ValueKey::from(ValueClass::Registry(
                    RegistryClass::Item {
                        object_id: object.to_id(),
                        item_id,
                    },
                )))
                .await?
            else {
                return Ok(None);
            };
            T::unpickle(&mut PickledStream::new(&bytes.0))
                .ok_or_else(|| {
                    trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                        .into_err()
                        .caused_by(trc::location!())
                        .id(item_id)
                        .details(object.as_str())
                        .ctx(trc::Key::Value, bytes.0)
                })
                .map(Some)
        }
    }

    pub async fn list<T: ObjectType>(&self) -> trc::Result<Vec<RegistryObject<T>>> {
        let object = T::object();

        if self.0.local_objects.contains(&object) {
            let mut results = Vec::new();

            for (id, item) in self.0.local_registry.read().iter() {
                if id.object() == object {
                    let item = serde_json::from_value::<T>(item.clone()).map_err(|err| {
                        trc::EventType::Registry(trc::RegistryEvent::LocalParseError)
                            .into_err()
                            .caused_by(trc::location!())
                            .id(id.id().id())
                            .details(object.as_str())
                            .reason(err)
                    })?;
                    results.push(RegistryObject {
                        id: *id,
                        object: item,
                    });
                }
            }

            Ok(results)
        } else {
            let mut results = Vec::new();
            self.0
                .store
                .iterate(
                    IterateParams::new(
                        ValueKey::from(ValueClass::Any(AnyClass {
                            subspace: SUBSPACE_REGISTRY,
                            key: KeySerializer::new(U16_LEN + 1)
                                .write(0u8)
                                .write(object.to_id())
                                .finalize(),
                        })),
                        ValueKey::from(ValueClass::Any(AnyClass {
                            subspace: SUBSPACE_REGISTRY,
                            key: KeySerializer::new(U16_LEN + U64_LEN + 1)
                                .write(0u8)
                                .write(object.to_id())
                                .write(u64::MAX)
                                .finalize(),
                        })),
                    ),
                    |key, value| {
                        let id = key
                            .get(U16_LEN + 1..)
                            .and_then(|key| key.read_leb128::<u64>())
                            .map(|r| r.0)
                            .ok_or_else(|| {
                                trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                                    .into_err()
                                    .caused_by(trc::location!())
                                    .details(object.as_str())
                                    .ctx(trc::Key::Key, key)
                            })?;
                        let item =
                            T::unpickle(&mut PickledStream::new(value)).ok_or_else(|| {
                                trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                                    .into_err()
                                    .caused_by(trc::location!())
                                    .id(id)
                                    .details(object.as_str())
                                    .ctx(trc::Key::Value, value)
                            })?;
                        results.push(RegistryObject {
                            id: ObjectId::new(object, Id::new(id)),
                            object: item,
                        });

                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;

            Ok(results)
        }
    }
}

struct PickledBytes(Vec<u8>);

impl Deserialize for PickledBytes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}
