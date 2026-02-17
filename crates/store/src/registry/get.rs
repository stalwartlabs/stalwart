/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Deserialize, IterateParams, RegistryStore, SUBSPACE_REGISTRY, U16_LEN, U64_LEN, ValueKey,
    registry::{RegistryObject, RegistryQuery},
    write::{AnyClass, RegistryClass, ValueClass, key::KeySerializer},
};
use registry::{
    pickle::PickledStream,
    schema::prelude::Object,
    types::{EnumType, ObjectType, id::ObjectId},
};
use roaring::RoaringBitmap;
use trc::AddContext;
use utils::codec::leb128::Leb128Reader;

impl RegistryStore {
    pub async fn object<T: ObjectType>(&self, id: impl Into<u64>) -> trc::Result<Option<T>> {
        let id = id.into();
        let object = T::object();

        if let Some(objects) = self.0.local_objects.get(&object) {
            let Some(item) = objects.get(&id) else {
                return Ok(None);
            };
            serde_json::from_value::<T>(item.clone())
                .map(Some)
                .map_err(|err| {
                    trc::EventType::Registry(trc::RegistryEvent::LocalParseError)
                        .into_err()
                        .caused_by(trc::location!())
                        .id(id)
                        .details(object.as_str())
                        .reason(err)
                })
        } else {
            let Some(bytes) = self
                .0
                .store
                .get_value::<PickledBytes>(ValueKey::from(ValueClass::Registry(
                    RegistryClass::Item(ObjectId::new(object, id)),
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
                        .id(id)
                        .details(object.as_str())
                        .ctx(trc::Key::Value, bytes.0)
                })
                .map(Some)
        }
    }

    pub async fn list<T: ObjectType>(&self) -> trc::Result<Vec<RegistryObject<T>>> {
        let object = T::object();

        if let Some(objects) = self.0.local_objects.get(&object) {
            let mut results = Vec::with_capacity(objects.len());

            for (id, item) in objects {
                let item = serde_json::from_value::<T>(item.clone()).map_err(|err| {
                    trc::EventType::Registry(trc::RegistryEvent::LocalParseError)
                        .into_err()
                        .caused_by(trc::location!())
                        .id(*id)
                        .details(object.as_str())
                        .reason(err)
                })?;
                results.push(RegistryObject {
                    id: ObjectId::new(object, *id),
                    object: item,
                });
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
                            id: ObjectId::new(object, id),
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

    pub async fn count(&self, object: Object) -> trc::Result<u64> {
        if let Some(objects) = self.0.local_objects.get(&object) {
            Ok(objects.len() as u64)
        } else {
            self.query::<RoaringBitmap>(RegistryQuery::new(object))
                .await
                .map(|r| r.len())
        }
    }
}

struct PickledBytes(Vec<u8>);

impl Deserialize for PickledBytes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}
