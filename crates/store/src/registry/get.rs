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
    pickle::{Pickle, PickledStream},
    schema::prelude::Object,
    types::{EnumImpl, ObjectImpl, id::ObjectId},
};
use trc::AddContext;
use types::id::Id;
use utils::codec::leb128::Leb128Reader;

impl RegistryStore {
    pub async fn get(&self, object_id: ObjectId) -> trc::Result<Option<Object>> {
        if self.0.local_objects.contains(&object_id.object()) {
            Ok(self.0.local_registry.read().get(&object_id).cloned())
        } else {
            self.0
                .store
                .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                    object_id: object_id.object().to_id(),
                    item_id: object_id.id().id(),
                })))
                .await
                .and_then(|v| {
                    if v.as_ref()
                        .is_none_or(|v| v.object_type() == object_id.object())
                    {
                        Ok(v)
                    } else {
                        Err(
                            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                                .into_err()
                                .caused_by(trc::location!())
                                .id(object_id.id().id())
                                .details(object_id.object().as_str())
                                .reason("Object type mismatch"),
                        )
                    }
                })
        }
    }

    pub async fn object<T: ObjectImpl + From<Object>>(&self, id: Id) -> trc::Result<Option<T>> {
        self.get(ObjectId::new(T::OBJECT, id))
            .await
            .map(|v| v.map(T::from))
    }

    pub async fn list<T: ObjectImpl + From<Object>>(&self) -> trc::Result<Vec<RegistryObject<T>>> {
        let object_type = T::OBJECT;

        if self.0.local_objects.contains(&object_type) {
            let mut results = Vec::new();

            for (id, item) in self.0.local_registry.read().iter() {
                if id.object() == object_type {
                    results.push(RegistryObject {
                        id: *id,
                        object: T::from(item.clone()),
                        revision: 0,
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
                                .write(object_type.to_id())
                                .finalize(),
                        })),
                        ValueKey::from(ValueClass::Any(AnyClass {
                            subspace: SUBSPACE_REGISTRY,
                            key: KeySerializer::new(U16_LEN + U64_LEN + 1)
                                .write(0u8)
                                .write(object_type.to_id())
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
                                    .details(object_type.as_str())
                                    .ctx(trc::Key::Key, key)
                            })?;
                        let mut stream = PickledStream::new(value);
                        let _ = u16::unpickle(&mut stream);
                        let (object, revision) = T::unpickle(&mut stream)
                            .and_then(|item| u32::unpickle(&mut stream).map(|rev| (item, rev)))
                            .ok_or_else(|| {
                                trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                                    .into_err()
                                    .caused_by(trc::location!())
                                    .id(id)
                                    .details(object_type.as_str())
                                    .ctx(trc::Key::Value, value)
                            })?;

                        results.push(RegistryObject {
                            id: ObjectId::new(object_type, Id::new(id)),
                            object,
                            revision,
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

impl Deserialize for Object {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Object::unpickle(&mut PickledStream::new(bytes)).ok_or_else(|| {
            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}
