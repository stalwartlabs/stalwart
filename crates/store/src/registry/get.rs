/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, RegistryStore, SUBSPACE_REGISTRY, U16_LEN, U64_LEN, ValueKey,
    registry::{RegistryObject, local::RegistryInit},
    write::{
        AnyClass, RegistryClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use registry::{
    pickle::PickledStream,
    schema::prelude::{Object, ObjectType},
    types::{EnumImpl, ObjectImpl, id::ObjectId},
};
use trc::AddContext;
use types::id::Id;

impl RegistryStore {
    pub async fn get(&self, object_id: ObjectId) -> trc::Result<Option<Object>> {
        if object_id.object() != ObjectType::DataStore {
            self.0
                .store
                .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                    object_id: object_id.object().to_id(),
                    item_id: object_id.id().id(),
                })))
                .await
        } else {
            match self.0.read_data_store().await {
                RegistryInit::Ok(data_store) => Ok(Some(Object {
                    inner: data_store.into(),
                    revision: 0,
                })),
                RegistryInit::Err(err) => {
                    Err(trc::EventType::Registry(trc::RegistryEvent::LocalReadError)
                        .into_err()
                        .caused_by(trc::location!())
                        .reason(err))
                }
                RegistryInit::Bootstrap => Ok(None),
            }
        }
    }

    pub async fn object<T: ObjectImpl + From<Object>>(&self, id: Id) -> trc::Result<Option<T>> {
        self.get(ObjectId::new(T::OBJECT, id))
            .await
            .map(|v| v.map(T::from))
    }

    pub async fn list<T: ObjectImpl + From<Object>>(&self) -> trc::Result<Vec<RegistryObject<T>>> {
        let object_type = T::OBJECT;

        let mut results = Vec::new();
        self.0
            .store
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_REGISTRY,
                        key: KeySerializer::new(U16_LEN)
                            .write(object_type.to_id())
                            .finalize(),
                    })),
                    ValueKey::from(ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_REGISTRY,
                        key: KeySerializer::new(U16_LEN + U64_LEN)
                            .write(object_type.to_id())
                            .write(u64::MAX)
                            .finalize(),
                    })),
                ),
                |key, value| {
                    let id = key.deserialize_be_u64(U16_LEN)?;
                    let object = PickledStream::new(value)
                        .and_then(|mut stream| T::unpickle(&mut stream))
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
                        revision: xxhash_rust::xxh3::xxh3_64(value),
                    });

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        Ok(results)
    }
}
