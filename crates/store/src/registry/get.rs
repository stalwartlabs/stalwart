/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, RegistryStore, U16_LEN, ValueKey,
    registry::{RegistryObject, local::RegistryInit},
    write::{RegistryClass, ValueClass, key::DeserializeBigEndian},
};
use registry::{
    pickle::{Pickle, PickledStream},
    schema::prelude::{Object, ObjectInner, ObjectType},
    types::{EnumImpl, ObjectImpl, id::ObjectId},
};
use trc::AddContext;
use types::id::Id;
use xxhash_rust::xxh3::xxh3_64;

impl RegistryStore {
    pub async fn get(&self, object_id: ObjectId) -> trc::Result<Option<Object>> {
        if object_id.object() != ObjectType::DataStore {
            self.0.store.get_value::<Object>(item_key(object_id)).await
        } else {
            match self.0.read_data_store().await {
                RegistryInit::Ok(data_store) => Ok(Some(Object {
                    inner: ObjectInner::DataStore(data_store),
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

    pub async fn get_fresh(&self, object_id: ObjectId) -> trc::Result<Option<Object>> {
        if object_id.object() != ObjectType::DataStore {
            self.0
                .store
                .get_value_fresh::<Object>(item_key(object_id))
                .await
        } else {
            self.get(object_id).await
        }
    }

    pub async fn object<T: ObjectImpl + From<Object>>(&self, id: Id) -> trc::Result<Option<T>> {
        self.get(ObjectId::new(T::OBJECT, id))
            .await
            .map(|v| v.map(T::from))
    }

    pub async fn list<T: ObjectImpl + Pickle + From<Object>>(
        &self,
    ) -> trc::Result<Vec<RegistryObject<T>>> {
        let mut results = Vec::new();
        self.iterate_objects(T::OBJECT, &mut |id, revision, value| {
            let Some(object) =
                PickledStream::new(value).and_then(|mut stream| T::unpickle(&mut stream))
            else {
                return false;
            };
            results.push(RegistryObject {
                id,
                object,
                revision,
            });
            true
        })
        .await?;

        Ok(results)
    }

    async fn iterate_objects(
        &self,
        object_type: ObjectType,
        cb: &mut (dyn FnMut(ObjectId, u64, &[u8]) -> bool + Send + Sync),
    ) -> trc::Result<()> {
        let (begin, end) = RegistryClass::item_range(object_type.to_id());
        self.0
            .store
            .iterate(IterateParams::new(begin, end), |key, value| {
                let id = key.deserialize_be_u64(U16_LEN)?;
                if cb(
                    ObjectId::new(object_type, Id::new(id)),
                    xxh3_64(value),
                    value,
                ) {
                    Ok(true)
                } else {
                    Err(
                        trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                            .into_err()
                            .caused_by(trc::location!())
                            .id(id)
                            .details(object_type.as_str())
                            .ctx(trc::Key::Value, value),
                    )
                }
            })
            .await
            .caused_by(trc::location!())
    }
}

fn item_key(object_id: ObjectId) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::Registry(RegistryClass::Item {
        object_id: object_id.object().to_id(),
        item_id: object_id.id().id(),
    }))
}
