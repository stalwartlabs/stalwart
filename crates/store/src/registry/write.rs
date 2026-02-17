/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, RegistryStore, SUBSPACE_REGISTRY, SerializeInfallible, U16_LEN, U64_LEN,
    ValueKey,
    write::{
        AnyClass, BatchBuilder, RegistryClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use registry::{
    schema::prelude::{OBJ_SEQ_ID, Object},
    types::{
        EnumType, ObjectType,
        error::Error,
        id::ObjectId,
        index::{IndexBuilder, IndexKey, IndexValue},
    },
};
use trc::AddContext;
use types::id::Id;
use utils::codec::leb128::Leb128Reader;

pub enum RegistryWriteResult<T> {
    Success(T),
    CannotDelete {
        object_id: ObjectId,
        linked_objects: Vec<ObjectId>,
    },
    NotFound {
        object_id: ObjectId,
    },
}

impl RegistryStore {
    pub async fn insert<T: ObjectType>(&self, object: &T) -> trc::Result<RegistryWriteResult<Id>> {
        todo!()
    }

    pub async fn update<T: ObjectType>(
        &self,
        id: Id,
        object: &T,
    ) -> trc::Result<RegistryWriteResult<()>> {
        todo!()
    }

    pub async fn delete<T: ObjectType>(&self, id: u64) -> trc::Result<RegistryWriteResult<()>> {
        let object_type = T::object();
        let object_id = ObjectId::new(object_type, id);

        let todo = "local registry";

        // Validate relationships
        let mut linked = Vec::new();
        let key = KeySerializer::new(U64_LEN + U16_LEN + 1)
            .write(1u8)
            .write(object_type.to_id())
            .write(id)
            .finalize();
        let prefix_len = key.len();
        let from_key = ValueKey::from(ValueClass::Any(AnyClass {
            subspace: SUBSPACE_REGISTRY,
            key,
        }));
        let key = KeySerializer::new((U64_LEN * 2) + U16_LEN + 1)
            .write(1u8)
            .write(object_type.to_id())
            .write(id)
            .write(u64::MAX)
            .finalize();
        let to_key = ValueKey::from(ValueClass::Any(AnyClass {
            subspace: SUBSPACE_REGISTRY,
            key,
        }));
        self.0
            .store
            .iterate(
                IterateParams::new(from_key, to_key).no_values().ascending(),
                |key, _| {
                    let object =
                        Object::from_id(key.deserialize_be_u16(prefix_len)?).ok_or_else(|| {
                            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                                .into_err()
                                .caused_by(trc::location!())
                                .ctx(trc::Key::Key, key)
                        })?;
                    let id = key
                        .get(prefix_len + U16_LEN..)
                        .and_then(|key| key.read_leb128::<u64>())
                        .map(|r| r.0)
                        .ok_or_else(|| {
                            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                                .into_err()
                                .caused_by(trc::location!())
                                .details(object.as_str())
                                .ctx(trc::Key::Key, key)
                        })?;
                    linked.push(ObjectId::new(object, id));

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if !linked.is_empty() {
            return Ok(RegistryWriteResult::CannotDelete {
                object_id: ObjectId::new(object_type, id),
                linked_objects: linked,
            });
        }

        let Some(object) = self.object::<T>(id).await? else {
            return Ok(RegistryWriteResult::NotFound {
                object_id: ObjectId::new(object_type, id),
            });
        };

        // Build deletion batch
        let mut batch = BatchBuilder::new();
        batch.clear(ValueClass::Registry(RegistryClass::Item(object_id)));
        if object_type.flags() & OBJ_SEQ_ID != 0 {
            batch.clear(ValueClass::Registry(RegistryClass::Id {
                item_id: object_id,
            }));
        }
        let mut index = IndexBuilder::default();
        object.index(&mut index);
        batch.registry_index(object_id, index.keys.iter(), false);

        self.0
            .store
            .write(batch.build_all())
            .await
            .map(|_| RegistryWriteResult::Success(()))
            .caused_by(trc::location!())
    }
}

impl RegistryClass {
    fn from_index_key(key: &IndexKey<'_>, item_id: ObjectId) -> Self {
        match key {
            IndexKey::Unique { property, value } => RegistryClass::Index {
                index_id: property.to_id(),
                item_id,
                key: value.serialize(),
            },
            IndexKey::Search { property, value } => RegistryClass::Index {
                index_id: property.to_id(),
                item_id,
                key: value.serialize(),
            },
            IndexKey::Global {
                property,
                value_1,
                value_2,
            } => RegistryClass::IndexGlobal {
                index_id: property.to_id(),
                item_id,
                key: serialize_composite_key(value_1, value_2),
            },
            IndexKey::ForeignKey { object_id, .. } => RegistryClass::Reference {
                to: *object_id,
                from: item_id,
            },
        }
    }
}

impl BatchBuilder {
    fn registry_index<'x>(
        &mut self,
        item_id: ObjectId,
        index_keys: impl Iterator<Item = &'x IndexKey<'x>>,
        is_set: bool,
    ) {
        for key in index_keys {
            if is_set {
                self.set(
                    ValueClass::Registry(RegistryClass::from_index_key(key, item_id)),
                    vec![],
                );
            } else {
                self.clear(ValueClass::Registry(RegistryClass::from_index_key(
                    key, item_id,
                )));
            }
        }
    }
}

fn serialize_composite_key(value_1: &IndexValue<'_>, value_2: &IndexValue<'_>) -> Vec<u8> {
    let mut key = value_1.serialize();

    match value_2 {
        IndexValue::Text(text) => key.extend_from_slice(text.as_bytes()),
        IndexValue::Bytes(bytes) => key.extend_from_slice(bytes),
        IndexValue::U64(num) => key.extend_from_slice(&num.to_be_bytes()),
        IndexValue::I64(num) => key.extend_from_slice(&num.to_be_bytes()),
        IndexValue::U32(num) => key.extend_from_slice(&num.to_be_bytes()),
        IndexValue::U16(num) => key.extend_from_slice(&num.to_be_bytes()),
        IndexValue::None => {}
    }
    key
}

impl SerializeInfallible for IndexValue<'_> {
    fn serialize(&self) -> Vec<u8> {
        match self {
            IndexValue::Text(text) => text.as_bytes().to_vec(),
            IndexValue::Bytes(bytes) => bytes.clone(),
            IndexValue::U64(num) => num.to_be_bytes().to_vec(),
            IndexValue::I64(num) => num.to_be_bytes().to_vec(),
            IndexValue::U32(num) => num.to_be_bytes().to_vec(),
            IndexValue::U16(num) => num.to_be_bytes().to_vec(),
            IndexValue::None => vec![],
        }
    }
}
