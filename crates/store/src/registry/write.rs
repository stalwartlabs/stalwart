/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, RegistryStore, SerializeInfallible, U16_LEN, U64_LEN, ValueKey,
    write::{
        BatchBuilder, RegistryClass, ValueClass,
        assert::AssertValue,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use registry::{
    schema::prelude::{
        OBJ_FILTER_ACCOUNT, OBJ_FILTER_TENANT, OBJ_SEQ_ID, OBJ_SINGLETON, Object, ObjectType,
        Property,
    },
    types::{
        EnumImpl,
        error::ValidationError,
        id::ObjectId,
        index::{IndexBuilder, IndexKey, IndexValue},
    },
};
use std::{borrow::Cow, fmt::Display};
use trc::AddContext;
use types::id::Id;

pub enum RegistryWriteResult {
    Success(Id),
    CannotDeleteLinked {
        object_id: ObjectId,
        linked_objects: Vec<ObjectId>,
    },
    InvalidSingletonId,
    CannotDeleteSingleton,
    NotFound {
        object_id: ObjectId,
    },
    InvalidForeignKey {
        object_id: ObjectId,
    },
    PrimaryKeyConflict {
        property: Property,
        existing_id: ObjectId,
    },
    ValidationError {
        errors: Vec<ValidationError>,
    },
    InvalidTenantId,
    InvalidAccountId,
    NotSupported,
}

pub struct RegistryWrite<'x> {
    op: RegistryWriteOp<'x>,
    current_tenant_id: Option<u32>,
    current_account_id: Option<u32>,
}

pub enum RegistryWriteOp<'x> {
    Insert {
        object: &'x Object,
        id: Option<Id>,
    },
    Update {
        object: &'x Object,
        id: Id,
        old_object: &'x Object,
    },
    Delete {
        object_id: ObjectId,
        object: Option<&'x Object>,
    },
}

impl RegistryStore {
    pub async fn write(&self, write: RegistryWrite<'_>) -> trc::Result<RegistryWriteResult> {
        let mut set_index = IndexBuilder::default();
        let mut clear_index = IndexBuilder::default();

        let object;
        let object_type;
        let object_flags;
        let object_id;
        let object_tenant_id;
        let mut item_id;

        let mut batch = BatchBuilder::new();
        let mut write_id = true;
        let mut generate_id = false;

        match write.op {
            RegistryWriteOp::Insert {
                object: insert_object,
                id,
            } => {
                object = insert_object;
                object_flags = object.flags();
                object_type = object.object_type();
                object_id = object_type.to_id();
                object.index(&mut set_index);
                object_tenant_id = set_index.tenant_id();

                item_id = if let Some(id) = id {
                    id.id()
                } else if object_flags & OBJ_SINGLETON != 0 {
                    write_id = false;
                    Id::singleton().id()
                } else if object_flags & OBJ_SEQ_ID != 0 {
                    generate_id = true;
                    u64::MAX
                } else {
                    self.0.id_generator.generate()
                };
            }
            RegistryWriteOp::Update {
                object: update_object,
                id,
                old_object,
            } => {
                object = update_object;
                object_flags = object.flags();
                object_type = object.object_type();
                object_id = object_type.to_id();
                object.index(&mut set_index);
                object_tenant_id = set_index.tenant_id();

                // Obtain changes
                let mut old_index = IndexBuilder::default();
                old_object.index(&mut old_index);
                for key in &old_index.keys {
                    set_index.keys.remove(key);
                }
                clear_index = old_index;

                // Validate singleton
                if object_flags & OBJ_SINGLETON != 0 && !id.is_singleton() {
                    return Ok(RegistryWriteResult::InvalidSingletonId);
                }

                // Assert value
                item_id = id.id();
                batch.assert_value(
                    ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                    AssertValue::Hash(old_object.revision),
                );
            }
            RegistryWriteOp::Delete { object_id, object } => {
                return if object_id.object().flags() & OBJ_SINGLETON == 0 {
                    self.delete(write, object_id, object).await
                } else {
                    Ok(RegistryWriteResult::CannotDeleteSingleton)
                };
            }
        }

        // Validate object
        let mut errors = Vec::new();
        object.validate(&mut errors);
        if !errors.is_empty() {
            return Ok(RegistryWriteResult::ValidationError { errors });
        }

        // Validate tenant ownership
        if write.current_tenant_id.is_some()
            && (object_flags & OBJ_FILTER_TENANT) != 0
            && write.current_tenant_id != object_tenant_id
        {
            return Ok(RegistryWriteResult::InvalidTenantId);
        }

        // Validate tenant and account changes
        if let Some(err) = write.validate_owner(&set_index) {
            return Ok(err);
        }

        // Write to local registry
        if self.0.local_objects.contains(&object_type) {
            if generate_id {
                return Ok(RegistryWriteResult::NotSupported);
            }
            let id = Id::new(item_id);
            self.0
                .local_registry
                .write()
                .insert(ObjectId::new(object_type, id), object.clone());
            return self
                .write_local_registry()
                .await
                .map(|_| RegistryWriteResult::Success(id));
        }

        // Validate foreign keys
        for key in &set_index.keys {
            match key {
                IndexKey::ForeignKey {
                    object_id: foreign_id,
                    type_filter,
                } => {
                    // Verify that the referenced object exists
                    let item_id = foreign_id.id().id();
                    let object_id = foreign_id.object().to_id();
                    let key = if type_filter != &IndexValue::None {
                        RegistryClass::Index {
                            index_id: Property::Type.to_id(),
                            object_id,
                            item_id,
                            key: type_filter.serialize(),
                        }
                    } else {
                        RegistryClass::IndexId { object_id, item_id }
                    };
                    if self
                        .0
                        .store
                        .get_value::<()>(ValueKey::from(ValueClass::Registry(key)))
                        .await
                        .caused_by(trc::location!())?
                        .is_none()
                    {
                        return Ok(RegistryWriteResult::InvalidForeignKey {
                            object_id: *foreign_id,
                        });
                    } else if let Some(tenant_id) = object_tenant_id
                        && (object_flags & OBJ_FILTER_TENANT) != 0
                        && self
                            .0
                            .store
                            .get_value::<()>(ValueKey::from(ValueClass::Registry(
                                RegistryClass::Index {
                                    index_id: Property::MemberTenantId.to_id(),
                                    object_id,
                                    item_id,
                                    key: IndexValue::U64(tenant_id as u64).serialize(),
                                },
                            )))
                            .await
                            .caused_by(trc::location!())?
                            .is_none()
                    {
                        return Ok(RegistryWriteResult::InvalidForeignKey {
                            object_id: *foreign_id,
                        });
                    } else if let Some(account_id) = write.current_account_id
                        && (object_flags & OBJ_FILTER_ACCOUNT) != 0
                        && self
                            .0
                            .store
                            .get_value::<()>(ValueKey::from(ValueClass::Registry(
                                RegistryClass::Index {
                                    index_id: Property::AccountId.to_id(),
                                    object_id,
                                    item_id,
                                    key: IndexValue::U64(account_id as u64).serialize(),
                                },
                            )))
                            .await
                            .caused_by(trc::location!())?
                            .is_none()
                    {
                        return Ok(RegistryWriteResult::InvalidForeignKey {
                            object_id: *foreign_id,
                        });
                    }
                }
                IndexKey::Unique {
                    property,
                    value_1,
                    value_2,
                    global,
                } => {
                    let key = ValueKey::from(ValueClass::Registry(RegistryClass::PrimaryKey {
                        object_id: (!*global).then_some(object_id),
                        index_id: property.to_id(),
                        key: serialize_composite_key(value_1, value_2),
                    }));
                    if let Some(existing_id) = self
                        .0
                        .store
                        .get_value::<ObjectId>(key)
                        .await
                        .caused_by(trc::location!())?
                        && existing_id != ObjectId::new(object_type, Id::new(item_id))
                    {
                        return Ok(RegistryWriteResult::PrimaryKeyConflict {
                            property: *property,
                            existing_id,
                        });
                    }
                }
                IndexKey::Search { .. } => {}
            }
        }

        // Assign id
        if generate_id {
            let mut id_batch = BatchBuilder::new();
            id_batch.add_and_get(
                ValueClass::Registry(RegistryClass::IdCounter { object_id }),
                1,
            );
            item_id = self
                .0
                .store
                .write(id_batch.build_all())
                .await
                .and_then(|v| v.last_counter_id())? as u64;
        }

        // It's pickle time!
        let mut out = Vec::with_capacity(256);
        object.inner.pickle(&mut out);

        // Build batch
        if write_id {
            batch.set(
                ValueClass::Registry(RegistryClass::IndexId { object_id, item_id }),
                vec![],
            );
        }
        batch
            .registry_index(object_id, item_id, set_index.keys.iter(), true)
            .registry_index(object_id, item_id, clear_index.keys.iter(), false)
            .set(
                ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                out,
            );

        Ok(RegistryWriteResult::Success(Id::new(item_id)))
    }

    async fn delete(
        &self,
        write: RegistryWrite<'_>,
        object_id: ObjectId,
        object: Option<&Object>,
    ) -> trc::Result<RegistryWriteResult> {
        let object_type = object_id.object();
        let object_type_id = object_type.to_id();
        let id = object_id.id();
        let item_id = id.id();

        if self.0.local_objects.contains(&object_type) {
            let object = ObjectId::new(object_type, id);
            return if self.0.local_registry.write().remove(&object).is_some() {
                self.write_local_registry()
                    .await
                    .map(|_| RegistryWriteResult::Success(id))
            } else {
                Ok(RegistryWriteResult::NotFound { object_id: object })
            };
        }

        // Fetch object
        let object = if let Some(object) = object {
            Cow::Borrowed(object)
        } else if let Some(object) = self.get(object_id).await? {
            Cow::Owned(object)
        } else {
            return Ok(RegistryWriteResult::NotFound {
                object_id: ObjectId::new(object_type, id),
            });
        };

        // Validate tenant and account changes
        let mut clear_index = IndexBuilder::default();
        object.index(&mut clear_index);
        if let Some(err) = write.validate_owner(&clear_index) {
            return Ok(err);
        }

        // Validate relationships
        let mut linked = Vec::new();
        let from_key = ValueKey::from(ValueClass::Registry(RegistryClass::Reference {
            to_object_id: object_type_id,
            to_item_id: item_id,
            from_object_id: 0,
            from_item_id: 0,
        }));
        let to_key = ValueKey::from(ValueClass::Registry(RegistryClass::Reference {
            to_object_id: object_type_id,
            to_item_id: item_id,
            from_object_id: u16::MAX,
            from_item_id: u64::MAX,
        }));

        self.0
            .store
            .iterate(
                IterateParams::new(from_key, to_key).no_values().ascending(),
                |key, _| {
                    if key.len() == (U16_LEN * 2) + (U64_LEN * 2) {
                        let object =
                            ObjectType::from_id(key.deserialize_be_u16(U64_LEN + U16_LEN)?)
                                .ok_or_else(|| {
                                    trc::EventType::Registry(
                                        trc::RegistryEvent::DeserializationError,
                                    )
                                    .into_err()
                                    .caused_by(trc::location!())
                                    .ctx(trc::Key::Key, key)
                                })?;
                        let id = key.deserialize_be_u64(U64_LEN + U16_LEN + U16_LEN)?;
                        linked.push(ObjectId::new(object, Id::new(id)));
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if !linked.is_empty() {
            return Ok(RegistryWriteResult::CannotDeleteLinked {
                object_id: ObjectId::new(object_type, id),
                linked_objects: linked,
            });
        }

        // Build deletion batch
        let mut batch = BatchBuilder::new();
        batch
            .assert_value(
                ValueClass::Registry(RegistryClass::Item {
                    object_id: object_type_id,
                    item_id,
                }),
                AssertValue::Hash(object.revision),
            )
            .clear(ValueClass::Registry(RegistryClass::Item {
                object_id: object_type_id,
                item_id,
            }))
            .clear(ValueClass::Registry(RegistryClass::IndexId {
                object_id: object_type_id,
                item_id,
            }))
            .registry_index(object_type_id, item_id, clear_index.keys.iter(), false);

        self.0
            .store
            .write(batch.build_all())
            .await
            .map(|_| RegistryWriteResult::Success(Id::from(item_id)))
            .caused_by(trc::location!())
    }
}

impl BatchBuilder {
    pub fn registry_index<'x>(
        &mut self,
        object_id: u16,
        item_id: u64,
        index_keys: impl Iterator<Item = &'x IndexKey<'x>>,
        is_set: bool,
    ) -> &mut Self {
        for key in index_keys {
            let (key, value) = match key {
                IndexKey::Search { property, value } => (
                    RegistryClass::Index {
                        index_id: property.to_id(),
                        object_id,
                        item_id,
                        key: value.serialize(),
                    },
                    vec![],
                ),
                IndexKey::Unique {
                    property,
                    value_1,
                    value_2,
                    global,
                } => (
                    RegistryClass::PrimaryKey {
                        object_id: (!*global).then_some(object_id),
                        index_id: property.to_id(),
                        key: serialize_composite_key(value_1, value_2),
                    },
                    KeySerializer::new(U16_LEN + U64_LEN)
                        .write(object_id)
                        .write(item_id)
                        .finalize(),
                ),
                IndexKey::ForeignKey {
                    object_id: to_object_id,
                    ..
                } => (
                    RegistryClass::Reference {
                        to_object_id: to_object_id.object().to_id(),
                        to_item_id: to_object_id.id().id(),
                        from_item_id: item_id,
                        from_object_id: object_id,
                    },
                    vec![],
                ),
            };
            if is_set {
                if !value.is_empty() {
                    self.assert_value(ValueClass::Registry(key.clone()), ());
                }
                self.set(ValueClass::Registry(key), value);
            } else {
                self.clear(ValueClass::Registry(key));
            }
        }
        self
    }
}

fn serialize_composite_key(value_1: &IndexValue<'_>, value_2: &IndexValue<'_>) -> Vec<u8> {
    let mut key = value_1.serialize();
    match value_2 {
        IndexValue::Text(text) => key.extend_from_slice(text.as_bytes()),
        IndexValue::Bytes(bytes) => key.extend_from_slice(bytes),
        IndexValue::U64(num) => key.extend_from_slice(&num.to_be_bytes()),
        IndexValue::I64(num) => key.extend_from_slice(&num.to_be_bytes()),
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
            IndexValue::U16(num) => num.to_be_bytes().to_vec(),
            IndexValue::None => vec![],
        }
    }
}

impl<'x> RegistryWrite<'x> {
    pub fn insert(object: &'x Object) -> Self {
        Self {
            op: RegistryWriteOp::Insert { object, id: None },
            current_tenant_id: None,
            current_account_id: None,
        }
    }

    pub fn insert_with_id(id: Id, object: &'x Object) -> Self {
        Self {
            op: RegistryWriteOp::Insert {
                object,
                id: Some(id),
            },
            current_tenant_id: None,
            current_account_id: None,
        }
    }

    pub fn update(id: Id, object: &'x Object, old_object: &'x Object) -> Self {
        Self {
            op: RegistryWriteOp::Update {
                object,
                id,
                old_object,
            },
            current_tenant_id: None,
            current_account_id: None,
        }
    }

    pub fn delete(object_id: ObjectId) -> Self {
        Self {
            op: RegistryWriteOp::Delete {
                object_id,
                object: None,
            },
            current_tenant_id: None,
            current_account_id: None,
        }
    }

    pub fn delete_object(object_id: ObjectId, object: &'x Object) -> Self {
        Self {
            op: RegistryWriteOp::Delete {
                object_id,
                object: Some(object),
            },
            current_tenant_id: None,
            current_account_id: None,
        }
    }

    pub fn with_current_tenant_id(mut self, tenant_id: u32) -> Self {
        self.current_tenant_id = Some(tenant_id);
        self
    }

    pub fn with_current_account_id(mut self, account_id: u32) -> Self {
        self.current_account_id = Some(account_id);
        self
    }

    fn validate_owner(&self, builder: &IndexBuilder<'_>) -> Option<RegistryWriteResult> {
        // Validate tenant and account changes
        if let Some(tenant_id) = self.current_tenant_id {
            for key in &builder.keys {
                if let IndexKey::Search {
                    property: Property::MemberTenantId,
                    value,
                } = key
                    && value != &IndexValue::U64(tenant_id as u64)
                {
                    return Some(RegistryWriteResult::InvalidTenantId);
                }
            }
        }
        if let Some(account_id) = self.current_account_id {
            for key in &builder.keys {
                if let IndexKey::Search {
                    property: Property::AccountId,
                    value,
                } = key
                    && value != &IndexValue::U64(account_id as u64)
                {
                    return Some(RegistryWriteResult::InvalidTenantId);
                }
            }
        }

        None
    }
}

trait FindTenantId {
    fn tenant_id(&self) -> Option<u32>;
}

impl FindTenantId for IndexBuilder<'_> {
    fn tenant_id(&self) -> Option<u32> {
        self.keys.iter().find_map(|key| {
            if let IndexKey::Search {
                property: Property::MemberTenantId,
                value: IndexValue::U64(tenant_id),
            } = key
            {
                Some(*tenant_id as u32)
            } else {
                None
            }
        })
    }
}

impl Display for RegistryWriteResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryWriteResult::Success(id) => write!(f, "Success: {}", id),
            RegistryWriteResult::CannotDeleteLinked {
                object_id,
                linked_objects,
            } => {
                write!(f, "Cannot delete {} because it is linked to: ", object_id)?;
                for linked in linked_objects {
                    write!(f, "{}, ", linked)?;
                }
                Ok(())
            }
            RegistryWriteResult::InvalidSingletonId => write!(f, "Invalid singleton id"),
            RegistryWriteResult::CannotDeleteSingleton => write!(f, "Cannot delete singleton"),
            RegistryWriteResult::NotFound { object_id } => write!(f, "Not found: {}", object_id),
            RegistryWriteResult::InvalidForeignKey { object_id } => {
                write!(f, "Invalid foreign key: {}", object_id)
            }
            RegistryWriteResult::PrimaryKeyConflict {
                property,
                existing_id,
            } => {
                write!(
                    f,
                    "Primary key conflict on property {:?} with existing object {}",
                    property.as_str(),
                    existing_id
                )
            }
            RegistryWriteResult::ValidationError { errors } => {
                write!(f, "Validation error: ")?;
                for error in errors {
                    write!(f, "{}, ", error)?;
                }
                Ok(())
            }
            RegistryWriteResult::InvalidTenantId => write!(f, "Invalid tenant id"),
            RegistryWriteResult::InvalidAccountId => write!(f, "Invalid account id"),
            RegistryWriteResult::NotSupported => write!(f, "Operation not supported"),
        }
    }
}
