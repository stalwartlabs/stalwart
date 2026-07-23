/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, Store, registry::RegistryObject};
use registry::{
    schema::{
        prelude::{Object, ObjectType, Property},
        structs::ClusterRole,
    },
    types::{
        ObjectImpl,
        error::{Error, ValidationError, Warning},
        id::ObjectId,
    },
};
use types::id::Id;

pub struct Bootstrap {
    pub registry: RegistryStore,
    pub data_store: Store,
    pub errors: Vec<Error>,
    pub warnings: Vec<Warning>,
    pub has_fatal_errors: bool,
    pub role: Option<ClusterRole>,
}

impl Bootstrap {
    pub async fn new(registry: RegistryStore) -> Self {
        let mut bp = Self::new_uninitialized(registry);

        let Some(role_name) = bp.registry.cluster_role().map(|r| r.to_string()) else {
            return bp;
        };

        for role in bp.list_infallible::<ClusterRole>().await {
            if role.object.name == role_name {
                bp.role = Some(role.object);
                return bp;
            }
        }

        bp.build_error(
            ObjectType::ClusterRole.singleton(),
            format!("Cluster role \"{role_name}\" not found in registry"),
        );

        bp
    }

    pub fn new_uninitialized(registry: RegistryStore) -> Self {
        Self {
            data_store: registry.0.store.clone(),
            registry,
            errors: Vec::new(),
            warnings: Vec::new(),
            has_fatal_errors: false,
            role: None,
        }
    }

    pub async fn setting<T: ObjectImpl + From<Object>>(&mut self) -> trc::Result<T> {
        let object_id = T::OBJECT.singleton();

        if let Some(setting) = self.registry.object::<T>(object_id.id()).await? {
            let mut errors = Vec::new();
            if setting.validate(&mut errors) {
                return Ok(setting);
            }
            self.errors.push(Error::Validation { object_id, errors });
        }

        Ok(T::default())
    }

    pub async fn setting_infallible<T: ObjectImpl + From<Object>>(&mut self) -> T {
        match self.setting::<T>().await {
            Ok(setting) => setting,
            Err(err) => {
                if !self.has_fatal_errors {
                    self.errors.push(Error::Internal {
                        object_id: Some(T::OBJECT.singleton()),
                        error: err,
                    });
                    self.has_fatal_errors = true;
                }
                T::default()
            }
        }
    }

    pub async fn get_infallible<T: ObjectImpl + From<Object>>(&mut self, id: Id) -> Option<T> {
        match self.registry.object::<T>(id).await {
            Ok(Some(setting)) => {
                let mut errors = Vec::new();
                if setting.validate(&mut errors) {
                    Some(setting)
                } else {
                    self.errors.push(Error::Validation {
                        object_id: ObjectId::new(T::OBJECT, id),
                        errors,
                    });
                    None
                }
            }
            Ok(None) => {
                self.errors.push(Error::NotFound {
                    object_id: ObjectId::new(T::OBJECT, id),
                });
                None
            }
            Err(err) => {
                if !self.has_fatal_errors {
                    self.errors.push(Error::Internal {
                        object_id: Some(ObjectId::new(T::OBJECT, id)),
                        error: err,
                    });
                    self.has_fatal_errors = true;
                }
                None
            }
        }
    }

    pub async fn list_infallible<T: ObjectImpl + From<Object>>(
        &mut self,
    ) -> Vec<RegistryObject<T>> {
        match self.registry.list::<T>().await {
            Ok(objects) => objects
                .into_iter()
                .filter(|object| self.validate(object.id, &object.object))
                .collect(),
            Err(err) => {
                if !self.has_fatal_errors {
                    self.errors.push(Error::Internal {
                        object_id: None,
                        error: err,
                    });
                    self.has_fatal_errors = true;
                }
                Vec::new()
            }
        }
    }

    pub fn build_error(&mut self, id: ObjectId, message: impl Into<String>) {
        self.errors.push(Error::Build {
            object_id: id,
            message: message.into(),
        });
    }

    pub fn build_warning(&mut self, id: ObjectId, message: impl Into<String>) {
        self.warnings.push(Warning {
            object_id: id,
            property: None,
            message: message.into(),
        });
    }

    pub fn invalid_property(&mut self, id: ObjectId, property: Property, value: impl Into<String>) {
        self.errors.push(Error::Validation {
            object_id: id,
            errors: vec![ValidationError::Invalid {
                property,
                value: value.into(),
            }],
        });
    }

    pub fn validate(&mut self, id: ObjectId, object: &impl ObjectImpl) -> bool {
        let mut errors = Vec::new();
        if object.validate(&mut errors) {
            true
        } else {
            self.errors.push(Error::Validation {
                object_id: id,
                errors,
            });
            false
        }
    }

    pub fn node_id(&self) -> u16 {
        self.registry.0.node_id
    }

    pub fn log_errors(&self) {
        for error in &self.errors {
            error.log();
        }
    }

    pub fn log_warnings(&self) {
        for warning in &self.warnings {
            warning.log();
        }
    }
}
