/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, Store, registry::RegistryObject};
use registry::{
    schema::{
        prelude::Property,
        structs::{LocalSettings, Node},
    },
    types::{
        EnumType, ObjectType,
        error::{Error, ValidationError, Warning},
        id::ObjectId,
    },
};

pub struct Bootstrap {
    pub registry: RegistryStore,
    pub data_store: Store,
    pub errors: Vec<Error>,
    pub warnings: Vec<Warning>,
    pub has_fatal_errors: bool,
    pub node: Node,
    pub local: LocalSettings,
}

impl Bootstrap {
    pub fn new(registry: RegistryStore) -> Self {
        Self {
            registry,
            errors: Vec::new(),
            warnings: Vec::new(),
            has_fatal_errors: false,
            node: Node::default(),
            local: LocalSettings::default(),
            data_store: Store::None,
        }
    }

    pub async fn setting<T: ObjectType>(&mut self) -> trc::Result<T> {
        let object_id = T::object().singleton();

        if let Some(setting) = self.registry.object::<T>(object_id.id()).await? {
            let mut errors = Vec::new();
            if setting.validate(&mut errors) {
                return Ok(setting);
            }
            self.errors.push(Error::Validation { object_id, errors });
        }

        Ok(T::default())
    }

    pub async fn setting_infallible<T: ObjectType>(&mut self) -> T {
        match self.setting::<T>().await {
            Ok(setting) => setting,
            Err(err) => {
                if !self.has_fatal_errors {
                    self.errors.push(Error::Internal {
                        object_id: Some(T::object().singleton()),
                        error: err,
                    });
                    self.has_fatal_errors = true;
                }
                T::default()
            }
        }
    }

    pub async fn get_infallible<T: ObjectType>(&mut self, id: impl Into<u64>) -> Option<T> {
        let id = id.into();
        match self.registry.object::<T>(id).await {
            Ok(Some(setting)) => {
                let mut errors = Vec::new();
                if setting.validate(&mut errors) {
                    Some(setting)
                } else {
                    self.errors.push(Error::Validation {
                        object_id: ObjectId::new(T::object(), id),
                        errors,
                    });
                    None
                }
            }
            Ok(None) => {
                self.errors.push(Error::NotFound {
                    object_id: ObjectId::new(T::object(), id),
                });
                None
            }
            Err(err) => {
                if !self.has_fatal_errors {
                    self.errors.push(Error::Internal {
                        object_id: Some(ObjectId::new(T::object(), id)),
                        error: err,
                    });
                    self.has_fatal_errors = true;
                }
                None
            }
        }
    }

    pub async fn list_infallible<T: ObjectType>(&mut self) -> Vec<RegistryObject<T>> {
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

    pub fn validate(&mut self, id: ObjectId, object: &impl ObjectType) -> bool {
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

    pub fn node_id(&self) -> u64 {
        self.node.node_id
    }

    pub fn hostname(&self) -> &str {
        &self.node.hostname
    }

    pub fn log_errors(&self) {
        for error in &self.errors {
            match error {
                Error::Validation { object_id, errors } => {
                    trc::event!(
                        Registry(trc::RegistryEvent::ValidationError),
                        Source = object_id.object().as_str(),
                        Id = object_id.id(),
                        Reason = errors
                            .iter()
                            .map(|err| trc::Value::from(err.to_string()))
                            .collect::<Vec<_>>(),
                    );
                }
                Error::Build { object_id, message } => {
                    trc::event!(
                        Registry(trc::RegistryEvent::BuildError),
                        Source = object_id.object().as_str(),
                        Id = object_id.id(),
                        Reason = message.clone(),
                    );
                }
                Error::Internal { object_id, error } => {
                    trc::event!(
                        Registry(trc::RegistryEvent::ReadError),
                        Source = object_id.as_ref().map(|id| id.object().as_str()),
                        Id = object_id.as_ref().map(|id| id.id()),
                        CausedBy = error.clone(),
                    );
                }
                Error::NotFound { object_id } => {
                    trc::event!(
                        Registry(trc::RegistryEvent::BuildError),
                        Source = object_id.object().as_str(),
                        Id = object_id.id(),
                        Reason = "Object not found",
                    );
                }
            }
        }
    }

    pub fn log_warnings(&self) {
        for warning in &self.warnings {
            trc::event!(
                Registry(trc::RegistryEvent::BuildWarning),
                Source = warning.object_id.object().as_str(),
                Id = warning.object_id.id(),
                Key = warning.property.map(|key| key.as_str()),
                Reason = warning.message.clone(),
            );
        }
    }
}
