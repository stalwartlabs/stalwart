/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{
    schema::{prelude::Property, structs::Node},
    types::{
        ObjectType,
        error::{Error, ValidationError, Warning},
        id::Id,
    },
};
use store::{RegistryStore, registry::RegistryObject};

pub struct Bootstrap {
    pub registry: RegistryStore,
    pub errors: Vec<Error>,
    pub warnings: Vec<Warning>,
    pub has_fatal_errors: bool,
    pub node: Node,
}

impl Bootstrap {
    pub fn new(registry: RegistryStore) -> Self {
        Self {
            registry,
            errors: Vec::new(),
            warnings: Vec::new(),
            has_fatal_errors: false,
            node: Node::default(),
        }
    }

    pub async fn setting<T: ObjectType>(&mut self) -> trc::Result<T> {
        let object_id = T::object().singleton();

        if let Some(setting) = self.registry.get::<T>(object_id).await? {
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

    pub fn build_error(&mut self, id: Id, message: impl Into<String>) {
        self.errors.push(Error::Build {
            object_id: id,
            message: message.into(),
        });
    }

    pub fn build_warning(&mut self, id: Id, message: impl Into<String>) {
        self.warnings.push(Warning {
            object_id: id,
            property: None,
            message: message.into(),
        });
    }

    pub fn invalid_property(&mut self, id: Id, property: Property, value: impl Into<String>) {
        self.errors.push(Error::Validation {
            object_id: id,
            errors: vec![ValidationError::Invalid {
                property,
                value: value.into(),
            }],
        });
    }

    pub fn validate(&mut self, id: Id, object: &impl ObjectType) -> bool {
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
}
