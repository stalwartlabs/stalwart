/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, Store, registry::RegistryObject};
use registry::{
    pickle::Pickle,
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
    pub notices: Vec<trc::Error>,
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
            notices: Vec::new(),
            has_fatal_errors: false,
            role: None,
        }
    }

    pub fn with_data_store(mut self, data_store: Store) -> Self {
        self.data_store = data_store;
        self
    }

    pub async fn setting<T: ObjectImpl + From<Object>>(&mut self) -> trc::Result<T> {
        let object_id = T::OBJECT.singleton();
        Ok(self
            .registry
            .get(object_id)
            .await?
            .map(T::from)
            .filter(|setting| self.validate(object_id, setting))
            .unwrap_or_default())
    }

    pub async fn setting_infallible<T: ObjectImpl + From<Object>>(&mut self) -> T {
        let object_id = T::OBJECT.singleton();
        self.fetch_object(object_id)
            .await
            .map(T::from)
            .filter(|setting| self.validate(object_id, setting))
            .unwrap_or_default()
    }

    pub async fn get_infallible<T: ObjectImpl + From<Object>>(&mut self, id: Id) -> Option<T> {
        let object_id = ObjectId::new(T::OBJECT, id);
        self.fetch_existing_object(object_id)
            .await
            .map(T::from)
            .filter(|setting| self.validate(object_id, setting))
    }

    pub async fn list_infallible<T: ObjectImpl + Pickle + From<Object>>(
        &mut self,
    ) -> Vec<RegistryObject<T>> {
        match self.registry.list::<T>().await {
            Ok(objects) => objects
                .into_iter()
                .filter(|object| self.validate(object.id, &object.object))
                .collect(),
            Err(err) => {
                self.internal_error(None, err);
                Vec::new()
            }
        }
    }

    async fn fetch_object(&mut self, object_id: ObjectId) -> Option<Object> {
        match self.registry.get(object_id).await {
            Ok(object) => object,
            Err(err) => {
                self.internal_error(Some(object_id), err);
                None
            }
        }
    }

    async fn fetch_existing_object(&mut self, object_id: ObjectId) -> Option<Object> {
        match self.registry.get(object_id).await {
            Ok(Some(object)) => Some(object),
            Ok(None) => {
                self.errors.push(Error::NotFound { object_id });
                None
            }
            Err(err) => {
                self.internal_error(Some(object_id), err);
                None
            }
        }
    }

    fn internal_error(&mut self, object_id: Option<ObjectId>, error: trc::Error) {
        if !self.has_fatal_errors {
            self.errors.push(Error::Internal { object_id, error });
            self.has_fatal_errors = true;
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

    pub fn log_notices(&mut self) {
        for notice in self.notices.drain(..) {
            trc::error!(notice);
        }
    }
}
