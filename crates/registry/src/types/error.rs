/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::JsonPointerPatch,
    schema::prelude::Property,
    types::{EnumImpl, id::ObjectId},
};
use std::{borrow::Cow, fmt::Display};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum ValidationError {
    Invalid { property: Property, value: String },
    Required { property: Property },
    MaxLength { property: Property, required: usize },
    MinLength { property: Property, required: usize },
    MaxValue { property: Property, required: i64 },
    MinValue { property: Property, required: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Validation {
        object_id: ObjectId,
        errors: Vec<ValidationError>,
    },
    Build {
        object_id: ObjectId,
        message: String,
    },
    Internal {
        object_id: Option<ObjectId>,
        error: trc::Error,
    },
    NotFound {
        object_id: ObjectId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchError {
    pub path: String,
    pub message: Cow<'static, str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub object_id: ObjectId,
    pub property: Option<Property>,
    pub message: String,
}

impl ValidationError {
    pub fn required(property: Property) -> Self {
        Self::Required { property }
    }

    pub fn invalid(property: Property, value: impl Display) -> Self {
        Self::Invalid {
            property,
            value: value.to_string(),
        }
    }

    pub fn min_items(property: Property, required: usize) -> Self {
        Self::MinLength { property, required }
    }

    pub fn max_items(property: Property, required: usize) -> Self {
        Self::MaxLength { property, required }
    }

    pub fn max_length(property: Property, required: usize) -> Self {
        Self::MaxLength { property, required }
    }

    pub fn min_length(property: Property, required: usize) -> Self {
        Self::MinLength { property, required }
    }

    pub fn max_value(property: Property, required: i64) -> Self {
        Self::MaxValue { property, required }
    }

    pub fn min_value(property: Property, required: i64) -> Self {
        Self::MinValue { property, required }
    }
}

impl Warning {
    pub fn new(object_id: ObjectId, message: impl Display) -> Self {
        Self {
            object_id,
            property: None,
            message: message.to_string(),
        }
    }

    pub fn for_property(object_id: ObjectId, property: Property, message: impl Display) -> Self {
        Self {
            object_id,
            property: Some(property),
            message: message.to_string(),
        }
    }

    pub fn log(&self) {
        trc::event!(
            Registry(trc::RegistryEvent::BuildWarning),
            Source = self.object_id.object().as_str(),
            Id = self.object_id.id().id(),
            Key = self.property.map(|key| key.as_str()),
            Reason = self.message.clone(),
        );
    }
}

impl Error {
    pub fn log(&self) {
        match self {
            Error::Validation { object_id, errors } => {
                trc::event!(
                    Registry(trc::RegistryEvent::ValidationError),
                    Source = object_id.object().as_str(),
                    Id = object_id.id().id(),
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
                    Id = object_id.id().id(),
                    Reason = message.clone(),
                );
            }
            Error::Internal { object_id, error } => {
                trc::event!(
                    Registry(trc::RegistryEvent::ReadError),
                    Source = object_id.as_ref().map(|id| id.object().as_str()),
                    Id = object_id.as_ref().map(|id| id.id().id()),
                    CausedBy = error.clone(),
                );
            }
            Error::NotFound { object_id } => {
                trc::event!(
                    Registry(trc::RegistryEvent::BuildError),
                    Source = object_id.object().as_str(),
                    Id = object_id.id().id(),
                    Reason = "Object not found",
                );
            }
        }
    }
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::Invalid { property, value } => {
                write!(f, "Invalid value '{}' for property '{}'", value, property)
            }
            ValidationError::Required { property } => {
                write!(f, "Property '{}' is required", property)
            }
            ValidationError::MaxLength { property, required } => {
                write!(
                    f,
                    "Property '{}' exceeds maximum length of {}",
                    property, required
                )
            }
            ValidationError::MinLength { property, required } => {
                write!(
                    f,
                    "Property '{}' is below minimum length of {}",
                    property, required
                )
            }
            ValidationError::MaxValue { property, required } => {
                write!(
                    f,
                    "Property '{}' exceeds maximum value of {}",
                    property, required
                )
            }
            ValidationError::MinValue { property, required } => {
                write!(
                    f,
                    "Property '{}' is below minimum value of {}",
                    property, required
                )
            }
        }
    }
}

impl PatchError {
    pub fn new(path: JsonPointerPatch<'_>, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            path: path.path(),
            message: message.into(),
        }
    }
}
