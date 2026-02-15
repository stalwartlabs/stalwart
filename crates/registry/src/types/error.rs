/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::JsonPointerPatch,
    schema::prelude::{Object, Property},
    types::id::ObjectId,
};
use std::{borrow::Cow, fmt::Display};

#[derive(Debug, Clone, PartialEq, Eq)]
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
    TypeMismatch {
        object_id: ObjectId,
        object_type: Object,
        expected_type: Object,
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
