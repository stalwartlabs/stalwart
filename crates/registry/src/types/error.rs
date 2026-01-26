/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{schema::prelude::Property, types::id::Id};
use std::fmt::Display;

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
        object_id: Id,
        errors: Vec<ValidationError>,
    },
    Build {
        object_id: Id,
        message: String,
    },
    Internal {
        object_id: Option<Id>,
        error: trc::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub object_id: Id,
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
    pub fn new(object_id: Id, message: impl Display) -> Self {
        Self {
            object_id,
            property: None,
            message: message.to_string(),
        }
    }

    pub fn for_property(object_id: Id, property: Property, message: impl Display) -> Self {
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
