/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::Property;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorType {
    Invalid,
    Required,
    MinItems(usize),
    MaxItems(usize),
    MaxLength(usize),
    MinLength(usize),
    MaxValue(i64),
    MinValue(i64),
}

pub struct ValidationError {
    pub property: Property,
    pub typ: ValidationErrorType,
}

impl ValidationError {
    pub fn new(property: Property, typ: ValidationErrorType) -> Self {
        Self { property, typ }
    }

    pub fn required(property: Property) -> Self {
        Self {
            property,
            typ: ValidationErrorType::Required,
        }
    }

    pub fn invalid(property: Property) -> Self {
        Self {
            property,
            typ: ValidationErrorType::Invalid,
        }
    }

    pub fn min_items(property: Property, value: usize) -> Self {
        Self {
            property,
            typ: ValidationErrorType::MinItems(value),
        }
    }

    pub fn max_items(property: Property, value: usize) -> Self {
        Self {
            property,
            typ: ValidationErrorType::MaxItems(value),
        }
    }

    pub fn max_length(property: Property, value: usize) -> Self {
        Self {
            property,
            typ: ValidationErrorType::MaxLength(value),
        }
    }

    pub fn min_length(property: Property, value: usize) -> Self {
        Self {
            property,
            typ: ValidationErrorType::MinLength(value),
        }
    }

    pub fn max_value(property: Property, value: i64) -> Self {
        Self {
            property,
            typ: ValidationErrorType::MaxValue(value),
        }
    }

    pub fn min_value(property: Property, value: i64) -> Self {
        Self {
            property,
            typ: ValidationErrorType::MinValue(value),
        }
    }
}
