/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    RegistryStore,
    registry::{RegistryFilter, RegistryFilterOp, RegistryFilterValue, RegistryQuery},
};
use registry::schema::prelude::{Object, Property};
use roaring::RoaringBitmap;

impl RegistryStore {
    pub async fn query<T: RegistryQueryResults>(&self, query: RegistryQuery) -> trc::Result<T> {
        todo!()
    }
}

pub trait RegistryQueryResults: Default {
    fn push(&mut self, id: u64);
}

impl RegistryQueryResults for Vec<u64> {
    fn push(&mut self, id: u64) {
        self.push(id);
    }
}

impl RegistryQueryResults for Vec<u32> {
    fn push(&mut self, id: u64) {
        self.push(id as u32);
    }
}

impl RegistryQueryResults for RoaringBitmap {
    fn push(&mut self, id: u64) {
        self.insert(id as u32);
    }
}

impl RegistryQuery {
    pub fn new(object_type: Object) -> Self {
        Self {
            object_type,
            filters: Vec::new(),
        }
    }

    pub fn equal(mut self, property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        self.filters.push(RegistryFilter::equal(property, value));
        self
    }

    pub fn equal_opt(
        mut self,
        property: Property,
        value: Option<impl Into<RegistryFilterValue>>,
    ) -> Self {
        if let Some(value) = value {
            self.filters.push(RegistryFilter::equal(property, value));
        }
        self
    }

    pub fn not_equal(mut self, property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        self.filters
            .push(RegistryFilter::not_equal(property, value));
        self
    }

    pub fn greater_than(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::greater_than(property, value));
        self
    }

    pub fn less_than(mut self, property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        self.filters
            .push(RegistryFilter::less_than(property, value));
        self
    }

    pub fn greater_than_or_equal(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::greater_than_or_equal(property, value));
        self
    }

    pub fn less_than_or_equal(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::less_than_or_equal(property, value));
        self
    }

    pub fn text(mut self, value: impl Into<String>) -> Self {
        self.filters.push(RegistryFilter::text(value));
        self
    }

    pub fn text_opt(mut self, value: Option<impl Into<String>>) -> Self {
        if let Some(value) = value {
            self.filters.push(RegistryFilter::text(value));
        }
        self
    }
}

impl RegistryFilter {
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            property: Property::Contents,
            op: RegistryFilterOp::TextMatch,
            value: RegistryFilterValue::String(value.into()),
        }
    }

    pub fn equal(property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::Equal,
            value: value.into(),
        }
    }

    pub fn not_equal(property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::NotEqual,
            value: value.into(),
        }
    }

    pub fn greater_than(property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::GreaterThan,
            value: value.into(),
        }
    }

    pub fn less_than(property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::LessThan,
            value: value.into(),
        }
    }

    pub fn greater_than_or_equal(
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::GreaterThanOrEqual,
            value: value.into(),
        }
    }

    pub fn less_than_or_equal(property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::LessThanOrEqual,
            value: value.into(),
        }
    }
}

impl From<String> for RegistryFilterValue {
    fn from(value: String) -> Self {
        RegistryFilterValue::String(value)
    }
}

impl From<u64> for RegistryFilterValue {
    fn from(value: u64) -> Self {
        RegistryFilterValue::Integer(value)
    }
}

impl From<u32> for RegistryFilterValue {
    fn from(value: u32) -> Self {
        RegistryFilterValue::Integer(value as u64)
    }
}
