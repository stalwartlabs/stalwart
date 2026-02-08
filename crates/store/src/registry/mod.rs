/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bootstrap;
pub mod query;

use registry::{
    schema::prelude::{Object, Property},
    types::{ObjectType, id::Id},
};

pub struct RegistryObject<T: ObjectType> {
    pub id: Id,
    pub object: T,
}

pub struct RegistryQuery {
    pub object_type: Object,
    pub filters: Vec<RegistryFilter>,
}

pub struct RegistryFilter {
    pub property: Property,
    pub op: RegistryFilterOp,
    pub value: RegistryFilterValue,
}

pub enum RegistryFilterOp {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    TextMatch,
}

pub enum RegistryFilterValue {
    String(String),
    Integer(u64),
    Boolean(bool),
}
