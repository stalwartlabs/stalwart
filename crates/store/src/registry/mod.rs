/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bootstrap;
pub mod get;
pub mod local;
pub mod query;
pub mod write;

use registry::{
    schema::prelude::{ObjectType, Property},
    types::{ObjectImpl, id::ObjectId},
};

pub struct RegistryObject<T: ObjectImpl> {
    pub id: ObjectId,
    pub object: T,
    pub revision: u32,
}

pub struct RegistryQuery {
    pub object_type: ObjectType,
    pub filters: Vec<RegistryFilter>,
    pub account_id: Option<u32>,
    pub tenant_id: Option<u32>,
}

pub struct RegistryFilter {
    pub property: Property,
    pub op: RegistryFilterOp,
    pub value: RegistryFilterValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryFilterOp {
    Equal,
    GreaterThan,
    GreaterEqualThan,
    LowerThan,
    LowerEqualThan,
    TextMatch,
}

pub enum RegistryFilterValue {
    String(String),
    U64(u64),
    U16(u16),
    Boolean(bool),
}
