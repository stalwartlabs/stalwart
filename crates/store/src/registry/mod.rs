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
    pickle::{Pickle, PickledStream},
    schema::prelude::{Object, Property},
    types::{ObjectType, id::ObjectId},
};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]

pub struct HashedObject<T> {
    pub hash: u64,
    pub object: T,
}

pub struct RegistryObject<T: ObjectType> {
    pub id: ObjectId,
    pub object: T,
}

pub struct RegistryQuery {
    pub object_type: Object,
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

impl<T: ObjectType> Pickle for HashedObject<T> {
    fn pickle(&self, out: &mut Vec<u8>) {
        self.object.pickle(out);
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let hash = xxhash_rust::xxh3::xxh3_64(stream.bytes());
        T::unpickle(stream).map(|object| Self { hash, object })
    }
}

impl<T: ObjectType> ObjectType for HashedObject<T> {
    const FLAGS: u64 = T::FLAGS;

    fn object() -> Object {
        T::object()
    }

    fn validate(&self, errors: &mut Vec<registry::schema::prelude::ValidationError>) -> bool {
        self.object.validate(errors)
    }

    fn index<'x>(&'x self, builder: &mut registry::schema::prelude::IndexBuilder<'x>) {
        self.object.index(builder)
    }
}
