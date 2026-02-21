/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    pickle::Pickle,
    schema::prelude::ObjectType,
    types::{error::ValidationError, index::IndexBuilder},
};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;

pub mod datetime;
pub mod duration;
pub mod error;
pub mod id;
pub mod index;
pub mod ipaddr;
pub mod ipmask;
pub mod socketaddr;
pub mod string;

pub trait EnumImpl: Sized + Debug + PartialEq + Eq {
    const COUNT: usize;

    fn parse(s: &str) -> Option<Self>;
    fn as_str(&self) -> &'static str;
    fn from_id(id: u16) -> Option<Self>;
    fn to_id(&self) -> u16;
}

pub trait ObjectImpl:
    Pickle + Serialize + DeserializeOwned + Default + Clone + Send + Sync
{
    const FLAGS: u64;
    const OBJECT: ObjectType;

    fn validate(&self, errors: &mut Vec<ValidationError>) -> bool;
    fn index<'x>(&'x self, builder: &mut IndexBuilder<'x>);
}
