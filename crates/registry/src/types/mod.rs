/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{pickle::Pickle, schema::prelude::Object, types::error::ValidationError};

pub mod datetime;
pub mod duration;
pub mod error;
pub mod id;
pub mod ipaddr;
pub mod ipmask;
pub mod socketaddr;

pub trait EnumType: Sized {
    fn parse(s: &str) -> Option<Self>;
    fn as_str(&self) -> &'static str;
    fn from_id(id: u16) -> Option<Self>;
    fn to_id(&self) -> u16;
}

pub trait ObjectType: Pickle + Default + Clone + Send + Sync {
    fn object() -> Object;
    fn validate(&self, errors: &mut Vec<ValidationError>) -> bool;
}
