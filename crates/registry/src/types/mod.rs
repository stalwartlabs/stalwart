/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    pickle::{Pickle, maybe_compress_pickle},
    schema::prelude::ObjectType,
    types::{error::ValidationError, index::IndexBuilder},
};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;

pub mod datetime;
pub mod duration;
pub mod error;
pub mod float;
pub mod id;
pub mod index;
pub mod ipaddr;
pub mod ipmask;
pub mod list;
pub mod map;
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
    const VERSION: u8;

    fn validate(&self, errors: &mut Vec<ValidationError>) -> bool;
    fn index<'x>(&'x self, builder: &mut IndexBuilder<'x>);
    fn to_pickled_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(Self::VERSION);
        self.pickle(&mut out);
        maybe_compress_pickle(out)
    }
}
