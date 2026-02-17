/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
pub use crate::jmap::{
    JsonPointerPatch, RegistryJsonEnumPatch, RegistryJsonPatch, RegistryJsonPropertyPatch,
    object_type,
};
pub use crate::pickle::Pickle;
pub use crate::schema::enums::*;
pub use crate::schema::properties::*;
pub use crate::schema::structs::*;
pub use crate::types::EnumType;
pub use crate::types::ObjectType;
pub use crate::types::datetime::UTCDateTime;
pub use crate::types::duration::Duration;
pub use crate::types::error::*;
pub use crate::types::index::IndexBuilder;
pub use crate::types::ipaddr::IpAddr;
pub use crate::types::ipmask::IpAddrOrMask;
pub use crate::types::socketaddr::SocketAddr;
pub use crate::types::string::StringValidator;
pub use serde::{Deserialize, Serialize};
pub use std::str::FromStr;
pub use types::id::Id;
pub use utils::map::vec_map::VecMap;

#[derive(Debug)]
pub struct ExpressionContext<'x> {
    pub expr: &'x Expression,
    pub default: Option<Expression>,
    pub property: Property,
    pub allowed_variables: &'static [ExpressionVariable],
    pub allowed_constants: &'static [ExpressionConstant],
}

pub const OBJ_SINGLETON: u64 = 1;
pub const OBJ_SEQ_ID: u64 = 1 << 1;
pub const OBJ_FILTER_ACCOUNT: u64 = 1 << 2;
pub const OBJ_FILTER_TENANT: u64 = 1 << 3;
