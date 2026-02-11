/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub use crate::pickle::Pickle;
pub use crate::schema::enums::*;
pub use crate::schema::properties::*;
pub use crate::schema::structs::*;
pub use crate::types::EnumType;
pub use crate::types::ObjectIndex;
pub use crate::types::ObjectType;
pub use crate::types::datetime::UTCDateTime;
pub use crate::types::duration::Duration;
pub use crate::types::error::*;
pub use crate::types::id::Id;
pub use crate::types::index::IndexBuilder;
pub use crate::types::ipaddr::IpAddr;
pub use crate::types::ipmask::IpAddrOrMask;
pub use crate::types::socketaddr::SocketAddr;
pub use serde::{Deserialize, Serialize};
pub use std::str::FromStr;
pub use utils::map::vec_map::VecMap;

#[derive(Debug)]
pub struct ExpressionContext<'x> {
    pub expr: &'x Expression,
    pub default: Option<Expression>,
    pub property: Property,
    pub allowed_variables: &'static [ExpressionVariable],
    pub allowed_constants: &'static [ExpressionConstant],
}
