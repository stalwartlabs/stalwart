/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::{get::GetResponse, set::SetResponse},
    object::registry::Registry,
};
use registry::{
    jmap::JmapValue,
    schema::prelude::{ObjectType, Property},
};
use store::ahash::AHashSet;
use types::id::Id;
use utils::map::vec_map::VecMap;

pub mod account;
pub mod deleted_item;
pub mod log;
pub mod queued_message;
pub mod report;
pub mod spam_sample;
pub mod task;
pub mod telemetry;

pub(crate) struct RegistryGetResponse<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub account_id: u32,
    pub ids: Option<Vec<Id>>,
    pub properties: AHashSet<Property>,
    pub response: GetResponse<Registry>,
    pub object_type: ObjectType,
    pub object_flags: u64,
    pub is_tenant_filtered: bool,
    pub is_account_filtered: bool,
}

pub(crate) struct RegistrySetResponse<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub account_id: u32,
    pub create: VecMap<String, JmapValue<'x>>,
    pub update: Vec<(Id, JmapValue<'x>)>,
    pub destroy: Vec<Id>,
    pub response: SetResponse<Registry>,
    pub object_type: ObjectType,
    pub object_flags: u64,
    pub is_tenant_filtered: bool,
    pub is_account_filtered: bool,
}
