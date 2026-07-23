/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::{get::GetResponse, query::QueryRequest, set::SetResponse},
    object::registry::Registry,
};
use jmap_tools::Map;
use registry::{
    jmap::{JmapValue, RegistryValue},
    schema::prelude::{ObjectType, Property},
    types::error::Error,
};
use std::net::IpAddr;
use store::ahash::AHashSet;
use types::id::Id;
use utils::map::vec_map::VecMap;

pub mod account;
pub mod action;
pub mod bootstrap;
pub mod cluster;
pub mod dkim;
pub mod domain;
pub mod log;
pub mod principal;
pub mod public_key;
pub mod queued_message;
pub mod report;
pub mod sieve;
pub mod spam_sample;
pub mod task;
pub mod tls;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod masked_email;

#[cfg(feature = "enterprise")]
pub mod archived_item;

#[cfg(feature = "enterprise")]
pub mod telemetry;
// SPDX-SnippetEnd

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
    pub remote_ip: IpAddr,
    pub access_token: &'x AccessToken,
    pub account_id: u32,
    pub create: VecMap<String, JmapValue<'x>>,
    pub update: Vec<(Id, JmapValue<'x>)>,
    pub destroy: Vec<Id>,
    pub response: SetResponse<Registry>,
    pub object_type: ObjectType,
    pub is_tenant_filtered: bool,
    pub is_account_filtered: bool,
}

pub(crate) struct RegistryQueryResponse<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub object_type: ObjectType,
    pub request: QueryRequest<Registry>,
}

pub type ValidationResult = trc::Result<Result<ObjectResponse, SetError<Property>>>;

pub struct ObjectResponse {
    pub id: Option<Id>,
    pub object: Map<'static, Property, RegistryValue>,
}

impl ObjectResponse {
    pub fn new(id: Id, object: Map<'static, Property, RegistryValue>) -> Self {
        Self {
            id: Some(id),
            object,
        }
    }
}

impl Default for ObjectResponse {
    fn default() -> Self {
        Self {
            id: None,
            object: Map::with_capacity(1),
        }
    }
}

pub(crate) fn map_bootstrap_error(error: Vec<Error>) -> SetError<Property> {
    match error.into_iter().next().unwrap() {
        Error::Validation { object_id, errors } => SetError::new(SetErrorType::ValidationFailed)
            .with_validation_errors(errors)
            .with_object_id(object_id),
        Error::Build { object_id, message } => SetError::new(SetErrorType::ValidationFailed)
            .with_description(message)
            .with_object_id(object_id),
        Error::Internal { object_id, error } => SetError::new(SetErrorType::Forbidden)
            .with_description(error.to_string())
            .with_object_id_opt(object_id),
        Error::NotFound { object_id } => {
            SetError::new(SetErrorType::NotFound).with_object_id(object_id)
        }
    }
}
