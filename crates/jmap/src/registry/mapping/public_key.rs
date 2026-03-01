/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, RegistrySetResponse, ValidationResult};
use jmap_proto::error::set::SetError;
use registry::{
    jmap::JmapValue,
    schema::{
        enums::StorageQuota,
        prelude::{ObjectType, Property},
        structs::PublicKey,
    },
};
use store::{ahash::AHashSet, registry::RegistryQuery};
use utils::map::vec_map::VecMap;

pub(crate) async fn validate_public_key(
    set: &RegistrySetResponse<'_>,
    key: &mut PublicKey,
    old_key: Option<&PublicKey>,
    unpatched_properties: VecMap<Property, JmapValue<'_>>,
) -> ValidationResult {
    let mut response = ObjectResponse::default();

    let todo = "validate key";

    if old_key.is_none() {
        // Validate quotas
        let num_masked = set
            .server
            .registry()
            .count(RegistryQuery::new(ObjectType::PublicKey).with_account(set.account_id))
            .await? as u32;
        let account = set.server.account(set.account_id).await?;
        let masked_quota = set
            .server
            .object_quota(account.object_quotas(), StorageQuota::MaxPublicKeys);
        if num_masked >= masked_quota {
            return Ok(Err(SetError::over_quota().with_description(format!(
                "You have exceeded your quota of {} public keys.",
                masked_quota
            ))));
        }
    }

    todo!()
}
