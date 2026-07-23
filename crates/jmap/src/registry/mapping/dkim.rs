/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{
    ObjectResponse, RegistrySetResponse, ValidationResult, principal::validate_tenant_quota,
};
use common::config::smtp::auth::DkimSigners;
use jmap_proto::error::set::SetError;
use registry::schema::{enums::TenantStorageQuota, structs::DkimSignature};

pub(crate) async fn validate_dkim_signature(
    set: &RegistrySetResponse<'_>,
    key: &mut DkimSignature,
    old_key: Option<&DkimSignature>,
) -> ValidationResult {
    let response = if old_key.is_none() {
        match validate_tenant_quota(set, TenantStorageQuota::MaxDkimKeys).await? {
            Ok(response) => response,
            Err(err) => {
                return Ok(Err(err));
            }
        }
    } else {
        ObjectResponse::default()
    };

    if old_key.is_none_or(|old_key| old_key.private_key() != key.private_key())
        && let Err(err) = DkimSigners::default()
            .insert("example.com".to_string(), key.clone())
            .await
    {
        return Ok(Err(SetError::invalid_properties().with_description(
            format!("Failed to validate DKIM signature: {err}"),
        )));
    }

    Ok(Ok(response))
}
