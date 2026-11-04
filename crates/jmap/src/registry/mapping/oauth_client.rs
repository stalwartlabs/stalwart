/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ObjectResponse, ValidationResult};
use common::{
    Server,
    auth::{AccessToken, oauth::registration::validate_oauth_client},
};
use directory::core::secret::{hash_secret, is_password_hash};
use jmap_proto::error::set::SetError;
use registry::schema::{enums::Permission, prelude::Property, structs::OAuthClient};
use trc::AddContext;

pub fn is_superuser(access_token: &AccessToken) -> bool {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let is_tenant_member = access_token.tenant_id().is_some();
    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    let is_tenant_member = false;
    !is_tenant_member && access_token.has_permission(Permission::Impersonate)
}

#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
pub async fn validate_oauth_client_object(
    server: &Server,
    access_token: &AccessToken,
    client: &mut OAuthClient,
) -> ValidationResult {
    let is_superuser = is_superuser(access_token);
    if let Err((property, err)) = validate_oauth_client(client, is_superuser) {
        return Ok(Err(SetError::invalid_properties()
            .with_property(property)
            .with_description(err.error_description.unwrap_or(err.error))));
    }
    if !is_superuser
        && server
            .inner
            .data
            .applications
            .is_application_client_id(&client.client_id)
    {
        return Ok(Err(SetError::invalid_properties()
            .with_property(Property::ClientId)
            .with_description(
                "Only a superuser can register the client id of a web application.",
            )));
    }

    if let Some(secret) = client.secret.as_mut()
        && !secret.is_empty()
        && !(matches!(secret.as_bytes().first(), Some(&b'$' | &b'{')) && is_password_hash(secret))
    {
        *secret = hash_secret(
            &server.inner.data.password_verifier,
            server.core.network.security.password_hash_algorithm,
            std::mem::take(secret).into_bytes(),
        )
        .await
        .caused_by(trc::location!())?;
    }

    Ok(Ok(ObjectResponse::default()))
}
