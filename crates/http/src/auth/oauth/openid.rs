/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::oauth::SUPPORTED_SCOPES, auth::oauth::oidc::Userinfo};
use http_proto::*;
use serde::Serialize;
use std::future::Future;

#[derive(Debug, Serialize)]
pub struct OpenIdMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: String,
    pub device_authorization_endpoint: String,
    pub scopes_supported: &'static [&'static str],
    pub response_types_supported: &'static [&'static str],
    pub subject_types_supported: &'static [&'static str],
    pub grant_types_supported: &'static [&'static str],
    pub token_endpoint_auth_methods_supported: &'static [&'static str],
    pub id_token_signing_alg_values_supported: &'static [&'static str],
    pub claims_supported: &'static [&'static str],
    pub code_challenge_methods_supported: &'static [&'static str],
    pub authorization_response_iss_parameter_supported: bool,
}

pub trait OpenIdHandler: Sync + Send {
    fn handle_userinfo_request(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_oidc_metadata(
        &self,
        strip_base_url: bool,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl OpenIdHandler for Server {
    async fn handle_userinfo_request(&self, account_id: u32) -> trc::Result<HttpResponse> {
        let account = self.account(account_id).await?;

        Ok(JsonResponse::new(Userinfo {
            sub: Some(account_id.to_string()),
            name: account.description().map(|d| d.to_string()),
            preferred_username: Some(account.name().to_string()),
            email: account.name().to_string().into(),
            email_verified: true,
            ..Default::default()
        })
        .no_cache()
        .into_http_response())
    }

    async fn handle_oidc_metadata(&self, strip_base_url: bool) -> trc::Result<HttpResponse> {
        let base_url = if strip_base_url {
            #[cfg(feature = "dev_mode")]
            {
                "http://127.0.0.1:8080"
            }

            #[cfg(not(feature = "dev_mode"))]
            {
                ""
            }
        } else {
            &self.core.network.http.url_https
        };

        Ok(JsonResponse::new(OpenIdMetadata {
            authorization_endpoint: format!("{base_url}/login",),
            token_endpoint: format!("{base_url}/auth/token"),
            userinfo_endpoint: format!("{base_url}/auth/userinfo"),
            jwks_uri: format!("{base_url}/auth/jwks.json"),
            registration_endpoint: format!("{base_url}/auth/register"),
            device_authorization_endpoint: format!("{base_url}/auth/device"),
            response_types_supported: &["code"],
            grant_types_supported: &[
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            scopes_supported: SUPPORTED_SCOPES,
            subject_types_supported: &["public"],
            token_endpoint_auth_methods_supported: &[
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            id_token_signing_alg_values_supported: &[
                "RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384", "PS512", "HS256",
                "HS384", "HS512",
            ],
            claims_supported: &[
                "sub",
                "name",
                "preferred_username",
                "email",
                "email_verified",
            ],
            code_challenge_methods_supported: &["S256"],
            authorization_response_iss_parameter_supported: true,
            issuer: base_url.to_string(),
        })
        .into_http_response()
        .with_cors_unrestricted())
    }
}
