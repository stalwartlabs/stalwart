/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::oauth::oidc::Userinfo};
use http_proto::*;
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: String,
    pub device_authorization_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub claims_supported: Vec<String>,
}

pub trait OpenIdHandler: Sync + Send {
    fn handle_userinfo_request(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_oidc_metadata(
        &self,
        req: HttpRequest,
        session: HttpSessionData,
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

    async fn handle_oidc_metadata(
        &self,
        req: HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let base_url = HttpContext::new(&session, &req)
            .resolve_response_url(self)
            .await;

        Ok(JsonResponse::new(OpenIdMetadata {
            authorization_endpoint: format!("{base_url}/authorize/code",),
            token_endpoint: format!("{base_url}/auth/token"),
            userinfo_endpoint: format!("{base_url}/auth/userinfo"),
            jwks_uri: format!("{base_url}/auth/jwks.json"),
            registration_endpoint: format!("{base_url}/auth/register"),
            device_authorization_endpoint: format!("{base_url}/auth/device"),
            response_types_supported: vec![
                "code".into(),
                "id_token".into(),
                "id_token token".into(),
            ],
            grant_types_supported: vec![
                "authorization_code".into(),
                "implicit".into(),
                "urn:ietf:params:oauth:grant-type:device_code".into(),
            ],
            scopes_supported: vec!["openid".into(), "offline_access".into()],
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec![
                "RS256".into(),
                "RS384".into(),
                "RS512".into(),
                "ES256".into(),
                "ES384".into(),
                "PS256".into(),
                "PS384".into(),
                "PS512".into(),
                "HS256".into(),
                "HS384".into(),
                "HS512".into(),
            ],
            claims_supported: vec![
                "sub".into(),
                "name".into(),
                "preferred_username".into(),
                "email".into(),
                "email_verified".into(),
            ],
            issuer: base_url,
        })
        .into_http_response())
    }
}
