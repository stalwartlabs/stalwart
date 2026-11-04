/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{GrantType, scope::OAuthScopes};
use crate::Server;
use serde::{Deserialize, Serialize};
use trc::{AuthEvent, EventType};

#[derive(Debug, Default, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct OAuthIntrospect {
    #[serde(default)]
    pub active: bool,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

impl Server {
    pub async fn introspect_access_token(&self, token: &str) -> trc::Result<OAuthIntrospect> {
        match self.introspect_grant_token(token).await {
            Ok(introspect) => Ok(introspect),
            Err(err)
                if matches!(
                    err.event_type(),
                    EventType::Auth(AuthEvent::Error) | EventType::Auth(AuthEvent::TokenExpired)
                ) =>
            {
                Ok(OAuthIntrospect::default())
            }
            Err(err) => Err(err.caused_by(trc::location!())),
        }
    }

    async fn introspect_grant_token(&self, token: &str) -> trc::Result<OAuthIntrospect> {
        let token_info = self.validate_access_token(None, token).await?;
        let token_type = match token_info.grant_type {
            GrantType::AccessToken => "bearer",
            GrantType::RefreshToken => "refresh_token",
            _ => return Ok(OAuthIntrospect::default()),
        };
        let Some(presented) = token_info.grant else {
            return Ok(OAuthIntrospect::default());
        };
        let Some(stored) = self
            .oauth_grant(presented.id)
            .await?
            .filter(|stored| stored.account_id() == token_info.account_id)
        else {
            return Ok(OAuthIntrospect::default());
        };
        if (token_info.grant_type == GrantType::RefreshToken
            && !stored.is_current(presented.generation))
            || (token_info.credential_expired
                && !OAuthScopes::from_grant(&stored.grant).allows_expired_credential())
        {
            return Ok(OAuthIntrospect::default());
        }

        let scope = match token_info.claims.filter(|claims| !claims.is_empty()) {
            Some(scope) if token_info.grant_type == GrantType::RefreshToken => scope,
            _ => OAuthScopes::from_registry(stored.grant.scopes.iter()).to_wire(),
        };
        let account = self.account(token_info.account_id).await?;

        Ok(OAuthIntrospect {
            active: true,
            scope: (!scope.is_empty()).then_some(scope),
            client_id: stored.grant.client_id.into(),
            username: account.name().to_string().into(),
            sub: token_info.account_id.to_string().into(),
            token_type: Some(token_type.into()),
            exp: Some(token_info.expiry as i64),
            iat: Some(token_info.issued_at as i64),
            ..Default::default()
        })
    }
}
