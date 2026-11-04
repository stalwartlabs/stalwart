/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CLIENT_ID_MAX_LEN,
    cimd::{CimdClient, CimdError},
    client_id::{CLIENT_ID_HEADER, ClientMeta, decode_client_id},
    registration::{
        is_safe_redirect_target, post_logout_redirect_uri_matches, redirect_uri_matches,
    },
    scope::OAuthScopes,
};
use crate::{
    Server,
    config::resource::ResourceIdentifiers,
    manager::{app_client::is_safe_authority, application::AppClientDocument},
};
use registry::schema::{
    enums::{OAuthClientKind, OAuthGrantType},
    prelude::{ObjectType, Property, UTCDateTime},
    structs::OAuthClient,
};
use std::net::IpAddr;
use trc::AddContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    Authorize,
    Token,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestOrigin<'x> {
    pub is_tls: bool,
    pub authority: &'x str,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolveContext<'x> {
    pub mode: ResolveMode,
    pub origin: Option<RequestOrigin<'x>>,
    pub remote_ip: IpAddr,
}

#[derive(Debug, Clone, Copy)]
pub enum AppOriginPolicy<'x> {
    TrustedHosts(&'x ResourceIdentifiers),
    SameOrigin(RequestOrigin<'x>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationClient {
    pub client_name: Option<String>,
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedClient {
    Stateless(ClientMeta),
    Registered(Box<OAuthClient>),
    RegisteredApplication(Box<OAuthClient>),
    Application(ApplicationClient),
    Cimd(Option<Box<CimdClient>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRejection {
    TooLong,
    Unknown,
    Expired,
    Metadata(CimdError),
}

const LOGO_DATA_URI_PREFIX: &str = "data:image/";

impl Server {
    pub async fn resolve_oauth_client(
        &self,
        client_id: &str,
        ctx: &ResolveContext<'_>,
    ) -> trc::Result<Result<ResolvedClient, ClientRejection>> {
        if client_id.len() > CLIENT_ID_MAX_LEN {
            return Ok(Err(ClientRejection::TooLong));
        } else if client_id.starts_with(CLIENT_ID_HEADER) {
            return Ok(
                decode_client_id(self.core.oauth.oauth_key.as_bytes(), client_id)
                    .map(ResolvedClient::Stateless)
                    .ok_or(ClientRejection::Unknown),
            );
        }

        let is_https = client_id.starts_with("https://");
        if is_https || client_id.starts_with("http://") {
            if let Some(app) = self.app_origin_policy(ctx.origin).and_then(|policy| {
                self.inner
                    .data
                    .applications
                    .recognize_client(client_id, policy)
            }) {
                return Ok(Ok(ResolvedClient::Application(app)));
            }

            match self.registered_oauth_client(client_id).await? {
                Err(ClientRejection::Unknown) if is_https => {}
                result => return Ok(result.map(|client| self.registered_client(client))),
            }

            let url = match self.check_cimd_policy(client_id) {
                Ok(url) => url,
                Err(err) => return Ok(Err(ClientRejection::Metadata(err))),
            };

            match ctx.mode {
                ResolveMode::Authorize => Ok(self
                    .cimd_client(client_id, url)
                    .await?
                    .map(|client| ResolvedClient::Cimd(Some(Box::new(client))))
                    .map_err(ClientRejection::Metadata)),
                ResolveMode::Token => Ok(Ok(ResolvedClient::Cimd(None))),
            }
        } else {
            Ok(self
                .registered_oauth_client(client_id)
                .await?
                .map(|client| self.registered_client(client)))
        }
    }

    fn registered_client(&self, client: Box<OAuthClient>) -> ResolvedClient {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if client.member_tenant_id.is_some() {
            return ResolvedClient::Registered(client);
        }
        // SPDX-SnippetEnd
        if self
            .inner
            .data
            .applications
            .is_application_client_id(&client.client_id)
        {
            ResolvedClient::RegisteredApplication(client)
        } else {
            ResolvedClient::Registered(client)
        }
    }

    pub async fn is_post_logout_redirect_uri_allowed(
        &self,
        client_id: &str,
        uri: &str,
        origin: RequestOrigin<'_>,
    ) -> trc::Result<bool> {
        if client_id.len() > CLIENT_ID_MAX_LEN
            || client_id.starts_with(CLIENT_ID_HEADER)
            || !is_safe_redirect_target(uri)
        {
            return Ok(false);
        }

        let is_https = client_id.starts_with("https://");
        if !is_https && !client_id.starts_with("http://") {
            return Ok(self
                .registered_oauth_client(client_id)
                .await?
                .is_ok_and(|client| {
                    post_logout_redirect_uri_matches(client.post_logout_redirect_uris.iter(), uri)
                }));
        }

        if let Some(matches) = self.app_origin_policy(Some(origin)).and_then(|policy| {
            self.inner
                .data
                .applications
                .post_logout_redirect_uri_matches(client_id, policy, uri)
        }) {
            return Ok(matches);
        }

        match self.registered_oauth_client(client_id).await? {
            Err(ClientRejection::Unknown) if is_https => {}
            result => {
                return Ok(result.is_ok_and(|client| {
                    post_logout_redirect_uri_matches(client.post_logout_redirect_uris.iter(), uri)
                }));
            }
        }

        let Ok(url) = self.check_cimd_policy(client_id) else {
            return Ok(false);
        };
        Ok(self.cimd_client(client_id, url).await?.is_ok_and(|client| {
            post_logout_redirect_uri_matches(&client.post_logout_redirect_uris, uri)
        }))
    }

    pub fn app_origin_policy<'x>(
        &'x self,
        origin: Option<RequestOrigin<'x>>,
    ) -> Option<AppOriginPolicy<'x>> {
        if self.registry().is_bootstrap_mode() || self.registry().is_recovery_mode() {
            origin.map(AppOriginPolicy::SameOrigin)
        } else {
            Some(AppOriginPolicy::TrustedHosts(&self.core.network.resources))
        }
    }

    pub fn application_client_document(
        &self,
        prefix: &str,
        origin: RequestOrigin<'_>,
    ) -> AppClientDocument {
        let applications = &self.inner.data.applications;
        if self.registry().is_bootstrap_mode() || self.registry().is_recovery_mode() {
            applications.client_document(
                prefix,
                origin.is_tls,
                origin.authority,
                AppOriginPolicy::SameOrigin(origin),
            )
        } else {
            applications.client_document(
                prefix,
                origin.is_tls || !cfg!(feature = "dev_mode"),
                origin.authority,
                AppOriginPolicy::TrustedHosts(&self.core.network.resources),
            )
        }
    }

    pub async fn external_issuer_for_host(&self, authority: &str) -> trc::Result<Option<String>> {
        if self.registry().is_bootstrap_mode() || self.registry().is_recovery_mode() {
            return Ok(None);
        }
        let host = match authority.strip_prefix('[') {
            Some(_) => return Ok(None),
            None => authority
                .rsplit_once(':')
                .map_or(authority, |(host, _)| host),
        };
        Ok(self
            .get_directory_for_host(host)
            .await
            .caused_by(trc::location!())?
            .and_then(|directory| directory.oidc_discovery_document())
            .map(|discovery| discovery.document.issuer.clone()))
    }

    async fn registered_oauth_client(
        &self,
        client_id: &str,
    ) -> trc::Result<Result<Box<OAuthClient>, ClientRejection>> {
        let Some(id) = self
            .registry()
            .primary_key(
                ObjectType::OAuthClient.into(),
                Property::ClientId,
                client_id.as_bytes().to_vec(),
            )
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Err(ClientRejection::Unknown));
        };
        let Some(client) = self
            .registry()
            .object::<OAuthClient>(id.id())
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Err(ClientRejection::Unknown));
        };

        if client
            .expires_at
            .is_some_and(|expires_at| expires_at.timestamp() <= UTCDateTime::now().timestamp())
        {
            Ok(Err(ClientRejection::Expired))
        } else {
            Ok(Ok(Box::new(client)))
        }
    }
}

impl AppOriginPolicy<'_> {
    #[cfg(feature = "dev_mode")]
    pub fn accepts(&self, _is_tls: bool, authority: &str) -> bool {
        is_safe_authority(authority)
    }

    #[cfg(not(feature = "dev_mode"))]
    pub fn accepts(&self, is_tls: bool, authority: &str) -> bool {
        match self {
            AppOriginPolicy::TrustedHosts(resources) => {
                is_tls && resources.is_trusted_host(authority)
            }
            AppOriginPolicy::SameOrigin(origin) => {
                origin.is_tls == is_tls
                    && is_safe_authority(authority)
                    && origin.authority.eq_ignore_ascii_case(authority)
            }
        }
    }
}

impl RequestOrigin<'_> {
    pub fn scheme(&self) -> &'static str {
        if self.is_tls { "https" } else { "http" }
    }
}

impl ResolvedClient {
    pub fn kind(&self) -> OAuthClientKind {
        match self {
            ResolvedClient::Stateless(_) => OAuthClientKind::Dynamic,
            ResolvedClient::Registered(_) => OAuthClientKind::Registered,
            ResolvedClient::RegisteredApplication(_) | ResolvedClient::Application(_) => {
                OAuthClientKind::FirstParty
            }
            ResolvedClient::Cimd(_) => OAuthClientKind::MetadataDocument,
        }
    }

    pub fn granted_scopes(&self, requested: OAuthScopes) -> OAuthScopes {
        match self {
            ResolvedClient::RegisteredApplication(_) | ResolvedClient::Application(_) => {
                requested | OAuthScopes::FULL
            }
            _ => requested,
        }
    }

    pub fn requires_consent(&self) -> bool {
        !matches!(self, ResolvedClient::Application(_))
    }

    pub fn is_verified(&self) -> bool {
        match self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ResolvedClient::Registered(client) => client.member_tenant_id.is_none(),
            // SPDX-SnippetEnd
            #[cfg(not(feature = "enterprise"))]
            ResolvedClient::Registered(_) => true,
            ResolvedClient::RegisteredApplication(_) | ResolvedClient::Application(_) => true,
            ResolvedClient::Stateless(_) | ResolvedClient::Cimd(_) => false,
        }
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn allows_tenant(&self, tenant_id: Option<u32>) -> bool {
        match self {
            ResolvedClient::Registered(client) => client
                .member_tenant_id
                .is_none_or(|owner| tenant_id == Some(owner.document_id())),
            ResolvedClient::Stateless(_)
            | ResolvedClient::RegisteredApplication(_)
            | ResolvedClient::Application(_)
            | ResolvedClient::Cimd(_) => true,
        }
    }
    // SPDX-SnippetEnd

    pub fn display_name(&self) -> Option<&str> {
        match self {
            ResolvedClient::Stateless(meta) => meta.client_name.as_deref(),
            ResolvedClient::Registered(client) | ResolvedClient::RegisteredApplication(client) => {
                client.description.as_deref()
            }
            ResolvedClient::Application(app) => app.client_name.as_deref(),
            ResolvedClient::Cimd(client) => client.as_ref()?.client_name.as_deref(),
        }
    }

    pub fn display_logo(&self) -> Option<&str> {
        match self {
            ResolvedClient::Registered(client) | ResolvedClient::RegisteredApplication(client) => {
                client
                    .logo
                    .as_deref()
                    .filter(|logo| logo.starts_with(LOGO_DATA_URI_PREFIX))
            }
            ResolvedClient::Application(app) => app.logo_uri.as_deref(),
            ResolvedClient::Stateless(_) | ResolvedClient::Cimd(_) => None,
        }
    }

    pub fn client_host(&self) -> Option<&str> {
        match self {
            ResolvedClient::Cimd(Some(client)) => Some(client.client_host.as_str()),
            _ => None,
        }
    }

    pub fn redirect_uris(&self) -> &[String] {
        match self {
            ResolvedClient::Stateless(meta) => &meta.redirect_uris,
            ResolvedClient::Registered(client) | ResolvedClient::RegisteredApplication(client) => {
                client.redirect_uris.as_slice()
            }
            ResolvedClient::Application(app) => &app.redirect_uris,
            ResolvedClient::Cimd(Some(client)) => &client.redirect_uris,
            ResolvedClient::Cimd(None) => &[],
        }
    }

    pub fn redirect_uri_matches(&self, redirect_uri: &str) -> bool {
        is_safe_redirect_target(redirect_uri)
            && self
                .redirect_uris()
                .iter()
                .any(|registered| redirect_uri_matches(registered, redirect_uri))
    }

    pub fn allowed_scopes(&self) -> Option<OAuthScopes> {
        let scopes = match self {
            ResolvedClient::RegisteredApplication(_) | ResolvedClient::Application(_) => {
                return None;
            }
            ResolvedClient::Stateless(meta) => meta.scopes,
            ResolvedClient::Registered(client) => OAuthScopes::from_registry(client.scopes.iter()),
            ResolvedClient::Cimd(Some(client)) => client.scopes,
            ResolvedClient::Cimd(None) => OAuthScopes::NONE,
        };
        let scopes = if self.is_verified() {
            scopes
        } else {
            scopes.without(OAuthScopes::FULL)
        };
        Some(scopes | OAuthScopes::ALWAYS_ALLOWED)
    }

    pub fn secret_hash(&self) -> Option<&str> {
        match self {
            ResolvedClient::Registered(client) | ResolvedClient::RegisteredApplication(client) => {
                client.secret.as_deref().filter(|secret| !secret.is_empty())
            }
            _ => None,
        }
    }

    pub fn is_confidential(&self) -> bool {
        self.secret_hash().is_some()
    }

    pub fn allows_grant(&self, grant: OAuthGrantType) -> bool {
        match self {
            ResolvedClient::Registered(client) | ResolvedClient::RegisteredApplication(client) => {
                client.grant_types.contains(&grant)
            }
            ResolvedClient::Stateless(_)
            | ResolvedClient::Application(_)
            | ResolvedClient::Cimd(_) => grant != OAuthGrantType::DeviceCode,
        }
    }
}

impl ClientRejection {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientRejection::TooLong => "Client id is too long",
            ClientRejection::Unknown => "Unknown client id",
            ClientRejection::Expired => "Client registration has expired",
            ClientRejection::Metadata(err) => err.as_str(),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/auth/oauth/client/tests.rs"]
mod tests;
