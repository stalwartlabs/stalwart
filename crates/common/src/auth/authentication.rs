/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{
        AccessToken, AuthRequest, DomainCache, TokenScope,
        credential::{ApiKey, AppPassword},
        oauth::{
            GrantType,
            scope::OAuthScopes,
            token::{TOKEN_HEADER, assert_credential_version},
        },
    },
};
use compact_str::CompactString;
use directory::{
    Credentials, Directory, Recipient,
    backend::oidc::{ExternalToken, TokenAccess, TokenContext},
    core::secret::{SecretVerificationResult, verify_mfa_secret_hash, verify_secret_hash},
};
use encodify::base64::URL_SAFE_NO_PAD;
use registry::schema::{
    enums::Permission,
    structs::{self, Credential},
};
use serde::Deserialize;
use std::{borrow::Cow, net::IpAddr, sync::Arc};
use store::write::now;
use trc::AddContext;

pub struct Authenticated {
    pub access_token: AccessToken,
    pub expires_in: Option<u64>,
}

pub struct UsernameParts {
    pub account: Username,
    pub master_user: Option<Username>,
}

#[derive(PartialEq, Eq)]
pub struct Username {
    pub name: String,
    pub domain_start: usize,
}

impl Server {
    pub async fn authenticate(&self, req: &AuthRequest) -> trc::Result<Authenticated> {
        let result = match &req.credentials {
            Credentials::Basic {
                username,
                secret,
                mfa_token,
            } => self
                .authenticate_basic(req, username, secret, mfa_token.as_deref())
                .await
                .map(|access_token| Authenticated {
                    access_token,
                    expires_in: None,
                }),
            Credentials::Bearer { username, token } => {
                self.authenticate_bearer(req, username.as_deref(), token)
                    .await
            }
        };

        match result.and_then(|authenticated| {
            authenticated
                .access_token
                .assert_has_permission(Permission::Authenticate)
                .map(|access_token| Authenticated {
                    access_token,
                    expires_in: authenticated.expires_in,
                })
        }) {
            Ok(authenticated) => Ok(authenticated),
            Err(err) => Err(self
                .reject_authentication(err, req.remote_ip, req.username())
                .await),
        }
    }

    pub(crate) async fn reject_authentication(
        &self,
        err: trc::Error,
        remote_ip: IpAddr,
        username: Option<&str>,
    ) -> trc::Error {
        self.delay_failed_authentication().await;
        self.auth_failure(err, remote_ip, username).await
    }

    pub(crate) async fn delay_failed_authentication(&self) {
        // Random delay to mitigate user enumeration attacks
        #[cfg(not(stalwart_tests))]
        {
            use store::rand::{self, RngExt};

            let delay = rand::rng().random_range(50..500);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
    }

    pub async fn auth_failure(
        &self,
        err: trc::Error,
        remote_ip: IpAddr,
        username: Option<&str>,
    ) -> trc::Error {
        if matches!(
            err.as_ref(),
            trc::EventType::Auth(trc::AuthEvent::Failed)
                | trc::EventType::Security(trc::SecurityEvent::IpUnauthorized)
        ) && self.has_auth_fail2ban()
        {
            match self.is_auth_fail2banned(remote_ip, username).await {
                Ok(true) => {
                    return trc::SecurityEvent::AuthenticationBan
                        .into_err()
                        .ctx(trc::Key::RemoteIp, remote_ip)
                        .ctx_opt(trc::Key::AccountName, username.map(CompactString::from));
                }
                Ok(false) => {}
                Err(err) => return err,
            }
        }

        err.details_to_reason().ctx(trc::Key::RemoteIp, remote_ip)
    }

    async fn authenticate_basic(
        &self,
        req: &AuthRequest,
        username: &str,
        secret: &str,
        mfa_token: Option<&str>,
    ) -> trc::Result<AccessToken> {
        let mut username = UsernameParts::new(username);

        // Try to authenticate as fallback admin if configured
        if let Some((fallback_user, fallback_hash)) = &self.registry().recovery_admin()
            && username.auth_as().address() == fallback_user
        {
            return if verify_secret_hash(
                &self.inner.data.password_verifier,
                fallback_hash,
                secret.as_bytes(),
            )
            .await?
            {
                if username.is_master() {
                    let address = username.account().address();
                    if let Some(account_id) =
                        self.impersonated_account_id(username.account()).await?
                    {
                        trc::event!(
                            Auth(trc::AuthEvent::Success),
                            AccountName = CompactString::from(address),
                            AccountId = account_id,
                            SpanId = req.session_id,
                            Address = CompactString::from(fallback_user),
                        );

                        self.access_token(account_id)
                            .await
                            .and_then(|token| AccessToken::new(token, req.remote_ip))
                    } else {
                        Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, CompactString::from(address))
                            .reason(
                                "Master user account not found for fallback admin authentication",
                            ))
                    }
                } else {
                    trc::event!(
                        Auth(trc::AuthEvent::Success),
                        AccountName = CompactString::from(fallback_user),
                        SpanId = req.session_id,
                    );

                    Ok(AccessToken::new_admin())
                }
            } else {
                Err(trc::AuthEvent::Failed
                    .into_err()
                    .ctx(trc::Key::AccountName, CompactString::from(fallback_user))
                    .ctx(trc::Key::SpanId, req.session_id)
                    .reason("Fallback admin authentication failed"))
            };
        }

        // Add domain if missing, use the default domain
        self.add_missing_domain(&mut username.account);
        if let Some(master_user) = &mut username.master_user {
            self.add_missing_domain(master_user);
        }

        // Obtain domain
        let auth_as = username.auth_as();
        let auth_as_address = auth_as.address();
        let auth_as_local = auth_as.local();
        let auth_as_domain = auth_as.domain().unwrap();
        let domain = self.resolve_domain(auth_as_domain).await?;

        // Authenticate app passwords
        if let Some(app_pass) = AppPassword::parse(secret) {
            if username.is_master() {
                return Err(trc::AuthEvent::Failed
                    .into_err()
                    .ctx(trc::Key::AccountName, CompactString::from(auth_as_address))
                    .ctx(trc::Key::SpanId, req.session_id)
                    .reason("App passwords cannot be used for impersonation"));
            }
            return if let Some(account_id) =
                self.account_id_from_parts(auth_as_local, domain.id).await?
            {
                self.validate_credential(
                    account_id,
                    app_pass.credential_id,
                    app_pass.secret.as_ref(),
                    req.remote_ip,
                    req.session_id,
                )
                .await
            } else {
                Err(trc::AuthEvent::Failed
                    .into_err()
                    .ctx(trc::Key::AccountName, CompactString::from(auth_as_address))
                    .reason("App password authentication failed: account not found"))
            };
        }

        // Obtain external directory, if any
        let mut is_alias_login = false;
        let token = if let Some(directory) = self.get_directory_for_cached_domain(&domain) {
            let directory_account = if username.is_master() {
                directory
                    .authenticate(
                        &Credentials::Basic {
                            username: auth_as_address.to_string(),
                            secret: secret.to_string(),
                            mfa_token: mfa_token.map(String::from),
                        },
                        &self.inner.data.password_verifier,
                    )
                    .await?
            } else {
                directory
                    .authenticate(&req.credentials, &self.inner.data.password_verifier)
                    .await?
            };

            self.assert_account_directory(&directory_account.email, directory)
                .await?;
            is_alias_login = directory_account.email != auth_as_address;
            self.build_directory_token(directory_account, req.remote_ip)
                .await
        } else if let Some(account_id) =
            self.account_id_from_parts(auth_as_local, domain.id).await?
        {
            if let Some(account) = self
                .registry()
                .object::<structs::Account>(account_id.into())
                .await?
                .and_then(|account| account.into_user())
            {
                let Some(credential) = account.password_credential() else {
                    return Err(trc::AuthEvent::Failed
                        .into_err()
                        .ctx(trc::Key::AccountName, CompactString::from(auth_as_address))
                        .ctx(trc::Key::AccountId, account_id)
                        .ctx(trc::Key::SpanId, req.session_id)
                        .reason("Password credential not found for account"));
                };

                match verify_mfa_secret_hash(
                    &self.inner.data.password_verifier,
                    credential.otp_url.as_deref(),
                    mfa_token,
                    credential.secret.as_str(),
                    secret,
                )
                .await?
                {
                    SecretVerificationResult::Valid => {
                        is_alias_login = account.name != auth_as_local;
                        self.access_token(account_id)
                            .await
                            .and_then(|token| AccessToken::new(token, req.remote_ip))
                    }
                    SecretVerificationResult::Invalid => Err(trc::AuthEvent::Failed
                        .into_err()
                        .ctx(trc::Key::AccountName, CompactString::from(auth_as_address))
                        .ctx(trc::Key::AccountId, account_id)
                        .ctx(trc::Key::SpanId, req.session_id)
                        .reason("Authentication failed")),
                    SecretVerificationResult::MissingMfaToken => Err(trc::AuthEvent::MfaRequired
                        .into_err()
                        .ctx(trc::Key::AccountName, CompactString::from(auth_as_address))
                        .ctx(trc::Key::AccountId, account_id)
                        .ctx(trc::Key::SpanId, req.session_id)
                        .reason("MFA token required")),
                }
            } else {
                Err(trc::AuthEvent::Error
                    .into_err()
                    .ctx(trc::Key::AccountName, CompactString::from(auth_as_address))
                    .ctx(trc::Key::AccountId, account_id)
                    .reason("Account not found in registry"))
            }
        } else {
            Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountName, CompactString::from(auth_as_address))
                .reason("Account not found"))
        }?;

        // Enforce alias login restrictions
        if is_alias_login && !token.has_permission(Permission::AuthenticateWithAlias) {
            return Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountName, CompactString::from(auth_as_address))
                .ctx(trc::Key::AccountId, token.account_id())
                .ctx(trc::Key::SpanId, req.session_id)
                .reason("Authenticated using an email alias but account does not have AuthenticateAlias permission"));
        }

        // Validate master user access
        if username.is_master() {
            token.assert_has_permissions(&[Permission::Impersonate, Permission::Authenticate])?;
            let address = username.account().address();
            let master_address = auth_as_address;
            if let Some(account_id) = self.impersonated_account_id(username.account()).await? {
                trc::event!(
                    Auth(trc::AuthEvent::Success),
                    AccountName = CompactString::from(address),
                    AccountId = account_id,
                    SpanId = req.session_id,
                    Address = CompactString::from(master_address),
                );

                self.access_token(account_id)
                    .await
                    .map(AccessToken::new_maybe_invalid)
            } else {
                Err(trc::AuthEvent::Failed
                    .into_err()
                    .ctx(trc::Key::AccountName, CompactString::from(address))
                    .ctx(trc::Key::Address, CompactString::from(master_address))
                    .reason("Master user account not found"))
            }
        } else {
            trc::event!(
                Auth(trc::AuthEvent::Success),
                AccountName = CompactString::from(auth_as_address),
                AccountId = token.account_id(),
                SpanId = req.session_id,
            );

            Ok(token)
        }
    }

    async fn authenticate_bearer(
        &self,
        req: &AuthRequest,
        username: Option<&str>,
        token: &str,
    ) -> trc::Result<Authenticated> {
        // Handle API key authentication
        if let Some(key) = ApiKey::parse(token) {
            return self
                .validate_credential(
                    key.account_id,
                    key.credential_id,
                    key.secret.as_ref(),
                    req.remote_ip,
                    req.session_id,
                )
                .await
                .map(|access_token| Authenticated {
                    access_token,
                    expires_in: None,
                });
        }

        #[cfg(feature = "dev_mode")]
        if std::env::var("API_TOKEN_ADMIN").is_ok_and(|admin_token| admin_token == token) {
            return Ok(Authenticated {
                access_token: AccessToken::new_admin(),
                expires_in: None,
            });
        }

        if token.starts_with(TOKEN_HEADER) {
            return self.authenticate_oauth_token(token, req.remote_ip).await;
        }

        // Obtain external directory, if any. When no username is supplied
        // (e.g. HTTP bearer auth), peek at the JWT claims to find the
        // user's domain so per-domain OIDC directories are reachable.
        let directory = self.bearer_directory(username, token).await?;

        // Try external directory authentication first if supported, then fallback to internal OAuth.
        let mut external_error = None;
        if let Some(directory) = directory
            && directory.has_bearer_token_support()
        {
            match self.authenticate_external_token(directory, token).await {
                Ok(external) => {
                    self.assert_account_directory(&external.account.email, directory)
                        .await?;
                    let token_scope = match external.access {
                        TokenAccess::Unrestricted => None,
                        TokenAccess::Scoped(scopes) => Some(TokenScope::External {
                            scopes: OAuthScopes::from_external(scopes),
                        }),
                    };
                    let expires_in = external.expires_at.map(|exp| exp.saturating_sub(now()));
                    return self
                        .build_directory_token(external.account, req.remote_ip)
                        .await
                        .map(|access_token| Authenticated {
                            access_token: access_token.with_token_scope(token_scope),
                            expires_in,
                        });
                }
                Err(err) => {
                    external_error = Some(err);
                }
            }
        }

        // Internal OAuth
        match self.authenticate_oauth_token(token, req.remote_ip).await {
            Ok(authenticated) => Ok(authenticated),
            Err(err) => {
                if let Some(external_error) = external_error {
                    Err(external_error)
                } else {
                    Err(err)
                }
            }
        }
    }

    pub async fn authenticate_external_token(
        &self,
        directory: &Directory,
        token: &str,
    ) -> trc::Result<ExternalToken> {
        let resources = &self.core.network.resources;
        let applications = &self.inner.data.applications;
        let app_policy = self.app_origin_policy(None);
        directory
            .authenticate_token(
                token,
                &TokenContext {
                    is_resource: &|audience| {
                        let audience = audience.strip_suffix('/').unwrap_or(audience);
                        resources
                            .identifiers
                            .iter()
                            .any(|identifier| identifier.eq_ignore_ascii_case(audience))
                    },
                    is_first_party: &|client_id| {
                        applications.is_first_party_client(client_id, app_policy)
                    },
                },
            )
            .await
    }

    async fn assert_account_directory(
        &self,
        email: &str,
        directory: &Arc<Directory>,
    ) -> trc::Result<()> {
        let account_directory = match email.rsplit_once('@') {
            Some((_, domain)) => self
                .get_directory_for_domain(domain)
                .await
                .caused_by(trc::location!())?,
            None => None,
        };
        if account_directory
            .is_some_and(|account_directory| Arc::ptr_eq(account_directory, directory))
        {
            Ok(())
        } else {
            Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountName, CompactString::from(email))
                .reason(
                    "The account's domain is not served by the directory that authenticated it",
                ))
        }
    }

    async fn authenticate_oauth_token(
        &self,
        token: &str,
        remote_ip: IpAddr,
    ) -> trc::Result<Authenticated> {
        let token_info = self
            .decode_access_token(GrantType::AccessToken.into(), token)
            .map_err(|err| {
                if err.matches(trc::EventType::Auth(trc::AuthEvent::Error)) {
                    trc::AuthEvent::Failed.into_err().caused_by(err)
                } else {
                    err
                }
            })?;
        let Some(grant) = token_info.grant else {
            return Err(trc::AuthEvent::Failed
                .into_err()
                .details("Access token is not bound to an OAuth grant"));
        };
        let inner = self.access_token(token_info.account_id).await?;
        assert_credential_version(token_info.credential_version, inner.credential_version())?;
        let token_scope = self
            .oauth_grant_scope(grant.id, token_info.account_id)
            .await?;

        AccessToken::renew(inner, None, Some(token_scope), remote_ip).map(|access_token| {
            Authenticated {
                access_token,
                expires_in: Some(token_info.expires_in),
            }
        })
    }

    async fn impersonated_account_id(&self, username: &Username) -> trc::Result<Option<u32>> {
        let address = username.address();

        if let Some(account_id) = self.account_id_from_email(address, false).await? {
            return Ok(Some(account_id));
        }

        if let Some(domain) = username.domain()
            && let Some(domain_cache) = self.domain(domain).await?
            && let Some(directory) = self.get_directory_for_cached_domain(&domain_cache)
            && let Recipient::Account(account) = directory.recipient(address).await?
        {
            return Ok(Some(self.synchronize_account(account).await?.id));
        }

        Ok(None)
    }

    async fn validate_credential(
        &self,
        account_id: u32,
        credential_id: u32,
        secret: &[u8],
        remote_ip: IpAddr,
        span_id: u64,
    ) -> trc::Result<AccessToken> {
        if let Some(account) = self
            .registry()
            .object::<structs::Account>(account_id.into())
            .await?
            .and_then(|account| account.into_user())
        {
            // Find credential by credential_id
            let mut authenticated = false;
            for (credential, credential_type) in
                account.credentials.iter().filter_map(|credential| {
                    credential
                        .as_secondary_credential()
                        .map(|secondary_credential| (secondary_credential, credential))
                })
            {
                if credential.credential_id.document_id() == credential_id {
                    if !verify_secret_hash(
                        &self.inner.data.password_verifier,
                        &credential.secret,
                        secret,
                    )
                    .await?
                    {
                        return Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, account.name)
                            .ctx(trc::Key::AccountId, account_id)
                            .ctx(trc::Key::Id, credential_id)
                            .ctx(trc::Key::SpanId, span_id)
                            .reason("Invalid credential secret"));
                    }

                    if credential
                        .expires_at
                        .as_ref()
                        .is_some_and(|exp| exp.timestamp() < now() as i64)
                    {
                        return Err(trc::AuthEvent::CredentialExpired
                            .into_err()
                            .ctx(trc::Key::AccountName, account.name)
                            .ctx(trc::Key::AccountId, account_id)
                            .ctx(trc::Key::Id, credential_id)
                            .ctx(trc::Key::SpanId, span_id)
                            .reason("Credential has expired"));
                    }

                    trc::event!(
                        Auth(trc::AuthEvent::Success),
                        AccountName = account.name.clone(),
                        AccountId = account_id,
                        Id = credential_id,
                        SpanId = span_id,
                        Details = match credential_type {
                            Credential::AppPassword(_) => "Authenticated with app password",
                            Credential::ApiKey(_) => "Authenticated with API key",
                            _ => "Authenticated with credential",
                        }
                    );

                    authenticated = true;
                    break;
                }
            }

            if authenticated {
                let token = self
                    .access_token_from_account(account_id, structs::Account::User(account))
                    .await?;

                AccessToken::new_scoped(token, credential_id, remote_ip)
                    .add_context(|ctx| ctx.span_id(span_id))
            } else {
                Err(trc::AuthEvent::Failed
                    .into_err()
                    .ctx(trc::Key::AccountId, account_id)
                    .ctx(trc::Key::Id, credential_id)
                    .ctx(trc::Key::SpanId, span_id)
                    .reason("Credential not found for account"))
            }
        } else {
            Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountId, account_id)
                .ctx(trc::Key::SpanId, span_id)
                .reason("Account not found for credential"))
        }
    }

    async fn resolve_domain(&self, domain_name: &str) -> trc::Result<Arc<DomainCache>> {
        if let Some(domain) = self.domain(domain_name).await? {
            Ok(domain)
        } else {
            Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::Domain, CompactString::from(domain_name))
                .reason("Domain not found"))
        }
    }

    fn add_missing_domain(&self, address: &mut Username) {
        if address.domain().is_none() {
            trc::event!(
                Auth(trc::AuthEvent::Warning),
                AccountName = CompactString::from(address.address()),
                Reason = "No domain in username",
            );
            address.domain_start = address.name.len() + 1;
            address.name = format!("{}@{}", address.name, self.core.email.default_domain_name);
        }
    }

    async fn build_directory_token(
        &self,
        account: directory::Account,
        remote_ip: IpAddr,
    ) -> trc::Result<AccessToken> {
        let account = self.synchronize_account(account).await?;
        self.access_token_from_account(account.id, account.account)
            .await
            .and_then(|token| AccessToken::new(token, remote_ip))
    }

    pub(crate) async fn bearer_directory(
        &self,
        username: Option<&str>,
        token: &str,
    ) -> trc::Result<Option<&Arc<Directory>>> {
        let username = username.map(UsernameParts::new);
        match username
            .as_ref()
            .and_then(|username| username.auth_as().domain())
        {
            Some(domain_name) => self.get_directory_for_domain(domain_name).await,
            None => self.get_directory_for_token(token).await,
        }
    }

    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    pub async fn get_directory_for_domain(
        &self,
        domain_name: &str,
    ) -> trc::Result<Option<&Arc<Directory>>> {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition() {
            return Ok(self
                .domain(domain_name)
                .await
                .caused_by(trc::location!())?
                .and_then(|domain| domain.id_directory)
                .and_then(|id_directory| self.core.storage.directories.get(&id_directory))
                .or_else(|| self.get_default_directory()));
        }
        // SPDX-SnippetEnd

        Ok(self.get_default_directory())
    }

    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    pub async fn get_directory_for_host(&self, host: &str) -> trc::Result<Option<&Arc<Directory>>> {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition() {
            let registrable_len = psl::domain_str(host).map_or(host.len(), str::len);
            let mut name = host;
            loop {
                if let Some(directory) = self
                    .domain(name)
                    .await
                    .caused_by(trc::location!())?
                    .and_then(|domain| domain.id_directory)
                    .and_then(|id_directory| self.core.storage.directories.get(&id_directory))
                {
                    return Ok(Some(directory));
                }
                match name.split_once('.') {
                    Some((_, parent)) if parent.len() >= registrable_len => name = parent,
                    _ => break,
                }
            }
        }
        // SPDX-SnippetEnd

        Ok(self.get_default_directory())
    }

    async fn get_directory_for_token(&self, token: &str) -> trc::Result<Option<&Arc<Directory>>> {
        let Some(payload) = JwtClaims::decode_payload(token) else {
            return Ok(self.get_default_directory());
        };
        let Some(claims) = JwtClaims::parse(&payload) else {
            return Ok(self.get_default_directory());
        };

        if let Some(directory) = claims
            .iss
            .as_deref()
            .and_then(|issuer| self.get_directory_for_issuer(issuer))
        {
            return Ok(Some(directory));
        }

        match claims.domain() {
            Some(domain_name) => self.get_directory_for_domain(domain_name).await,
            None => Ok(self.get_default_directory()),
        }
    }

    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    fn get_directory_for_issuer(&self, issuer: &str) -> Option<&Arc<Directory>> {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition() {
            let mut matches = self
                .core
                .storage
                .directories
                .values()
                .filter(|directory| directory.accepts_oidc_issuer(issuer));

            return match (matches.next(), matches.next()) {
                (Some(directory), None) => Some(directory),
                _ => None,
            };
        }
        // SPDX-SnippetEnd

        None
    }

    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    pub fn get_directory_for_cached_domain(&self, domain: &DomainCache) -> Option<&Arc<Directory>> {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition() {
            return domain
                .id_directory
                .and_then(|domain_id| self.core.storage.directories.get(&domain_id))
                .or_else(|| self.get_default_directory());
        }
        // SPDX-SnippetEnd

        self.get_default_directory()
    }
}

#[derive(Deserialize)]
struct JwtClaims<'x> {
    #[serde(borrow, default)]
    iss: Option<Cow<'x, str>>,
    #[serde(borrow, default)]
    email: Option<Cow<'x, str>>,
    #[serde(borrow, default)]
    preferred_username: Option<Cow<'x, str>>,
    #[serde(borrow, default)]
    upn: Option<Cow<'x, str>>,
}

impl<'x> JwtClaims<'x> {
    fn decode_payload(token: &str) -> Option<Vec<u8>> {
        if token.starts_with(TOKEN_HEADER) {
            return None;
        }

        let mut parts = token.split('.');
        let _header = parts.next()?;
        let payload = parts.next()?;
        let _signature = parts.next()?;
        if parts.next().is_some() {
            return None;
        }

        URL_SAFE_NO_PAD.decode(payload).ok()
    }

    fn parse(payload: &'x [u8]) -> Option<Self> {
        serde_json::from_slice(payload).ok()
    }

    fn domain(&self) -> Option<&str> {
        [&self.email, &self.preferred_username, &self.upn]
            .into_iter()
            .flatten()
            .find_map(|claim| {
                claim
                    .rsplit_once('@')
                    .map(|(_, domain)| domain)
                    .filter(|domain| !domain.is_empty())
            })
    }
}

impl UsernameParts {
    pub fn new(address: &str) -> Self {
        let mut account = Username {
            name: String::with_capacity(address.len()),
            domain_start: usize::MAX,
        };
        let mut master_user = None;

        for ch in address.chars() {
            if ch == '%' {
                master_user = Some(Username {
                    name: String::with_capacity(address.len()),
                    domain_start: usize::MAX,
                });
            } else {
                let target = master_user.as_mut().unwrap_or(&mut account);
                if ch != '@' {
                    for lower in ch.to_lowercase() {
                        target.name.push(lower);
                    }
                } else {
                    target.name.push(ch);
                    target.domain_start = target.name.len();
                }
            }
        }

        UsernameParts {
            master_user: master_user.filter(|u| u != &account),
            account,
        }
    }

    pub fn auth_as(&self) -> &Username {
        self.master_user.as_ref().unwrap_or(&self.account)
    }

    pub fn account(&self) -> &Username {
        &self.account
    }

    pub fn is_master(&self) -> bool {
        self.master_user.is_some()
    }
}

impl Username {
    pub fn address(&self) -> &str {
        self.name.as_str()
    }

    pub fn local(&self) -> &str {
        self.name
            .get(..self.domain_start.saturating_sub(1))
            .unwrap_or_default()
    }

    pub fn domain(&self) -> Option<&str> {
        self.name.get(self.domain_start..)
    }
}

impl AuthRequest {
    pub fn from_credentials(credentials: Credentials, session_id: u64, remote_ip: IpAddr) -> Self {
        Self {
            credentials,
            session_id,
            remote_ip,
        }
    }

    pub fn from_plain(
        user: impl Into<String>,
        pass: impl Into<String>,
        session_id: u64,
        remote_ip: IpAddr,
    ) -> Self {
        Self::from_credentials(
            Credentials::Basic {
                username: user.into(),
                secret: pass.into(),
                mfa_token: None,
            },
            session_id,
            remote_ip,
        )
    }

    pub fn username(&self) -> Option<&str> {
        match &self.credentials {
            Credentials::Basic { username, .. } => Some(username.as_str()),
            Credentials::Bearer { username, .. } => username.as_deref(),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/auth/authentication/tests.rs"]
mod tests;
