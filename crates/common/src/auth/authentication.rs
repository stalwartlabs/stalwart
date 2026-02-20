/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{
        AccessToken, AuthRequest, DomainCache,
        credential::{ApiKey, AppPassword},
        oauth::GrantType,
    },
};
use directory::{
    Credentials,
    core::secret::{verify_mfa_secret_hash, verify_secret_hash},
};
use registry::schema::{
    enums::{CredentialType, Permission},
    structs,
};
use std::{net::IpAddr, sync::Arc};
use store::write::now;
use trc::AddContext;

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
    pub async fn authenticate(&self, req: &AuthRequest) -> trc::Result<AccessToken> {
        match self
            .route_auth_request(req)
            .await
            .and_then(|token| token.assert_has_permission(Permission::Authenticate))
        {
            Ok(token) => Ok(token),
            Err(err) => {
                if err.matches(trc::EventType::Auth(trc::AuthEvent::Failed))
                    && self.has_auth_fail2ban()
                    && self
                        .is_auth_fail2banned(req.remote_ip, req.username())
                        .await?
                {
                    Err(trc::SecurityEvent::AuthenticationBan
                        .into_err()
                        .ctx(trc::Key::RemoteIp, req.remote_ip)
                        .ctx_opt(trc::Key::AccountName, req.username().map(|s| s.to_string())))
                } else {
                    Err(err.ctx(trc::Key::RemoteIp, req.remote_ip))
                }
            }
        }
    }

    async fn route_auth_request(&self, req: &AuthRequest) -> trc::Result<AccessToken> {
        match &req.credentials {
            Credentials::Basic { username, secret } => {
                let username = UsernameParts::new(username);

                // Try to authenticate as fallback admin if configured
                if let Some((fallback_user, fallback_hash)) =
                    &self.core.network.security.fallback_admin
                    && username.auth_as().address() == fallback_user
                {
                    return if verify_secret_hash(fallback_hash, secret.as_bytes()).await? {
                        if username.is_master() {
                            let address = username.account().address();
                            if let Some(account_id) =
                                self.account_id_from_email(address, false).await?
                            {
                                trc::event!(
                                    Auth(trc::AuthEvent::Success),
                                    AccountName = address.to_string(),
                                    AccountId = account_id,
                                    SpanId = req.session_id,
                                    Details = fallback_user.to_string(),
                                );

                                self.access_token(account_id).await.map(AccessToken::new)
                            } else {
                                Err(trc::AuthEvent::Failed
                                    .into_err()
                                    .ctx(trc::Key::AccountName, address.to_string())
                                    .reason("Master user account not found for fallback admin authentication"))
                            }
                        } else {
                            trc::event!(
                                Auth(trc::AuthEvent::Success),
                                AccountName = fallback_user.to_string(),
                                SpanId = req.session_id,
                            );

                            Ok(AccessToken::new_admin())
                        }
                    } else {
                        Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, fallback_user.to_string())
                            .ctx(trc::Key::SpanId, req.session_id)
                            .reason("Fallback admin authentication failed"))
                    };
                }

                // Obtain domain
                let auth_as = username.auth_as();
                let auth_as_address = auth_as.address();
                let auth_as_local = auth_as.local();
                let auth_as_domain = auth_as.domain();
                let domain = self
                    .domain_or_default(auth_as_address, auth_as_domain)
                    .await?;

                // Authenticate app passwords
                if let Some(app_pass) = AppPassword::parse(secret) {
                    return if let Some(account_id) =
                        self.account_id_from_parts(auth_as_local, domain.id).await?
                    {
                        self.validate_credential(
                            account_id,
                            app_pass.credential_id,
                            app_pass.secret.as_ref(),
                            req.session_id,
                        )
                        .await
                    } else {
                        Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, auth_as_address.to_string())
                            .reason("App password authentication failed: account not found"))
                    };
                }

                // Obtain external directory, if any
                let directory = domain
                    .id_directory
                    .and_then(|domain_id| self.core.storage.directories.get(&domain_id))
                    .or_else(|| self.get_default_directory());

                let mut is_alias_login = false;
                let token = if let Some(directory) = directory {
                    let directory_account = directory.authenticate(&req.credentials).await?;

                    is_alias_login = directory_account.email != auth_as_address;
                    self.build_directory_token(directory_account).await
                } else if let Some(account_id) =
                    self.account_id_from_parts(auth_as_local, domain.id).await?
                {
                    if let Some(account) = self
                        .registry()
                        .object::<structs::Account>(account_id.into())
                        .await?
                        .and_then(|account| account.into_user())
                    {
                        if verify_mfa_secret_hash(
                            account.otp_auth.as_deref(),
                            account.secret.as_str(),
                            secret,
                        )
                        .await?
                        {
                            is_alias_login = account.name != auth_as_address;
                            self.access_token(account_id).await.map(AccessToken::new)
                        } else {
                            Err(trc::AuthEvent::Failed
                                .into_err()
                                .ctx(trc::Key::AccountName, auth_as_address.to_string())
                                .ctx(trc::Key::AccountId, account_id)
                                .ctx(trc::Key::SpanId, req.session_id)
                                .reason("Authentication failed"))
                        }
                    } else {
                        Err(trc::AuthEvent::Error
                            .into_err()
                            .ctx(trc::Key::AccountName, auth_as_address.to_string())
                            .ctx(trc::Key::AccountId, account_id)
                            .reason("Account not found in registry"))
                    }
                } else {
                    Err(trc::AuthEvent::Failed
                        .into_err()
                        .ctx(trc::Key::AccountName, auth_as_address.to_string())
                        .reason("Account not found"))
                }?;

                // Enforce alias login restrictions
                if is_alias_login && !token.has_permission(Permission::AuthenticateAlias) {
                    return Err(trc::AuthEvent::Failed
                        .into_err()
                        .ctx(trc::Key::AccountName, auth_as_address.to_string())
                        .ctx(trc::Key::AccountId, token.account_id())
                        .ctx(trc::Key::SpanId, req.session_id)
                        .reason("Authenticated using an email alias but account does not have AuthenticateAlias permission"));
                }

                // Validate master user access
                if username.is_master() {
                    token.assert_has_permissions(&[
                        Permission::Impersonate,
                        Permission::Authenticate,
                    ])?;
                    let address = username.account().address();
                    let master_address = username.account().address();
                    if let Some(account_id) = self.account_id_from_email(address, false).await? {
                        trc::event!(
                            Auth(trc::AuthEvent::Success),
                            AccountName = address.to_string(),
                            AccountId = account_id,
                            SpanId = req.session_id,
                            Details = master_address.to_string(),
                        );

                        self.access_token(account_id).await.map(AccessToken::new)
                    } else {
                        Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, address.to_string())
                            .details(master_address.to_string())
                            .reason("Master user account not found"))
                    }
                } else {
                    trc::event!(
                        Auth(trc::AuthEvent::Success),
                        AccountName = auth_as_address.to_string(),
                        AccountId = token.account_id(),
                        SpanId = req.session_id,
                    );

                    Ok(token)
                }
            }
            Credentials::Bearer { username, token } => {
                // Handle API key authentication
                if let Some(key) = ApiKey::parse(token) {
                    return self
                        .validate_credential(
                            key.account_id,
                            key.credential_id,
                            key.secret.as_ref(),
                            req.session_id,
                        )
                        .await;
                }

                // Obtain external directory, if any
                let directory = if let Some(username) = username.as_deref().map(UsernameParts::new)
                {
                    if let Some(domain_name) = username.auth_as().domain() {
                        self.domain(domain_name)
                            .await
                            .caused_by(trc::location!())?
                            .and_then(|domain| self.core.storage.directories.get(&domain.id))
                            .or_else(|| self.get_default_directory())
                    } else {
                        self.get_default_directory()
                    }
                } else {
                    self.get_default_directory()
                };
                if let Some(directory) = directory
                    && directory.has_bearer_token_support()
                {
                    match directory.authenticate(&req.credentials).await {
                        Ok(result) => {
                            return self.build_directory_token(result).await;
                        }
                        Err(err) => {
                            if !err.matches(trc::EventType::Auth(trc::AuthEvent::Failed)) {
                                return Err(err);
                            }
                        }
                    }
                }

                // Internal OAuth
                let token_info = self
                    .validate_access_token(GrantType::AccessToken.into(), token)
                    .await?;
                self.access_token(token_info.account_id)
                    .await
                    .map(AccessToken::new)
            }
        }
    }

    async fn validate_credential(
        &self,
        account_id: u32,
        credential_id: u32,
        secret: &[u8],
        span_id: u64,
    ) -> trc::Result<AccessToken> {
        if let Some(account) = self
            .registry()
            .object::<structs::Account>(account_id.into())
            .await?
            .and_then(|account| account.into_user())
        {
            // Find credential by credential_id
            for (id, credential) in &account.credentials {
                if *id == credential_id {
                    if !verify_secret_hash(&credential.secret, secret).await? {
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
                        return Err(trc::AuthEvent::Failed
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
                        Details = match credential.credential_type {
                            CredentialType::AppPassword => "Authenticated with app password",
                            CredentialType::ApiKey => "Authenticated with API key",
                        }
                    );

                    let token = self
                        .access_token_from_account(account_id, structs::Account::User(account))
                        .await?;

                    return AccessToken::scoped(token, credential_id)
                        .add_context(|ctx| ctx.span_id(span_id));
                }
            }

            Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountId, account_id)
                .ctx(trc::Key::Id, credential_id)
                .ctx(trc::Key::SpanId, span_id)
                .reason("Credential not found for account"))
        } else {
            Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountId, account_id)
                .ctx(trc::Key::SpanId, span_id)
                .reason("Account not found for credential"))
        }
    }

    async fn domain_or_default(
        &self,
        address: &str,
        domain_name: Option<&str>,
    ) -> trc::Result<Arc<DomainCache>> {
        if let Some(domain_name) = domain_name {
            if let Some(domain) = self.domain(domain_name).await? {
                Ok(domain)
            } else {
                Err(trc::AuthEvent::Failed
                    .into_err()
                    .ctx(trc::Key::AccountName, address.to_string())
                    .reason("Domain not found"))
            }
        } else {
            trc::event!(
                Auth(trc::AuthEvent::Warning),
                AccountName = address.to_string(),
                Reason = "No domain in username",
            );
            self.domain_by_id(self.core.email.default_domain_id)
                .await?
                .ok_or_else(|| {
                    trc::AuthEvent::Error
                        .into_err()
                        .details("Default domain does not exist or has been disabled")
                        .ctx(trc::Key::Id, self.core.email.default_domain_id)
                })
        }
    }

    async fn build_directory_token(&self, account: directory::Account) -> trc::Result<AccessToken> {
        let account = self.synchronize_account(account).await?;
        self.access_token_from_account(account.id, account.account)
            .await
            .map(AccessToken::new)
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
