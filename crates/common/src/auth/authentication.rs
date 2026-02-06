/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;

impl Server {
    pub async fn authenticate(&self, req: &AuthRequest<'_>) -> trc::Result<Arc<AccessToken>> {
        // Resolve directory
        let directory = req.directory.unwrap_or(&self.core.storage.directory);

        // Validate credentials
        match &req.credentials {
            Credentials::OAuthBearer { token } if !directory.has_bearer_token_support() => {
                match self
                    .validate_access_token(GrantType::AccessToken.into(), token)
                    .await
                {
                    Ok(token_into) => self.get_access_token(token_into.account_id).await,
                    Err(err) => Err(err),
                }
            }
            _ => match self.authenticate_credentials(req, directory).await {
                Ok(principal) => self.get_access_token(principal).await,
                Err(err) => Err(err),
            },
        }
        .and_then(|token| {
            token
                .assert_has_permission(Permission::Authenticate)
                .map(|_| token)
        })
    }

    async fn authenticate_credentials(
        &self,
        req: &AuthRequest<'_>,
        directory: &Directory,
    ) -> trc::Result<Principal> {
        // First try to authenticate the user against the default directory
        let result = match directory
            .query(
                QueryParams::credentials(&req.credentials)
                    .with_return_member_of(req.return_member_of),
            )
            .await
        {
            Ok(Some(principal)) => {
                trc::event!(
                    Auth(trc::AuthEvent::Success),
                    AccountName = principal.name().to_string(),
                    AccountId = principal.id(),
                    SpanId = req.session_id,
                );

                return Ok(principal);
            }
            Ok(None) => Ok(()),
            Err(err) => {
                if err.matches(trc::EventType::Auth(trc::AuthEvent::MissingTotp)) {
                    return Err(err);
                } else {
                    Err(err)
                }
            }
        };

        match &req.credentials {
            Credentials::Plain { username, secret } => {
                // Then check if the credentials match the fallback admin or master user
                let master_user: Option<(String, String)> = None;
                let todo = "implement master";
                match (&self.core.network.security.fallback_admin, &master_user) {
                    (Some((fallback_admin, fallback_pass)), _) if username == fallback_admin => {
                        if verify_secret_hash(fallback_pass, secret).await? {
                            trc::event!(
                                Auth(trc::AuthEvent::Success),
                                AccountName = username.clone(),
                                SpanId = req.session_id,
                            );

                            return Ok(Principal::fallback_admin(fallback_pass));
                        }
                    }
                    (_, Some((master_user, master_pass))) if username.ends_with(master_user) => {
                        if verify_secret_hash(master_pass, secret).await? {
                            let username = username.strip_suffix(master_user).unwrap();
                            let username = username.strip_suffix('%').unwrap_or(username);

                            if let Some(principal) = directory
                                .query(
                                    QueryParams::name(username)
                                        .with_return_member_of(req.return_member_of),
                                )
                                .await?
                            {
                                trc::event!(
                                    Auth(trc::AuthEvent::Success),
                                    AccountName = username.to_string(),
                                    SpanId = req.session_id,
                                    AccountId = principal.id(),
                                    Type = principal.typ().description(),
                                );

                                return Ok(principal);
                            }
                        }
                    }
                    _ => {
                        // Validate API credentials
                        if req.allow_api_access
                            && let Ok(Some(principal)) = self
                                .store()
                                .query(
                                    QueryParams::credentials(&req.credentials)
                                        .with_return_member_of(req.return_member_of),
                                )
                                .await
                            && principal.typ == Type::ApiKey
                        {
                            trc::event!(
                                Auth(trc::AuthEvent::Success),
                                AccountName = principal.name().to_string(),
                                AccountId = principal.id(),
                                SpanId = req.session_id,
                            );

                            return Ok(principal);
                        }
                    }
                }
            }
            Credentials::OAuthBearer { token } if directory.has_bearer_token_support() => {
                // Check for bearer tokens issued locally
                if let Ok(token_info) = self
                    .validate_access_token(GrantType::AccessToken.into(), token)
                    .await
                {
                    let principal = if token_info.account_id != FALLBACK_ADMIN_ID {
                        directory
                            .query(
                                QueryParams::id(token_info.account_id)
                                    .with_return_member_of(req.return_member_of),
                            )
                            .await
                            .unwrap_or_default()
                    } else if let Some((_, fallback_pass)) =
                        &self.core.network.security.fallback_admin
                    {
                        Principal::fallback_admin(fallback_pass).into()
                    } else {
                        None
                    };
                    if let Some(principal) = principal {
                        trc::event!(
                            Auth(trc::AuthEvent::Success),
                            AccountName = principal.name().to_string(),
                            AccountId = principal.id(),
                            SpanId = req.session_id,
                        );

                        return Ok(principal);
                    }
                }
            }
            _ => (),
        };

        if let Err(err) = result {
            Err(err)
        } else if self.has_auth_fail2ban() {
            let login = req.credentials.login();
            if self.is_auth_fail2banned(req.remote_ip, login).await? {
                Err(trc::SecurityEvent::AuthenticationBan
                    .into_err()
                    .ctx(trc::Key::RemoteIp, req.remote_ip)
                    .ctx_opt(trc::Key::AccountName, login.map(|s| s.to_string())))
            } else {
                Err(trc::AuthEvent::Failed
                    .ctx(trc::Key::RemoteIp, req.remote_ip)
                    .ctx_opt(trc::Key::AccountName, login.map(|s| s.to_string())))
            }
        } else {
            Err(trc::AuthEvent::Failed
                .ctx(trc::Key::RemoteIp, req.remote_ip)
                .ctx_opt(
                    trc::Key::AccountName,
                    req.credentials.login().map(|s| s.to_string()),
                ))
        }
    }
}

impl<'x> AuthRequest<'x> {
    pub fn from_credentials(
        credentials: Credentials<String>,
        session_id: u64,
        remote_ip: IpAddr,
    ) -> Self {
        Self {
            credentials,
            session_id,
            remote_ip,
            return_member_of: true,
            directory: None,
            allow_api_access: false,
        }
    }

    pub fn from_plain(
        user: impl Into<String>,
        pass: impl Into<String>,
        session_id: u64,
        remote_ip: IpAddr,
    ) -> Self {
        Self::from_credentials(
            Credentials::Plain {
                username: user.into(),
                secret: pass.into(),
            },
            session_id,
            remote_ip,
        )
    }

    pub fn without_members(mut self) -> Self {
        self.return_member_of = false;
        self
    }

    pub fn with_directory(mut self, directory: &'x Directory) -> Self {
        self.directory = Some(directory);
        self
    }

    pub fn with_api_access(mut self, allow_api_access: bool) -> Self {
        self.allow_api_access = allow_api_access;
        self
    }
}

pub(crate) trait CredentialsUsername {
    fn login(&self) -> Option<&str>;
}

impl CredentialsUsername for Credentials<String> {
    fn login(&self) -> Option<&str> {
        match self {
            Credentials::Plain { username, .. } | Credentials::XOauth2 { username, .. } => {
                username.as_str().into()
            }
            Credentials::OAuthBearer { .. } => None,
        }
    }
}
