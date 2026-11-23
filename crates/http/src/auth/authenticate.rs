/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::is_exchange_enabled;
use common::{
    HttpAuthCache, Server,
    auth::{AccessToken, AuthRequest, authentication::Authenticated},
    cache::http_auth::RevocationEpoch,
    network::limiter::InFlight,
};
use compact_str::CompactString;
use directory::Credentials;
use encodify::base64::LENIENT;
use http_proto::{HttpRequest, HttpSessionData};
use hyper::header;
use mail_parser::Charset;
use std::future::Future;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BasicLogin {
    Strict,
    Exchange,
}

pub struct HttpAuthenticated {
    pub in_flight: Option<InFlight>,
    pub access_token: AccessToken,
    pub epoch: RevocationEpoch,
}

pub trait Authenticator: Sync + Send {
    fn authenticate_headers(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpAuthenticated>> + Send;
}

impl Authenticator for Server {
    async fn authenticate_headers(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<HttpAuthenticated> {
        let revocations = &self.inner.cache.grant_revocations;
        let epoch = revocations.epoch();
        if let Some((mechanism, token)) = req.authorization() {
            // Check if the credentials are cached
            if let Some(http_cache) = self.inner.cache.http_auth.get(token) {
                // Make sure the revision is still valid
                if self.inner.cache.http_auth.is_live(&http_cache) {
                    let access_token = AccessToken::renew(
                        self.access_token(http_cache.account_id).await?,
                        http_cache.credential_id,
                        http_cache.token_scope,
                        session.remote_ip,
                    )?;

                    if access_token.revision() == http_cache.revision {
                        // Enforce authenticated rate limit
                        return self
                            .is_http_authenticated_request_allowed(&access_token, session.remote_ip)
                            .await
                            .map(|in_flight| HttpAuthenticated {
                                in_flight,
                                access_token,
                                epoch,
                            });
                    }
                }

                // If the revision is not valid, remove the cached credentials
                self.inner.cache.http_auth.remove(token);
            }

            let credentials = if mechanism.eq_ignore_ascii_case("basic") {
                // Decode the base64 encoded credentials
                let login = if is_exchange_enabled(&self.core) {
                    BasicLogin::Exchange
                } else {
                    BasicLogin::Strict
                };
                decode_plain_auth(token, login).ok_or_else(|| {
                    trc::AuthEvent::Error
                        .into_err()
                        .details("Failed to decode Basic auth request.")
                        .id(CompactString::from(token))
                        .caused_by(trc::location!())
                })?
            } else if mechanism.eq_ignore_ascii_case("bearer") {
                // Enforce anonymous rate limit
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;

                Credentials::Bearer {
                    username: None,
                    token: token.to_string(),
                }
            } else {
                // Enforce anonymous rate limit
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;

                return Err(trc::AuthEvent::Error
                    .into_err()
                    .reason("Unsupported authentication mechanism.")
                    .details(CompactString::from(token))
                    .caused_by(trc::location!()));
            };

            // Authenticate
            let Authenticated {
                access_token,
                expires_in,
            } = self
                .authenticate(&AuthRequest::from_credentials(
                    credentials,
                    session.session_id,
                    session.remote_ip,
                ))
                .await?;

            // Cache credentials
            let cache_ttl = expires_in.map_or(self.core.oauth.oauth_expiry_token, |expires_in| {
                expires_in.min(self.core.oauth.oauth_expiry_token)
            });
            revocations.insert(
                &self.inner.cache.http_auth,
                token,
                HttpAuthCache {
                    account_id: access_token.account_id(),
                    expires: self.inner.cache.http_auth.expires_in(cache_ttl),
                    credential_id: access_token.credential_id(),
                    revision: access_token.revision(),
                    token_scope: access_token.token_scope(),
                },
                epoch,
            );

            // Enforce authenticated rate limit
            self.is_http_authenticated_request_allowed(&access_token, session.remote_ip)
                .await
                .map(|in_flight| HttpAuthenticated {
                    in_flight,
                    access_token,
                    epoch,
                })
        } else {
            // Enforce anonymous rate limit
            self.is_http_anonymous_request_allowed(session.remote_ip)
                .await?;

            Err(trc::AuthEvent::Failed
                .into_err()
                .details("Missing Authorization header.")
                .caused_by(trc::location!()))
        }
    }
}

pub trait HttpHeaders {
    fn authorization(&self) -> Option<(&str, &str)>;
    fn authorization_basic(&self) -> Option<&str>;
}

impl HttpHeaders for HttpRequest {
    fn authorization(&self) -> Option<(&str, &str)> {
        self.headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split_once(' ').map(|(l, t)| (l, t.trim())))
    }

    fn authorization_basic(&self) -> Option<&str> {
        self.authorization().and_then(|(l, t)| {
            if l.eq_ignore_ascii_case("basic") {
                Some(t)
            } else {
                None
            }
        })
    }
}

fn decode_plain_auth(token: &str, login: BasicLogin) -> Option<Credentials> {
    match login {
        BasicLogin::Strict => LENIENT.decode_to_string(token).ok().and_then(|token| {
            token
                .split_once(':')
                .map(|(login, secret)| Credentials::Basic {
                    username: login.trim().to_lowercase(),
                    secret: secret.to_string(),
                    mfa_token: None,
                })
        }),
        BasicLogin::Exchange => {
            let token = match String::from_utf8(LENIENT.decode(token).ok()?) {
                Ok(token) => token,
                Err(err) => Charset::Windows1252.decode_owned(err.into_bytes()),
            };
            let (login, secret) = token.split_once(':')?;
            let username = match login.split_once('%') {
                Some((account, master)) => {
                    let mut username = without_domain(account)?.to_lowercase();
                    username.push('%');
                    username.push_str(&without_domain(master)?.to_lowercase());
                    username
                }
                None => without_domain(login)?.to_lowercase(),
            };
            Some(Credentials::Basic {
                username,
                secret: secret.to_string(),
                mfa_token: None,
            })
        }
    }
}

fn without_domain(login: &str) -> Option<&str> {
    let login = login
        .rsplit_once('\\')
        .map_or(login, |(_, user)| user)
        .trim();
    (!login.is_empty()).then_some(login)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/http/src/auth/authenticate/tests.rs"]
mod tests;
