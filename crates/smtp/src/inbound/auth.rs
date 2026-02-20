/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{auth::AuthRequest, network::SessionStream};
use directory::Credentials;
use mail_parser::decoders::base64::base64_decode;
use registry::schema::enums::Permission;
use smtp_proto::{AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2, IntoString};
use trc::AuthEvent;

use crate::core::Session;

pub struct SaslToken {
    mechanism: u64,
    credentials: Credentials,
}

impl SaslToken {
    pub fn from_mechanism(mechanism: u64) -> Option<SaslToken> {
        match mechanism {
            AUTH_PLAIN | AUTH_LOGIN => SaslToken {
                mechanism,
                credentials: Credentials::Basic {
                    username: String::new(),
                    secret: String::new(),
                },
            }
            .into(),
            AUTH_OAUTHBEARER | AUTH_XOAUTH2 => SaslToken {
                mechanism,
                credentials: Credentials::Bearer {
                    username: None,
                    token: String::new(),
                },
            }
            .into(),
            _ => None,
        }
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn handle_sasl_response(
        &mut self,
        token: &mut SaslToken,
        response: &[u8],
    ) -> Result<bool, ()> {
        if response.is_empty() {
            match (token.mechanism, &token.credentials) {
                (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER, _) => {
                    self.write(b"334 Go ahead.\r\n").await?;
                    return Ok(true);
                }
                (AUTH_LOGIN, Credentials::Basic { username, secret }) => {
                    if username.is_empty() && secret.is_empty() {
                        self.write(b"334 VXNlcm5hbWU6\r\n").await?;
                        return Ok(true);
                    }
                }
                _ => (),
            }
        } else if let Some(response) = base64_decode(response) {
            match (token.mechanism, &mut token.credentials) {
                (AUTH_PLAIN, _) => {
                    if let Some(credentials) = Credentials::decode_sasl_challenge_plain(&response) {
                        return self.authenticate(credentials).await;
                    }
                }
                (AUTH_LOGIN, Credentials::Basic { username, secret }) => {
                    return if username.is_empty() {
                        *username = response.into_string();
                        self.write(b"334 UGFzc3dvcmQ6\r\n").await?;
                        Ok(true)
                    } else {
                        *secret = response.into_string();
                        self.authenticate(std::mem::replace(
                            &mut token.credentials,
                            Credentials::Basic {
                                username: String::new(),
                                secret: String::new(),
                            },
                        ))
                        .await
                    };
                }
                (AUTH_OAUTHBEARER | AUTH_XOAUTH2, _) => {
                    if let Some(credentials) = Credentials::decode_sasl_challenge_oauth(&response) {
                        return self.authenticate(credentials).await;
                    }
                }
                _ => (),
            }
        }

        self.auth_error(b"500 5.5.6 Invalid challenge.\r\n").await
    }

    pub async fn authenticate(&mut self, credentials: Credentials) -> Result<bool, ()> {
        // Authenticate
        let result = self
            .server
            .authenticate(&AuthRequest::from_credentials(
                credentials,
                self.data.session_id,
                self.data.remote_ip,
            ))
            .await
            .and_then(|access_token| access_token.assert_has_permission(Permission::EmailSend));

        let result = match result {
            Ok(access_token) => {
                self.server
                    .account_info(access_token.account_id())
                    .await
            }
            Err(err) => Err(err),
        };

        match result {
            Ok(account_info) => {
                self.data.authenticated_as = account_info.into();
                self.eval_post_auth_params().await;
                self.write(b"235 2.7.0 Authentication succeeded.\r\n")
                    .await?;
                return Ok(false);
            }
            Err(err) => {
                let reason = *err.as_ref();

                trc::error!(err.span_id(self.data.session_id));

                match reason {
                    trc::EventType::Auth(trc::AuthEvent::Failed) => {
                        return self
                            .auth_error(b"535 5.7.8 Authentication credentials invalid.\r\n")
                            .await;
                    }
                    trc::EventType::Auth(trc::AuthEvent::TokenExpired) => {
                        return self.auth_error(b"535 5.7.8 OAuth token expired.\r\n").await;
                    }
                    trc::EventType::Auth(trc::AuthEvent::MissingTotp) => {
                        return self
                            .auth_error(
                                b"334 5.7.8 Missing TOTP token, try with 'secret$totp_code'.\r\n",
                            )
                            .await;
                    }
                    trc::EventType::Security(trc::SecurityEvent::Unauthorized) => {
                        self.write(
                            concat!(
                                "550 5.7.1 Your account is not authorized ",
                                "to use this service.\r\n"
                            )
                            .as_bytes(),
                        )
                        .await?;
                        return Ok(false);
                    }
                    trc::EventType::Security(_) => {
                        return Err(());
                    }
                    _ => (),
                }
            }
        }

        self.write(b"454 4.7.0 Temporary authentication failure\r\n")
            .await?;

        Ok(false)
    }

    pub async fn auth_error(&mut self, response: &[u8]) -> Result<bool, ()> {
        tokio::time::sleep(self.params.auth_errors_wait).await;
        self.data.auth_errors += 1;
        self.write(response).await?;
        if self.data.auth_errors < self.params.auth_errors_max {
            Ok(false)
        } else {
            trc::event!(
                Auth(AuthEvent::TooManyAttempts),
                SpanId = self.data.session_id,
            );

            self.write(b"455 4.3.0 Too many authentication errors, disconnecting.\r\n")
                .await?;
            Err(())
        }
    }

    pub fn authenticated_as(&self) -> Option<&str> {
        self.data
            .authenticated_as
            .as_ref()
            .map(|authenticated_as| authenticated_as.name())
    }

    pub fn is_authenticated(&self) -> bool {
        self.data.authenticated_as.is_some()
    }

    pub fn authenticated_emails(&self) -> &[String] {
        self.data.authenticated_as.as_ref().unwrap().addresses()
    }
}
