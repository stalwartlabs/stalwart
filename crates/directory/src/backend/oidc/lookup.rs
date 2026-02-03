/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::OpenIdDirectory;
use crate::{Account, Credentials};
use ahash::HashMap;
use reqwest::{RequestBuilder, StatusCode};
use trc::AuthEvent;
use utils::sanitize_email;

type OpenIdResponse = HashMap<String, serde_json::Value>;

impl OpenIdDirectory {
    pub async fn authenticate(&self, credentials: &Credentials) -> trc::Result<Option<Account>> {
        let token = match credentials {
            Credentials::Bearer { token } => token,
            _ => {
                return Err(AuthEvent::Error
                    .into_err()
                    .details("Unsupported credentials type for OIDC authentication"));
            }
        };
        let email;
        let name;
        let aud;
        let iss;
        let scopes;

        let response = match self {
            OpenIdDirectory::Introspect {
                client,
                endpoint,
                claim_email,
                claim_name,
                require_aud,
                require_scopes,
            } => {
                email = claim_email;
                name = claim_name;
                aud = require_aud;
                scopes = require_scopes.as_slice();
                iss = &None;

                send_request(client.post(endpoint).form(&[
                    ("token", token.as_str()),
                    ("token_type_hint", "access_token"),
                ]))
                .await?
            }
            OpenIdDirectory::UserInfo {
                endpoint,
                timeout,
                allow_invalid_certs,
                claim_email,
                claim_name,
            } => {
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(*allow_invalid_certs)
                    .timeout(*timeout)
                    .build()
                    .map_err(|err| {
                        AuthEvent::Error
                            .into_err()
                            .reason(err)
                            .details("Failed to build client")
                    })?;
                email = claim_email;
                name = claim_name;
                aud = &None;
                iss = &None;
                scopes = &[];
                send_request(client.get(endpoint).bearer_auth(token)).await?
            }
            OpenIdDirectory::Jwt {
                jwks_url,
                jwks_cache,
                claim_email,
                claim_name,
                require_aud,
                require_iss,
            } => {
                email = claim_email;
                name = claim_name;
                aud = require_aud;
                iss = require_iss;
                scopes = &[];
                todo!()
            }
        };

        let mut account = Account::default();
        let mut aud_matched = aud.is_none();
        let mut iss_matched = iss.is_none();
        let mut scopes_unmatched = scopes.len();

        for (field, value) in response {
            let serde_json::Value::String(value) = value else {
                continue;
            };

            if email == &field {
                if let Some(sanitized_email) = sanitize_email(&value) {
                    account.email = sanitized_email;
                }
            } else if let Some(name_field) = name
                && name_field == &field
            {
                account.description = Some(value);
            } else if !aud_matched
                && let Some(required_aud) = aud
                && field == "aud"
            {
                if value == *required_aud {
                    aud_matched = true;
                } else {
                    return Err(AuthEvent::Error
                        .into_err()
                        .details("Audience claim does not match"));
                }
            } else if !iss_matched
                && let Some(required_iss) = iss
                && field == "iss"
            {
                if value == *required_iss {
                    iss_matched = true;
                } else {
                    return Err(AuthEvent::Error
                        .into_err()
                        .details("Issuer claim does not match"));
                }
            } else if scopes_unmatched > 0 && field == "scope" {
                for scope in value.split_whitespace() {
                    if scopes.iter().any(|required_scope| required_scope == &scope) {
                        scopes_unmatched -= 1;
                        if scopes_unmatched == 0 {
                            break;
                        }
                    }
                }
            }
        }

        if !aud_matched {
            Err(AuthEvent::Error
                .into_err()
                .details("Audience claim not found in OIDC response"))
        } else if !iss_matched {
            Err(AuthEvent::Error
                .into_err()
                .details("Issuer claim not found in OIDC response"))
        } else if scopes_unmatched > 0 {
            Err(AuthEvent::Error
                .into_err()
                .details("One or more required scopes not found in OIDC response"))
        } else if !account.email.is_empty() {
            account.is_authenticated = true;
            Ok(Some(account))
        } else {
            Err(trc::AuthEvent::Error
                .into_err()
                .details("Email claim not found in OIDC response"))
        }
    }
}

async fn send_request(request: RequestBuilder) -> trc::Result<OpenIdResponse> {
    let response = request.send().await.map_err(|err| {
        AuthEvent::Error
            .into_err()
            .reason(err)
            .details("OIDC HTTP request failed")
    })?;

    match response.status() {
        StatusCode::OK => {
            // Fetch response
            let response = response.bytes().await.map_err(|err| {
                AuthEvent::Error
                    .into_err()
                    .reason(err)
                    .details("Failed to read OIDC response")
            })?;

            let todo = "deserialize directly into string, not serde_json::Value";

            // Deserialize response
            serde_json::from_slice::<OpenIdResponse>(&response).map_err(|err| {
                AuthEvent::Error
                    .into_err()
                    .reason(err)
                    .details("Failed to deserialize OIDC response")
            })
        }
        StatusCode::UNAUTHORIZED => Err(trc::AuthEvent::Failed
            .into_err()
            .code(401)
            .details("Unauthorized")),
        other => Err(trc::AuthEvent::Error
            .into_err()
            .code(other.as_u16())
            .ctx(trc::Key::Reason, response.text().await.unwrap_or_default())
            .details("Unexpected status code")),
    }
}
