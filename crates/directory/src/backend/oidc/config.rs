/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::OpenIdDirectory;
use crate::Directory;
use registry::schema::structs;

impl OpenIdDirectory {
    pub async fn open(config: structs::OidcDirectory) -> Result<Directory, String> {
        Ok(Directory::OpenId(match config {
            structs::OidcDirectory::UserInfo(config) => OpenIdDirectory::UserInfo {
                endpoint: config.endpoint,
                timeout: config.timeout.into_inner(),
                allow_invalid_certs: config.allow_invalid_certs,
                claim_email: config.claim_email,
                claim_name: config.claim_name,
            },
            structs::OidcDirectory::Introspect(config) => {
                let client = config
                    .http_auth
                    .build_http_client(
                        config.http_headers,
                        None,
                        config.timeout,
                        config.allow_invalid_certs,
                    )
                    .await?;
                OpenIdDirectory::Introspect {
                    client,
                    endpoint: config.endpoint,
                    claim_email: config.claim_email,
                    claim_name: config.claim_name,
                    require_aud: config.require_audience,
                    require_scopes: config.require_scopes,
                }
            }
            structs::OidcDirectory::Jwt(config) => OpenIdDirectory::Jwt {
                jwks_url: config.jwks_url,
                jwks_cache: config.jwks_cache_duration.into_inner(),
                claim_email: config.claim_email,
                claim_name: config.claim_name,
                require_aud: config.require_audience,
                require_iss: config.require_issuer,
            },
        }))
    }
}
