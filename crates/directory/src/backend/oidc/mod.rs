/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod config;
pub mod lookup;

use std::time::Duration;

pub enum OpenIdDirectory {
    Introspect {
        client: reqwest::Client,
        endpoint: String,
        claim_email: String,
        claim_name: Option<String>,
        require_aud: Option<String>,
        require_scopes: Vec<String>,
    },
    UserInfo {
        endpoint: String,
        timeout: Duration,
        allow_invalid_certs: bool,
        claim_email: String,
        claim_name: Option<String>,
    },
    Jwt {
        jwks_url: String,
        jwks_cache: Duration,
        claim_email: String,
        claim_name: Option<String>,
        require_aud: Option<String>,
        require_iss: Option<String>,
    },
}
