/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::{Duration, HttpAuth};
use utils::{
    Client, HeaderMap,
    http::{build_http_client, build_http_headers},
    map::vec_map::VecMap,
};

impl HttpAuth {
    pub async fn build_headers(
        &self,
        extra_headers: VecMap<String, String>,
        content_type: Option<&str>,
    ) -> Result<HeaderMap, String> {
        match self {
            HttpAuth::Unauthenticated => {
                build_http_headers(extra_headers, None, None, None, content_type)
            }
            HttpAuth::Basic(auth) => build_http_headers(
                extra_headers,
                auth.username.as_str().into(),
                auth.secret.secret().await?.as_ref().into(),
                None,
                content_type,
            ),
            HttpAuth::Bearer(auth) => build_http_headers(
                extra_headers,
                None,
                None,
                auth.bearer_token.secret().await?.as_ref().into(),
                content_type,
            ),
        }
    }

    pub async fn build_http_client(
        &self,
        extra_headers: VecMap<String, String>,
        content_type: Option<&str>,
        timeout: Duration,
        allow_invalid_certs: bool,
    ) -> Result<Client, String> {
        match self {
            HttpAuth::Unauthenticated => build_http_client(
                extra_headers,
                None,
                None,
                None,
                content_type,
                timeout.into_inner(),
                allow_invalid_certs,
            ),
            HttpAuth::Basic(auth) => build_http_client(
                extra_headers,
                auth.username.as_str().into(),
                auth.secret.secret().await?.as_ref().into(),
                None,
                content_type,
                timeout.into_inner(),
                allow_invalid_certs,
            ),
            HttpAuth::Bearer(auth) => build_http_client(
                extra_headers,
                None,
                None,
                auth.bearer_token.secret().await?.as_ref().into(),
                content_type,
                timeout.into_inner(),
                allow_invalid_certs,
            ),
        }
    }
}
