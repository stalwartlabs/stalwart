/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    directory::oidc::get_token_for_client,
    utils::{containers, server::TestServerBuilder},
};
use encodify::base64::URL_SAFE_NO_PAD;
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{Action, Directory, OidcDirectory},
    },
    types::map::Map,
};
use serde_json::json;
use std::time::Duration;

const ISSUER: &str = "http://localhost:9080/realms/stalwart";
const DOMAIN: &str = "example.org";
const ACCOUNT: &str = "john.doe@example.org";
const PASSWORD: &str = "this is an OIDC password";

pub async fn test() {
    println!("Running OIDC issuer routing tests...");
    containers::ensure_keycloak().await;
    let test = TestServerBuilder::new("directory_issuer_test")
        .await
        .with_default_listeners()
        .await
        .disable_services()
        .build()
        .await;

    let admin = test.account("admin");
    let directory_id = admin
        .registry_create_object(Directory::Oidc(OidcDirectory {
            description: "Issuer routing test OIDC directory".to_string(),
            issuer_url: ISSUER.to_string(),
            claim_username: "email".to_string(),
            claim_name: Some("name".to_string()),
            claim_groups: Some("groups".to_string()),
            require_audience: Some("stalwart".to_string()),
            require_scopes: Map::new(vec!["openid".to_string()]),
            ..Default::default()
        }))
        .await;
    let domain_id = admin.find_or_create_domain(DOMAIN).await;
    admin
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({ Property::DirectoryId: directory_id.to_string() }),
        )
        .await;
    admin.reload_settings().await;
    admin.registry_create_object(Action::InvalidateCaches).await;

    assert!(
        test.server.get_default_directory().is_none(),
        "The OIDC directory must be reachable only through the domain for this test to mean anything"
    );

    let token = get_token_for_client(
        "stalwart-fallback",
        "stalwart-fallback-secret",
        ACCOUNT,
        PASSWORD,
        "openid",
    )
    .await;
    let claims = access_token_claims(&token);
    for claim in ["email", "preferred_username", "upn"] {
        assert!(
            claims.get(claim).is_none(),
            "The access token carries a {claim} claim, so it no longer covers issuer based routing: {claims}"
        );
    }
    assert_eq!(claims["iss"], json!(ISSUER));

    assert_eq!(
        session_status(&token).await,
        200,
        "A bearer token without a username claim did not reach the domain's OIDC directory"
    );
}

fn access_token_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("The token is not a JWT");

    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .expect("Failed to decode the token payload"),
    )
    .expect("Failed to parse the token claims")
}

async fn session_status(token: &str) -> u16 {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get("https://127.0.0.1:8899/jmap/session")
        .bearer_auth(token)
        .send()
        .await
        .expect("Failed to send session request")
        .status()
        .as_u16()
}
