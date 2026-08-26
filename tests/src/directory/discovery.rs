/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{http::HttpRequest, server::TestServerBuilder};
use registry::{
    schema::structs::{Directory, OidcDirectory},
    types::map::Map,
};

const EXTERNAL_ENDPOINT: &str =
    "http://localhost:9080/realms/stalwart/protocol/openid-connect/auth";
const INTERNAL_ENDPOINT: &str = "https://127.0.0.1:8899/login";

pub async fn test() {
    println!("Running OIDC account discovery tests...");
    crate::utils::containers::ensure_keycloak().await;
    let test = TestServerBuilder::new("directory_discovery_test")
        .await
        .with_default_listeners()
        .await
        .disable_services()
        .with_object(Directory::Oidc(oidc_test_directory()))
        .await
        .build()
        .await;
    assert!(
        test.server
            .get_default_directory()
            .and_then(|directory| directory.oidc_discovery_document())
            .is_some_and(|discovery| discovery.document.authorization_endpoint
                == EXTERNAL_ENDPOINT),
        "The default directory is not the test OpenID Connect provider"
    );
    let http = HttpRequest::new();

    for (account_name, expected) in [
        ("john.doe@example.org", EXTERNAL_ENDPOINT),
        ("John.Doe@Example.org", EXTERNAL_ENDPOINT),
        (
            "jane.smith@example.org%john.doe@example.org",
            EXTERNAL_ENDPOINT,
        ),
        ("admin", INTERNAL_ENDPOINT),
        ("john.doe@example.org%admin", INTERNAL_ENDPOINT),
        ("John.Doe@Example.org%Admin", INTERNAL_ENDPOINT),
        ("john.doe@", INTERNAL_ENDPOINT),
    ] {
        assert_eq!(
            authorization_endpoint(&http, account_name).await,
            expected,
            "Unexpected discovery document for {account_name:?}"
        );
    }
}

async fn authorization_endpoint(http: &HttpRequest, account_name: &str) -> String {
    http.get::<serde_json::Value>(&format!(
        "/api/discover/{}",
        account_name.replace('%', "%25")
    ))
    .await
    .unwrap()
    .get("authorization_endpoint")
    .and_then(|endpoint| endpoint.as_str())
    .unwrap_or_else(|| panic!("No authorization endpoint returned for {account_name:?}"))
    .to_string()
}

fn oidc_test_directory() -> OidcDirectory {
    OidcDirectory {
        description: "Test OIDC directory".to_string(),
        issuer_url: "http://localhost:9080/realms/stalwart".to_string(),
        claim_username: "preferred_username".to_string(),
        claim_name: Some("name".to_string()),
        claim_groups: Some("groups".to_string()),
        require_audience: Some("stalwart".to_string()),
        require_scopes: Map::new(vec![
            "email".to_string(),
            "profile".to_string(),
            "openid".to_string(),
        ]),
        ..Default::default()
    }
}
