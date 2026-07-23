/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use directory::{Account, Credentials, Directory, backend::oidc::OpenIdDirectory};
use registry::{schema::structs, types::map::Map};

pub async fn test() {
    println!("Running OIDC directory tests...");
    crate::utils::containers::ensure_keycloak().await;
    let config = structs::OidcDirectory {
        description: "Test OIDC directory".to_string(),
        issuer_url: "http://localhost:9080/realms/stalwart".to_string(),
        claim_username: "preferred_username".to_string(),
        claim_name: Some("name".to_string()),
        claim_groups: Some("groups".to_string()),
        username_domain: None,
        require_audience: Some("stalwart".to_string()),
        require_scopes: Map::new(vec![
            "email".to_string(),
            "profile".to_string(),
            "openid".to_string(),
        ]),
        member_tenant_id: None,
    };
    let mut oidc = OpenIdDirectory::open(config.clone()).await.unwrap();
    let token = get_token("john.doe@example.org", "this is an OIDC password").await;

    // Test the userinfo endpoint
    assert_eq!(
        oidc.authenticate(&Credentials::Bearer {
            username: None,
            token: format!(".{token}"), // Prefix with '.' to force userinfo in test mode
        })
        .await
        .unwrap(),
        Account {
            email: "john.doe@example.org".to_string(),
            email_aliases: vec![],
            secret: None,
            groups: Some(vec!["sales@example.org".to_string()]),
            description: Some("John Doe".to_string())
        }
    );

    // Make sure the userinfo endpoint is not being used
    if let Directory::OpenId(directory) = &mut oidc {
        directory.discovery.document.userinfo_endpoint = "http://invalid".to_string();
    }

    // JWT authentication should still work without the userinfo endpoint
    assert_eq!(
        oidc.authenticate(&Credentials::Bearer {
            username: None,
            token: token.clone(),
        })
        .await
        .unwrap(),
        Account {
            email: "john.doe@example.org".to_string(),
            email_aliases: vec![],
            secret: None,
            groups: Some(vec!["sales@example.org".to_string()]),
            description: Some("John Doe".to_string())
        }
    );

    // Test ODIC userinfo fallback
    let mut config_userinfo_fallback = config.clone();
    config_userinfo_fallback.claim_username = "email".to_string();
    config_userinfo_fallback.require_scopes = Map::new(vec!["openid".to_string()]);

    let token_openid_only = get_token_for_client(
        "stalwart-fallback",
        "stalwart-fallback-secret",
        "john.doe@example.org",
        "this is an OIDC password",
        "openid",
    )
    .await;

    let mut oidc_broken_userinfo = OpenIdDirectory::open(config_userinfo_fallback.clone())
        .await
        .unwrap();
    if let Directory::OpenId(directory) = &mut oidc_broken_userinfo {
        directory.discovery.document.userinfo_endpoint = "http://invalid".to_string();
    }
    assert!(
        oidc_broken_userinfo
            .authenticate(&Credentials::Bearer {
                username: None,
                token: token_openid_only.clone(),
            })
            .await
            .is_err()
    );
    let oidc_userinfo_fallback = OpenIdDirectory::open(config_userinfo_fallback)
        .await
        .unwrap();
    assert_eq!(
        oidc_userinfo_fallback
            .authenticate(&Credentials::Bearer {
                username: None,
                token: token_openid_only,
            })
            .await
            .unwrap(),
        Account {
            email: "john.doe@example.org".to_string(),
            email_aliases: vec![],
            secret: None,
            groups: Some(vec!["sales@example.org".to_string()]),
            description: None,
        }
    );

    // Not matching the required audience should fail
    let mut config_wrong_audience = config.clone();
    config_wrong_audience.require_audience = Some("wrong_audience".to_string());
    assert!(
        OpenIdDirectory::open(config_wrong_audience)
            .await
            .unwrap()
            .authenticate(&Credentials::Bearer {
                username: None,
                token: token.clone(),
            })
            .await
            .is_err()
    );

    // Not having the required scopes should fail
    let mut config_wrong_scopes = config.clone();
    config_wrong_scopes.require_scopes = Map::new(vec![
        "email".to_string(),
        "profile".to_string(),
        "openid".to_string(),
        "missing_scope".to_string(),
    ]);
    assert!(
        OpenIdDirectory::open(config_wrong_scopes)
            .await
            .unwrap()
            .authenticate(&Credentials::Bearer {
                username: None,
                token,
            })
            .await
            .is_err()
    );

    // Test authorization endpoint retrieval
    assert_eq!(
        oidc.oidc_discovery_document()
            .as_ref()
            .map(|oidc| oidc.document.authorization_endpoint.as_str()),
        Some("http://localhost:9080/realms/stalwart/protocol/openid-connect/auth")
    );
}

async fn get_token(username: &str, password: &str) -> String {
    get_token_for_client(
        "stalwart",
        "stalwart-secret",
        username,
        password,
        "openid email profile",
    )
    .await
}

async fn get_token_for_client(
    client_id: &str,
    client_secret: &str,
    username: &str,
    password: &str,
    scope: &str,
) -> String {
    let client = reqwest::Client::new();

    let response = client
        .post("http://localhost:9080/realms/stalwart/protocol/openid-connect/token")
        .form(&[
            ("grant_type", "password"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("username", username),
            ("password", password),
            ("scope", scope),
        ])
        .send()
        .await
        .expect("Failed to send token request");

    let body = response
        .text()
        .await
        .expect("Failed to read token response");

    let json: serde_json::Value =
        serde_json::from_str(&body).expect("Failed to parse token response");

    json["access_token"]
        .as_str()
        .expect("No access_token in response")
        .to_string()
}
