/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::{Credentials, Directory, UnavailableDirectory, backend::oidc::OpenIdDirectory};
use registry::{
    schema::{enums::DirectoryType, structs},
    types::map::Map,
};
use std::time::{Duration, Instant};

const DISCOVERY_RETRY_FOR: Duration = Duration::from_secs(30);

pub async fn test() {
    println!("Running unavailable directory tests...");

    let started_at = Instant::now();
    let error = OpenIdDirectory::open(structs::OidcDirectory {
        description: "Unreachable OIDC directory".to_string(),
        issuer_url: "http://localhost:59999/realms/stalwart".to_string(),
        claim_username: "preferred_username".to_string(),
        claim_name: None,
        claim_groups: None,
        username_domain: None,
        require_audience: None,
        require_scopes: Map::new(vec![]),
        member_tenant_id: None,
    })
    .await
    .expect_err("Discovery against an unreachable issuer must fail");
    let elapsed = started_at.elapsed();
    assert!(
        elapsed >= DISCOVERY_RETRY_FOR,
        "Discovery gave up after {elapsed:?}: {error}"
    );

    let oidc = Directory::Unavailable(UnavailableDirectory::new(DirectoryType::Oidc, error));
    assert!(
        oidc.authenticate(&Credentials::Basic {
            username: "john.doe@example.org".to_string(),
            secret: "this is an OIDC password".to_string(),
            mfa_token: None,
        })
        .await
        .is_err(),
        "Password authentication must not fall back to internal credentials"
    );
    assert!(
        oidc.authenticate(&Credentials::Bearer {
            username: None,
            token: "not a token".to_string(),
        })
        .await
        .is_err()
    );
    assert!(oidc.has_bearer_token_support());
    assert!(!oidc.can_lookup_recipients());
    assert!(oidc.oidc_discovery_document().is_none());

    let ldap = Directory::Unavailable(UnavailableDirectory::new(
        DirectoryType::Ldap,
        "LDAP bind password is required when bind DN is set",
    ));
    assert!(
        ldap.authenticate(&Credentials::Basic {
            username: "john.doe@example.org".to_string(),
            secret: "this is John's LDAP password".to_string(),
            mfa_token: None,
        })
        .await
        .is_err()
    );
    assert!(ldap.recipient("john.doe@example.org").await.is_err());
    assert!(ldap.can_lookup_recipients());
    assert!(!ldap.has_bearer_token_support());
}
