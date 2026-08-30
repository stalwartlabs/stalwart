/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    scim::{ScimTest, patch_body, query},
    utils::{containers, server::TestServer},
};
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{self, Action, OidcDirectory, UserAccount},
    },
    types::map::Map,
};
use scim_proto::SCHEMA_USER;
use serde_json::json;
use std::str::FromStr;
use types::id::Id;

pub const OIDC_DOMAIN: &str = "example.org";
const KEYCLOAK_PASSWORD: &str = "this is an OIDC password";
const JOHN: &str = "john.doe@example.org";
const BILL: &str = "bill.foobar@example.org";
const SCIM_DISPLAY_NAME: &str = "Provisioned By SCIM";
const SCIM_GROUP: &str = "Provisioned Group";

pub async fn test(test: &TestServer, scim: &ScimTest) {
    println!("Running SCIM OIDC interaction tests...");
    containers::ensure_keycloak().await;

    let domain_id = bind_directory(test).await;

    just_in_time_account_creation_is_disabled(test, scim).await;
    scim_managed_attributes_survive_a_login(test, scim).await;
    clearing_the_flag_restores_just_in_time_provisioning(test, scim, domain_id).await;

    cleanup(test, scim, domain_id).await;
}

async fn bind_directory(test: &TestServer) -> Id {
    let admin = test.account("admin");
    let directory_id = admin
        .registry_create_object(structs::Directory::Oidc(OidcDirectory {
            description: "SCIM test OIDC directory".to_string(),
            issuer_url: "http://localhost:9080/realms/stalwart".to_string(),
            claim_username: "email".to_string(),
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
        }))
        .await;

    let domain_id = admin.find_or_create_domain(OIDC_DOMAIN).await;
    admin
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DirectoryId: directory_id.to_string(),
                Property::AllowScimProvisioning: true,
            }),
        )
        .await;
    admin.reload_settings().await;
    admin.registry_create_object(Action::InvalidateCaches).await;

    domain_id
}

async fn just_in_time_account_creation_is_disabled(test: &TestServer, scim: &ScimTest) {
    let token = keycloak_token(BILL).await;

    assert_eq!(
        bearer_session_status(&token).await,
        401,
        "A domain provisioned through SCIM must not create accounts on login"
    );

    let response = scim
        .client
        .get(&query("/Users", &format!("userName eq \"{BILL}\"")))
        .await;
    response.assert_status(200);
    assert_eq!(
        response.total_results(),
        0,
        "The login created an account: {}",
        response.body
    );
    assert!(!account_exists(test, BILL).await);
    assert!(!account_exists(test, "corporate@example.org").await);
}

async fn scim_managed_attributes_survive_a_login(test: &TestServer, scim: &ScimTest) {
    let user_id = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": JOHN,
                "displayName": SCIM_DISPLAY_NAME,
                "externalId": "OIDC-1",
            }),
        )
        .await
        .assert_status(201)
        .id();
    let group_id = scim.create_group(SCIM_GROUP).await;

    scim.client
        .patch(
            &format!("/Groups/{group_id}"),
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": user_id}]}])),
        )
        .await
        .assert_status(200);

    let before = scim.client.get(&format!("/Users/{user_id}")).await;
    before.assert_status(200);

    let token = keycloak_token(JOHN).await;
    assert_eq!(
        bearer_session_status(&token).await,
        200,
        "A SCIM provisioned account must still authenticate over OIDC"
    );

    let after = scim.client.get(&format!("/Users/{user_id}")).await;
    after.assert_status(200);
    assert_eq!(
        after.json["displayName"],
        json!(SCIM_DISPLAY_NAME),
        "The OIDC name claim overwrote the SCIM displayName"
    );
    assert_eq!(
        after.json["groups"], before.json["groups"],
        "The OIDC groups claim overwrote the SCIM membership"
    );
    assert_eq!(after.json["groups"][0]["display"], json!(SCIM_GROUP));
    assert_eq!(after.etag(), before.etag());

    assert!(
        !account_exists(test, "sales@example.org").await,
        "The OIDC groups claim created a group account"
    );

    assert_eq!(
        bearer_session_status(&keycloak_token(JOHN).await).await,
        200,
        "A second login must be equally inert"
    );
    let repeated = scim.client.get(&format!("/Users/{user_id}")).await;
    assert_eq!(repeated.etag(), before.etag());
}

async fn clearing_the_flag_restores_just_in_time_provisioning(
    test: &TestServer,
    scim: &ScimTest,
    domain_id: Id,
) {
    let john_id = scim
        .client
        .get(&query("/Users", &format!("userName eq \"{JOHN}\"")))
        .await
        .resource_ids()
        .remove(0);

    let admin = test.account("admin");
    admin
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({ Property::AllowScimProvisioning: false }),
        )
        .await;
    admin.registry_create_object(Action::InvalidateCaches).await;

    assert_eq!(
        bearer_session_status(&keycloak_token(BILL).await).await,
        200,
        "Just-in-time provisioning must be unchanged when the flag is off"
    );

    let bill = user_account(
        test,
        account_id(test, BILL).await.expect("Bill was not created"),
    )
    .await;
    assert_eq!(bill.description.as_deref(), Some("Bill Foobar"));
    let corporate = account_id(test, "corporate@example.org")
        .await
        .expect("The groups claim did not create a group account");
    assert!(bill.member_group_ids.contains(&corporate));

    assert_eq!(
        bearer_session_status(&keycloak_token(JOHN).await).await,
        200
    );

    let john = user_account(test, Id::from_str(&john_id).unwrap()).await;
    assert_eq!(
        john.description.as_deref(),
        Some("John Doe"),
        "Without the flag the name claim must win, which is what the flag exists to prevent"
    );
    let sales = account_id(test, "sales@example.org")
        .await
        .expect("The groups claim did not create a group account");
    assert_eq!(
        john.member_group_ids.iter().copied().collect::<Vec<_>>(),
        vec![sales],
        "Without the flag the groups claim must replace the SCIM membership"
    );

    admin
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({ Property::AllowScimProvisioning: true }),
        )
        .await;
    admin.registry_create_object(Action::InvalidateCaches).await;
}

async fn user_account(test: &TestServer, id: Id) -> UserAccount {
    match test
        .server
        .registry()
        .object::<structs::Account>(id)
        .await
        .unwrap()
        .expect("The account no longer exists")
    {
        structs::Account::User(account) => account,
        other => panic!("Expected a user account but got {other:?}"),
    }
}

async fn cleanup(test: &TestServer, scim: &ScimTest, domain_id: Id) {
    let admin = test.account("admin");

    for user_name in [JOHN, BILL] {
        let ids = scim
            .client
            .get(&query("/Users", &format!("userName eq \"{user_name}\"")))
            .await
            .resource_ids();
        for id in ids {
            scim.client.delete(&format!("/Users/{id}")).await;
        }
    }

    let group_ids = scim
        .client
        .get(&query(
            "/Groups",
            &format!("displayName eq \"{SCIM_GROUP}\""),
        ))
        .await
        .resource_ids();
    for id in group_ids {
        scim.client.delete(&format!("/Groups/{id}")).await;
    }

    for address in ["sales@example.org", "corporate@example.org"] {
        if let Some(id) = account_id(test, address).await {
            admin.registry_destroy(ObjectType::Account, [id]).await;
        }
    }

    admin
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DirectoryId: Option::<String>::None,
                Property::AllowScimProvisioning: false,
            }),
        )
        .await;
    admin.reload_settings().await;
    admin.registry_create_object(Action::InvalidateCaches).await;
}

async fn account_exists(test: &TestServer, address: &str) -> bool {
    account_id(test, address).await.is_some()
}

async fn account_id(test: &TestServer, address: &str) -> Option<Id> {
    test.server
        .account_id_from_email(address, false)
        .await
        .unwrap_or(None)
        .map(Id::from)
}

async fn keycloak_token(username: &str) -> String {
    let response = reqwest::Client::new()
        .post("http://localhost:9080/realms/stalwart/protocol/openid-connect/token")
        .form(&[
            ("grant_type", "password"),
            ("client_id", "stalwart"),
            ("client_secret", "stalwart-secret"),
            ("username", username),
            ("password", KEYCLOAK_PASSWORD),
            ("scope", "openid email profile"),
        ])
        .send()
        .await
        .expect("Failed to request a Keycloak token");
    let body = response.text().await.expect("Failed to read the token");

    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|json| json["access_token"].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("No access_token in the Keycloak response: {body}"))
}

async fn bearer_session_status(token: &str) -> u16 {
    crate::scim::jmap_session_status(&format!("Bearer {token}")).await
}
