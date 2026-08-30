/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    scim::{ScimClient, ScimTest, api_key},
    utils::server::TestServer,
};
use registry::{
    schema::{
        enums::Permission,
        structs::{Enterprise, Http, Rate, SecretKeyOptional, SecretKeyValue},
    },
    types::duration::Duration,
};
use serde_json::json;

pub async fn test(test: &TestServer, scim: &ScimTest) {
    println!("Running SCIM limit tests...");

    exceeding_the_rate_limit_returns_a_scim_error(test).await;
    the_enterprise_licence_gates_every_endpoint(test, scim).await;
}

async fn exceeding_the_rate_limit_returns_a_scim_error(test: &TestServer) {
    let admin = test.account("admin");
    let principal = admin
        .create_user_account(
            "rate-svc@scim.example.com",
            "these_pretzels_are_making_me_thirsty",
            "Rate Limited Principal",
            &[],
            vec![Permission::ScimAccess, Permission::SysAccountGet],
        )
        .await;
    let client =
        ScimClient::bearer(&api_key(admin, &principal, json!({ "@type": "Inherit" })).await);

    client.get("/Users?count=0").await.assert_status(200);

    admin
        .registry_create_object(Http {
            rate_limit_authenticated: Some(Rate {
                count: 5,
                period: Duration::from_millis(60000),
            }),
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;

    let mut limited = None;
    for _ in 0..50 {
        let response = client.get("/Users?count=0").await;
        if response.status.as_u16() == 429 {
            limited = Some(response);
            break;
        }
    }

    let response = limited.expect("The authenticated rate limit was never enforced");
    response.assert_error(429, None);
    assert!(
        response.header("retry-after").is_some(),
        "A 429 must carry a Retry-After header: {:?}",
        response.headers
    );

    admin.registry_create_object(Http::default()).await;
    admin.reload_settings().await;

    admin
        .registry_destroy(
            registry::schema::prelude::ObjectType::Account,
            [principal.id()],
        )
        .await
        .assert_destroyed(&[principal.id()]);
}

async fn the_enterprise_licence_gates_every_endpoint(test: &TestServer, scim: &ScimTest) {
    let admin = test.account("admin");

    admin
        .registry_create_object(Enterprise {
            license_key: SecretKeyOptional::Value(SecretKeyValue {
                secret: "not-a-valid-licence".to_string(),
            }),
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;

    for (method, path) in [
        ("GET", "/Users"),
        ("GET", "/Groups"),
        ("GET", "/ServiceProviderConfig"),
        ("GET", "/ResourceTypes"),
        ("GET", "/Schemas"),
        ("POST", "/Bulk"),
        ("GET", "/Me"),
    ] {
        let response = scim.client.request(method, path, None).await;
        response.assert_error(403, None);
        response.assert_detail_contains("Enterprise edition");
    }

    scim.anonymous
        .get("/ServiceProviderConfig")
        .await
        .assert_error(403, None);

    admin
        .registry_create_object(Enterprise {
            license_key: SecretKeyOptional::None,
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;

    scim.client.get("/Users").await.assert_status(200);
    scim.anonymous
        .get("/ServiceProviderConfig")
        .await
        .assert_status(200);
}
