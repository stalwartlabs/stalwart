/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    scim::{PLAIN_DOMAIN, ScimClient, ScimTest, group_body, patch_body, user_body},
    utils::server::TestServer,
};
use serde_json::json;

pub async fn test(test: &TestServer, scim: &ScimTest) {
    println!("Running SCIM authentication and authorization tests...");

    anonymous_requests_are_challenged(scim).await;
    basic_authentication_is_refused(scim).await;
    invalid_bearer_tokens_are_rejected(scim).await;
    the_scim_access_permission_gates_every_endpoint(scim).await;
    the_permission_matrix_is_enforced(scim).await;
    the_gate_fires_before_any_store_read(scim).await;
    the_service_principal_cannot_deprovision_itself(scim).await;
    resources_outside_a_provisionable_domain_are_invisible(test, scim).await;
}

async fn resources_outside_a_provisionable_domain_are_invisible(
    test: &TestServer,
    scim: &ScimTest,
) {
    let account = test
        .account("admin")
        .create_user_account(
            "outsider@plain.example.com",
            "these_pretzels_are_making_me_thirsty",
            "Outsider",
            &[],
            vec![],
        )
        .await;
    let id = account.id().to_string();
    let path = format!("/Users/{id}");

    let listing = scim.client.get("/Users?count=200").await;
    listing.assert_status(200);
    assert!(
        !listing
            .resources()
            .iter()
            .any(|resource| resource["userName"] == json!(format!("outsider@{PLAIN_DOMAIN}"))),
        "An account outside a provisionable domain was listed: {}",
        listing.body
    );
    listing.assert_lacks_id(&id);

    scim.client.get(&path).await.assert_error(404, None);
    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "displayName", "value": "Taken Over"}])),
        )
        .await
        .assert_error(404, None);
    scim.client
        .put(&path, user_body(&format!("outsider@{PLAIN_DOMAIN}")))
        .await
        .assert_error(404, None);
    scim.client.delete(&path).await.assert_error(404, None);

    scim.client
        .post("/Users", user_body(&format!("outsider@{PLAIN_DOMAIN}")))
        .await
        .assert_error(400, Some("invalidValue"))
        .assert_detail_contains(PLAIN_DOMAIN);

    let bulk = scim
        .client
        .post(
            "/Bulk",
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations": [{"method": "DELETE", "path": path}],
            }),
        )
        .await;
    bulk.assert_status(200);
    assert_eq!(bulk.json["Operations"][0]["status"], json!("404"));

    let group = scim.create_group("Outsider Team").await;
    scim.client
        .patch(
            &format!("/Groups/{group}"),
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": id}]}])),
        )
        .await
        .assert_error(400, Some("invalidValue"));
    scim.destroy(&format!("/Groups/{group}")).await;

    test.account("admin")
        .registry_destroy(
            registry::schema::prelude::ObjectType::Account,
            [account.id()],
        )
        .await;
}

async fn anonymous_requests_are_challenged(scim: &ScimTest) {
    for (method, path) in [
        ("GET", "/Users"),
        ("POST", "/Users"),
        ("GET", "/Groups"),
        ("POST", "/Bulk"),
        ("POST", "/.search"),
    ] {
        let response = scim.anonymous.request(method, path, None).await;
        response.assert_error(401, None);
        assert_eq!(
            response.header("www-authenticate"),
            Some("Bearer realm=\"Stalwart SCIM\""),
            "{method} {path}"
        );
    }
}

async fn basic_authentication_is_refused(scim: &ScimTest) {
    let response = scim.basic.get("/Users").await;
    response.assert_error(401, None);
    response.assert_detail_contains("bearer token");
    assert_eq!(
        response.header("www-authenticate"),
        Some("Bearer realm=\"Stalwart SCIM\"")
    );
}

async fn invalid_bearer_tokens_are_rejected(_scim: &ScimTest) {
    for token in ["API_notarealkey", "not-a-token"] {
        ScimClient::bearer(token)
            .get("/Users")
            .await
            .assert_error(401, None);
    }
}

async fn the_scim_access_permission_gates_every_endpoint(scim: &ScimTest) {
    for (method, path) in [
        ("GET", "/Users"),
        ("POST", "/Users"),
        ("GET", "/Groups"),
        ("POST", "/Bulk"),
        ("POST", "/.search"),
    ] {
        let response = scim.no_scim.request(method, path, None).await;
        response.assert_error(403, None);
        response.assert_detail_contains("scimAccess");
    }

    for path in ["/ServiceProviderConfig", "/ResourceTypes", "/Schemas"] {
        scim.no_scim.get(path).await.assert_status(200);
    }
}

async fn the_permission_matrix_is_enforced(scim: &ScimTest) {
    let user_id = scim.create_user("matrix@scim.example.com").await;
    let group_id = scim.create_group("Matrix Group").await;
    let user_path = format!("/Users/{user_id}");
    let group_path = format!("/Groups/{group_id}");
    let activate = patch_body(json!([{"op": "replace", "path": "active", "value": true}]));

    for (client, method, path, body, permission) in [
        (
            &scim.no_get,
            "GET",
            "/Users".to_string(),
            None,
            "sysAccountGet",
        ),
        (
            &scim.no_get,
            "GET",
            user_path.clone(),
            None,
            "sysAccountGet",
        ),
        (
            &scim.no_get,
            "GET",
            "/Groups".to_string(),
            None,
            "sysAccountGet",
        ),
        (
            &scim.no_get,
            "GET",
            group_path.clone(),
            None,
            "sysAccountGet",
        ),
        (
            &scim.no_get,
            "POST",
            "/Users/.search".to_string(),
            Some(json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]})),
            "sysAccountGet",
        ),
        (
            &scim.no_get,
            "POST",
            "/.search".to_string(),
            Some(json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]})),
            "sysAccountGet",
        ),
        (
            &scim.no_create,
            "POST",
            "/Users".to_string(),
            Some(user_body("denied@scim.example.com")),
            "sysAccountCreate",
        ),
        (
            &scim.no_create,
            "POST",
            "/Groups".to_string(),
            Some(group_body("Denied Group")),
            "sysAccountCreate",
        ),
        (
            &scim.no_update,
            "PUT",
            user_path.clone(),
            Some(user_body("matrix@scim.example.com")),
            "sysAccountUpdate",
        ),
        (
            &scim.no_update,
            "PATCH",
            user_path.clone(),
            Some(activate.clone()),
            "sysAccountUpdate",
        ),
        (
            &scim.no_update,
            "PUT",
            group_path.clone(),
            Some(group_body("Matrix Group")),
            "sysAccountUpdate",
        ),
        (
            &scim.no_update,
            "PATCH",
            group_path.clone(),
            Some(patch_body(
                json!([{"op": "replace", "path": "displayName", "value": "Matrix Group"}]),
            )),
            "sysAccountUpdate",
        ),
        (
            &scim.no_destroy,
            "DELETE",
            user_path.clone(),
            None,
            "sysAccountDestroy",
        ),
        (
            &scim.no_destroy,
            "DELETE",
            group_path.clone(),
            None,
            "sysAccountDestroy",
        ),
    ] {
        let response = client
            .request(method, &path, body.map(|body| body.to_string()))
            .await;
        response.assert_error(403, None);
        response.assert_detail_contains(permission);
    }

    scim.destroy(&group_path).await;
    scim.destroy(&user_path).await;
}

async fn the_gate_fires_before_any_store_read(scim: &ScimTest) {
    let id = scim.create_user("gone@scim.example.com").await;
    let path = format!("/Users/{id}");
    scim.destroy(&path).await;
    scim.client.get(&path).await.assert_error(404, None);

    let response = scim.no_get.get(&path).await;
    response.assert_error(403, None);
    response.assert_detail_contains("sysAccountGet");

    let response = scim.no_destroy.delete(&path).await;
    response.assert_error(403, None);
    response.assert_detail_contains("sysAccountDestroy");
}

async fn the_service_principal_cannot_deprovision_itself(scim: &ScimTest) {
    let path = format!("/Users/{}", scim.service_principal_id);

    scim.client
        .get(&path)
        .await
        .assert_status(200)
        .assert_scim_content_type();

    scim.client
        .delete(&path)
        .await
        .assert_error(403, None)
        .assert_detail_contains("cannot deprovision or deactivate its own service principal");

    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "active", "value": false}])),
        )
        .await
        .assert_error(403, None)
        .assert_detail_contains("cannot deprovision or deactivate its own service principal");

    let mut body = user_body(crate::scim::SERVICE_PRINCIPAL);
    body["active"] = json!(false);
    scim.client
        .put(&path, body)
        .await
        .assert_error(403, None)
        .assert_detail_contains("cannot deprovision or deactivate its own service principal");

    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "active", "value": true}])),
        )
        .await
        .assert_status(200);
}
