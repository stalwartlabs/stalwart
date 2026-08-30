/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::scim::{ScimClient, ScimResponse, ScimTest, patch_body, user_body};
use scim_proto::{
    MESSAGE_BULK_REQUEST, MESSAGE_BULK_RESPONSE, SCHEMA_GROUP, SCHEMA_USER,
    schema::spc::ServiceProviderConfig,
};
use serde_json::{Value, json};

pub async fn test(scim: &ScimTest) {
    println!("Running SCIM bulk tests...");

    independent_creates_are_applied(scim).await;
    forward_references_are_resolved(scim).await;
    circular_references_are_detected(scim).await;
    operations_fail_independently(scim).await;
    fail_on_errors_stops_processing(scim).await;
    permissions_are_enforced_per_operation(scim).await;
    versions_are_honoured_per_operation(scim).await;
    malformed_requests_are_rejected(scim).await;
    the_advertised_limits_are_enforced(scim).await;
}

async fn independent_creates_are_applied(scim: &ScimTest) {
    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "one",
                    "path": "/Users",
                    "data": user_body("bulk.one@scim.example.com"),
                },
                {
                    "method": "POST",
                    "bulkId": "two",
                    "path": "/Users",
                    "data": user_body("bulk.two@scim.example.com"),
                },
            ],
        }),
    )
    .await;
    response.assert_status(200);
    assert_eq!(response.json["schemas"], json!([MESSAGE_BULK_RESPONSE]));

    let operations = bulk_operations(&response);
    assert_eq!(operations.len(), 2);

    let mut ids = Vec::new();
    for (operation, bulk_id) in operations.iter().zip(["one", "two"]) {
        assert_eq!(operation["status"], json!("201"), "{operation}");
        assert_eq!(operation["method"], json!("POST"));
        assert_eq!(operation["bulkId"], json!(bulk_id));
        assert!(operation.get("response").is_none(), "{operation}");

        let location = operation["location"].as_str().unwrap();
        let id = location.rsplit('/').next().unwrap().to_string();
        assert_eq!(location, scim.location("/Users", &id));

        let fetched = scim.client.get(&format!("/Users/{id}")).await;
        fetched.assert_status(200);
        assert_eq!(operation["version"], json!(fetched.etag()));
        ids.push(id);
    }

    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [
                {
                    "method": "PATCH",
                    "path": format!("/Users/{}", ids[0]),
                    "data": patch_body(
                        json!([{"op": "replace", "path": "displayName", "value": "Bulk Patched"}]),
                    ),
                },
                {
                    "method": "PUT",
                    "path": format!("/Users/{}", ids[1]),
                    "data": user_body("bulk.two.renamed@scim.example.com"),
                },
            ],
        }),
    )
    .await;
    response.assert_status(200);
    for operation in bulk_operations(&response) {
        assert_eq!(operation["status"], json!("200"), "{operation}");
    }

    let fetched = scim.client.get(&format!("/Users/{}", ids[0])).await;
    assert_eq!(fetched.json["displayName"], json!("Bulk Patched"));
    let fetched = scim.client.get(&format!("/Users/{}", ids[1])).await;
    assert_eq!(
        fetched.json["userName"],
        json!("bulk.two.renamed@scim.example.com")
    );

    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": ids
                .iter()
                .map(|id| json!({"method": "DELETE", "path": format!("/Users/{id}")}))
                .collect::<Vec<_>>(),
        }),
    )
    .await;
    response.assert_status(200);
    for operation in bulk_operations(&response) {
        assert_eq!(operation["status"], json!("204"), "{operation}");
    }
    for id in &ids {
        scim.client
            .get(&format!("/Users/{id}"))
            .await
            .assert_error(404, None);
    }
}

async fn forward_references_are_resolved(scim: &ScimTest) {
    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "group",
                    "path": "/Groups",
                    "data": {
                        "schemas": [SCHEMA_GROUP],
                        "displayName": "Bulk Team",
                        "members": [{"value": "bulkId:member"}],
                    },
                },
                {
                    "method": "POST",
                    "bulkId": "member",
                    "path": "/Users",
                    "data": user_body("bulk.member@scim.example.com"),
                },
            ],
        }),
    )
    .await;
    response.assert_status(200);

    let operations = bulk_operations(&response);
    let member = operations
        .iter()
        .find(|operation| operation["bulkId"] == json!("member"))
        .unwrap();
    let group = operations
        .iter()
        .find(|operation| operation["bulkId"] == json!("group"))
        .unwrap();
    assert_eq!(member["status"], json!("201"), "{member}");
    assert_eq!(group["status"], json!("201"), "{group}");

    let member_id = last_segment(member["location"].as_str().unwrap());
    let group_id = last_segment(group["location"].as_str().unwrap());

    let fetched = scim.client.get(&format!("/Groups/{group_id}")).await;
    fetched.assert_status(200);
    assert_eq!(fetched.json["members"][0]["value"], json!(member_id));

    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [{
                "method": "POST",
                "bulkId": "orphan",
                "path": "/Groups",
                "data": {
                    "schemas": [SCHEMA_GROUP],
                    "displayName": "Orphan Team",
                    "members": [{"value": "bulkId:missing"}],
                },
            }],
        }),
    )
    .await;
    response.assert_status(200);
    let operation = &bulk_operations(&response)[0];
    assert_eq!(operation["status"], json!("400"), "{operation}");
    assert_eq!(operation["response"]["scimType"], json!("invalidValue"));

    scim.client
        .patch(
            &format!("/Groups/{group_id}"),
            patch_body(json!([{"op": "remove", "path": "members"}])),
        )
        .await
        .assert_status(200);
    scim.destroy(&format!("/Groups/{group_id}")).await;
    scim.destroy(&format!("/Users/{member_id}")).await;
}

async fn circular_references_are_detected(scim: &ScimTest) {
    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "left",
                    "path": "/Groups",
                    "data": {
                        "schemas": [SCHEMA_GROUP],
                        "displayName": "Left Team",
                        "members": [{"value": "bulkId:right"}],
                    },
                },
                {
                    "method": "POST",
                    "bulkId": "right",
                    "path": "/Groups",
                    "data": {
                        "schemas": [SCHEMA_GROUP],
                        "displayName": "Right Team",
                        "members": [{"value": "bulkId:left"}],
                    },
                },
            ],
        }),
    )
    .await;
    response.assert_error(409, None);
    response.assert_detail_contains("Circular");

    scim.client
        .get(&crate::scim::query(
            "/Groups",
            "displayName eq \"Left Team\"",
        ))
        .await
        .assert_status(200);
}

async fn operations_fail_independently(scim: &ScimTest) {
    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "good",
                    "path": "/Users",
                    "data": user_body("bulk.good@scim.example.com"),
                },
                {
                    "method": "POST",
                    "bulkId": "bad",
                    "path": "/Users",
                    "data": user_body("bulk.bad@plain.example.com"),
                },
                {
                    "method": "POST",
                    "bulkId": "alsogood",
                    "path": "/Users",
                    "data": user_body("bulk.also.good@scim.example.com"),
                },
            ],
        }),
    )
    .await;
    response.assert_status(200);

    let operations = bulk_operations(&response);
    assert_eq!(operations.len(), 3);
    assert_eq!(operations[0]["status"], json!("201"));
    assert_eq!(operations[1]["status"], json!("400"));
    assert_eq!(
        operations[1]["response"]["scimType"],
        json!("invalidValue"),
        "{}",
        operations[1]
    );
    assert!(operations[1].get("location").is_none());
    assert_eq!(operations[2]["status"], json!("201"));

    for operation in [&operations[0], &operations[2]] {
        scim.destroy(&format!(
            "/Users/{}",
            last_segment(operation["location"].as_str().unwrap())
        ))
        .await;
    }
}

async fn fail_on_errors_stops_processing(scim: &ScimTest) {
    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "failOnErrors": 1,
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "first",
                    "path": "/Users",
                    "data": user_body("bulk.stop@plain.example.com"),
                },
                {
                    "method": "POST",
                    "bulkId": "second",
                    "path": "/Users",
                    "data": user_body("bulk.never@scim.example.com"),
                },
            ],
        }),
    )
    .await;
    response.assert_status(200);

    let operations = bulk_operations(&response);
    assert_eq!(operations.len(), 1, "{}", response.body);
    assert_eq!(operations[0]["status"], json!("400"));

    let response = scim
        .client
        .get(&crate::scim::query(
            "/Users",
            "userName eq \"bulk.never@scim.example.com\"",
        ))
        .await;
    response.assert_status(200);
    assert_eq!(response.total_results(), 0, "{}", response.body);
}

async fn permissions_are_enforced_per_operation(scim: &ScimTest) {
    let id = scim.create_user("bulk.perm@scim.example.com").await;

    let response = bulk(
        &scim.no_create,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "denied",
                    "path": "/Users",
                    "data": user_body("bulk.denied@scim.example.com"),
                },
                {
                    "method": "PATCH",
                    "path": format!("/Users/{id}"),
                    "data": patch_body(
                        json!([{"op": "replace", "path": "displayName", "value": "Allowed"}]),
                    ),
                },
            ],
        }),
    )
    .await;
    response.assert_status(200);

    let operations = bulk_operations(&response);
    assert_eq!(operations[0]["status"], json!("403"), "{}", response.body);
    assert!(
        operations[0]["response"]["detail"]
            .as_str()
            .unwrap()
            .contains("sysAccountCreate"),
        "{}",
        response.body
    );
    assert_eq!(operations[1]["status"], json!("200"), "{}", response.body);

    let fetched = scim.client.get(&format!("/Users/{id}")).await;
    assert_eq!(fetched.json["displayName"], json!("Allowed"));

    scim.destroy(&format!("/Users/{id}")).await;
}

async fn versions_are_honoured_per_operation(scim: &ScimTest) {
    let id = scim.create_user("bulk.version@scim.example.com").await;
    let path = format!("/Users/{id}");
    let version = scim.client.get(&path).await.etag();

    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [{
                "method": "PATCH",
                "path": path,
                "version": "W/\"0000000000000000\"",
                "data": patch_body(
                    json!([{"op": "replace", "path": "displayName", "value": "Stale"}]),
                ),
            }],
        }),
    )
    .await;
    response.assert_status(200);

    let operation = &bulk_operations(&response)[0];
    assert_eq!(operation["status"], json!("412"), "{operation}");
    assert_eq!(
        operation["location"],
        json!(scim.location("/Users", &id)),
        "A failed non-POST operation must carry a location"
    );

    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [{
                "method": "PATCH",
                "path": path,
                "version": version,
                "data": patch_body(
                    json!([{"op": "replace", "path": "displayName", "value": "Fresh"}]),
                ),
            }],
        }),
    )
    .await;
    response.assert_status(200);
    assert_eq!(bulk_operations(&response)[0]["status"], json!("200"));

    let fetched = scim.client.get(&path).await;
    assert_eq!(fetched.json["displayName"], json!("Fresh"));

    scim.destroy(&path).await;
}

async fn malformed_requests_are_rejected(scim: &ScimTest) {
    for (body, scim_type) in [
        (json!({"schemas": [MESSAGE_BULK_REQUEST]}), "invalidSyntax"),
        (
            json!({"schemas": [MESSAGE_BULK_REQUEST], "Operations": []}),
            "invalidSyntax",
        ),
        (
            json!({"schemas": [SCHEMA_USER], "Operations": []}),
            "invalidSyntax",
        ),
        (
            json!({
                "schemas": [MESSAGE_BULK_REQUEST],
                "Operations": [{"method": "POST", "path": "/Users", "data": user_body("a@scim.example.com")}],
            }),
            "invalidSyntax",
        ),
        (
            json!({
                "schemas": [MESSAGE_BULK_REQUEST],
                "Operations": [{"method": "POST", "bulkId": "a", "path": "/Users/abc", "data": user_body("a@scim.example.com")}],
            }),
            "invalidValue",
        ),
        (
            json!({
                "schemas": [MESSAGE_BULK_REQUEST],
                "Operations": [{"method": "POST", "bulkId": "a", "path": "/Devices", "data": {}}],
            }),
            "invalidValue",
        ),
        (
            json!({
                "schemas": [MESSAGE_BULK_REQUEST],
                "Operations": [{"method": "DELETE", "path": "/Users"}],
            }),
            "invalidValue",
        ),
        (
            json!({
                "schemas": [MESSAGE_BULK_REQUEST],
                "Operations": [{"method": "PUT", "path": "/Users/abc"}],
            }),
            "invalidSyntax",
        ),
        (
            json!({
                "schemas": [MESSAGE_BULK_REQUEST],
                "Operations": [
                    {"method": "POST", "bulkId": "dup", "path": "/Users", "data": user_body("a@scim.example.com")},
                    {"method": "POST", "bulkId": "dup", "path": "/Users", "data": user_body("b@scim.example.com")},
                ],
            }),
            "invalidValue",
        ),
    ] {
        bulk(&scim.client, body)
            .await
            .assert_error(400, Some(scim_type));
    }
}

async fn the_advertised_limits_are_enforced(scim: &ScimTest) {
    let max_operations = ServiceProviderConfig::DEFAULT.bulk.max_operations;
    let operations = (0..=max_operations)
        .map(|index| {
            json!({
                "method": "POST",
                "bulkId": format!("b{index}"),
                "path": "/Users",
                "data": user_body(&format!("overflow-{index}@scim.example.com")),
            })
        })
        .collect::<Vec<_>>();

    let response = bulk(
        &scim.client,
        json!({"schemas": [MESSAGE_BULK_REQUEST], "Operations": operations}),
    )
    .await;
    response.assert_error(413, None);
    response.assert_detail_contains(&max_operations.to_string());

    let padding = "x".repeat(ServiceProviderConfig::DEFAULT.bulk.max_payload_size);
    let response = bulk(
        &scim.client,
        json!({
            "schemas": [MESSAGE_BULK_REQUEST],
            "Operations": [{
                "method": "POST",
                "bulkId": "big",
                "path": "/Users",
                "data": {
                    "schemas": [SCHEMA_USER],
                    "userName": "big@scim.example.com",
                    "displayName": padding,
                },
            }],
        }),
    )
    .await;
    response.assert_error(413, None);
    response.assert_detail_contains(
        &ServiceProviderConfig::DEFAULT
            .bulk
            .max_payload_size
            .to_string(),
    );

    let response = scim
        .client
        .get(&crate::scim::query(
            "/Users",
            "userName eq \"overflow-0@scim.example.com\"",
        ))
        .await;
    response.assert_status(200);
    assert_eq!(response.total_results(), 0, "{}", response.body);
}

async fn bulk(client: &ScimClient, body: Value) -> ScimResponse {
    client.post("/Bulk", body).await
}

fn bulk_operations(response: &ScimResponse) -> &[Value] {
    response.json["Operations"]
        .as_array()
        .unwrap_or_else(|| panic!("Missing Operations in {}", response.body))
}

fn last_segment(location: &str) -> String {
    location.rsplit('/').next().unwrap().to_string()
}
