/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::scim::{ScimTest, group_body, patch_body, query};
use scim_proto::{SCHEMA_GROUP, SCHEMA_USER};
use serde_json::json;

pub async fn test(scim: &ScimTest) {
    println!("Running SCIM group tests...");

    a_create_returns_the_full_resource(scim).await;
    duplicate_display_names_are_rejected(scim).await;
    members_are_managed_through_patch(scim).await;
    membership_is_reflected_on_the_user(scim).await;
    the_version_covers_the_membership(scim).await;
    members_can_be_excluded(scim).await;
    invalid_members_are_rejected(scim).await;
    put_replaces_the_membership(scim).await;
    filters_select_groups(scim).await;
    a_group_with_members_cannot_be_deleted(scim).await;
}

async fn a_create_returns_the_full_resource(scim: &ScimTest) {
    let response = scim
        .client
        .post(
            "/Groups",
            json!({
                "schemas": [SCHEMA_GROUP],
                "displayName": "Sales Team",
                "externalId": "GRP-1",
            }),
        )
        .await;
    response.assert_status(201);
    let id = response.id();

    assert_eq!(response.json["schemas"], json!([SCHEMA_GROUP]));
    assert_eq!(response.json["displayName"], json!("Sales Team"));
    assert_eq!(response.json["externalId"], json!("GRP-1"));
    assert_eq!(response.json["members"], json!([]));
    assert_eq!(response.json["meta"]["resourceType"], json!("Group"));
    assert!(response.json["meta"].get("lastModified").is_none());
    assert_eq!(
        response.str("/meta/location"),
        scim.location("/Groups", &id)
    );
    assert_eq!(response.location(), scim.location("/Groups", &id));
    assert_eq!(response.etag(), response.version());

    let fetched = scim.client.get(&format!("/Groups/{id}")).await;
    fetched.assert_status(200);
    assert_eq!(fetched.json, response.json);

    scim.client
        .post("/Groups", json!({ "schemas": [SCHEMA_GROUP] }))
        .await
        .assert_error(400, Some("invalidValue"));
    scim.client
        .post("/Groups", group_body(""))
        .await
        .assert_error(400, Some("invalidValue"));
    scim.client
        .post(
            "/Groups",
            json!({"schemas": [SCHEMA_GROUP], "displayName": "x", "members": [{"nosuch": "y"}]}),
        )
        .await
        .assert_error(400, Some("invalidSyntax"));

    scim.destroy(&format!("/Groups/{id}")).await;
}

async fn duplicate_display_names_are_rejected(scim: &ScimTest) {
    let id = scim.create_group("Marketing Team").await;

    for display_name in ["Marketing Team", "MARKETING TEAM", "marketing team"] {
        scim.client
            .post("/Groups", group_body(display_name))
            .await
            .assert_error(409, Some("uniqueness"));
    }

    let other = scim.create_group("Other Team").await;
    scim.client
        .patch(
            &format!("/Groups/{other}"),
            patch_body(
                json!([{"op": "replace", "path": "displayName", "value": "Marketing Team"}]),
            ),
        )
        .await
        .assert_error(409, Some("uniqueness"));

    scim.client
        .patch(
            &format!("/Groups/{other}"),
            patch_body(json!([{"op": "replace", "path": "displayName", "value": "Other Team"}])),
        )
        .await
        .assert_status(200);

    scim.destroy(&format!("/Groups/{other}")).await;
    scim.destroy(&format!("/Groups/{id}")).await;
}

async fn members_are_managed_through_patch(scim: &ScimTest) {
    let group = scim.create_group("Engineering").await;
    let group_path = format!("/Groups/{group}");
    let alice = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "eng.alice@scim.example.com",
                "displayName": "Alice Engineer",
            }),
        )
        .await
        .assert_status(201)
        .id();
    let bob = scim.create_user("eng.bob@scim.example.com").await;

    let response = scim
        .client
        .patch(
            &group_path,
            patch_body(json!([{
                "op": "add",
                "path": "members",
                "value": [{"value": alice, "$ref": scim.location("/Users", &alice)}],
            }])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(
        response.json["members"],
        json!([{
            "value": alice,
            "$ref": scim.location("/Users", &alice),
            "display": "Alice Engineer",
            "type": "User",
        }])
    );

    let response = scim
        .client
        .patch(
            &group_path,
            patch_body(json!([{
                "op": "add",
                "path": "members",
                "value": [{"value": bob}, {"value": alice}],
            }])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["members"].as_array().unwrap().len(), 2);
    assert_eq!(
        response.json["members"][1]["display"],
        json!("eng.bob@scim.example.com"),
        "A member without a display name falls back to the email address"
    );

    let response = scim
        .client
        .patch(
            &group_path,
            patch_body(json!([{
                "op": "remove",
                "path": format!("members[value eq \"{bob}\"]"),
            }])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["members"].as_array().unwrap().len(), 1);
    assert_eq!(response.json["members"][0]["value"], json!(alice));

    let response = scim
        .client
        .patch(
            &group_path,
            patch_body(json!([{
                "op": "replace",
                "path": "members",
                "value": [{"value": bob}],
            }])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["members"].as_array().unwrap().len(), 1);
    assert_eq!(response.json["members"][0]["value"], json!(bob));

    let response = scim
        .client
        .patch(
            &group_path,
            patch_body(json!([{"op": "remove", "path": "members"}])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["members"], json!([]));

    scim.client
        .patch(
            &group_path,
            patch_body(json!([{
                "op": "remove",
                "path": format!("members[value eq \"{alice}\"]"),
            }])),
        )
        .await
        .assert_error(400, Some("noTarget"));

    scim.destroy(&format!("/Users/{alice}")).await;
    scim.destroy(&format!("/Users/{bob}")).await;
    scim.destroy(&group_path).await;
}

async fn membership_is_reflected_on_the_user(scim: &ScimTest) {
    let group = scim.create_group("Support Desk").await;
    let user = scim.create_user("support.member@scim.example.com").await;

    scim.client
        .patch(
            &format!("/Groups/{group}"),
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": user}]}])),
        )
        .await
        .assert_status(200);

    let response = scim.client.get(&format!("/Users/{user}")).await;
    response.assert_status(200);
    assert_eq!(
        response.json["groups"],
        json!([{
            "value": group,
            "$ref": scim.location("/Groups", &group),
            "display": "Support Desk",
            "type": "direct",
        }])
    );

    let response = scim
        .client
        .get(&format!("/Users/{user}?excludedAttributes=groups"))
        .await;
    response.assert_status(200);
    assert!(response.json.get("groups").is_none(), "{}", response.body);

    let response = scim
        .client
        .get(&format!("/Users?filter=groups%20eq%20%22{group}%22"))
        .await;
    response.assert_status(200);
    assert_eq!(response.resource_ids(), vec![user.clone()]);

    let response = scim
        .client
        .get(&format!("/Groups?filter=members%20eq%20%22{user}%22"))
        .await;
    response.assert_status(200);
    assert_eq!(response.resource_ids(), vec![group.clone()]);

    scim.client
        .patch(
            &format!("/Groups/{group}"),
            patch_body(json!([{"op": "remove", "path": "members"}])),
        )
        .await
        .assert_status(200);

    let response = scim.client.get(&format!("/Users/{user}")).await;
    assert!(response.json.get("groups").is_none(), "{}", response.body);

    scim.destroy(&format!("/Users/{user}")).await;
    scim.destroy(&format!("/Groups/{group}")).await;
}

async fn the_version_covers_the_membership(scim: &ScimTest) {
    let group = scim.create_group("Versioned Team").await;
    let group_path = format!("/Groups/{group}");
    let user = scim.create_user("versioned@scim.example.com").await;

    let before = scim.client.get(&group_path).await.etag();
    let after = scim
        .client
        .patch(
            &group_path,
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": user}]}])),
        )
        .await
        .assert_status(200)
        .etag();
    assert_ne!(before, after, "The group version must cover the membership");

    let excluded = scim
        .client
        .get(&format!("{group_path}?excludedAttributes=members"))
        .await;
    excluded.assert_status(200);
    assert_eq!(
        excluded.etag(),
        after,
        "The version must not depend on the attribute selection"
    );

    scim.client
        .request_with_headers("GET", &group_path, [("if-none-match", after.clone())], None)
        .await
        .assert_status(304);

    scim.client
        .request_with_headers(
            "PATCH",
            &group_path,
            [("if-match", before)],
            Some(patch_body(json!([{"op": "remove", "path": "members"}])).to_string()),
        )
        .await
        .assert_error(412, None);

    scim.client
        .request_with_headers(
            "PATCH",
            &group_path,
            [("if-match", after)],
            Some(patch_body(json!([{"op": "remove", "path": "members"}])).to_string()),
        )
        .await
        .assert_status(200);

    scim.destroy(&format!("/Users/{user}")).await;
    scim.destroy(&group_path).await;
}

async fn members_can_be_excluded(scim: &ScimTest) {
    let group = scim.create_group("Excluded Team").await;
    let user = scim.create_user("excluded@scim.example.com").await;

    scim.client
        .patch(
            &format!("/Groups/{group}"),
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": user}]}])),
        )
        .await
        .assert_status(200);

    let response = scim
        .client
        .get(&format!("/Groups/{group}?excludedAttributes=members"))
        .await;
    response.assert_status(200);
    assert!(response.json.get("members").is_none(), "{}", response.body);
    assert_eq!(response.json["displayName"], json!("Excluded Team"));

    let response = scim
        .client
        .get(&format!("/Groups/{group}?attributes=displayName"))
        .await;
    response.assert_status(200);
    assert!(response.json.get("members").is_none(), "{}", response.body);
    assert_eq!(response.json["id"], json!(group));

    scim.client
        .get(&format!(
            "/Groups/{group}?attributes=displayName&excludedAttributes=members"
        ))
        .await
        .assert_error(400, Some("invalidValue"));

    scim.client
        .patch(
            &format!("/Groups/{group}"),
            patch_body(json!([{"op": "remove", "path": "members"}])),
        )
        .await
        .assert_status(200);
    scim.destroy(&format!("/Users/{user}")).await;
    scim.destroy(&format!("/Groups/{group}")).await;
}

async fn invalid_members_are_rejected(scim: &ScimTest) {
    let group = scim.create_group("Guarded Team").await;
    let group_path = format!("/Groups/{group}");
    let user = scim.create_user("guarded@scim.example.com").await;
    let nested = scim.create_group("Nested Team").await;

    scim.client
        .patch(
            &group_path,
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": user}]}])),
        )
        .await
        .assert_status(200);

    for value in [
        json!([{"value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]),
        json!([{"value": nested, "type": "Group"}]),
        json!([{"value": nested}]),
        json!([{"value": ""}]),
        json!([{"display": "No value"}]),
        json!([{"value": "!!!"}]),
    ] {
        scim.client
            .patch(
                &group_path,
                patch_body(json!([{"op": "add", "path": "members", "value": value}])),
            )
            .await
            .assert_error(400, Some("invalidValue"));
    }

    let response = scim.client.get(&group_path).await;
    response.assert_status(200);
    assert_eq!(
        response.json["members"].as_array().unwrap().len(),
        1,
        "A rejected membership change must not persist"
    );

    scim.client
        .patch(
            &group_path,
            patch_body(json!([{
                "op": "add",
                "path": format!("members[value eq \"{user}\"]"),
                "value": {"value": user},
            }])),
        )
        .await
        .assert_error(400, Some("invalidPath"));

    scim.client
        .patch(
            &group_path,
            patch_body(json!([{"op": "remove", "path": "displayName"}])),
        )
        .await
        .assert_error(400, Some("invalidValue"));

    scim.client
        .patch(
            &group_path,
            patch_body(
                json!([{"op": "replace", "path": "userName", "value": "x@scim.example.com"}]),
            ),
        )
        .await
        .assert_error(400, Some("invalidSyntax"));

    scim.client
        .patch(
            &group_path,
            patch_body(json!([{"op": "remove", "path": "members"}])),
        )
        .await
        .assert_status(200);
    scim.destroy(&format!("/Users/{user}")).await;
    scim.destroy(&format!("/Groups/{nested}")).await;
    scim.destroy(&group_path).await;
}

async fn put_replaces_the_membership(scim: &ScimTest) {
    let group = scim.create_group("Replaced Team").await;
    let group_path = format!("/Groups/{group}");
    let alice = scim.create_user("rep.alice@scim.example.com").await;
    let bob = scim.create_user("rep.bob@scim.example.com").await;

    let response = scim
        .client
        .put(
            &group_path,
            json!({
                "schemas": [SCHEMA_GROUP],
                "displayName": "Replaced Team",
                "members": [{"value": alice}, {"value": bob}],
            }),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["members"].as_array().unwrap().len(), 2);

    let response = scim
        .client
        .put(
            &group_path,
            json!({
                "schemas": [SCHEMA_GROUP],
                "displayName": "Renamed Team",
                "members": [{"value": bob}],
            }),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["displayName"], json!("Renamed Team"));
    assert_eq!(response.json["members"][0]["value"], json!(bob));

    let response = scim
        .client
        .put(
            &group_path,
            json!({"schemas": [SCHEMA_GROUP], "displayName": "Renamed Team"}),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["members"], json!([]));

    scim.client
        .put(&group_path, json!({"schemas": [SCHEMA_GROUP]}))
        .await
        .assert_error(400, Some("invalidValue"));

    scim.destroy(&format!("/Users/{alice}")).await;
    scim.destroy(&format!("/Users/{bob}")).await;
    scim.destroy(&group_path).await;
}

async fn filters_select_groups(scim: &ScimTest) {
    let group = scim
        .client
        .post(
            "/Groups",
            json!({
                "schemas": [SCHEMA_GROUP],
                "displayName": "Filtered Team",
                "externalId": "GRP-FILTER",
            }),
        )
        .await
        .assert_status(201)
        .id();

    for filter in [
        "displayName eq \"Filtered Team\"",
        "displayName eq \"filtered team\"",
        "externalId eq \"GRP-FILTER\"",
        "externalId eq \"GRP-FILTER\" and displayName eq \"Filtered Team\"",
    ] {
        let response = scim.client.get(&query("/Groups", filter)).await;
        response.assert_status(200);
        assert_eq!(response.resource_ids(), vec![group.clone()], "{filter}");
    }

    for filter in [
        "userName eq \"x@scim.example.com\"",
        "active eq true",
        "emails eq \"x@scim.example.com\"",
        "nosuchattr eq \"x\"",
    ] {
        scim.client
            .get(&query("/Groups", filter))
            .await
            .assert_error(400, Some("invalidFilter"));
    }

    scim.destroy(&format!("/Groups/{group}")).await;
}

async fn a_group_with_members_cannot_be_deleted(scim: &ScimTest) {
    let group = scim.create_group("Doomed Team").await;
    let group_path = format!("/Groups/{group}");
    let user = scim.create_user("doomed@scim.example.com").await;

    scim.client
        .patch(
            &group_path,
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": user}]}])),
        )
        .await
        .assert_status(200);

    scim.client
        .delete(&group_path)
        .await
        .assert_error(409, None)
        .assert_detail_contains("depend on it");

    scim.client
        .patch(
            &group_path,
            patch_body(json!([{"op": "remove", "path": "members"}])),
        )
        .await
        .assert_status(200);

    scim.destroy(&group_path).await;
    scim.client.get(&group_path).await.assert_error(404, None);

    let response = scim.client.get(&format!("/Users/{user}")).await;
    response.assert_status(200);
    assert!(response.json.get("groups").is_none(), "{}", response.body);

    scim.destroy(&format!("/Users/{user}")).await;
}
