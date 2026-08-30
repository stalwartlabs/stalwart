/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    scim::{PLAIN_DOMAIN, ScimTest, patch_body, query, user_body},
    utils::{
        imap::{ImapConnection, Type},
        server::TestServer,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use imap_proto::ResponseType;
use registry::schema::{
    enums::Permission,
    structs::{Account, Permissions, PermissionsList},
};
use scim_proto::{
    MESSAGE_LIST_RESPONSE, SCHEMA_USER, schema::user::SCHEMA_ENTERPRISE_USER as ENTERPRISE_USER,
};
use serde_json::json;
use std::str::FromStr;
use types::id::Id;

const PASSWORD: &str = "these_pretzels_are_making_me_thirsty";

pub async fn test(test: &TestServer, scim: &ScimTest) {
    println!("Running SCIM user tests...");

    a_minimal_create_returns_the_full_resource(scim).await;
    a_create_echoes_every_supported_attribute(scim).await;
    display_name_takes_precedence_over_name_formatted(scim).await;
    duplicate_user_names_are_rejected(scim).await;
    user_names_must_resolve_to_a_provisionable_domain(scim).await;
    unimplemented_core_attributes_are_ignored(scim).await;
    structured_names_compose_a_display_name(scim).await;
    unknown_attributes_are_rejected(scim).await;
    client_supplied_identifiers_are_ignored(scim).await;
    identifiers_are_validated_canonically(scim).await;
    filters_select_users(scim).await;
    unsupported_filters_are_rejected(scim).await;
    patch_updates_the_supported_attributes(scim).await;
    patch_is_atomic(scim).await;
    patch_rejects_unsupported_paths(scim).await;
    emails_are_patched_through_value_filters(scim).await;
    put_resets_every_absent_attribute(scim).await;
    etags_drive_conditional_requests(scim).await;
    deactivation_moves_the_authenticate_permission(test, scim).await;
    reactivation_collapses_back_to_inherit(test, scim).await;
    delete_removes_the_account(scim).await;
}

async fn a_minimal_create_returns_the_full_resource(scim: &ScimTest) {
    let response = scim
        .client
        .post("/Users", user_body("minimal@scim.example.com"))
        .await;
    response.assert_status(201);

    let id = response.id();
    assert_eq!(response.json["schemas"], json!([SCHEMA_USER]));
    assert_eq!(response.json["userName"], json!("minimal@scim.example.com"));
    assert_eq!(response.json["active"], json!(true));
    assert_eq!(response.json["locale"], json!("en-US"));
    assert_eq!(response.json["preferredLanguage"], json!("en-US"));
    assert_eq!(
        response.json["emails"],
        json!([{"value": "minimal@scim.example.com", "type": "work", "primary": true}])
    );
    assert!(response.json.get("groups").is_none(), "{}", response.body);
    assert!(
        response.json.get("displayName").is_none(),
        "{}",
        response.body
    );

    assert_eq!(response.json["meta"]["resourceType"], json!("User"));
    assert!(
        response.json["meta"].get("lastModified").is_none(),
        "meta.lastModified must never be emitted: {}",
        response.body
    );
    assert!(
        !response.str("/meta/created").is_empty(),
        "{}",
        response.body
    );
    assert_eq!(response.str("/meta/location"), scim.location("/Users", &id));
    assert_eq!(response.location(), scim.location("/Users", &id));
    assert_eq!(response.etag(), response.version());
    assert!(response.etag().starts_with("W/\""), "{}", response.etag());

    let fetched = scim.client.get(&format!("/Users/{id}")).await;
    fetched.assert_status(200);
    assert_eq!(fetched.json, response.json);
    assert_eq!(fetched.etag(), response.etag());

    scim.destroy(&format!("/Users/{id}")).await;
}

async fn a_create_echoes_every_supported_attribute(scim: &ScimTest) {
    let body = json!({
        "schemas": [SCHEMA_USER],
        "externalId": "Ext-0042",
        "userName": "babs@scim.example.com",
        "name": { "formatted": "Ms. Barbara J Jensen, III" },
        "active": true,
        "emails": [
            { "value": "babs@scim.example.com", "type": "work", "primary": true },
            { "value": "barbara@alias.example.com" },
        ],
        "locale": "de-DE",
        "timezone": "America/Los_Angeles",
    });

    let response = scim.client.post("/Users", body).await;
    response.assert_status(201);
    let id = response.id();

    assert_eq!(response.json["externalId"], json!("Ext-0042"));
    assert_eq!(response.json["userName"], json!("babs@scim.example.com"));
    assert_eq!(
        response.json["name"]["formatted"],
        json!("Ms. Barbara J Jensen, III")
    );
    assert_eq!(
        response.json["displayName"],
        json!("Ms. Barbara J Jensen, III")
    );
    assert_eq!(response.json["locale"], json!("de-DE"));
    assert_eq!(response.json["preferredLanguage"], json!("de-DE"));
    assert_eq!(response.json["timezone"], json!("America/Los_Angeles"));
    assert_eq!(
        response.json["emails"],
        json!([
            {"value": "babs@scim.example.com", "type": "work", "primary": true},
            {"value": "barbara@alias.example.com", "type": "work"},
        ])
    );

    let fetched = scim.client.get(&format!("/Users/{id}")).await;
    fetched.assert_status(200);
    assert_eq!(fetched.json, response.json);

    let unknown_type = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "ignored-type@scim.example.com",
                "emails": [{"value": "ignored-type@alias.example.com", "type": "home"}],
            }),
        )
        .await;
    unknown_type.assert_status(201);
    assert_eq!(
        unknown_type.json["emails"][1]["type"],
        json!("work"),
        "The emails type is derived, not stored"
    );
    scim.destroy(&format!("/Users/{}", unknown_type.id())).await;
    scim.destroy(&format!("/Users/{id}")).await;
}

async fn display_name_takes_precedence_over_name_formatted(scim: &ScimTest) {
    let response = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "precedence@scim.example.com",
                "displayName": "Babs Jensen",
                "name": { "formatted": "Ms. Barbara J Jensen, III" },
            }),
        )
        .await;
    response.assert_status(201);

    assert_eq!(response.json["displayName"], json!("Babs Jensen"));
    assert_eq!(response.json["name"]["formatted"], json!("Babs Jensen"));

    scim.destroy(&format!("/Users/{}", response.id())).await;
}

async fn duplicate_user_names_are_rejected(scim: &ScimTest) {
    let id = scim.create_user("duplicate@scim.example.com").await;

    for user_name in [
        "duplicate@scim.example.com",
        "DUPLICATE@scim.example.com",
        "Duplicate@SCIM.example.com",
    ] {
        scim.client
            .post("/Users", user_body(user_name))
            .await
            .assert_error(409, Some("uniqueness"));
    }

    scim.client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "duplicate-alias@scim.example.com",
                "emails": [{"value": "duplicate@scim.example.com"}],
            }),
        )
        .await
        .assert_error(409, Some("uniqueness"));

    scim.destroy(&format!("/Users/{id}")).await;
}

async fn user_names_must_resolve_to_a_provisionable_domain(scim: &ScimTest) {
    let response = scim
        .client
        .post("/Users", user_body("nobody@nosuch.example.com"))
        .await;
    response.assert_error(400, Some("invalidValue"));
    response.assert_detail_contains("nosuch.example.com");

    let response = scim
        .client
        .post("/Users", user_body(&format!("nobody@{PLAIN_DOMAIN}")))
        .await;
    response.assert_error(400, Some("invalidValue"));
    response.assert_detail_contains(PLAIN_DOMAIN);
    response.assert_detail_contains("SCIM provisioning is not enabled");

    scim.client
        .post("/Users", user_body("nodomain"))
        .await
        .assert_error(400, Some("invalidValue"));

    scim.client
        .post("/Users", user_body(""))
        .await
        .assert_error(400, Some("invalidValue"));

    scim.client
        .post("/Users", json!({ "schemas": [SCHEMA_USER] }))
        .await
        .assert_error(400, Some("invalidValue"));

    let response = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "alias-domain@scim.example.com",
                "emails": [{"value": format!("nobody@{PLAIN_DOMAIN}")}],
            }),
        )
        .await;
    response.assert_error(400, Some("invalidValue"));
    response.assert_detail_contains(PLAIN_DOMAIN);
}

async fn unimplemented_core_attributes_are_ignored(scim: &ScimTest) {
    let response = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER, ENTERPRISE_USER],
                "userName": "tolerant@scim.example.com",
                "displayName": "Tolerant Person",
                "password": "hunter2",
                "title": "Vice President",
                "nickName": "Tol",
                "userType": "Employee",
                "profileUrl": "https://example.com/tolerant",
                "phoneNumbers": [{"value": "555-1234", "type": "work"}],
                "addresses": [{"streetAddress": "1 Main St", "type": "work"}],
                "ims": [],
                "photos": [],
                "roles": [],
                "entitlements": [],
                "x509Certificates": [],
                ENTERPRISE_USER: {"department": "Sales", "employeeNumber": "42"},
            }),
        )
        .await;
    response.assert_status(201);

    let id = response.id();
    assert_eq!(response.json["displayName"], json!("Tolerant Person"));
    assert!(response.json.get("title").is_none(), "{}", response.body);
    assert!(
        response.json.get("phoneNumbers").is_none(),
        "{}",
        response.body
    );
    assert!(!response.body.contains("hunter2"), "{}", response.body);
    assert!(!response.body.contains("Sales"), "{}", response.body);

    assert!(
        !can_authenticate("tolerant@scim.example.com", "hunter2").await,
        "The ignored password attribute was stored as a credential"
    );

    scim.client
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([
                {"op": "replace", "path": "title", "value": "President"},
                {"op": "replace", "path": "name.givenName", "value": "Tolerant"},
                {"op": "add", "path": "phoneNumbers", "value": [{"value": "555"}]},
                {"op": "replace", "path": "displayName", "value": "Still Tolerant"},
            ])),
        )
        .await
        .assert_status(200);

    let patched = scim.client.get(&format!("/Users/{id}")).await;
    assert_eq!(patched.json["displayName"], json!("Still Tolerant"));

    scim.client
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([
                {"op": "replace", "value": {ENTERPRISE_USER: {"department": "Marketing"}}},
            ])),
        )
        .await
        .assert_status(200);

    scim.client
        .put(
            &format!("/Users/{id}"),
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "tolerant@scim.example.com",
                "password": "hunter2",
                "name": {"givenName": "Tolerant", "familyName": "Person"},
            }),
        )
        .await
        .assert_status(200);

    scim.destroy(&format!("/Users/{id}")).await;
}

async fn structured_names_compose_a_display_name(scim: &ScimTest) {
    let response = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "composed@scim.example.com",
                "name": {
                    "givenName": "Barbara",
                    "familyName": "Jensen",
                    "middleName": "J",
                    "honorificPrefix": "Ms.",
                },
            }),
        )
        .await;
    response.assert_status(201);
    assert_eq!(response.json["displayName"], json!("Barbara Jensen"));
    assert_eq!(response.json["name"]["formatted"], json!("Barbara Jensen"));
    assert!(
        response.json["name"].get("givenName").is_none(),
        "{}",
        response.body
    );
    let id = response.id();

    let explicit = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "composed.explicit@scim.example.com",
                "displayName": "Babs Jensen",
                "name": {"givenName": "Barbara", "familyName": "Jensen"},
            }),
        )
        .await;
    explicit.assert_status(201);
    assert_eq!(
        explicit.json["displayName"],
        json!("Babs Jensen"),
        "An explicit displayName must win over the composed name"
    );

    let formatted = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "composed.formatted@scim.example.com",
                "name": {
                    "formatted": "Ms. Barbara J Jensen, III",
                    "givenName": "Barbara",
                    "familyName": "Jensen",
                },
            }),
        )
        .await;
    formatted.assert_status(201);
    assert_eq!(
        formatted.json["displayName"],
        json!("Ms. Barbara J Jensen, III")
    );

    let partial = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "composed.partial@scim.example.com",
                "name": {"givenName": "Barbara"},
            }),
        )
        .await;
    partial.assert_status(201);
    assert_eq!(partial.json["displayName"], json!("Barbara"));

    let patched = scim
        .client
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([{
                "op": "replace",
                "path": "name",
                "value": {"givenName": "Babs", "familyName": "Jensen"},
            }])),
        )
        .await;
    patched.assert_status(200);
    assert_eq!(patched.json["displayName"], json!("Babs Jensen"));

    for id in [id, explicit.id(), formatted.id(), partial.id()] {
        scim.destroy(&format!("/Users/{id}")).await;
    }
}

async fn unknown_attributes_are_rejected(scim: &ScimTest) {
    for body in [
        json!({"schemas": [SCHEMA_USER], "userName": "x@scim.example.com", "dispalyName": "typo"}),
        json!({"schemas": [SCHEMA_USER], "userName": "x@scim.example.com", "name": {"nosuch": "x"}}),
        json!({"schemas": [SCHEMA_USER], "userName": "x@scim.example.com", "emails": [{"value": "a@b.c", "nosuch": 1}]}),
        json!({"userName": "x@scim.example.com"}),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Device"],
            "userName": "x@scim.example.com",
        }),
        json!({
            "schemas": [SCHEMA_USER, "urn:example:custom:2.0:User"],
            "userName": "x@scim.example.com",
        }),
    ] {
        scim.client
            .post("/Users", body)
            .await
            .assert_error(400, Some("invalidSyntax"));
    }

    scim.client
        .request("POST", "/Users", Some("not json".to_string()))
        .await
        .assert_error(400, Some("invalidSyntax"));
}

async fn client_supplied_identifiers_are_ignored(scim: &ScimTest) {
    let response = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "id": "aaaaaaaa",
                "userName": "supplied-id@scim.example.com",
                "meta": {
                    "resourceType": "User",
                    "created": "2010-01-23T04:56:22Z",
                    "lastModified": "2011-05-13T04:42:34Z",
                },
            }),
        )
        .await;
    response.assert_status(201);

    let id = response.id();
    assert_ne!(id, "aaaaaaaa");
    assert_ne!(response.str("/meta/created"), "2010-01-23T04:56:22Z");
    assert!(response.json["meta"].get("lastModified").is_none());

    scim.client
        .get("/Users/aaaaaaaa")
        .await
        .assert_error(404, None);
    scim.destroy(&format!("/Users/{id}")).await;
}

async fn identifiers_are_validated_canonically(scim: &ScimTest) {
    let id = scim.create_user("canonical@scim.example.com").await;

    for candidate in [
        id.to_uppercase(),
        format!("a{id}"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        "!!!".to_string(),
    ] {
        if candidate == id {
            continue;
        }
        scim.client
            .get(&format!("/Users/{candidate}"))
            .await
            .assert_error(404, None);
    }

    scim.client
        .get(&format!("/Users/{id}"))
        .await
        .assert_status(200);
    scim.destroy(&format!("/Users/{id}")).await;
}

async fn filters_select_users(scim: &ScimTest) {
    let alice = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "alice.filter@scim.example.com",
                "externalId": "FILTER-ALICE",
                "displayName": "Alice Filter",
                "emails": [{"value": "alice.alias@alias.example.com"}],
            }),
        )
        .await
        .assert_status(201)
        .id();
    let bob = scim.create_user("bob.filter@scim.example.com").await;

    for filter in [
        "userName eq \"alice.filter@scim.example.com\"",
        "userName eq \"ALICE.Filter@SCIM.example.com\"",
        "externalId eq \"FILTER-ALICE\"",
        "emails eq \"alice.alias@alias.example.com\"",
        "emails.value eq \"alice.filter@scim.example.com\"",
        "displayName eq \"Alice Filter\"",
        "displayName eq \"alice filter\"",
        "name.formatted eq \"Alice Filter\"",
        "userName eq \"alice.filter@scim.example.com\" and active eq true",
        "externalId eq \"FILTER-ALICE\" and displayName eq \"Alice Filter\"",
    ] {
        let response = scim.client.get(&query("/Users", filter)).await;
        response.assert_status(200);
        assert_eq!(response.total_results(), 1, "{filter}: {}", response.body);
        assert_eq!(response.resource_ids(), vec![alice.clone()], "{filter}");
    }

    for filter in [
        "externalId eq \"filter-alice\"",
        "userName eq \"nobody@scim.example.com\"",
        "userName eq \"nobody@nosuch.example.com\"",
        "emails eq \"nobody@scim.example.com\"",
        "userName eq \"alice.filter@scim.example.com\" and active eq false",
        &format!("id eq \"{bob}\" and userName eq \"alice.filter@scim.example.com\""),
    ] {
        let response = scim.client.get(&query("/Users", filter)).await;
        response.assert_status(200);
        assert_eq!(response.total_results(), 0, "{filter}: {}", response.body);
    }

    let response = scim
        .client
        .get(&query("/Users", &format!("id eq \"{alice}\"")))
        .await;
    response.assert_status(200);
    assert_eq!(response.resource_ids(), vec![alice.clone()]);

    let response = scim.client.get("/Users").await;
    response.assert_status(200);
    assert_eq!(response.json["schemas"], json!([MESSAGE_LIST_RESPONSE]));
    response.assert_contains_id(&alice);
    response.assert_contains_id(&bob);

    scim.destroy(&format!("/Users/{alice}")).await;
    scim.destroy(&format!("/Users/{bob}")).await;
}

async fn unsupported_filters_are_rejected(scim: &ScimTest) {
    for filter in [
        "userName co \"ali\"",
        "userName sw \"ali\"",
        "userName pr",
        "userName eq \"a@b.com\" or userName eq \"c@d.com\"",
        "not (userName eq \"a@b.com\")",
        "emails[type eq \"work\"].value eq \"x@scim.example.com\"",
        "nosuchattr eq \"x\"",
        "timezone eq \"America/Los_Angeles\"",
        "locale eq \"en-US\"",
        "meta.created eq \"2020-01-01T00:00:00Z\"",
        "id eq \"!!!\"",
        "id eq \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
        "groups eq \"!!!\"",
    ] {
        scim.client
            .get(&query("/Users", filter))
            .await
            .assert_error(400, Some("invalidFilter"));
    }

    scim.client
        .get(&query("/Users", "active eq \"maybe\""))
        .await
        .assert_error(400, Some("invalidFilter"));
}

async fn patch_updates_the_supported_attributes(scim: &ScimTest) {
    let id = scim.create_user("patch@scim.example.com").await;
    let path = format!("/Users/{id}");

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([
                {"op": "replace", "path": "displayName", "value": "Patched Name"},
                {"op": "add", "path": "externalId", "value": "PATCH-1"},
                {"op": "replace", "path": "timezone", "value": "Europe/Madrid"},
                {"op": "replace", "path": "locale", "value": "fr-FR"},
            ])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["displayName"], json!("Patched Name"));
    assert_eq!(response.json["name"]["formatted"], json!("Patched Name"));
    assert_eq!(response.json["externalId"], json!("PATCH-1"));
    assert_eq!(response.json["timezone"], json!("Europe/Madrid"));
    assert_eq!(response.json["locale"], json!("fr-FR"));

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([
                {"op": "replace", "path": "name.formatted", "value": "Formatted Name"},
            ])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["displayName"], json!("Formatted Name"));

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([
                {"op": "replace", "path": "name", "value": {"formatted": "Complex Name"}},
            ])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["displayName"], json!("Complex Name"));

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([
                {"op": "replace", "value": {
                    "displayName": "Path Less",
                    "timezone": "America/New_York",
                    "userName": "patched@scim.example.com",
                }},
            ])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["displayName"], json!("Path Less"));
    assert_eq!(response.json["timezone"], json!("America/New_York"));
    assert_eq!(response.json["userName"], json!("patched@scim.example.com"));

    let added = scim
        .client
        .patch(
            &path,
            patch_body(json!([{"op": "add", "path": "displayName", "value": "Same Way"}])),
        )
        .await;
    added.assert_status(200);
    let replaced = scim
        .client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "displayName", "value": "Same Way"}])),
        )
        .await;
    replaced.assert_status(200);
    assert_eq!(added.json, replaced.json);

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([
                {"op": "remove", "path": "displayName"},
                {"op": "remove", "path": "externalId"},
                {"op": "remove", "path": "timezone"},
                {"op": "remove", "path": "locale"},
            ])),
        )
        .await;
    response.assert_status(200);
    assert!(
        response.json.get("displayName").is_none(),
        "{}",
        response.body
    );
    assert!(
        response.json.get("externalId").is_none(),
        "{}",
        response.body
    );
    assert!(response.json.get("timezone").is_none(), "{}", response.body);
    assert_eq!(response.json["locale"], json!("en-US"));

    scim.destroy(&path).await;
}

async fn patch_is_atomic(scim: &ScimTest) {
    let id = scim.create_user("atomic@scim.example.com").await;
    let path = format!("/Users/{id}");

    scim.client
        .patch(
            &path,
            patch_body(json!([
                {"op": "replace", "path": "displayName", "value": "Before"},
            ])),
        )
        .await
        .assert_status(200);

    scim.client
        .patch(
            &path,
            patch_body(json!([
                {"op": "replace", "path": "displayName", "value": "After"},
                {"op": "replace", "path": "timezone", "value": "Mars/Olympus"},
            ])),
        )
        .await
        .assert_error(400, Some("invalidValue"));

    let response = scim.client.get(&path).await;
    response.assert_status(200);
    assert_eq!(
        response.json["displayName"],
        json!("Before"),
        "A failed operation must not persist a partial change"
    );

    scim.destroy(&path).await;
}

async fn patch_rejects_unsupported_paths(scim: &ScimTest) {
    let id = scim.create_user("paths@scim.example.com").await;
    let path = format!("/Users/{id}");

    for (operations, status, scim_type) in [
        (
            json!([{"op": "replace", "path": "nosuchattr", "value": "x"}]),
            400,
            "invalidSyntax",
        ),
        (
            json!([{"op": "replace", "path": "groups", "value": []}]),
            400,
            "mutability",
        ),
        (
            json!([{"op": "replace", "path": "id", "value": "aaaa"}]),
            400,
            "mutability",
        ),
        (
            json!([{"op": "replace", "path": "meta.version", "value": "x"}]),
            400,
            "mutability",
        ),
        (
            json!([{"op": "replace", "value": "not an object"}]),
            400,
            "invalidSyntax",
        ),
        (
            json!([{"op": "replace", "path": "userName"}]),
            400,
            "invalidSyntax",
        ),
        (
            json!([{"op": "remove", "path": "userName"}]),
            400,
            "invalidValue",
        ),
        (
            json!([{"op": "remove", "path": "active"}]),
            400,
            "invalidValue",
        ),
        (
            json!([{"op": "nosuchop", "path": "displayName", "value": "x"}]),
            400,
            "invalidSyntax",
        ),
        (
            json!([{"op": "replace", "path": "emails[type eq \"work\"]", "value": {"value": "x@scim.example.com"}}]),
            400,
            "invalidPath",
        ),
        (
            json!([{"op": "replace", "path": "emails.value", "value": "x@scim.example.com"}]),
            400,
            "invalidPath",
        ),
        (
            json!([{"op": "replace", "path": "displayName[type eq \"work\"]", "value": "x"}]),
            400,
            "invalidPath",
        ),
        (
            json!([{"op": "replace", "path": "emails[value eq \"nobody@scim.example.com\"].value", "value": "x@scim.example.com"}]),
            400,
            "noTarget",
        ),
    ] {
        scim.client
            .patch(&path, patch_body(operations.clone()))
            .await
            .assert_error(status, Some(scim_type));
    }

    for body in [
        json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]}),
        json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": []}),
        json!({"Operations": [{"op": "replace", "path": "displayName", "value": "x"}]}),
    ] {
        scim.client
            .patch(&path, body)
            .await
            .assert_error(400, Some("invalidSyntax"));
    }

    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "remove", "value": {"displayName": "x"}}])),
        )
        .await
        .assert_error(400, Some("noTarget"));

    scim.destroy(&path).await;
}

async fn emails_are_patched_through_value_filters(scim: &ScimTest) {
    let id = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "emails@scim.example.com",
                "emails": [{"value": "emails.alias@alias.example.com"}],
            }),
        )
        .await
        .assert_status(201)
        .id();
    let path = format!("/Users/{id}");

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([{
                "op": "replace",
                "path": "emails[value eq \"emails.alias@alias.example.com\"].value",
                "value": "renamed.alias@alias.example.com",
            }])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(
        response.json["emails"][1]["value"],
        json!("renamed.alias@alias.example.com")
    );

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([{
                "op": "replace",
                "path": "emails[primary eq true].value",
                "value": "moved@scim.example.com",
            }])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["userName"], json!("moved@scim.example.com"));
    assert_eq!(
        response.json["emails"][0]["value"],
        json!("moved@scim.example.com")
    );

    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "remove", "path": "emails[primary eq true]"}])),
        )
        .await
        .assert_error(400, Some("invalidValue"));

    scim.client
        .patch(
            &path,
            patch_body(json!([{
                "op": "replace",
                "path": "emails[type eq \"work\"].value",
                "value": "ambiguous@scim.example.com",
            }])),
        )
        .await
        .assert_error(400, Some("invalidFilter"));

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([{
                "op": "add",
                "path": "emails",
                "value": [{"value": "second.alias@alias.example.com"}],
            }])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["emails"].as_array().unwrap().len(), 3);

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([{
                "op": "replace",
                "path": "emails",
                "value": [{"value": "only.alias@alias.example.com"}],
            }])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(
        response.json["emails"],
        json!([
            {"value": "moved@scim.example.com", "type": "work", "primary": true},
            {"value": "only.alias@alias.example.com", "type": "work"},
        ])
    );

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([{
                "op": "remove",
                "path": "emails[value eq \"only.alias@alias.example.com\"]",
            }])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["emails"].as_array().unwrap().len(), 1);

    scim.destroy(&path).await;
}

async fn put_resets_every_absent_attribute(scim: &ScimTest) {
    let id = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": "replace@scim.example.com",
                "externalId": "PUT-1",
                "displayName": "Replace Me",
                "locale": "de-DE",
                "timezone": "Europe/Madrid",
                "emails": [{"value": "replace.alias@alias.example.com"}],
                "active": false,
            }),
        )
        .await
        .assert_status(201)
        .id();
    let path = format!("/Users/{id}");

    let response = scim.client.get(&path).await;
    assert_eq!(response.json["active"], json!(false));

    let response = scim
        .client
        .put(&path, user_body("replace@scim.example.com"))
        .await;
    response.assert_status(200);

    assert_eq!(response.json["active"], json!(true));
    assert_eq!(response.json["locale"], json!("en-US"));
    assert!(response.json.get("timezone").is_none(), "{}", response.body);
    assert!(
        response.json.get("externalId").is_none(),
        "{}",
        response.body
    );
    assert!(
        response.json.get("displayName").is_none(),
        "{}",
        response.body
    );
    assert_eq!(response.json["emails"].as_array().unwrap().len(), 1);

    scim.client
        .put(&path, json!({ "schemas": [SCHEMA_USER] }))
        .await
        .assert_error(400, Some("invalidValue"));

    scim.destroy(&path).await;
}

async fn etags_drive_conditional_requests(scim: &ScimTest) {
    let id = scim.create_user("etag@scim.example.com").await;
    let path = format!("/Users/{id}");
    let created = scim.client.get(&path).await;
    let etag = created.etag();

    let response = scim
        .client
        .request_with_headers("GET", &path, [("if-none-match", etag.clone())], None)
        .await;
    response.assert_status(304);
    assert_eq!(response.header("etag"), Some(etag.as_str()));
    assert!(response.body.is_empty(), "{}", response.body);

    let stale = "W/\"0000000000000000\"".to_string();
    scim.client
        .request_with_headers(
            "PATCH",
            &path,
            [("if-match", stale.clone())],
            Some(
                patch_body(json!([{"op": "replace", "path": "displayName", "value": "Nope"}]))
                    .to_string(),
            ),
        )
        .await
        .assert_error(412, None);

    let response = scim
        .client
        .request_with_headers(
            "PATCH",
            &path,
            [("if-match", etag.clone())],
            Some(
                patch_body(json!([{"op": "replace", "path": "displayName", "value": "Tagged"}]))
                    .to_string(),
            ),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["displayName"], json!("Tagged"));
    let updated_etag = response.etag();
    assert_ne!(updated_etag, etag, "A write must change meta.version");

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "displayName", "value": "Tagged"}])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(
        response.etag(),
        updated_etag,
        "meta.version is a content hash and must not change on a no-op write"
    );

    scim.client
        .request_with_headers("DELETE", &path, [("if-match", stale)], None)
        .await
        .assert_error(412, None);

    let response = scim
        .client
        .request_with_headers("DELETE", &path, [("if-match", updated_etag)], None)
        .await;
    response.assert_status(204);
    assert!(response.body.is_empty(), "{}", response.body);
}

async fn deactivation_moves_the_authenticate_permission(test: &TestServer, scim: &ScimTest) {
    let account = test
        .account("admin")
        .create_user_account(
            "suspend@scim.example.com",
            PASSWORD,
            "Suspend Me",
            &[],
            vec![],
        )
        .await;
    let id = account.id().to_string();
    let path = format!("/Users/{id}");

    assert!(can_authenticate("suspend@scim.example.com", PASSWORD).await);
    assert_imap_authentication_succeeds("suspend@scim.example.com", PASSWORD).await;
    assert!(!is_deactivated(&permissions(test, &id).await));

    let response = scim.client.get(&path).await;
    response.assert_status(200);
    assert_eq!(response.json["active"], json!(true));

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "active", "value": false}])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["active"], json!(false));

    assert_eq!(
        permissions(test, &id).await,
        merged(&[], &[Permission::Authenticate])
    );
    assert!(
        !can_authenticate("suspend@scim.example.com", PASSWORD).await,
        "The HTTP authentication cache was not invalidated"
    );
    assert_imap_authentication_fails("suspend@scim.example.com", PASSWORD).await;

    scim.client
        .get(&path)
        .await
        .assert_status(200)
        .assert_scim_content_type();
    scim.client
        .get("/Users")
        .await
        .assert_status(200)
        .assert_contains_id(&id);
    scim.client
        .get(&query("/Users", "active eq false"))
        .await
        .assert_status(200)
        .assert_contains_id(&id);
    scim.client
        .get(&query("/Users", "active eq true"))
        .await
        .assert_status(200)
        .assert_lacks_id(&id);

    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "active", "value": false}])),
        )
        .await
        .assert_status(200);
    assert_eq!(
        permissions(test, &id).await,
        merged(&[], &[Permission::Authenticate]),
        "Deactivation must be idempotent"
    );

    let response = scim
        .client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "value": {"active": true}}])),
        )
        .await;
    response.assert_status(200);
    assert_eq!(response.json["active"], json!(true));
    assert_eq!(
        permissions(test, &id).await,
        Permissions::Inherit,
        "Reactivation must collapse back to Inherit"
    );
    assert!(can_authenticate("suspend@scim.example.com", PASSWORD).await);
    assert_imap_authentication_succeeds("suspend@scim.example.com", PASSWORD).await;

    test.account("admin")
        .registry_update_object(
            registry::schema::prelude::ObjectType::Account,
            Id::from_str(&id).unwrap(),
            json!({ "permissions": merged(&[Permission::ImapAuthenticate], &[]) }),
        )
        .await;
    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "active", "value": false}])),
        )
        .await
        .assert_status(200);
    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "active", "value": true}])),
        )
        .await
        .assert_status(200);
    assert_eq!(
        permissions(test, &id).await,
        merged(&[Permission::ImapAuthenticate], &[]),
        "An unrelated customisation must survive a deactivation cycle"
    );

    scim.destroy(&path).await;
}

async fn reactivation_collapses_back_to_inherit(test: &TestServer, scim: &ScimTest) {
    let id = scim.create_user("inherit@scim.example.com").await;
    let path = format!("/Users/{id}");

    assert_eq!(permissions(test, &id).await, Permissions::Inherit);

    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "active", "value": false}])),
        )
        .await
        .assert_status(200);
    assert_eq!(
        permissions(test, &id).await,
        merged(&[], &[Permission::Authenticate])
    );

    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "active", "value": true}])),
        )
        .await
        .assert_status(200);
    assert_eq!(permissions(test, &id).await, Permissions::Inherit);

    scim.destroy(&path).await;
}

async fn delete_removes_the_account(scim: &ScimTest) {
    let id = scim.create_user("ephemeral@scim.example.com").await;
    let path = format!("/Users/{id}");

    let response = scim.client.delete(&path).await;
    response.assert_status(204);
    assert!(response.body.is_empty(), "{}", response.body);

    scim.client.get(&path).await.assert_error(404, None);
    scim.client.delete(&path).await.assert_error(404, None);
    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "displayName", "value": "x"}])),
        )
        .await
        .assert_error(404, None);
    scim.client
        .put(&path, user_body("ephemeral@scim.example.com"))
        .await
        .assert_error(404, None);
    scim.client
        .get("/Users")
        .await
        .assert_status(200)
        .assert_lacks_id(&id);

    let reused = scim.create_user("ephemeral@scim.example.com").await;
    assert_ne!(reused, id);
    scim.destroy(&format!("/Users/{reused}")).await;
}

fn is_deactivated(permissions: &Permissions) -> bool {
    match permissions {
        Permissions::Inherit => false,
        Permissions::Merge(list) | Permissions::Replace(list) => list
            .disabled_permissions
            .contains(&Permission::Authenticate),
    }
}

fn merged(enabled: &[Permission], disabled: &[Permission]) -> Permissions {
    let mut list = PermissionsList::default();
    for permission in enabled {
        list.enabled_permissions.push(*permission);
    }
    for permission in disabled {
        list.disabled_permissions.push(*permission);
    }
    Permissions::Merge(list)
}

async fn permissions(test: &TestServer, id: &str) -> Permissions {
    match test
        .server
        .registry()
        .object::<Account>(Id::from_str(id).unwrap())
        .await
        .unwrap()
        .expect("The account no longer exists")
    {
        Account::User(account) => account.permissions,
        other => panic!("Expected a user account but got {other:?}"),
    }
}

async fn can_authenticate(name: &str, secret: &str) -> bool {
    crate::scim::jmap_session_status(&format!(
        "Basic {}",
        STANDARD.encode(format!("{name}:{secret}").as_bytes())
    ))
    .await
        == 200
}

async fn assert_imap_authentication_fails(name: &str, secret: &str) {
    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;

    let credentials = STANDARD.encode(format!("\0{name}\0{secret}").as_bytes());
    imap.send(&format!(
        "AUTHENTICATE PLAIN {{{}+}}\r\n{credentials}",
        credentials.len()
    ))
    .await;
    imap.assert_disconnect().await;
}

async fn assert_imap_authentication_succeeds(name: &str, secret: &str) {
    ImapConnection::connect(b"_x ")
        .await
        .authenticate(name, secret)
        .await;
}
