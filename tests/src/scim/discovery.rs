/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::scim::ScimTest;
use scim_proto::{
    MESSAGE_LIST_RESPONSE, SCHEMA_GROUP, SCHEMA_RESOURCE_TYPE, SCHEMA_SCHEMA,
    SCHEMA_SERVICE_PROVIDER_CONFIG, SCHEMA_USER,
};
use serde_json::{Value, json};

pub async fn test(scim: &ScimTest) {
    println!("Running SCIM discovery tests...");

    service_provider_config_is_anonymous(scim).await;
    resource_types_are_published(scim).await;
    schemas_are_published(scim).await;
    the_user_schema_publishes_only_the_supported_attributes(scim).await;
    the_meta_definition_omits_last_modified(scim).await;
    discovery_endpoints_reject_filters(scim).await;
    unknown_endpoints_are_not_found(scim).await;
    the_me_endpoint_is_not_implemented(scim).await;
    collections_are_empty_not_missing(scim).await;
    trailing_slashes_are_tolerated(scim).await;
    unsupported_methods_carry_an_allow_header(scim).await;
}

async fn service_provider_config_is_anonymous(scim: &ScimTest) {
    let response = scim.anonymous.get("/ServiceProviderConfig").await;
    response.assert_status(200);

    assert_eq!(
        response.json["schemas"],
        json!([SCHEMA_SERVICE_PROVIDER_CONFIG])
    );
    assert_eq!(response.json["patch"]["supported"], json!(true));
    assert_eq!(response.json["etag"]["supported"], json!(true));
    assert_eq!(response.json["sort"]["supported"], json!(true));
    assert_eq!(response.json["changePassword"]["supported"], json!(false));
    assert_eq!(response.json["filter"]["supported"], json!(true));
    assert_eq!(response.json["filter"]["maxResults"], json!(200));
    assert_eq!(response.json["bulk"]["supported"], json!(true));
    assert_eq!(response.json["bulk"]["maxOperations"], json!(1000));
    assert_eq!(response.json["bulk"]["maxPayloadSize"], json!(1048576));
    assert_eq!(response.json["pagination"]["cursor"], json!(true));
    assert_eq!(response.json["pagination"]["index"], json!(true));
    assert_eq!(response.json["interopProfileConformant"], json!(false));
    assert_eq!(
        response.json["authenticationSchemes"][0]["type"],
        json!("oauthbearertoken")
    );
    assert_eq!(
        response.str("/meta/location"),
        format!("{}/ServiceProviderConfig", scim.base_url)
    );
}

async fn resource_types_are_published(scim: &ScimTest) {
    let response = scim.anonymous.get("/ResourceTypes").await;
    response.assert_status(200);

    assert_eq!(response.json["schemas"], json!([MESSAGE_LIST_RESPONSE]));
    assert_eq!(response.total_results(), 2);

    for (index, (name, endpoint, schema)) in [
        ("User", "/Users", SCHEMA_USER),
        ("Group", "/Groups", SCHEMA_GROUP),
    ]
    .into_iter()
    .enumerate()
    {
        let resource = &response.resources()[index];
        assert_eq!(resource["schemas"], json!([SCHEMA_RESOURCE_TYPE]));
        assert_eq!(resource["id"], json!(name));
        assert_eq!(resource["name"], json!(name));
        assert_eq!(resource["endpoint"], json!(endpoint));
        assert_eq!(resource["schema"], json!(schema));
        assert_eq!(
            resource["meta"]["location"],
            json!(format!("{}/ResourceTypes/{name}", scim.base_url))
        );

        scim.anonymous
            .get(&format!("/ResourceTypes/{name}"))
            .await
            .assert_status(200);
    }

    scim.anonymous
        .get("/ResourceTypes/Device")
        .await
        .assert_error(404, None);
}

async fn schemas_are_published(scim: &ScimTest) {
    let response = scim.anonymous.get("/Schemas").await;
    response.assert_status(200);
    assert_eq!(response.total_results(), 2);

    let ids = response
        .resources()
        .iter()
        .map(|schema| schema["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec![SCHEMA_USER.to_string(), SCHEMA_GROUP.to_string()]);

    for schema in response.resources() {
        assert_eq!(schema["schemas"], json!([SCHEMA_SCHEMA]));
        assert_eq!(schema["meta"]["resourceType"], json!("Schema"));
    }

    let response = scim.anonymous.get(&format!("/Schemas/{SCHEMA_USER}")).await;
    response.assert_status(200);
    assert_eq!(response.json["id"], json!(SCHEMA_USER));
    assert_eq!(response.json["name"], json!("User"));

    scim.anonymous
        .get("/Schemas/urn:ietf:params:scim:schemas:core:2.0:Device")
        .await
        .assert_error(404, None);
}

async fn the_user_schema_publishes_only_the_supported_attributes(scim: &ScimTest) {
    let response = scim.anonymous.get(&format!("/Schemas/{SCHEMA_USER}")).await;
    let attributes = response.json["attributes"].as_array().unwrap();

    let names = attributes
        .iter()
        .map(|attribute| attribute["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "id",
            "externalId",
            "userName",
            "name",
            "displayName",
            "active",
            "emails",
            "locale",
            "preferredLanguage",
            "timezone",
            "groups",
            "meta",
        ]
    );

    let name = attribute(attributes, "name");
    assert_eq!(
        sub_attribute_names(name),
        vec!["formatted"],
        "The published name attribute must not carry givenName or familyName"
    );

    let emails = attribute(attributes, "emails");
    assert_eq!(
        emails["subAttributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|sub| sub["name"] == json!("type"))
            .unwrap()["canonicalValues"],
        json!(["work"])
    );
    for read_only in ["type", "display", "primary"] {
        let sub = emails["subAttributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|sub| sub["name"] == json!(read_only))
            .unwrap();
        assert_eq!(sub["mutability"], json!("readOnly"), "{read_only}");
    }

    assert_eq!(
        attribute(attributes, "groups")["mutability"],
        json!("readOnly")
    );
    assert!(
        !response.body.contains("password"),
        "The published User schema must not carry a password attribute"
    );
}

async fn the_meta_definition_omits_last_modified(scim: &ScimTest) {
    for schema in [SCHEMA_USER, SCHEMA_GROUP] {
        let response = scim.anonymous.get(&format!("/Schemas/{schema}")).await;
        let attributes = response.json["attributes"].as_array().unwrap();
        let meta = attribute(attributes, "meta");

        assert_eq!(
            sub_attribute_names(meta),
            vec!["resourceType", "created", "location", "version"],
            "{schema}"
        );
    }
}

async fn discovery_endpoints_reject_filters(scim: &ScimTest) {
    for endpoint in ["/ServiceProviderConfig", "/ResourceTypes", "/Schemas"] {
        scim.client
            .get(&format!("{endpoint}?filter=id%20eq%20%22User%22"))
            .await
            .assert_error(403, None);
    }
}

async fn unknown_endpoints_are_not_found(scim: &ScimTest) {
    for path in ["/Devices", "/Users/abc/def", "/Bulk/abc", "/.search/abc"] {
        scim.client.get(path).await.assert_error(404, None);
    }

    scim.client
        .request("GET", "", None)
        .await
        .assert_error(404, None);
}

async fn the_me_endpoint_is_not_implemented(scim: &ScimTest) {
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        scim.client
            .request(method, "/Me", None)
            .await
            .assert_error(501, None);
    }
}

async fn collections_are_empty_not_missing(scim: &ScimTest) {
    for endpoint in ["/Users", "/Groups"] {
        let response = scim
            .client
            .get(&format!("{endpoint}?startIndex=1&count=0"))
            .await;
        response.assert_status(200);

        assert_eq!(response.json["schemas"], json!([MESSAGE_LIST_RESPONSE]));
        assert_eq!(response.json["startIndex"], json!(1));
        assert_eq!(response.json["itemsPerPage"], json!(0));
        assert!(response.resources().is_empty(), "{}", response.body);
    }

    let response = scim.client.get("/Groups").await;
    response.assert_status(200);
    assert_eq!(response.total_results(), 0);
}

async fn trailing_slashes_are_tolerated(scim: &ScimTest) {
    scim.client.get("/Users/").await.assert_status(200);

    let id = scim.create_user("trailing@scim.example.com").await;
    scim.client
        .get(&format!("/Users/{id}/"))
        .await
        .assert_status(200);
    scim.destroy(&format!("/Users/{id}")).await;
}

async fn unsupported_methods_carry_an_allow_header(scim: &ScimTest) {
    for (method, path, allow) in [
        ("GET", "/Users/.search", "POST"),
        ("GET", "/Groups/.search", "POST"),
        ("GET", "/Bulk", "POST"),
        ("GET", "/.search", "POST"),
        ("POST", "/ServiceProviderConfig", "GET"),
        ("DELETE", "/Schemas", "GET"),
    ] {
        let response = scim.client.request(method, path, None).await;
        response.assert_error(405, None);
        assert_eq!(
            response.header("allow"),
            Some(allow),
            "{method} {path} did not carry the expected Allow header"
        );
    }
}

fn attribute<'x>(attributes: &'x [Value], name: &str) -> &'x Value {
    attributes
        .iter()
        .find(|attribute| attribute["name"] == json!(name))
        .unwrap_or_else(|| panic!("Missing attribute {name}"))
}

fn sub_attribute_names(attribute: &Value) -> Vec<&str> {
    attribute["subAttributes"]
        .as_array()
        .map(|sub_attributes| {
            sub_attributes
                .iter()
                .map(|sub| sub["name"].as_str().unwrap())
                .collect()
        })
        .unwrap_or_default()
}
