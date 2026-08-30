/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::scim::{ScimTest, query};
use ahash::AHashSet;
use scim_proto::{MESSAGE_LIST_RESPONSE, MESSAGE_SEARCH_REQUEST, SCHEMA_USER};
use serde_json::json;

const PAGE_USERS: usize = 24;
const DISPLAY_NAME: &str = "Paged Person";
const FILTER: &str = "displayName eq \"Paged Person\"";

pub async fn test(scim: &ScimTest) {
    println!("Running SCIM pagination and search tests...");

    let ids = create_users(scim).await;

    index_pagination_covers_every_resource(scim, &ids).await;
    the_page_size_is_bounded(scim, &ids).await;
    cursor_pagination_covers_every_resource(scim, &ids).await;
    cursors_are_validated(scim).await;
    sorting_is_supported_on_indexed_attributes(scim, &ids).await;
    attribute_selection_is_honoured(scim).await;
    the_search_endpoints_mirror_the_get_endpoints(scim, &ids).await;

    for id in &ids {
        scim.destroy(&format!("/Users/{id}")).await;
    }
}

async fn create_users(scim: &ScimTest) -> Vec<String> {
    let mut ids = Vec::with_capacity(PAGE_USERS);

    for index in 0..PAGE_USERS {
        ids.push(
            scim.client
                .post(
                    "/Users",
                    json!({
                        "schemas": [SCHEMA_USER],
                        "userName": format!("paged-{index:02}@scim.example.com"),
                        "displayName": DISPLAY_NAME,
                        "externalId": format!("PAGED-{index:02}"),
                    }),
                )
                .await
                .assert_status(201)
                .id(),
        );
    }

    ids
}

async fn index_pagination_covers_every_resource(scim: &ScimTest, ids: &[String]) {
    let response = scim.client.get(&query("/Users", FILTER)).await;
    response.assert_status(200);
    assert_eq!(response.total_results(), PAGE_USERS);
    assert_eq!(response.json["itemsPerPage"], json!(PAGE_USERS));
    assert_eq!(response.json["startIndex"], json!(1));
    assert_eq!(response.json["schemas"], json!([MESSAGE_LIST_RESPONSE]));
    assert!(response.json.get("nextCursor").is_none());

    let mut seen = AHashSet::new();
    let mut start_index = 1;
    while start_index <= PAGE_USERS {
        let response = scim
            .client
            .get(&format!(
                "{}&startIndex={start_index}&count=5",
                query("/Users", FILTER)
            ))
            .await;
        response.assert_status(200);
        assert_eq!(response.total_results(), PAGE_USERS);
        assert_eq!(response.json["startIndex"], json!(start_index));

        let page = response.resource_ids();
        assert_eq!(response.json["itemsPerPage"], json!(page.len()));
        for id in page {
            assert!(seen.insert(id.clone()), "{id} was returned twice");
        }
        start_index += 5;
    }
    assert_eq!(seen.len(), PAGE_USERS);
    for id in ids {
        assert!(seen.contains(id), "{id} was never returned");
    }

    let response = scim
        .client
        .get(&format!("{}&startIndex=0&count=5", query("/Users", FILTER)))
        .await;
    response.assert_status(200);
    assert_eq!(response.json["startIndex"], json!(1));
    assert_eq!(response.resource_ids().len(), 5);

    let response = scim
        .client
        .get(&format!(
            "{}&startIndex={}&count=5",
            query("/Users", FILTER),
            PAGE_USERS + 100
        ))
        .await;
    response.assert_status(200);
    assert_eq!(response.total_results(), PAGE_USERS);
    assert!(response.resources().is_empty(), "{}", response.body);
}

async fn the_page_size_is_bounded(scim: &ScimTest, ids: &[String]) {
    let response = scim
        .client
        .get(&format!("{}&count=1000", query("/Users", FILTER)))
        .await;
    response.assert_status(200);
    assert_eq!(response.resource_ids().len(), ids.len());

    let response = scim
        .client
        .get(&format!("{}&count=0", query("/Users", FILTER)))
        .await;
    response.assert_status(200);
    assert_eq!(response.total_results(), PAGE_USERS);
    assert!(response.resources().is_empty(), "{}", response.body);

    let response = scim
        .client
        .get(&format!("{}&count=-5", query("/Users", FILTER)))
        .await;
    response.assert_status(200);
    assert!(response.resources().is_empty(), "{}", response.body);

    scim.client
        .get(&format!("{}&count=many", query("/Users", FILTER)))
        .await
        .assert_error(400, Some("invalidCount"));

    scim.client
        .get(&format!("{}&startIndex=many", query("/Users", FILTER)))
        .await
        .assert_error(400, Some("invalidValue"));
}

async fn cursor_pagination_covers_every_resource(scim: &ScimTest, ids: &[String]) {
    let mut seen = Vec::new();
    let mut cursor = String::new();
    let mut pages = 0;

    loop {
        let response = scim
            .client
            .get(&format!(
                "{}&count=5&cursor={cursor}",
                query("/Users", FILTER)
            ))
            .await;
        response.assert_status(200);
        assert_eq!(response.total_results(), PAGE_USERS);
        assert!(
            response.json.get("startIndex").is_none(),
            "A cursor paged response must not carry startIndex: {}",
            response.body
        );

        seen.extend(response.resource_ids());
        pages += 1;
        assert!(pages <= PAGE_USERS, "The cursor never terminated");

        match response.json.get("nextCursor") {
            Some(next) => cursor = next.as_str().unwrap().to_string(),
            None => break,
        }
    }

    assert_eq!(seen.len(), PAGE_USERS);
    assert_eq!(
        seen.iter().collect::<AHashSet<_>>().len(),
        PAGE_USERS,
        "The cursor returned duplicates"
    );
    for id in ids {
        assert!(seen.contains(id), "{id} was never returned");
    }
}

async fn cursors_are_validated(scim: &ScimTest) {
    let response = scim
        .client
        .get(&format!("{}&count=5&cursor=", query("/Users", FILTER)))
        .await;
    response.assert_status(200);
    let cursor = response.json["nextCursor"].as_str().unwrap().to_string();

    scim.client
        .get(&format!(
            "{}&count=5&cursor={cursor}",
            query("/Users", "displayName eq \"Somebody Else\"")
        ))
        .await
        .assert_error(400, Some("invalidCursor"));

    scim.client
        .get(&format!(
            "{}&count=5&sortBy=userName&cursor={cursor}",
            query("/Users", FILTER)
        ))
        .await
        .assert_error(400, Some("invalidCursor"));

    for malformed in [
        "abc".to_string(),
        "z".to_string(),
        "0".repeat(47),
        "z".repeat(48),
    ] {
        scim.client
            .get(&format!(
                "{}&count=5&cursor={malformed}",
                query("/Users", FILTER)
            ))
            .await
            .assert_error(400, Some("invalidCursor"));
    }
}

async fn sorting_is_supported_on_indexed_attributes(scim: &ScimTest, ids: &[String]) {
    let ascending = scim
        .client
        .get(&format!(
            "{}&sortBy=userName&sortOrder=ascending&count=100",
            query("/Users", FILTER)
        ))
        .await;
    ascending.assert_status(200);
    let names = ascending
        .resources()
        .iter()
        .map(|resource| resource["userName"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "{}", ascending.body);

    let descending = scim
        .client
        .get(&format!(
            "{}&sortBy=userName&sortOrder=descending&count=100",
            query("/Users", FILTER)
        ))
        .await;
    descending.assert_status(200);
    let mut reversed = descending
        .resources()
        .iter()
        .map(|resource| resource["userName"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    reversed.reverse();
    assert_eq!(reversed, names);

    let by_id = scim
        .client
        .get(&format!("{}&sortBy=id&count=100", query("/Users", FILTER)))
        .await;
    by_id.assert_status(200);
    assert_eq!(by_id.resource_ids().len(), ids.len());

    for sort_by in ["externalId", "displayName", "meta.created", "nosuchattr"] {
        scim.client
            .get(&format!("{}&sortBy={sort_by}", query("/Users", FILTER)))
            .await
            .assert_error(400, Some("invalidValue"));
    }

    scim.client
        .get(&format!(
            "{}&sortBy=userName&sortOrder=sideways",
            query("/Users", FILTER)
        ))
        .await
        .assert_error(400, Some("invalidValue"));
}

async fn attribute_selection_is_honoured(scim: &ScimTest) {
    let response = scim
        .client
        .get(&format!(
            "{}&count=1&attributes=userName,active",
            query("/Users", FILTER)
        ))
        .await;
    response.assert_status(200);

    let resource = &response.resources()[0];
    assert!(resource.get("id").is_some(), "{resource}");
    assert!(resource.get("userName").is_some(), "{resource}");
    assert!(resource.get("active").is_some(), "{resource}");
    assert!(resource.get("emails").is_none(), "{resource}");
    assert!(resource.get("locale").is_none(), "{resource}");
    assert!(resource.get("externalId").is_none(), "{resource}");

    let response = scim
        .client
        .get(&format!(
            "{}&count=1&excludedAttributes=emails,locale",
            query("/Users", FILTER)
        ))
        .await;
    response.assert_status(200);

    let resource = &response.resources()[0];
    assert!(resource.get("emails").is_none(), "{resource}");
    assert!(resource.get("locale").is_none(), "{resource}");
    assert!(resource.get("userName").is_some(), "{resource}");
    assert!(resource.get("displayName").is_some(), "{resource}");

    scim.client
        .get(&format!(
            "{}&attributes=userName&excludedAttributes=emails",
            query("/Users", FILTER)
        ))
        .await
        .assert_error(400, Some("invalidValue"));
}

async fn the_search_endpoints_mirror_the_get_endpoints(scim: &ScimTest, ids: &[String]) {
    let expected = scim
        .client
        .get(&format!(
            "{}&sortBy=userName&count=5&startIndex=6",
            query("/Users", FILTER)
        ))
        .await;
    expected.assert_status(200);

    let searched = scim
        .client
        .post(
            "/Users/.search",
            json!({
                "schemas": [MESSAGE_SEARCH_REQUEST],
                "filter": FILTER,
                "sortBy": "userName",
                "count": 5,
                "startIndex": 6,
            }),
        )
        .await;
    searched.assert_status(200);
    assert_eq!(searched.json, expected.json);

    let all = scim
        .client
        .post(
            "/.search",
            json!({
                "schemas": [MESSAGE_SEARCH_REQUEST],
                "filter": FILTER,
                "count": 100,
            }),
        )
        .await;
    all.assert_status(200);
    assert_eq!(all.total_results(), ids.len());
    for id in ids {
        all.assert_contains_id(id);
    }

    let group = scim.create_group("Searchable Team").await;
    let response = scim
        .client
        .post(
            "/.search",
            json!({
                "schemas": [MESSAGE_SEARCH_REQUEST],
                "filter": "displayName eq \"Searchable Team\"",
                "count": 100,
            }),
        )
        .await;
    response.assert_status(200);
    response.assert_contains_id(&group);
    scim.destroy(&format!("/Groups/{group}")).await;

    scim.client
        .post(
            "/Users/.search",
            json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"]}),
        )
        .await
        .assert_error(400, Some("invalidSyntax"));

    scim.client
        .post("/Users/.search", json!({"filter": FILTER}))
        .await
        .assert_error(400, Some("invalidSyntax"));

    scim.client
        .post(
            "/Users/.search",
            json!({"schemas": [MESSAGE_SEARCH_REQUEST], "filter": "userName co \"paged\""}),
        )
        .await
        .assert_error(400, Some("invalidFilter"));
}
