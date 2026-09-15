/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::properties::destroy_tree;
use crate::utils::{jmap::JmapUtils, server::TestServer};
use hyper::StatusCode;
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running File Storage WebDAV naming tests...");
    let account = test.account("jdoe@example.com");
    let client = account.webdav_client();

    let folder_id = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "dav names"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let folder = "/dav/file/jdoe%40example.com/dav%20names";

    for path in ["file%281%29.txt", "%c3%9cbersicht.txt"] {
        client
            .request_with_headers(
                "PUT",
                &format!("{folder}/{path}"),
                [("content-type", "text/plain")],
                "hello",
            )
            .await
            .with_status(StatusCode::CREATED);
    }
    client
        .request("MKCOL", &format!("{folder}/My%20Folder"), "")
        .await
        .with_status(StatusCode::CREATED);
    client
        .request_with_headers(
            "PUT",
            &format!("{folder}/a%2Fb.txt"),
            [("content-type", "text/plain")],
            "hello",
        )
        .await
        .with_status(StatusCode::BAD_REQUEST);
    client
        .request("MKCOL", &format!("{folder}/{}", "a".repeat(256)), "")
        .await
        .with_status(StatusCode::URI_TOO_LONG);

    let names = child_names(account, &folder_id).await;
    assert_eq!(names, ["file(1).txt", "My Folder", "Übersicht.txt"]);

    client
        .propfind_with_headers(folder, ["D:getetag"], [("depth", "1")])
        .await
        .with_hrefs([
            format!("{folder}/").as_str(),
            format!("{folder}/file(1).txt").as_str(),
            format!("{folder}/%C3%9Cbersicht.txt").as_str(),
            format!("{folder}/My%20Folder/").as_str(),
        ]);
    for (path, href) in [
        ("file%281%29.txt", "file%281%29.txt"),
        ("%c3%9cbersicht.txt", "%c3%9cbersicht.txt"),
        ("My%20Folder", "My%20Folder/"),
    ] {
        client
            .propfind_with_headers(&format!("{folder}/{path}"), ["D:getetag"], [("depth", "0")])
            .await
            .with_hrefs([format!("{folder}/{href}").as_str()]);
    }

    for path in [
        "file(1).txt",
        "file%281%29.txt",
        "%C3%9Cbersicht.txt",
        "%c3%9cbersicht.txt",
    ] {
        client
            .request("GET", &format!("{folder}/{path}"), "")
            .await
            .with_status(StatusCode::OK)
            .with_body("hello");
    }
    client
        .request("MKCOL", &format!("{folder}/My%20Folder"), "")
        .await
        .with_status(StatusCode::METHOD_NOT_ALLOWED);

    let file_id = child_id(account, &folder_id, "file(1).txt").await;
    account
        .jmap_update(
            MethodObject::FileNode,
            [(&file_id, json!({"name": "renamed (1).txt"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&file_id);

    account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "link", "parentId": &folder_id, "target": ["My Folder"]})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0);
    client
        .propfind_with_headers(folder, ["D:getetag"], [("depth", "1")])
        .await
        .with_hrefs([
            format!("{folder}/").as_str(),
            format!("{folder}/renamed%20(1).txt").as_str(),
            format!("{folder}/%C3%9Cbersicht.txt").as_str(),
            format!("{folder}/My%20Folder/").as_str(),
        ]);
    client
        .request("GET", &format!("{folder}/link"), "")
        .await
        .with_status(StatusCode::NOT_FOUND);
    client
        .request_with_headers(
            "PUT",
            &format!("{folder}/link"),
            [("content-type", "text/plain")],
            "hello",
        )
        .await
        .with_status(StatusCode::CONFLICT);

    let blob_id = super::properties::upload_blob(account, "hello").await;
    account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "a b&c (1) \u{fc}.txt", "parentId": &folder_id, "blobId": &blob_id})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0);

    for path in ["%E9t%E9.txt", "Plain%20Name.txt"] {
        client
            .request_with_headers(
                "PUT",
                &format!("{folder}/{path}"),
                [("content-type", "text/plain")],
                "hello",
            )
            .await
            .with_status(StatusCode::CREATED);
    }
    let names = child_names(account, &folder_id).await;
    for name in ["%E9t%E9.txt", "Plain Name.txt", "a b&c (1) \u{fc}.txt"] {
        assert!(
            names.iter().any(|n| n == name),
            "{name} missing from {names:?}"
        );
    }
    client
        .propfind_with_headers(folder, ["D:getetag"], [("depth", "1")])
        .await
        .with_hrefs([
            format!("{folder}/").as_str(),
            format!("{folder}/renamed%20(1).txt").as_str(),
            format!("{folder}/%C3%9Cbersicht.txt").as_str(),
            format!("{folder}/My%20Folder/").as_str(),
            format!("{folder}/a%20b&c%20(1)%20%C3%BC.txt").as_str(),
            format!("{folder}/%25E9t%25E9.txt").as_str(),
            format!("{folder}/Plain%20Name.txt").as_str(),
        ]);
    for path in [
        "a%20b%26c%20%281%29%20%c3%bc.txt",
        "a%20b&c%20(1)%20%C3%BC.txt",
        "%E9t%E9.txt",
        "%e9t%e9.txt",
        "%25E9t%25E9.txt",
        "Plain%20Name.txt",
    ] {
        client
            .request("GET", &format!("{folder}/{path}"), "")
            .await
            .with_status(StatusCode::OK)
            .with_body("hello");
    }

    let latin1_id = child_id(account, &folder_id, "%E9t%E9.txt").await;
    account
        .jmap_update(
            MethodObject::FileNode,
            [(&latin1_id, json!({"name": "\u{e9}t\u{e9}.txt"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&latin1_id);
    client
        .request("GET", &format!("{folder}/%C3%A9t%C3%A9.txt"), "")
        .await
        .with_status(StatusCode::OK);
    client
        .request("GET", &format!("{folder}/%E9t%E9.txt"), "")
        .await
        .with_status(StatusCode::NOT_FOUND);

    let spelled = format!("{folder}/sub%28x%29");
    client
        .request("MKCOL", &spelled, "")
        .await
        .with_status(StatusCode::CREATED);
    client
        .request_with_headers(
            "PUT",
            &format!("{spelled}/in%20%281%29.txt"),
            [("content-type", "text/plain")],
            "hello",
        )
        .await
        .with_status(StatusCode::CREATED);
    client
        .propfind_with_headers(&format!("{spelled}/"), ["D:getetag"], [("depth", "1")])
        .await
        .with_hrefs([
            format!("{spelled}/").as_str(),
            format!("{folder}/sub(x)/in%20(1).txt").as_str(),
        ]);
    assert!(
        child_names(account, &folder_id)
            .await
            .iter()
            .any(|name| name == "sub(x)")
    );

    destroy_tree(account, &folder_id).await;
    test.assert_is_empty().await;
}

async fn child_names(account: &crate::utils::account::Account, parent_id: &str) -> Vec<String> {
    account
        .jmap_method_calls(json!([
            [
                "FileNode/query",
                {
                    "accountId": account.id_string(),
                    "filter": {"parentId": parent_id},
                    "sort": [{"property": "name"}]
                },
                "0"
            ],
            [
                "FileNode/get",
                {
                    "accountId": account.id_string(),
                    "#ids": {"resultOf": "0", "name": "FileNode/query", "path": "/ids"},
                    "properties": ["name"]
                },
                "1"
            ]
        ]))
        .await
        .pointer("/methodResponses/1/1/list")
        .and_then(Value::as_array)
        .expect("child list")
        .iter()
        .map(|node| node.text_field("name").to_string())
        .collect()
}

async fn child_id(account: &crate::utils::account::Account, parent_id: &str, name: &str) -> String {
    account
        .jmap_method_calls(json!([[
            "FileNode/query",
            {
                "accountId": account.id_string(),
                "filter": {"operator": "AND", "conditions": [{"parentId": parent_id}, {"name": name}]}
            },
            "0"
        ]]))
        .await
        .pointer("/methodResponses/0/1/ids/0")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{name} not found"))
        .to_string()
}
