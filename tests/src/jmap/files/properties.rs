/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use ahash::AHashSet;
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running File Storage property tests...");
    let account = test.account("jdoe@example.com");
    let blob_id = upload_blob(account, "hello world").await;

    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "no-blob", "nodeType": "file"}),
                json!({"name": "dir-with-blob", "nodeType": "directory", "blobId": &blob_id}),
                json!({"name": "bad-size", "blobId": &blob_id, "size": 12}),
                json!({"name": "bad-type", "blobId": &blob_id, "type": "text"}),
                json!({"name": "con.txt", "blobId": &blob_id}),
                json!({"name": "exec-dir", "executable": true}),
                json!({"name": "role-file", "blobId": &blob_id, "role": "trash"}),
                json!({"name": "bad-role", "role": "garbage"}),
                json!({"name": "bad-target", "target": ["a", ""]}),
                json!({"name": "link-with-blob", "target": ["a"], "blobId": &blob_id}),
                json!({"name": "symlink-no-target", "nodeType": "symlink"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for idx in 0..11 {
        assert_eq!(
            response.not_created(idx).typ(),
            "invalidProperties",
            "create {idx}: {:?}",
            response.not_created(idx)
        );
    }

    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({
                    "name": "file.txt",
                    "blobId": &blob_id,
                    "type": "Text/Plain",
                    "size": 11,
                    "executable": true,
                    "created": "2020-01-01T00:00:00Z",
                    "modified": "2021-01-01T00:00:00Z",
                    "accessed": "2022-01-01T00:00:00Z"
                }),
                json!({"name": "trash", "role": "trash"}),
                json!({"name": "link", "target": ["", "trash", "file.txt"]}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let file_id = response.created(0).id().to_string();
    let trash_id = response.created(1).id().to_string();
    let link_id = response.created(2).id().to_string();

    let file = get_node(account, &file_id).await;
    assert_eq!(file.text_field("nodeType"), "file");
    assert_eq!(file.text_field("type"), "text/plain");
    assert_eq!(file.integer_field("size"), 11);
    assert_eq!(file["executable"], json!(true));
    assert_eq!(file.text_field("created"), "2020-01-01T00:00:00Z");
    assert_eq!(file.text_field("modified"), "2021-01-01T00:00:00Z");
    assert_eq!(file.text_field("accessed"), "2022-01-01T00:00:00Z");
    assert!(file["changed"].is_string());
    assert_eq!(file["role"], Value::Null);
    assert_eq!(file["target"], Value::Null);
    assert_eq!(file["isSubscribed"], json!(true));
    assert_eq!(file["shareWith"], Value::Null);

    let trash = get_node(account, &trash_id).await;
    assert_eq!(trash.text_field("nodeType"), "directory");
    assert_eq!(trash.text_field("role"), "trash");
    assert_eq!(trash["size"], Value::Null);
    assert_eq!(trash["type"], Value::Null);
    assert_eq!(trash["blobId"], Value::Null);
    assert_eq!(trash["executable"], json!(false));

    let link = get_node(account, &link_id).await;
    assert_eq!(link.text_field("nodeType"), "symlink");
    assert_eq!(link["target"], json!(["", "trash", "file.txt"]));
    assert_eq!(link["size"], Value::Null);
    assert_eq!(link["type"], Value::Null);
    assert_eq!(link["blobId"], Value::Null);

    let response = account
        .jmap_update(
            MethodObject::FileNode,
            [
                (&file_id, json!({"blobId": null})),
                (&trash_id, json!({"blobId": &blob_id})),
                (&link_id, json!({"target": null})),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for id in [&file_id, &trash_id, &link_id] {
        assert_eq!(response.not_updated(id).typ(), "invalidProperties");
    }
    let response = account
        .jmap_update(
            MethodObject::FileNode,
            [
                (&file_id, json!({"nodeType": "directory"})),
                (&trash_id, json!({"target": ["x"]})),
                (&link_id, json!({"role": "home"})),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for id in [&file_id, &trash_id, &link_id] {
        assert_eq!(response.not_updated(id).typ(), "invalidProperties");
    }
    assert_eq!(
        account
            .jmap_update(
                MethodObject::FileNode,
                [(&file_id, json!({"size": 5}))],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .not_updated(&file_id)
            .typ(),
        "invalidProperties"
    );

    let response = account
        .jmap_update(
            MethodObject::FileNode,
            [
                (
                    &file_id,
                    json!({
                        "name": "renamed.txt",
                        "nodeType": "file",
                        "created": "2019-01-01T00:00:00Z",
                        "accessed": null,
                        "isSubscribed": false
                    }),
                ),
                (&link_id, json!({"target": ["..", "x"]})),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.updated(&file_id);
    response.updated(&link_id);
    let file = get_node(account, &file_id).await;
    assert_eq!(file.text_field("name"), "renamed.txt");
    assert_eq!(file.text_field("modified"), "2021-01-01T00:00:00Z");
    assert_eq!(file.text_field("created"), "2019-01-01T00:00:00Z");
    assert_ne!(file.text_field("accessed"), "2022-01-01T00:00:00Z");
    assert_eq!(file["isSubscribed"], json!(false));
    assert_eq!(
        get_node(account, &link_id).await["target"],
        json!(["..", "x"])
    );

    assert_eq!(
        account
            .jmap_create(
                MethodObject::FileNode,
                [json!({"name": "child", "parentId": &link_id})],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .not_created(0)
            .description(),
        "Parent ID does not exist or is not a folder."
    );

    let mut chain = vec![json!({"name": "d0"})];
    for depth in 1..65 {
        chain.push(json!({"name": format!("d{depth}"), "parentId": format!("#i{}", depth - 1)}));
    }
    let response = account
        .jmap_create(MethodObject::FileNode, chain, Vec::<(&str, &str)>::new())
        .await;
    let chain_root = response.created(0).id().to_string();
    response.created(63);
    assert_eq!(
        response.not_created(64).description(),
        "Maximum folder depth exceeded."
    );
    destroy_tree(account, &chain_root).await;

    for order in [[0, 1, 2], [2, 1, 0]] {
        let response = account
            .jmap_create(
                MethodObject::FileNode,
                [
                    json!({"name": "parent"}),
                    json!({"name": "child-a", "parentId": "#i0"}),
                    json!({"name": "child-b", "parentId": "#i0"}),
                ],
                Vec::<(&str, &str)>::new(),
            )
            .await;
        let ids = (0..3)
            .map(|idx| response.created(idx).id().to_string())
            .collect::<Vec<_>>();
        let requested = order
            .iter()
            .map(|idx| ids[*idx].as_str())
            .collect::<Vec<_>>();
        let destroyed = account
            .jmap_destroy(
                MethodObject::FileNode,
                requested,
                Vec::<(&str, &str)>::new(),
            )
            .await;
        assert_eq!(
            destroyed.destroyed().collect::<AHashSet<_>>(),
            ids.iter().map(String::as_str).collect::<AHashSet<_>>()
        );
    }

    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "same.txt", "blobId": &blob_id})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let old_id = response.created(0).id().to_string();
    let response = account
        .jmap_method_calls(json!([[
            "FileNode/set",
            {
                "accountId": account.id_string(),
                "create": {"new": {"name": "same.txt", "blobId": &blob_id}},
                "destroy": [&old_id]
            },
            "0"
        ]]))
        .await;
    let new_id = response
        .pointer("/methodResponses/0/1/created/new")
        .expect("create must succeed")
        .id()
        .to_string();
    assert_eq!(
        response
            .pointer("/methodResponses/0/1/destroyed/0")
            .and_then(Value::as_str),
        Some(old_id.as_str())
    );

    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "a.txt", "blobId": &blob_id})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let a_id = response.created(0).id().to_string();
    let response = account
        .jmap_update(
            MethodObject::FileNode,
            [
                (&a_id, json!({"name": "same.txt"})),
                (&new_id, json!({"name": "a.txt"})),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.updated(&a_id);
    response.updated(&new_id);
    assert_eq!(
        get_node(account, &a_id).await.text_field("name"),
        "same.txt"
    );
    assert_eq!(get_node(account, &new_id).await.text_field("name"), "a.txt");

    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&file_id, &trash_id, &link_id, &a_id, &new_id],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);
    test.assert_is_empty().await;
}

pub(super) async fn upload_blob(account: &Account, contents: &str) -> String {
    account
        .jmap_method_calls(json!([[
            "Blob/upload",
            {
                "accountId": account.id_string(),
                "create": {"b": {"data": [{"data:asText": contents}]}}
            },
            "0"
        ]]))
        .await
        .pointer("/methodResponses/0/1/created/b/id")
        .and_then(Value::as_str)
        .expect("blob upload")
        .to_string()
}

pub(super) async fn get_node(account: &Account, id: &str) -> Value {
    account
        .jmap_method_calls(json!([[
            "FileNode/get",
            {"accountId": account.id_string(), "ids": [id]},
            "0"
        ]]))
        .await
        .pointer("/methodResponses/0/1/list/0")
        .cloned()
        .unwrap_or_else(|| panic!("FileNode {id} not found"))
}

pub(super) async fn destroy_tree(account: &Account, id: &str) {
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [id],
            [("onDestroyRemoveChildren", true)],
        )
        .await
        .destroyed()
        .for_each(drop);
}
