/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::properties::{destroy_tree, get_node, upload_blob};
use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use ahash::AHashMap;
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running File Storage query tests...");
    let account = test.account("jdoe@example.com");
    let blob_a = upload_blob(account, "aaa").await;
    let blob_b = upload_blob(account, "bbbbb").await;
    let blob_c = upload_blob(account, "custom data").await;
    let blob_z = upload_blob(account, "hello world").await;

    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "Docs", "role": "documents", "modified": "2023-01-01T00:00:00Z"}),
                json!({"name": "a.txt", "parentId": "#i0", "blobId": &blob_a, "type": "text/plain",
                       "created": "2020-01-01T00:00:00Z", "modified": "2020-06-01T00:00:00Z"}),
                json!({"name": "b.md", "parentId": "#i0", "blobId": &blob_b, "type": "text/markdown",
                       "executable": true, "modified": "2022-01-01T00:00:00Z"}),
                json!({"name": "sub", "parentId": "#i0", "modified": "2023-01-01T00:00:00Z"}),
                json!({"name": "c.bin", "parentId": "#i3", "blobId": &blob_c,
                       "type": "application/x-stalwart-custom", "modified": "2023-01-01T00:00:00Z"}),
                json!({"name": "z.txt", "blobId": &blob_z, "type": "text/plain",
                       "modified": "2024-01-01T00:00:00Z"}),
                json!({"name": "link", "target": ["Docs", "a.txt"], "modified": "2023-01-01T00:00:00Z"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let names = ["Docs", "a.txt", "b.md", "sub", "c.bin", "z.txt", "link"];
    let ids = names
        .iter()
        .enumerate()
        .map(|(idx, name)| (response.created(idx as u32).id().to_string(), *name))
        .collect::<AHashMap<_, _>>();
    let id_of = |name: &str| {
        ids.iter()
            .find(|(_, n)| **n == name)
            .map(|(id, _)| id.clone())
            .expect("known name")
    };
    let c_blob_id = get_node(account, &id_of("c.bin")).await["blobId"]
        .as_str()
        .expect("blob id")
        .to_string();

    for (filter, expected) in [
        (json!({"nodeType": "symlink"}), vec!["link"]),
        (json!({"nodeType": "directory"}), vec!["Docs", "sub"]),
        (json!({"role": "documents"}), vec!["Docs"]),
        (json!({"role": "trash"}), vec![]),
        (json!({"hasAnyRole": true}), vec!["Docs"]),
        (json!({"isExecutable": true}), vec!["b.md"]),
        (json!({"minSize": 5}), vec!["b.md", "c.bin", "z.txt"]),
        (json!({"maxSize": 5}), vec!["a.txt"]),
        (
            json!({"createdBefore": "2021-01-01T00:00:00Z"}),
            vec!["a.txt"],
        ),
        (
            json!({"modifiedBefore": "2022-06-01T00:00:00Z"}),
            vec!["a.txt", "b.md"],
        ),
        (
            json!({"modifiedAfter": "2024-01-01T00:00:00Z"}),
            vec!["z.txt"],
        ),
        (json!({"name": "a.txt"}), vec!["a.txt"]),
        (json!({"nameMatch": "*.TXT"}), vec!["a.txt", "z.txt"]),
        (json!({"type": "text/plain"}), vec!["a.txt", "z.txt"]),
        (json!({"type": "Text/Plain"}), vec![]),
        (
            json!({"typeMatch": "text/*"}),
            vec!["a.txt", "b.md", "z.txt"],
        ),
        (
            json!({"typeMatch": "application/x-stalwart-*"}),
            vec!["c.bin"],
        ),
        (json!({"text": "*.md"}), vec!["b.md"]),
        (json!({"blobId": &c_blob_id}), vec!["c.bin"]),
        (
            json!({"parentId": id_of("Docs")}),
            vec!["a.txt", "b.md", "sub"],
        ),
        (
            json!({"ancestorId": id_of("Docs")}),
            vec!["a.txt", "b.md", "sub", "c.bin"],
        ),
        (json!({"descendantId": id_of("c.bin")}), vec!["Docs", "sub"]),
        (json!({"isTopLevel": true}), vec!["Docs", "z.txt", "link"]),
    ] {
        let mut found = query(account, filter.clone(), json!([]), None).await;
        let mut expected = expected.into_iter().map(id_of).collect::<Vec<_>>();
        found.sort();
        expected.sort();
        assert_eq!(found, expected, "filter {filter}");
    }

    let mut found = query(
        account,
        json!({"parentId": id_of("Docs")}),
        json!([]),
        Some(1),
    )
    .await;
    let mut expected = ["a.txt", "b.md", "sub", "c.bin"].map(id_of).to_vec();
    found.sort();
    expected.sort();
    assert_eq!(found, expected, "parentId with depth 1");

    for (sort, expected) in [
        (
            json!([{"property": "tree"}]),
            vec!["Docs", "a.txt", "b.md", "sub", "c.bin", "link", "z.txt"],
        ),
        (
            json!([{"property": "nodeType"}, {"property": "name"}]),
            vec!["Docs", "sub", "link", "a.txt", "b.md", "c.bin", "z.txt"],
        ),
        (
            json!([{"property": "size", "isAscending": false}, {"property": "name"}]),
            vec!["c.bin", "z.txt", "b.md", "a.txt", "Docs", "link", "sub"],
        ),
        (
            json!([{"property": "modified"}, {"property": "name"}]),
            vec!["a.txt", "b.md", "c.bin", "Docs", "link", "sub", "z.txt"],
        ),
        (
            json!([{"property": "type"}, {"property": "name"}]),
            vec!["Docs", "sub", "link", "c.bin", "b.md", "a.txt", "z.txt"],
        ),
    ] {
        let found = query(account, json!({}), sort.clone(), None).await;
        let expected = expected.into_iter().map(id_of).collect::<Vec<_>>();
        let found_names = found.iter().map(|id| ids[id]).collect::<Vec<_>>();
        assert_eq!(found, expected, "sort {sort}: got {found_names:?}");
    }

    let response = account
        .jmap_method_calls(json!([[
            "FileNode/query",
            {"accountId": account.id_string(), "filter": {"nodeType": "socket"}},
            "0"
        ]]))
        .await;
    assert_eq!(response.error_type_at(0), Some("unsupportedFilter"));

    let response = account
        .jmap_method_calls(json!([[
            "FileNode/query",
            {"accountId": account.id_string(), "sort": [{"property": "name", "collation": "i;bogus"}]},
            "0"
        ]]))
        .await;
    assert_eq!(response.error_type_at(0), Some("unsupportedSort"));

    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "treecase"}),
                json!({"name": "a", "parentId": "#i0"}),
                json!({"name": "A", "parentId": "#i0"}),
                json!({"name": "y", "parentId": "#i1"}),
                json!({"name": "z", "parentId": "#i2"}),
                json!({"name": "x", "parentId": "#i2"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let [tree_root, lower, upper, y, z, x] =
        [0, 1, 2, 3, 4, 5].map(|idx| response.created(idx).id().to_string());
    assert_eq!(
        query(
            account,
            json!({"ancestorId": &tree_root}),
            json!([{"property": "tree"}]),
            None
        )
        .await,
        vec![upper, x, z, lower, y]
    );
    destroy_tree(account, &tree_root).await;

    destroy_tree(account, &id_of("Docs")).await;
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [id_of("z.txt"), id_of("link")],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);
    test.assert_is_empty().await;
}

async fn query(account: &Account, filter: Value, sort: Value, depth: Option<u32>) -> Vec<String> {
    let mut arguments = json!({
        "accountId": account.id_string(),
        "filter": filter,
        "sort": sort,
    });
    if let Some(depth) = depth {
        arguments["depth"] = json!(depth);
    }
    let description = arguments.to_string();
    account
        .jmap_method_calls(json!([["FileNode/query", arguments, "0"]]))
        .await
        .pointer("/methodResponses/0/1/ids")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("query failed for {description}"))
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}
