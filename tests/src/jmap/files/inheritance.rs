/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::properties::{destroy_tree, upload_blob};
use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use ahash::AHashSet;
use jmap_proto::request::method::MethodObject;
use registry::schema::prelude::ObjectType;
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running File Storage ACL inheritance tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let jane_id = jane.id_string().to_string();
    let blob_id = upload_blob(john, "shared content").await;

    let response = john
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "shared"}),
                json!({"name": "sub", "parentId": "#i0"}),
                json!({"name": "deep.txt", "parentId": "#i1", "blobId": &blob_id}),
                json!({"name": "private"}),
                json!({"name": "inner", "parentId": "#i3"}),
                json!({"name": "leaf", "parentId": "#i4"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let [shared, sub, deep, private, inner, leaf] =
        [0, 1, 2, 3, 4, 5].map(|idx| response.created(idx).id().to_string());

    let state = john_state(john).await;

    john.jmap_update(
        MethodObject::FileNode,
        [(&shared, json!({"shareWith": {&jane_id: {"mayRead": true}}}))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&shared);

    let changes = jane
        .jmap_method_calls(json!([[
            "FileNode/changes",
            {"accountId": john.id_string(), "sinceState": state},
            "0"
        ]]))
        .await;
    let changed = ["created", "updated"]
        .iter()
        .flat_map(|kind| {
            changes
                .pointer(&format!("/methodResponses/0/1/{kind}"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
        })
        .collect::<AHashSet<_>>();
    for id in [&shared, &sub, &deep] {
        assert!(
            changed.contains(id),
            "{id} missing from changes {changed:?}"
        );
    }

    let node = jane_get(jane, john, &deep).await;
    assert_eq!(node["myRights"]["mayRead"], json!(true));
    assert_eq!(node["myRights"]["mayAddChildren"], json!(false));
    assert_eq!(
        jane_query(jane, john).await,
        [&shared, &sub, &deep]
            .map(String::clone)
            .into_iter()
            .collect()
    );

    for filter in [
        json!({"descendantId": &leaf}),
        json!({"parentId": &private}),
        json!({"ancestorId": &private}),
    ] {
        let response = jane
            .jmap_method_calls(json!([[
                "FileNode/query",
                {"accountId": john.id_string(), "filter": filter},
                "0"
            ]]))
            .await;
        assert_eq!(
            response.pointer("/methodResponses/0/1/ids"),
            Some(&json!([])),
            "{filter}"
        );
    }
    let response = jane
        .jmap_method_calls(json!([[
            "FileNode/get",
            {"accountId": john.id_string(), "ids": [&leaf], "fetchParents": true},
            "0"
        ]]))
        .await;
    assert_eq!(
        response.pointer("/methodResponses/0/1/list"),
        Some(&json!([]))
    );

    john.jmap_update(
        MethodObject::FileNode,
        [(
            &leaf,
            json!({"shareWith": {&jane_id: {"mayRead": true, "mayAddChildren": true}}}),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&leaf);
    assert_eq!(
        jane_query(jane, john).await,
        [&shared, &sub, &deep, &private, &inner, &leaf]
            .map(String::clone)
            .into_iter()
            .collect()
    );
    let ancestor = jane_get(jane, john, &private).await;
    assert_eq!(ancestor["name"], json!("private"));
    assert_eq!(ancestor["nodeType"], json!("directory"));
    assert!(
        ancestor["myRights"]
            .as_object()
            .expect("myRights")
            .values()
            .all(|value| *value == json!(false)),
        "{ancestor}"
    );
    for property in ["shareWith", "created", "modified", "changed", "role"] {
        assert_eq!(ancestor[property], Value::Null, "{property}");
    }

    let response = jane
        .jmap_create_account(
            john,
            MethodObject::FileNode,
            [
                json!({"name": "denied", "parentId": &sub}),
                json!({"name": "allowed", "parentId": &leaf}),
                json!({"name": "top-level"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "forbidden");
    let allowed = response.created(1).id().to_string();
    assert_eq!(response.not_created(2).typ(), "forbidden");
    assert_eq!(
        jane_get(jane, john, &allowed).await["myRights"]["mayAddChildren"],
        json!(true)
    );

    let response = john
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "movable"}),
                json!({"name": "moved.txt", "parentId": "#i0", "blobId": &blob_id}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let [movable, moved_file] = [0, 1].map(|idx| response.created(idx).id().to_string());
    let state = john_state(john).await;
    john.jmap_update(
        MethodObject::FileNode,
        [(&movable, json!({"parentId": &sub}))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&movable);
    let changes = jane
        .jmap_method_calls(json!([[
            "FileNode/changes",
            {"accountId": john.id_string(), "sinceState": state},
            "0"
        ]]))
        .await;
    let changed = ["created", "updated"]
        .iter()
        .flat_map(|kind| {
            changes
                .pointer(&format!("/methodResponses/0/1/{kind}"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
        })
        .collect::<AHashSet<_>>();
    for id in [&movable, &moved_file] {
        assert!(changed.contains(id), "{id} missing from {changed:?}");
    }

    let state = john_state(john).await;
    assert!(
        john.jmap_destroy(
            MethodObject::FileNode,
            [moved_file.as_str()],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .any(|id| id == moved_file)
    );
    let changes = jane
        .jmap_method_calls(json!([[
            "FileNode/changes",
            {"accountId": john.id_string(), "sinceState": state},
            "0"
        ]]))
        .await;
    assert!(
        changes
            .pointer("/methodResponses/0/1/destroyed")
            .and_then(Value::as_array)
            .is_some_and(|destroyed| destroyed.iter().any(|id| id.as_str() == Some(&moved_file))),
        "{changes}"
    );

    group_rights(test, john, &blob_id).await;

    john.jmap_update(
        MethodObject::FileNode,
        [(&shared, json!({"shareWith": null}))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&shared);
    let response = jane
        .jmap_method_calls(json!([[
            "FileNode/get",
            {"accountId": john.id_string(), "ids": [&deep, &sub, &shared]},
            "0"
        ]]))
        .await;
    assert_eq!(
        response
            .pointer("/methodResponses/0/1/notFound")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        3
    );

    destroy_tree(john, &shared).await;
    destroy_tree(john, &private).await;
    test.assert_is_empty().await;
}

async fn group_rights(test: &TestServer, john: &Account, blob_id: &str) {
    let admin = test.account("admin@example.com");
    let robert = test.account("robert@example.com");
    let sales_id = test.account("sales@example.com").id();
    let sales = sales_id.to_string();
    let robert_id = robert.id_string().to_string();
    admin
        .registry_update_object(
            ObjectType::Account,
            robert.id(),
            json!({"memberGroupIds": {sales_id: true}}),
        )
        .await;

    let response = john
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "team", "shareWith": {&sales: {"mayRead": true, "mayAddChildren": true}}}),
                json!({"name": "reports", "parentId": "#i0", "shareWith": {&robert_id: {"mayShare": true}}}),
                json!({"name": "q1.txt", "parentId": "#i1", "blobId": blob_id}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let [team, reports, q1] = [0, 1, 2].map(|idx| response.created(idx).id().to_string());
    for id in [&reports, &q1] {
        let node = jane_get(robert, john, id).await;
        assert_eq!(node["myRights"]["mayRead"], json!(true), "{node}");
        assert_eq!(node["myRights"]["mayAddChildren"], json!(true), "{node}");
        assert_eq!(node["myRights"]["mayShare"], json!(true), "{node}");
    }

    admin
        .registry_update_object(
            ObjectType::Account,
            robert.id(),
            json!({"memberGroupIds": {sales_id: false}}),
        )
        .await;
    let response = robert
        .jmap_method_calls(json!([[
            "FileNode/get",
            {"accountId": john.id_string(), "ids": [&q1]},
            "0"
        ]]))
        .await;
    assert!(
        response.pointer("/methodResponses/0/1/list/0").is_none(),
        "{:?}",
        response
    );
    destroy_tree(john, &team).await;
}

async fn john_state(john: &Account) -> String {
    john.jmap_method_calls(json!([[
        "FileNode/get",
        {"accountId": john.id_string(), "ids": []},
        "0"
    ]]))
    .await
    .pointer("/methodResponses/0/1/state")
    .and_then(Value::as_str)
    .expect("state")
    .to_string()
}

async fn jane_get(jane: &Account, john: &Account, id: &str) -> Value {
    jane.jmap_method_calls(json!([[
        "FileNode/get",
        {"accountId": john.id_string(), "ids": [id]},
        "0"
    ]]))
    .await
    .pointer("/methodResponses/0/1/list/0")
    .cloned()
    .unwrap_or_else(|| panic!("{id} is not visible to the sharee"))
}

async fn jane_query(jane: &Account, john: &Account) -> AHashSet<String> {
    jane.jmap_method_calls(json!([[
        "FileNode/query",
        {"accountId": john.id_string()},
        "0"
    ]]))
    .await
    .pointer("/methodResponses/0/1/ids")
    .and_then(Value::as_array)
    .expect("query ids")
    .iter()
    .filter_map(Value::as_str)
    .map(str::to_string)
    .collect()
}
