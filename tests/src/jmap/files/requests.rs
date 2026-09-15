/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::properties::{destroy_tree, get_node, upload_blob};
use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running File Storage in-request ordering tests...");
    let account = test.account("jdoe@example.com");
    let blob_id = upload_blob(account, "request content").await;

    cycles(account).await;
    depth(account).await;
    replace_conflicts(account, &blob_id).await;
    vacated_names(account).await;
    newest_without_modified(account, &blob_id).await;
    server_set_values(account, &blob_id).await;
    move_out_then_destroy(account).await;

    test.assert_is_empty().await;
}

async fn cycles(account: &Account) {
    let [a, b] = create_roots(account, ["cycle-a", "cycle-b"]).await;
    let response = set(
        account,
        json!({"update": {&a: {"parentId": &b}, &b: {"parentId": &a}}}),
    )
    .await;
    let updated = [&a, &b]
        .into_iter()
        .filter(|id| response.pointer(&format!("/updated/{id}")).is_some())
        .count();
    assert_eq!(updated, 1, "{response}");
    let rejected = [&a, &b]
        .into_iter()
        .find_map(|id| response.pointer(&format!("/notUpdated/{id}")))
        .expect("one move must be rejected");
    assert_eq!(rejected["type"], json!("invalidProperties"));
    for id in [&a, &b] {
        let node = get_node(account, id).await;
        assert!(
            node["parentId"].is_null()
                || node["parentId"] == json!(&a)
                || node["parentId"] == json!(&b)
        );
    }
    let root = if get_node(account, &a).await["parentId"].is_null() {
        &a
    } else {
        &b
    };
    destroy_tree(account, root).await;
}

async fn depth(account: &Account) {
    for reverse in [false, true] {
        let deep = create_chain(account, "deep", 40).await;
        let tall = create_chain(account, "tall", 30).await;
        let [mover] = create_roots(account, ["mover"]).await;
        let deep_leaf = deep.last().expect("chain");
        let tall_root = tall.first().expect("chain");
        let mut updates = vec![
            (mover.clone(), json!({"parentId": deep_leaf})),
            (tall_root.clone(), json!({"parentId": &mover})),
        ];
        if reverse {
            updates.reverse();
        }
        let update = updates
            .into_iter()
            .collect::<serde_json::Map<String, Value>>();
        let response = set(account, json!({"update": update})).await;
        let rejected = [&mover, tall_root]
            .into_iter()
            .filter_map(|id| response.pointer(&format!("/notUpdated/{id}/description")))
            .collect::<Vec<_>>();
        assert_eq!(
            rejected,
            [&json!("Maximum folder depth exceeded.")],
            "{response}"
        );
        let mut roots = Vec::with_capacity(3);
        for root in [&deep[0], tall_root, &mover] {
            if get_node(account, root).await["parentId"].is_null() {
                roots.push(root);
            }
        }
        for root in roots {
            destroy_tree(account, root).await;
        }
    }
}

async fn replace_conflicts(account: &Account, blob_id: &str) {
    let [folder] = create_roots(account, ["replace-a"]).await;
    let response = set(
        account,
        json!({
            "create": {
                "child": {"name": "f", "parentId": &folder, "blobId": blob_id},
                "twin": {"name": "replace-a"}
            },
            "onExists": "replace"
        }),
    )
    .await;
    assert!(response.pointer("/created/child").is_some(), "{response}");
    assert_eq!(
        response.pointer("/notCreated/twin/type"),
        Some(&json!("alreadyExists")),
        "{response}"
    );
    assert_eq!(
        response.pointer("/notCreated/twin/existingId"),
        Some(&json!(&folder))
    );
    assert!(response.pointer("/destroyed").is_none(), "{response}");
    destroy_tree(account, &folder).await;

    let [folder, moved, claimant] =
        create_roots(account, ["replace-b", "replace-moved", "replace-claimant"]).await;
    let response = set(
        account,
        json!({
            "update": {
                &moved: {"parentId": &folder},
                &claimant: {"name": "replace-b"}
            },
            "onExists": "replace"
        }),
    )
    .await;
    assert!(
        response.pointer(&format!("/updated/{moved}")).is_some(),
        "{response}"
    );
    assert_eq!(
        response.pointer(&format!("/notUpdated/{claimant}/type")),
        Some(&json!("alreadyExists")),
        "{response}"
    );
    assert_eq!(get_node(account, &moved).await["parentId"], json!(&folder));
    destroy_tree(account, &folder).await;
    destroy_tree(account, &claimant).await;

    let [holder, claimant] = create_roots(account, ["replace-c", "replace-d"]).await;
    let response = set(
        account,
        json!({
            "update": {
                &holder: {"modified": "2024-01-01T00:00:00Z"},
                &claimant: {"name": "replace-c"}
            },
            "onExists": "replace"
        }),
    )
    .await;
    assert!(
        response.pointer(&format!("/updated/{holder}")).is_some(),
        "{response}"
    );
    assert_eq!(
        response.pointer(&format!("/notUpdated/{claimant}/type")),
        Some(&json!("alreadyExists")),
        "{response}"
    );
    destroy_tree(account, &holder).await;
    destroy_tree(account, &claimant).await;
}

async fn vacated_names(account: &Account) {
    let [holder] = create_roots(account, ["vacate"]).await;
    let response = set(
        account,
        json!({
            "create": {"new": {"name": "vacate"}},
            "update": {&holder: {"name": "vacated"}}
        }),
    )
    .await;
    let created = response
        .pointer("/created/new/id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("create must succeed: {response}"))
        .to_string();
    assert!(
        response.pointer(&format!("/updated/{holder}")).is_some(),
        "{response}"
    );
    destroy_tree(account, &created).await;
    destroy_tree(account, &holder).await;

    let [p, q, r] = create_roots(account, ["swap-p", "swap-q", "swap-r"]).await;
    let response = set(
        account,
        json!({
            "update": {
                &p: {"name": "swap-q"},
                &q: {"name": "swap-p"},
                &r: {"name": "swap-p"}
            }
        }),
    )
    .await;
    assert!(
        response.pointer(&format!("/updated/{p}")).is_some(),
        "{response}"
    );
    assert!(
        response.pointer(&format!("/updated/{q}")).is_some(),
        "{response}"
    );
    assert_eq!(
        response.pointer(&format!("/notUpdated/{r}/type")),
        Some(&json!("alreadyExists")),
        "{response}"
    );
    assert_eq!(get_node(account, &p).await["name"], json!("swap-q"));
    assert_eq!(get_node(account, &q).await["name"], json!("swap-p"));
    for id in [&p, &q, &r] {
        destroy_tree(account, id).await;
    }
}

async fn newest_without_modified(account: &Account, blob_id: &str) {
    let response = set(
        account,
        json!({"create": {"old": {"name": "newest.txt", "blobId": blob_id, "modified": "2001-01-01T00:00:00Z"}}}),
    )
    .await;
    let old_id = response
        .pointer("/created/old/id")
        .and_then(Value::as_str)
        .expect("create")
        .to_string();
    let response = set(
        account,
        json!({
            "create": {"new": {"name": "newest.txt", "blobId": blob_id}},
            "onExists": "newest"
        }),
    )
    .await;
    let new_id = response
        .pointer("/created/new/id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("newest must replace the older node: {response}"))
        .to_string();
    assert_eq!(response.pointer("/destroyed/0"), Some(&json!(&old_id)));
    destroy_tree(account, &new_id).await;
}

async fn server_set_values(account: &Account, blob_id: &str) {
    let response = set(
        account,
        json!({"create": {"file": {"name": "server-set.txt", "blobId": blob_id}}}),
    )
    .await;
    let created = response.pointer("/created/file").expect("create");
    for property in [
        "id",
        "size",
        "type",
        "nodeType",
        "executable",
        "created",
        "modified",
        "accessed",
        "changed",
        "isSubscribed",
        "myRights",
    ] {
        assert!(
            created.get(property).is_some(),
            "{property} missing from {created}"
        );
    }
    assert_eq!(created["size"], json!(15));
    assert_eq!(created["type"], json!("application/octet-stream"));
    assert!(created.get("name").is_none());
    let file_id = created["id"].as_str().expect("id").to_string();

    let other_blob = upload_blob(account, "longer request content").await;
    let response = set(
        account,
        json!({"update": {&file_id: {"blobId": &other_blob}}}),
    )
    .await;
    let updated = response
        .pointer(&format!("/updated/{file_id}"))
        .expect("update");
    assert_eq!(updated["size"], json!(22));
    assert!(updated.get("changed").is_some(), "{updated}");

    let node = get_node(account, &file_id).await;
    let response = set(
        account,
        json!({"update": {&file_id: {
            "modified": null,
            "type": "Text/Plain",
            "changed": node["changed"],
            "myRights": node["myRights"],
        }}}),
    )
    .await;
    let updated = response
        .pointer(&format!("/updated/{file_id}"))
        .unwrap_or_else(|| panic!("{response}"));
    assert!(updated.get("modified").is_some(), "{updated}");
    assert_eq!(updated["type"], json!("text/plain"));
    let response = set(
        account,
        json!({"update": {&file_id: {"changed": "2001-01-01T00:00:00Z"}}}),
    )
    .await;
    assert_eq!(
        response.pointer(&format!("/notUpdated/{file_id}/type")),
        Some(&json!("invalidProperties")),
        "{response}"
    );
    destroy_tree(account, &file_id).await;
}

async fn move_out_then_destroy(account: &Account) {
    let [parent, other] = create_roots(account, ["emptied", "receiver"]).await;
    let child = set(
        account,
        json!({"create": {"child": {"name": "child", "parentId": &parent}}}),
    )
    .await
    .pointer("/created/child/id")
    .and_then(Value::as_str)
    .expect("child")
    .to_string();
    let response = set(
        account,
        json!({"update": {&child: {"parentId": &other}}, "destroy": [&parent]}),
    )
    .await;
    assert!(
        response.pointer(&format!("/updated/{child}")).is_some(),
        "{response}"
    );
    assert_eq!(response["destroyed"], json!([&parent]), "{response}");

    let [kept] = create_roots(account, ["kept"]).await;
    let response = set(
        account,
        json!({"create": {"c": {"name": "c", "parentId": &kept}}}),
    )
    .await;
    let kept_child = response
        .pointer("/created/c/id")
        .and_then(Value::as_str)
        .expect("child")
        .to_string();
    let response = set(
        account,
        json!({"update": {&kept_child: {"parentId": &kept, "name": "../bad"}}, "destroy": [&kept]}),
    )
    .await;
    assert_eq!(
        response.pointer(&format!("/notDestroyed/{kept}/type")),
        Some(&json!("nodeHasChildren")),
        "{response}"
    );
    destroy_tree(account, &kept).await;
    destroy_tree(account, &other).await;
}

async fn set(account: &Account, mut arguments: Value) -> Value {
    arguments["accountId"] = json!(account.id_string());
    let response = account
        .jmap_method_calls(json!([["FileNode/set", arguments, "0"]]))
        .await;
    assert_eq!(response.name_at(0), "FileNode/set", "{:?}", response);
    response
        .pointer("/methodResponses/0/1")
        .cloned()
        .expect("set response")
}

async fn create_roots<const N: usize>(account: &Account, names: [&str; N]) -> [String; N] {
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            names.map(|name| json!({"name": name})),
            Vec::<(&str, &str)>::new(),
        )
        .await;
    std::array::from_fn(|idx| response.created(idx as u32).id().to_string())
}

async fn create_chain(account: &Account, prefix: &str, length: usize) -> Vec<String> {
    let chain = (0..length)
        .map(|depth| match depth {
            0 => json!({"name": format!("{prefix}0")}),
            depth => {
                json!({"name": format!("{prefix}{depth}"), "parentId": format!("#i{}", depth - 1)})
            }
        })
        .collect::<Vec<_>>();
    let response = account
        .jmap_create(MethodObject::FileNode, chain, Vec::<(&str, &str)>::new())
        .await;
    (0..length)
        .map(|idx| response.created(idx as u32).id().to_string())
        .collect()
}
