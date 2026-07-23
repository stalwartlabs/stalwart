/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    jmap::{ChangeType, JmapUtils},
    server::TestServer,
};
use ahash::AHashSet;
use jmap_proto::{object::file_node::FileNodeProperty, request::method::MethodObject};
use serde_json::json;

pub async fn test(test: &TestServer) {
    println!("Running File Storage tests...");
    let account = test.account("jdoe@example.com");

    // Obtain change id
    let change_id = account
        .jmap_get(
            MethodObject::FileNode,
            [FileNodeProperty::Id],
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();

    // Create test folders
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({
                    "name": "Root Folder",
                    "parentId": null,
                }),
                json!({
                    "name": "Sub Folder",
                    "parentId": "#i0",
                }),
                json!({
                    "name": "Sub-sub Folder",
                    "parentId": "#i1",
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let root_folder_id = response.created(0).id().to_string();
    let sub_folder_id = response.created(1).id().to_string();
    let sub_sub_folder_id = response.created(2).id().to_string();

    // Validate changes
    assert_eq!(
        account
            .jmap_changes(MethodObject::FileNode, change_id)
            .await
            .changes()
            .collect::<AHashSet<_>>(),
        [
            ChangeType::Created(&root_folder_id),
            ChangeType::Created(&sub_folder_id),
            ChangeType::Created(&sub_sub_folder_id)
        ]
        .into_iter()
        .collect::<AHashSet<_>>()
    );

    // Verify folder structure
    let response = account
        .jmap_get(
            MethodObject::FileNode,
            [
                FileNodeProperty::Id,
                FileNodeProperty::Name,
                FileNodeProperty::ParentId,
            ],
            [&root_folder_id, &sub_folder_id, &sub_sub_folder_id],
        )
        .await;
    let list = response.list();
    assert_eq!(list.len(), 3);
    list[0].assert_is_equal(json!({
        "id": &root_folder_id,
        "name": "Root Folder",
        "parentId": null,
    }));
    list[1].assert_is_equal(json!({
        "id": &sub_folder_id,
        "name": "Sub Folder",
        "parentId": &root_folder_id,
    }));
    list[2].assert_is_equal(json!({
        "id": &sub_sub_folder_id,
        "name": "Sub-sub Folder",
        "parentId": &sub_folder_id,
    }));

    // Create file in root folder
    let response = account
        .jmap_method_calls(json!([
         [
          "Blob/upload",
          {
           "accountId": account.id_string(),
           "create": {
            "hello": {
             "data": [
              {
               "data:asText": r#"hello world"#
              }
            ]
           }
          }
         },
         "S4"
        ],
        [
          "FileNode/set",
          {
            "accountId": account.id_string(),
            "create": {
              "i0": {
                "name": "hello.txt",
                "parentId": &root_folder_id,
                "blobId": "#hello",
                "type": "text/plain",
              }
            }
          },
          "G4"
         ]
        ]))
        .await;
    let file_id = response
        .pointer("/methodResponses/1/1/created/i0")
        .unwrap()
        .id()
        .to_string();

    // Verify file creation
    let response = account
        .jmap_get(
            MethodObject::FileNode,
            [
                FileNodeProperty::Id,
                FileNodeProperty::BlobId,
                FileNodeProperty::Name,
                FileNodeProperty::ParentId,
                FileNodeProperty::Type,
                FileNodeProperty::Size,
            ],
            [&file_id],
        )
        .await;
    let blob_id = response.list()[0].blob_id().to_string();
    response.list()[0].assert_is_equal(json!({
        "id": &file_id,
        "name": "hello.txt",
        "parentId": &root_folder_id,
        "type": "text/plain",
        "size": 11,
        "blobId": &blob_id,
    }));
    assert_eq!(
        account
            .jmap_get(MethodObject::Blob, ["data:asText"], [&blob_id])
            .await
            .list()[0]
            .text_field("data:asText"),
        "hello world"
    );

    // Creating folders with invalid names or parent ids should fail
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({
                    "name": "Sub Folder",
                    "parentId": &root_folder_id,
                }),
                json!({
                    "name": "Folder under file",
                    "parentId": &file_id,
                }),
                json!({
                    "name": "My/Sub/Folder",
                }),
                json!({
                    "name": ".",
                }),
                json!({
                    "name": "..",
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let err = response.not_created(0);
    assert_eq!(err.typ(), "alreadyExists");
    assert_eq!(err.text_field("existingId"), sub_folder_id.as_str());
    assert_eq!(
        response.not_created(1).description(),
        "Parent ID does not exist or is not a folder."
    );
    assert_eq!(
        response.not_created(2).description(),
        "Name contains a forbidden character."
    );
    assert_eq!(
        response.not_created(3).description(),
        "Name is reserved and cannot be used."
    );
    assert_eq!(
        response.not_created(4).description(),
        "Name is reserved and cannot be used."
    );

    // Circular folder references should fail
    let response = account
        .jmap_update(
            MethodObject::FileNode,
            [(
                &root_folder_id,
                json!({
                    "parentId": &sub_sub_folder_id,
                }),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(
        response.not_updated(&root_folder_id).description(),
        "Circular reference in parent ids."
    );

    // Rename folder and file
    let response = account
        .jmap_update(
            MethodObject::FileNode,
            [
                (
                    &sub_folder_id,
                    json!({
                        "name": "Renamed Sub Folder",
                    }),
                ),
                (
                    &file_id,
                    json!({
                        "name": "renamed-hello.txt",
                    }),
                ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.updated(&sub_folder_id);
    response.updated(&file_id);

    // Verify rename
    let response = account
        .jmap_get(
            MethodObject::FileNode,
            [
                FileNodeProperty::Id,
                FileNodeProperty::Name,
                FileNodeProperty::ParentId,
            ],
            [&sub_folder_id, &file_id],
        )
        .await;
    let list = response.list();
    assert_eq!(list.len(), 2);
    list[0].assert_is_equal(json!({
        "id": &sub_folder_id,
        "name": "Renamed Sub Folder",
        "parentId": &root_folder_id,
    }));
    list[1].assert_is_equal(json!({
        "id": &file_id,
        "name": "renamed-hello.txt",
        "parentId": &root_folder_id,
    }));

    // Destroying a folder with children should fail
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::FileNode,
                [&root_folder_id],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .not_destroyed(&root_folder_id)
            .description(),
        "Cannot delete non-empty folder."
    );

    // Delete file and sub folders
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::FileNode,
                [&file_id],
                [("onDestroyRemoveChildren", true)],
            )
            .await
            .destroyed()
            .collect::<AHashSet<_>>(),
        [file_id.as_str(),].into_iter().collect::<AHashSet<_>>()
    );
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::FileNode,
                [&root_folder_id],
                [("onDestroyRemoveChildren", true)],
            )
            .await
            .destroyed()
            .collect::<AHashSet<_>>(),
        [
            sub_sub_folder_id.as_str(),
            sub_folder_id.as_str(),
            root_folder_id.as_str()
        ]
        .into_iter()
        .collect::<AHashSet<_>>()
    );

    // fetchParents: requesting a leaf should return its ancestors too
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "fp-root"}),
                json!({"name": "fp-sub", "parentId": "#i0"}),
                json!({"name": "fp-leaf", "parentId": "#i1"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let fp_root = response.created(0).id().to_string();
    let fp_sub = response.created(1).id().to_string();
    let fp_leaf = response.created(2).id().to_string();
    let response = account
        .jmap_method_calls(json!([[
            "FileNode/get",
            {
                "accountId": account.id_string(),
                "ids": [&fp_leaf],
                "fetchParents": true,
                "properties": ["id"]
            },
            "0"
        ]]))
        .await;
    let ids = response
        .pointer("/methodResponses/0/1/list")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .map(|n| n.text_field("id").to_string())
                .collect::<AHashSet<_>>()
        })
        .expect("fetchParents response");
    assert_eq!(
        ids,
        [fp_leaf.as_str(), fp_sub.as_str(), fp_root.as_str()]
            .into_iter()
            .map(str::to_string)
            .collect::<AHashSet<_>>()
    );
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&fp_root],
            [("onDestroyRemoveChildren", true)],
        )
        .await
        .destroyed()
        .for_each(drop);

    // onExists=rename should produce a unique sibling name
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "dupe.txt", "parentId": null, "blobId": null})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let dupe_orig = response.created(0).id().to_string();
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "dupe.txt"})],
            [("onExists", "rename")],
        )
        .await;
    let dupe_renamed = response.created(0);
    let dupe_renamed_id = dupe_renamed.id().to_string();
    assert_eq!(dupe_renamed.text_field("name"), "dupe (2).txt");

    // onExists=reject (default) should return alreadyExists with existingId
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "dupe.txt"})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let err = response.not_created(0);
    assert_eq!(err.typ(), "alreadyExists");
    assert_eq!(err.text_field("existingId"), dupe_orig.as_str());

    // onExists=replace should destroy the existing sibling
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "dupe.txt"})],
            [("onExists", "replace")],
        )
        .await;
    let dupe_replacement = response.created(0).id().to_string();
    let destroyed = response.destroyed().collect::<AHashSet<_>>();
    assert!(
        destroyed.contains(dupe_orig.as_str()),
        "Expected old id {dupe_orig} to be destroyed, got {destroyed:?}"
    );
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&dupe_renamed_id, &dupe_replacement],
            [("onDestroyRemoveChildren", true)],
        )
        .await
        .destroyed()
        .for_each(drop);

    // compareCaseInsensitively should treat sibling names as case-insensitive
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "CASE"})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let case_id = response.created(0).id().to_string();
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "case"})],
            [("compareCaseInsensitively", true)],
        )
        .await;
    let err = response.not_created(0);
    assert_eq!(err.typ(), "alreadyExists");
    assert_eq!(err.text_field("existingId"), case_id.as_str());
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&case_id],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);

    // Pending+Reject: two creates with the same name in one batch, default onExists
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "twin-reject"}),
                json!({"name": "twin-reject"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let twin_first = response.created(0).id().to_string();
    let err = response.not_created(1);
    assert_eq!(err.typ(), "alreadyExists");
    assert!(
        err.pointer("/existingId").is_none(),
        "Pending Create collision has no committed existingId, got {err:?}"
    );
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&twin_first],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);

    // Pending+Rename: second create within the batch should auto-rename
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "twin-rename"}),
                json!({"name": "twin-rename"}),
            ],
            [("onExists", "rename")],
        )
        .await;
    let twin_a = response.created(0).id().to_string();
    let twin_b_entry = response.created(1);
    let twin_b = twin_b_entry.id().to_string();
    assert_eq!(twin_b_entry.text_field("name"), "twin-rename (2)");
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&twin_a, &twin_b],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);

    // Pending+Replace: within-batch replace is intentionally not supported; second is rejected
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "twin-replace"}),
                json!({"name": "twin-replace"}),
            ],
            [("onExists", "replace")],
        )
        .await;
    let twin_survivor = response.created(0).id().to_string();
    let err = response.not_created(1);
    assert_eq!(err.typ(), "alreadyExists");
    assert!(
        err.pointer("/existingId").is_none(),
        "Pending Create + Replace returns alreadyExists with no existingId, got {err:?}"
    );
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&twin_survivor],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);

    // Pending+Newest: in-batch newest comparison is intentionally not supported; second is rejected
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "twin-newest", "modified": "2020-01-01T00:00:00Z"}),
                json!({"name": "twin-newest", "modified": "2040-01-01T00:00:00Z"}),
            ],
            [("onExists", "newest")],
        )
        .await;
    let twin_keep = response.created(0).id().to_string();
    let err = response.not_created(1);
    assert_eq!(err.typ(), "alreadyExists");
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&twin_keep],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);

    // Create+Update collision in one batch
    let setup = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "lhs"})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let lhs_id = setup.created(0).id().to_string();
    let response = account
        .jmap_method_calls(json!([[
            "FileNode/set",
            {
                "accountId": account.id_string(),
                "update": { &lhs_id: { "name": "merged" } },
                "create": { "new1": { "name": "merged" } }
            },
            "0"
        ]]))
        .await;
    let created_new = response
        .pointer("/methodResponses/0/1/created/new1")
        .expect("new1 should be in created");
    let new1_id = created_new.id().to_string();
    let upd_err = response
        .pointer(&format!("/methodResponses/0/1/notUpdated/{lhs_id}"))
        .expect("update should fail");
    assert_eq!(upd_err.typ(), "alreadyExists");
    assert!(
        upd_err.pointer("/existingId").is_none(),
        "Pending-from-Create collision has no existingId, got {upd_err:?}"
    );
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&lhs_id, &new1_id],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);

    // compareCaseInsensitively + Pending: in-batch "FOO"/"foo" collide when the flag is set
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "FOO"}), json!({"name": "foo"})],
            [("compareCaseInsensitively", true)],
        )
        .await;
    let case_keep = response.created(0).id().to_string();
    assert_eq!(response.not_created(1).typ(), "alreadyExists");
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&case_keep],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);

    // onExists=newest: incoming must have a strictly later modified to win
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "stamped", "modified": "2030-01-01T00:00:00Z"})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let stamped_id = response.created(0).id().to_string();
    let older_attempt = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "stamped", "modified": "2020-01-01T00:00:00Z"})],
            [("onExists", "newest")],
        )
        .await;
    let err = older_attempt.not_created(0);
    assert_eq!(err.typ(), "alreadyExists");
    assert_eq!(err.text_field("existingId"), stamped_id.as_str());
    let newer_attempt = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "stamped", "modified": "2040-01-01T00:00:00Z"})],
            [("onExists", "newest")],
        )
        .await;
    let stamped_winner = newer_attempt.created(0).id().to_string();
    assert_ne!(stamped_winner, stamped_id);
    let destroyed = newer_attempt.destroyed().collect::<AHashSet<_>>();
    assert!(
        destroyed.contains(stamped_id.as_str()),
        "Expected {stamped_id} to be destroyed by newer onExists=newest, got {destroyed:?}"
    );
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [&stamped_winner],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);

    // Make sure everything is gone
    test.assert_is_empty().await;
}
