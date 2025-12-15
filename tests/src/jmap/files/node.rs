/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{ChangeType, JMAPTest, JmapUtils};
use ahash::AHashSet;
use jmap_proto::{object::file_node::FileNodeProperty, request::method::MethodObject};
use serde_json::json;

pub async fn test(params: &mut JMAPTest) {
    println!("Running File Storage tests...");
    let account = params.account("jdoe@example.com");

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
    assert_eq!(
        response.not_created(0).description(),
        "A node with the same name already exists in this folder."
    );
    assert_eq!(
        response.not_created(1).description(),
        "Parent ID does not exist or is not a folder."
    );
    assert_eq!(
        response.not_created(2).description(),
        "Field could not be set."
    );
    assert_eq!(
        response.not_created(3).description(),
        "Field could not be set."
    );
    assert_eq!(
        response.not_created(4).description(),
        "Field could not be set."
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

    // Make sure everything is gone
    params.assert_is_empty().await;
}
