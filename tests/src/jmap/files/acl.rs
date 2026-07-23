/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{jmap::JmapUtils, server::TestServer};
use jmap_proto::{
    object::{file_node::FileNodeProperty, share_notification::ShareNotificationProperty},
    request::method::MethodObject,
};
use serde_json::json;

pub async fn test(test: &TestServer) {
    println!("Running File Storage ACL tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();

    // Create test folders
    let response = john
        .jmap_create(
            MethodObject::FileNode,
            [json!({
                "name": "Test #1",
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let john_folder_id = response.created(0).id().to_string();

    // Verify myRights
    john.jmap_get(
        MethodObject::FileNode,
        [
            FileNodeProperty::Id,
            FileNodeProperty::Name,
            FileNodeProperty::MyRights,
            FileNodeProperty::ShareWith,
        ],
        [john_folder_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_folder_id,
        "name": "Test #1",
        "myRights": {
          "mayRead": true,
          "mayAddChildren": true,
          "mayRename": true,
          "mayDelete": true,
          "mayModifyContent": true,
          "mayShare": true
        },
        "shareWith": {}
        }));

    // Obtain share notifications
    let mut jane_share_change_id = jane
        .jmap_get(
            MethodObject::ShareNotification,
            Vec::<&str>::new(),
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();

    // Make sure Jane has no access
    assert_eq!(
        jane.jmap_get_account(
            john,
            MethodObject::FileNode,
            Vec::<&str>::new(),
            [john_folder_id.as_str()],
        )
        .await
        .method_response()
        .typ(),
        "forbidden"
    );

    // Share folder with Jane
    john.jmap_update(
        MethodObject::FileNode,
        [(
            &john_folder_id,
            json!({
                "shareWith": {
                   &jane_id : {
                     "mayRead": true,
                   }
                }
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_folder_id);
    john.jmap_get(
        MethodObject::FileNode,
        [
            FileNodeProperty::Id,
            FileNodeProperty::Name,
            FileNodeProperty::ShareWith,
        ],
        [john_folder_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_folder_id,
        "name": "Test #1",
        "shareWith": {
            &jane_id : {
                "mayRead": true,
                "mayAddChildren": false,
                "mayRename": false,
                "mayDelete": false,
                "mayModifyContent": false,
                "mayShare": false
            }
        }
        }));

    // Verify Jane can access the contact
    jane.jmap_get_account(
        john,
        MethodObject::FileNode,
        [
            FileNodeProperty::Id,
            FileNodeProperty::Name,
            FileNodeProperty::MyRights,
        ],
        [john_folder_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_folder_id,
        "name": "Test #1",
        "myRights": {
            "mayRead": true,
            "mayAddChildren": false,
            "mayRename": false,
            "mayDelete": false,
            "mayModifyContent": false,
            "mayShare": false
        }
        }));

    // Verify Jane received a share notification
    let response = jane
        .jmap_changes(MethodObject::ShareNotification, &jane_share_change_id)
        .await;
    jane_share_change_id = response.new_state().to_string();
    let changes = response.changes().collect::<Vec<_>>();
    assert_eq!(changes.len(), 1);
    let share_id = changes[0].as_created();
    jane.jmap_get(
        MethodObject::ShareNotification,
        [
            ShareNotificationProperty::Id,
            ShareNotificationProperty::ChangedBy,
            ShareNotificationProperty::ObjectType,
            ShareNotificationProperty::ObjectAccountId,
            ShareNotificationProperty::ObjectId,
            ShareNotificationProperty::OldRights,
            ShareNotificationProperty::NewRights,
            ShareNotificationProperty::Name,
        ],
        [share_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
          "id": &share_id,
          "changedBy": {
            "principalId": &john_id,
            "name": "John Doe",
            "email": "jdoe@example.com"
          },
          "objectType": "FileNode",
          "objectAccountId": &john_id,
          "objectId": &john_folder_id,
          "oldRights": {
            "mayRead": false,
            "mayAddChildren": false,
            "mayRename": false,
            "mayDelete": false,
            "mayModifyContent": false,
            "mayShare": false
          },
          "newRights": {
            "mayRead": true,
            "mayAddChildren": false,
            "mayRename": false,
            "mayDelete": false,
            "mayModifyContent": false,
            "mayShare": false
          },
          "name": null
        }));

    // Updating and deleting should fail
    assert_eq!(
        jane.jmap_update_account(
            john,
            MethodObject::FileNode,
            [(&john_folder_id, json!({}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&john_folder_id)
        .description(),
        "You are not allowed to modify this file node."
    );
    assert_eq!(
        jane.jmap_destroy_account(
            john,
            MethodObject::FileNode,
            [&john_folder_id],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_destroyed(&john_folder_id)
        .description(),
        "You are not allowed to delete this file node."
    );

    // Grant Jane write access
    john.jmap_update(
        MethodObject::FileNode,
        [(
            &john_folder_id,
            json!({
                format!("shareWith/{jane_id}/mayAddChildren"): true,
                format!("shareWith/{jane_id}/mayRename"): true,
                format!("shareWith/{jane_id}/mayDelete"): true,
                format!("shareWith/{jane_id}/mayModifyContent"): true,
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_folder_id);
    jane.jmap_get_account(
        john,
        MethodObject::FileNode,
        [
            FileNodeProperty::Id,
            FileNodeProperty::Name,
            FileNodeProperty::MyRights,
        ],
        [john_folder_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_folder_id,
        "name": "Test #1",
        "myRights": {
            "mayRead": true,
            "mayAddChildren": true,
            "mayRename": true,
            "mayDelete": true,
            "mayModifyContent": true,
            "mayShare": false
        }
        }));

    // Verify Jane received a share notification with the updated rights
    let response = jane
        .jmap_changes(MethodObject::ShareNotification, &jane_share_change_id)
        .await;
    jane_share_change_id = response.new_state().to_string();
    let changes = response.changes().collect::<Vec<_>>();
    assert_eq!(changes.len(), 1);
    let share_id = changes[0].as_created();
    jane.jmap_get(
        MethodObject::ShareNotification,
        [
            ShareNotificationProperty::Id,
            ShareNotificationProperty::ChangedBy,
            ShareNotificationProperty::ObjectType,
            ShareNotificationProperty::ObjectAccountId,
            ShareNotificationProperty::ObjectId,
            ShareNotificationProperty::OldRights,
            ShareNotificationProperty::NewRights,
            ShareNotificationProperty::Name,
        ],
        [share_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
          "id": &share_id,
          "changedBy": {
            "principalId": &john_id,
            "name": "John Doe",
            "email": "jdoe@example.com"
          },
          "objectType": "FileNode",
          "objectAccountId": &john_id,
          "objectId": &john_folder_id,
          "oldRights": {
            "mayRead": true,
            "mayAddChildren": false,
            "mayRename": false,
            "mayDelete": false,
            "mayModifyContent": false,
            "mayShare": false
          },
          "newRights": {
            "mayRead": true,
            "mayAddChildren": true,
            "mayRename": true,
            "mayDelete": true,
            "mayModifyContent": true,
            "mayShare": false
          },
          "name": null
        }));

    // Creating a root folder should fail
    assert_eq!(
        jane.jmap_create_account(
            john,
            MethodObject::FileNode,
            [json!({
                "name": "A new shared folder",
            })],
            Vec::<(&str, &str)>::new()
        )
        .await
        .not_created(0)
        .description(),
        "Cannot create top-level folder in a shared account."
    );

    // Update John's folder name
    jane.jmap_update_account(
        john,
        MethodObject::FileNode,
        [(
            &john_folder_id,
            json!({
                "name": "Jane's updated name",
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_folder_id);
    jane.jmap_get_account(
        john,
        MethodObject::FileNode,
        [FileNodeProperty::Id, FileNodeProperty::Name],
        [john_folder_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_folder_id,
        "name": "Jane's updated name",
        }));

    // Revoke Jane's access
    john.jmap_update(
        MethodObject::FileNode,
        [(
            &john_folder_id,
            json!({
                format!("shareWith/{jane_id}"): ()
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_folder_id);
    john.jmap_get(
        MethodObject::FileNode,
        [
            FileNodeProperty::Id,
            FileNodeProperty::Name,
            FileNodeProperty::ShareWith,
        ],
        [john_folder_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_folder_id,
        "name": "Jane's updated name",
        "shareWith": {}
        }));

    // Verify Jane can no longer access the folder or its contacts
    assert_eq!(
        jane.jmap_get_account(
            john,
            MethodObject::FileNode,
            Vec::<&str>::new(),
            [john_folder_id.as_str()],
        )
        .await
        .method_response()
        .typ(),
        "forbidden"
    );

    // Verify Jane received a share notification with the updated rights
    let response = jane
        .jmap_changes(MethodObject::ShareNotification, &jane_share_change_id)
        .await;
    let changes = response.changes().collect::<Vec<_>>();
    assert_eq!(changes.len(), 1);
    let share_id = changes[0].as_created();
    jane.jmap_get(
        MethodObject::ShareNotification,
        [
            ShareNotificationProperty::Id,
            ShareNotificationProperty::ChangedBy,
            ShareNotificationProperty::ObjectType,
            ShareNotificationProperty::ObjectAccountId,
            ShareNotificationProperty::ObjectId,
            ShareNotificationProperty::OldRights,
            ShareNotificationProperty::NewRights,
            ShareNotificationProperty::Name,
        ],
        [share_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
          "id": &share_id,
          "changedBy": {
            "principalId": &john_id,
            "name": "John Doe",
            "email": "jdoe@example.com"
          },
          "objectType": "FileNode",
          "objectAccountId": &john_id,
          "objectId": &john_folder_id,
          "oldRights": {
            "mayRead": true,
            "mayAddChildren": true,
            "mayRename": true,
            "mayDelete": true,
            "mayModifyContent": true,
            "mayShare": false
          },
          "newRights": {
            "mayRead": false,
            "mayAddChildren": false,
            "mayRename": false,
            "mayDelete": false,
            "mayModifyContent": false,
            "mayShare": false
          },
          "name": null
        }));

    // Grant Jane delete access once again
    john.jmap_update(
        MethodObject::FileNode,
        [(
            &john_folder_id,
            json!({
                format!("shareWith/{jane_id}/mayRead"): true,
                format!("shareWith/{jane_id}/mayAddChildren"): true,
                format!("shareWith/{jane_id}/mayRename"): true,
                format!("shareWith/{jane_id}/mayDelete"): true,
                format!("shareWith/{jane_id}/mayModifyContent"): true,
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_folder_id);

    // FileNode/copy: Jane copies a node from her own account into John's shared folder
    let jane_folder_id = jane
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "jane-src"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let copied = jane
        .jmap_copy(
            jane,
            john,
            MethodObject::FileNode,
            [(
                &jane_folder_id,
                json!({ "parentId": &john_folder_id, "name": "copied-here" }),
            )],
            false,
        )
        .await;
    let copied_id = copied.copied(&jane_folder_id).id().to_string();
    assert_ne!(copied_id, jane_folder_id);
    jane.jmap_get_account(
        john,
        MethodObject::FileNode,
        [
            FileNodeProperty::Id,
            FileNodeProperty::Name,
            FileNodeProperty::ParentId,
        ],
        [copied_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
            "id": &copied_id,
            "name": "copied-here",
            "parentId": &john_folder_id,
        }));
    // Original still exists in Jane's account (onSuccessDestroyOriginal=false)
    jane.jmap_get(
        MethodObject::FileNode,
        [FileNodeProperty::Id],
        [jane_folder_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({ "id": &jane_folder_id }));

    // onExists=rename on copy: colliding into John's folder again must echo the new name
    let renamed_copy = jane
        .jmap_method_calls(json!([[
            "FileNode/copy",
            {
                "fromAccountId": jane.id_string(),
                "accountId": john.id_string(),
                "onExists": "rename",
                "create": {
                    &jane_folder_id: { "parentId": &john_folder_id, "name": "copied-here" }
                }
            },
            "0"
        ]]))
        .await;
    let renamed_entry = renamed_copy.copied(&jane_folder_id);
    let renamed_copy_id = renamed_entry.id().to_string();
    assert_eq!(renamed_entry.text_field("name"), "copied-here (2)");

    jane.jmap_destroy(
        MethodObject::FileNode,
        [&jane_folder_id],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .destroyed()
    .for_each(drop);

    // Verify Jane can delete the folder (and the node copied into it)
    assert_eq!(
        jane.jmap_destroy_account(
            john,
            MethodObject::FileNode,
            [john_folder_id.as_str()],
            [("onDestroyRemoveChildren", true)],
        )
        .await
        .destroyed()
        .collect::<std::collections::HashSet<_>>(),
        [
            john_folder_id.as_str(),
            copied_id.as_str(),
            renamed_copy_id.as_str()
        ]
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
    );

    // Destroy all mailboxes
    test.assert_is_empty().await;
}
