/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{JMAPTest, JmapUtils};
use jmap_proto::{
    object::{file_node::FileNodeProperty, share_notification::ShareNotificationProperty},
    request::method::MethodObject,
};
use serde_json::json;

pub async fn test(params: &mut JMAPTest) {
    println!("Running File Storage ACL tests...");
    let john = params.account("jdoe@example.com");
    let jane = params.account("jane.smith@example.com");
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
          "mayWrite": true,
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
                "mayWrite": false,
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
            "mayWrite": false,
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
            "mayWrite": false,
            "mayShare": false
          },
          "newRights": {
            "mayRead": true,
            "mayWrite": false,
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
                format!("shareWith/{jane_id}/mayWrite"): true,
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
            "mayWrite": true,
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
            "mayWrite": false,
            "mayShare": false
          },
          "newRights": {
            "mayRead": true,
            "mayWrite": true,
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
            "mayWrite": true,
            "mayShare": false
          },
          "newRights": {
            "mayRead": false,
            "mayWrite": false,
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
                format!("shareWith/{jane_id}/mayWrite"): true,
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_folder_id);

    // Verify Jane can delete the folder
    assert_eq!(
        jane.jmap_destroy_account(
            john,
            MethodObject::FileNode,
            [john_folder_id.as_str()],
            [("onDestroyRemoveChildren", true)],
        )
        .await
        .destroyed()
        .collect::<Vec<_>>(),
        [john_folder_id.as_str()]
    );

    // Destroy all mailboxes
    params.assert_is_empty().await;
}
