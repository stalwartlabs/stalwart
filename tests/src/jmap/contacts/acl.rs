/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{JMAPTest, JmapUtils};
use calcard::jscontact::JSContactProperty;
use jmap_proto::{
    object::{addressbook::AddressBookProperty, share_notification::ShareNotificationProperty},
    request::method::MethodObject,
};
use serde_json::json;
use types::id::Id;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Contacts ACL tests...");
    let john = params.account("jdoe@example.com");
    let jane = params.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();

    // Create test address books
    let response = john
        .jmap_create(
            MethodObject::AddressBook,
            [json!({
                "name": "Test #1",
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let john_book_id = response.created(0).id().to_string();
    let john_contact_id = john
        .jmap_create(
            MethodObject::ContactCard,
            [json!({
                "uid": "abc123",
                "name": {
                    "full": "John's Simple Contact",
                },
                "addressBookIds": {
                    &john_book_id: true
                },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let response = jane
        .jmap_create(
            MethodObject::AddressBook,
            [json!({
                "name": "Test #1",
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let jane_book_id = response.created(0).id().to_string();
    let jane_contact_id = jane
        .jmap_create(
            MethodObject::ContactCard,
            [json!({
                "uid": "abc456",
                "name": {
                    "full": "Jane's Simple Contact",
                },
                "addressBookIds": {
                    &jane_book_id: true
                },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    // Verify myRights
    john.jmap_get(
        MethodObject::AddressBook,
        [
            AddressBookProperty::Id,
            AddressBookProperty::Name,
            AddressBookProperty::MyRights,
            AddressBookProperty::ShareWith,
        ],
        [john_book_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_book_id,
        "name": "Test #1",
        "myRights": {
          "mayRead": true,
          "mayWrite": true,
          "mayDelete": true,
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
            MethodObject::AddressBook,
            Vec::<&str>::new(),
            [john_book_id.as_str()],
        )
        .await
        .method_response()
        .typ(),
        "forbidden"
    );

    // Share address book with Jane
    john.jmap_update(
        MethodObject::AddressBook,
        [(
            &john_book_id,
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
    .updated(&john_book_id);
    john.jmap_get(
        MethodObject::AddressBook,
        [
            AddressBookProperty::Id,
            AddressBookProperty::Name,
            AddressBookProperty::ShareWith,
        ],
        [john_book_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_book_id,
        "name": "Test #1",
        "shareWith": {
            &jane_id : {
                "mayRead": true,
                "mayWrite": false,
                "mayDelete": false,
                "mayShare": false
            }
        }
        }));

    // Verify Jane can access the contact
    jane.jmap_get_account(
        john,
        MethodObject::AddressBook,
        [
            AddressBookProperty::Id,
            AddressBookProperty::Name,
            AddressBookProperty::MyRights,
        ],
        [john_book_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_book_id,
        "name": "Test #1",
        "myRights": {
            "mayRead": true,
            "mayWrite": false,
            "mayDelete": false,
            "mayShare": false
        }
        }));
    jane.jmap_get_account(
        john,
        MethodObject::ContactCard,
        [AddressBookProperty::Id, AddressBookProperty::Name],
        [john_contact_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_contact_id,
        "name": {
                "full": "John's Simple Contact"
            },
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
          "objectType": "AddressBook",
          "objectAccountId": &john_id,
          "objectId": &john_book_id,
          "oldRights": {
            "mayRead": false,
            "mayWrite": false,
            "mayDelete": false,
            "mayShare": false
          },
          "newRights": {
            "mayRead": true,
            "mayWrite": false,
            "mayDelete": false,
            "mayShare": false
          },
          "name": null
        }));

    // Updating and deleting should fail
    assert_eq!(
        jane.jmap_update_account(
            john,
            MethodObject::AddressBook,
            [(&john_book_id, json!({}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&john_book_id)
        .description(),
        "You are not allowed to modify this address book."
    );
    assert_eq!(
        jane.jmap_destroy_account(
            john,
            MethodObject::AddressBook,
            [&john_book_id],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_destroyed(&john_book_id)
        .description(),
        "You are not allowed to delete this address book."
    );
    assert!(
        jane.jmap_update_account(
            john,
            MethodObject::ContactCard,
            [(&john_contact_id, json!({}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&john_contact_id)
        .description()
        .contains("You are not allowed to modify address book"),
    );
    assert!(
        jane.jmap_destroy_account(
            john,
            MethodObject::ContactCard,
            [&john_contact_id],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_destroyed(&john_contact_id)
        .description()
        .contains("You are not allowed to remove contacts from address book"),
    );

    // Grant Jane write access
    john.jmap_update(
        MethodObject::AddressBook,
        [(
            &john_book_id,
            json!({
                format!("shareWith/{jane_id}/mayWrite"): true,
                format!("shareWith/{jane_id}/mayDelete"): true,
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_book_id);
    jane.jmap_get_account(
        john,
        MethodObject::AddressBook,
        [
            AddressBookProperty::Id,
            AddressBookProperty::Name,
            AddressBookProperty::MyRights,
        ],
        [john_book_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_book_id,
        "name": "Test #1",
        "myRights": {
            "mayRead": true,
            "mayWrite": true,
            "mayDelete": true,
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
          "objectType": "AddressBook",
          "objectAccountId": &john_id,
          "objectId": &john_book_id,
          "oldRights": {
            "mayRead": true,
            "mayWrite": false,
            "mayDelete": false,
            "mayShare": false
          },
          "newRights": {
            "mayRead": true,
            "mayWrite": true,
            "mayDelete": true,
            "mayShare": false
          },
          "name": null
        }));

    // Creating a root folder should fail
    assert_eq!(
        jane.jmap_create_account(
            john,
            MethodObject::AddressBook,
            [json!({
                "name": "A new shared address book",
            })],
            Vec::<(&str, &str)>::new()
        )
        .await
        .not_created(0)
        .description(),
        "Cannot create address books in a shared account."
    );

    // Copy Jane's contact into John's address book
    let john_copied_contact_id = jane
        .jmap_copy(
            jane,
            john,
            MethodObject::ContactCard,
            [(
                &jane_contact_id,
                json!({
                    "addressBookIds": {
                        &john_book_id: true
                    }
                }),
            )],
            false,
        )
        .await
        .copied(&jane_contact_id)
        .id()
        .to_string();
    jane.jmap_get_account(
        john,
        MethodObject::ContactCard,
        [
            JSContactProperty::<Id>::Id,
            JSContactProperty::AddressBookIds,
            JSContactProperty::Name,
        ],
        [john_copied_contact_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_copied_contact_id,
        "name": {
                "full": "Jane's Simple Contact"
            },
        "addressBookIds": {
            &john_book_id: true
        }
        }));

    // Destroy the copied contact
    assert_eq!(
        jane.jmap_destroy_account(
            john,
            MethodObject::ContactCard,
            [john_copied_contact_id.as_str()],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .collect::<Vec<_>>(),
        [&john_copied_contact_id]
    );

    // Update John's contact
    jane.jmap_update_account(
        john,
        MethodObject::ContactCard,
        [(
            &john_contact_id,
            json!({
                "name": {
                    "full": "John's Updated Contact",
                }
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_contact_id);
    jane.jmap_get_account(
        john,
        MethodObject::ContactCard,
        [JSContactProperty::<Id>::Id, JSContactProperty::Name],
        [john_contact_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_contact_id,
        "name": {
                "full": "John's Updated Contact"
            },
        }));

    // Update John's address book name
    jane.jmap_update_account(
        john,
        MethodObject::AddressBook,
        [(
            &john_book_id,
            json!({
                "name": "Jane's version of John's Address Book",
                "description": "This is John's address book, but Jane can edit it now"
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_book_id);
    jane.jmap_get_account(
        john,
        MethodObject::AddressBook,
        [
            AddressBookProperty::Id,
            AddressBookProperty::Name,
            AddressBookProperty::Description,
        ],
        [john_book_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_book_id,
        "name": "Jane's version of John's Address Book",
        "description": "This is John's address book, but Jane can edit it now"
        }));

    // John should still see the old name
    john.jmap_get(
        MethodObject::AddressBook,
        [
            AddressBookProperty::Id,
            AddressBookProperty::Name,
            AddressBookProperty::Description,
        ],
        [john_book_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_book_id,
        "name": "Test #1",
        "description": null
        }));

    // Revoke Jane's access
    john.jmap_update(
        MethodObject::AddressBook,
        [(
            &john_book_id,
            json!({
                format!("shareWith/{jane_id}"): ()
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_book_id);
    john.jmap_get(
        MethodObject::AddressBook,
        [
            AddressBookProperty::Id,
            AddressBookProperty::Name,
            AddressBookProperty::ShareWith,
        ],
        [john_book_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_book_id,
        "name": "Test #1",
        "shareWith": {}
        }));

    // Verify Jane can no longer access the address book or its contacts
    assert_eq!(
        jane.jmap_get_account(
            john,
            MethodObject::AddressBook,
            Vec::<&str>::new(),
            [john_book_id.as_str()],
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
          "objectType": "AddressBook",
          "objectAccountId": &john_id,
          "objectId": &john_book_id,
          "oldRights": {
            "mayRead": true,
            "mayWrite": true,
            "mayDelete": true,
            "mayShare": false
          },
          "newRights": {
            "mayRead": false,
            "mayWrite": false,
            "mayDelete": false,
            "mayShare": false
          },
          "name": null
        }));

    // Grant Jane delete access once again
    john.jmap_update(
        MethodObject::AddressBook,
        [(
            &john_book_id,
            json!({
                format!("shareWith/{jane_id}/mayRead"): true,
                format!("shareWith/{jane_id}/mayDelete"): true,
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_book_id);

    // Verify Jane can delete the address book
    assert_eq!(
        jane.jmap_destroy_account(
            john,
            MethodObject::AddressBook,
            [john_book_id.as_str()],
            [("onDestroyRemoveContents", true)],
        )
        .await
        .destroyed()
        .collect::<Vec<_>>(),
        [john_book_id.as_str()]
    );

    // Destroy all mailboxes
    john.destroy_all_addressbooks().await;
    jane.destroy_all_addressbooks().await;
    params.assert_is_empty().await;
}
