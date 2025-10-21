/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{object::addressbook::AddressBookProperty, request::method::MethodObject};
use serde_json::json;

use crate::jmap::{ChangeType, JMAPTest, JmapUtils};

pub async fn test(params: &mut JMAPTest) {
    println!("Running AddressBook tests...");
    let account = params.account("jdoe@example.com");

    // Make sure the default address book exists
    let response = account
        .jmap_get(
            MethodObject::AddressBook,
            [
                AddressBookProperty::Id,
                AddressBookProperty::Name,
                AddressBookProperty::Description,
                AddressBookProperty::SortOrder,
                AddressBookProperty::IsSubscribed,
                AddressBookProperty::IsDefault,
            ],
            Vec::<&str>::new(),
        )
        .await;
    let list = response.list();
    assert_eq!(list.len(), 1);
    let default_addressbook_id = list[0].id().to_string();
    assert_eq!(
        list[0],
        json!({
            "name": "Stalwart Address Book (jdoe@example.com)",
            "description": (),
            "sortOrder": 0,
            "isSubscribed": false,
            "isDefault": true,
            "id": default_addressbook_id,
        })
    );
    let change_id = response.state();

    // Create Address Book
    let addressbook_id = account
        .jmap_create(
            MethodObject::AddressBook,
            [json!({
                "name": "Test address book",
                "description": "My personal address book",
                "sortOrder": 1,
                "isSubscribed": true

            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    // Validate changes
    assert_eq!(
        account
            .jmap_changes(MethodObject::AddressBook, change_id)
            .await
            .changes()
            .collect::<Vec<_>>(),
        [ChangeType::Created(&addressbook_id)]
    );

    // Get Address Book
    let response = account
        .jmap_get(
            MethodObject::AddressBook,
            [
                AddressBookProperty::Id,
                AddressBookProperty::Name,
                AddressBookProperty::Description,
                AddressBookProperty::SortOrder,
                AddressBookProperty::IsSubscribed,
                AddressBookProperty::IsDefault,
            ],
            [&addressbook_id],
        )
        .await;
    assert_eq!(
        response.list()[0],
        json!({
            "name": "Test address book",
            "description": "My personal address book",
            "sortOrder": 1,
            "isSubscribed": true,
            "isDefault": false,
            "id": addressbook_id,
        })
    );

    // Update Address Book and set it as default
    account
        .jmap_update(
            MethodObject::AddressBook,
            [(
                addressbook_id.as_str(),
                json!({
                    "name": "Updated address book",
                    "description": "My updated personal address book",
                    "sortOrder": 2,
                    "isSubscribed": false
                }),
            )],
            [("onSuccessSetIsDefault", addressbook_id.as_str())],
        )
        .await
        .updated(&addressbook_id);

    // Validate changes
    assert_eq!(
        account
            .jmap_get(
                MethodObject::AddressBook,
                [
                    AddressBookProperty::Id,
                    AddressBookProperty::Name,
                    AddressBookProperty::Description,
                    AddressBookProperty::SortOrder,
                    AddressBookProperty::IsSubscribed,
                    AddressBookProperty::IsDefault,
                ],
                [&addressbook_id, &default_addressbook_id],
            )
            .await
            .list(),
        vec![
            json!({
                "name": "Updated address book",
                "description": "My updated personal address book",
                "sortOrder": 2,
                "isSubscribed": false,
                "isDefault": true,
                "id": addressbook_id,
            }),
            json!({
                "name": "Stalwart Address Book (jdoe@example.com)",
                "description": (),
                "sortOrder": 0,
                "isSubscribed": false,
                "isDefault": false,
                "id": default_addressbook_id,
            })
        ]
    );

    // Create a contact
    let _ = account
        .jmap_create(
            MethodObject::ContactCard,
            [json!({
              "addressBookIds": {
                &addressbook_id: true
              },
              "name": {
                "components": [
                  { "kind": "given", "value": "Joe" },
                  { "kind": "surname", "value": "Bloggs" }
                ]
              },
              "emails": {
                "0": {
                  "address": "joe.bloggs@example.com"
                }
              }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id();

    // Try destroying the address book (should fail)
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::AddressBook,
                [&addressbook_id],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .not_destroyed(&addressbook_id)
            .typ(),
        "addressBookHasContents"
    );

    // Destroy using force
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::AddressBook,
                [&addressbook_id],
                [("onDestroyRemoveContents", true)],
            )
            .await
            .destroyed()
            .collect::<Vec<_>>(),
        vec![&addressbook_id]
    );

    // Destroy all mailboxes
    account.destroy_all_addressbooks().await;
    params.assert_is_empty().await;
}
