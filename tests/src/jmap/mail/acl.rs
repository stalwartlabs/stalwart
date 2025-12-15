/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{directory::internal::TestInternalDirectory, jmap::JMAPTest};
use ::email::mailbox::{INBOX_ID, TRASH_ID};
use jmap_client::{
    core::{
        error::{MethodError, MethodErrorType},
        set::{SetError, SetErrorType},
    },
    email::{self, Property, import::EmailImportResponse, query::Filter},
    mailbox::{self, Role},
    principal::ACL,
};
use std::fmt::Debug;
use store::ahash::AHashMap;
use types::id::Id;

pub async fn test(params: &mut JMAPTest) {
    println!("Running ACL tests...");
    let server = params.server.clone();

    // Create a group and three test accounts
    let inbox_id = Id::new(INBOX_ID as u64).to_string();
    let trash_id = Id::new(TRASH_ID as u64).to_string();

    let john = params.account("jdoe@example.com");
    let jane = params.account("jane.smith@example.com");
    let bill = params.account("bill@example.com");
    let sales = params.account("sales@example.com");

    // Authenticate all accounts
    let mut john_client = john.client_owned().await;
    let mut jane_client = jane.client_owned().await;
    let mut bill_client = bill.client_owned().await;

    // Insert two emails in each account
    let mut email_ids = AHashMap::default();
    for (client, account_id, name) in [
        (&mut john_client, john.id(), "john"),
        (&mut jane_client, jane.id(), "jane"),
        (&mut bill_client, bill.id(), "bill"),
        (
            &mut params.account("admin").client_owned().await,
            sales.id(),
            "sales",
        ),
    ] {
        let user_name = client.session().username().to_string();
        let mut ids = Vec::with_capacity(2);
        for (mailbox_id, mailbox_name) in [(&inbox_id, "inbox"), (&trash_id, "trash")] {
            ids.push(
                client
                    .set_default_account_id(account_id.to_string())
                    .email_import(
                        format!(
                            concat!(
                                "From: acl_test@example.com\r\n",
                                "To: {}\r\n",
                                "Subject: Owned by {} in {}\r\n",
                                "\r\n",
                                "This message is owned by {}.",
                            ),
                            user_name, name, mailbox_name, name
                        )
                        .into_bytes(),
                        [mailbox_id],
                        None::<Vec<&str>>,
                        None,
                    )
                    .await
                    .unwrap()
                    .take_id(),
            );
        }
        email_ids.insert(name, ids);
    }

    // John should have access to his emails only
    assert_eq!(
        john_client
            .email_get(
                email_ids.get("john").unwrap().first().unwrap(),
                [Property::Subject].into(),
            )
            .await
            .unwrap()
            .unwrap()
            .subject()
            .unwrap(),
        "Owned by john in inbox"
    );
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .email_get(
                email_ids.get("jane").unwrap().first().unwrap(),
                [Property::Subject].into(),
            )
            .await,
    );
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .mailbox_get(&inbox_id, None::<Vec<_>>)
            .await,
    );
    assert_forbidden(
        john_client
            .set_default_account_id(sales.id_string())
            .email_get(
                email_ids.get("sales").unwrap().first().unwrap(),
                [Property::Subject].into(),
            )
            .await,
    );
    assert_forbidden(
        john_client
            .set_default_account_id(sales.id_string())
            .mailbox_get(&inbox_id, None::<Vec<_>>)
            .await,
    );
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .email_query(None::<Filter>, None::<Vec<_>>)
            .await,
    );

    // Jane grants Inbox ReadItems access to John
    jane_client
        .mailbox_update_acl(&inbox_id, john.id_string(), [ACL::ReadItems])
        .await
        .unwrap();

    // John should have ReadItems access to Inbox
    assert_eq!(
        john_client
            .set_default_account_id(jane.id_string())
            .email_get(
                email_ids.get("jane").unwrap().first().unwrap(),
                [Property::Subject].into(),
            )
            .await
            .unwrap()
            .unwrap()
            .subject()
            .unwrap(),
        "Owned by jane in inbox"
    );
    assert_eq!(
        john_client
            .set_default_account_id(jane.id_string())
            .email_query(None::<Filter>, None::<Vec<_>>)
            .await
            .unwrap()
            .ids(),
        [email_ids.get("jane").unwrap().first().unwrap().as_str()]
    );

    // John's session resource should contain Jane's account details
    john_client.refresh_session().await.unwrap();
    assert_eq!(
        john_client
            .session()
            .account(jane.id_string())
            .unwrap()
            .name(),
        "jane.smith@example.com"
    );

    // John should not have access to emails in Jane's Trash folder
    assert!(
        john_client
            .set_default_account_id(jane.id_string())
            .email_get(
                email_ids.get("jane").unwrap().last().unwrap(),
                [Property::Subject].into(),
            )
            .await
            .unwrap()
            .is_none()
    );

    // John should only be able to copy blobs he has access to
    let blob_id = jane_client
        .email_get(
            email_ids.get("jane").unwrap().first().unwrap(),
            [Property::BlobId].into(),
        )
        .await
        .unwrap()
        .unwrap()
        .take_blob_id();
    john_client
        .set_default_account_id(john.id_string())
        .blob_copy(jane.id_string(), &blob_id)
        .await
        .unwrap();
    let blob_id = jane_client
        .email_get(
            email_ids.get("jane").unwrap().last().unwrap(),
            [Property::BlobId].into(),
        )
        .await
        .unwrap()
        .unwrap()
        .take_blob_id();
    assert_forbidden(
        john_client
            .set_default_account_id(john.id_string())
            .blob_copy(jane.id_string(), &blob_id)
            .await,
    );

    // John only has ReadItems access to Inbox
    jane_client
        .mailbox_update_acl(&inbox_id, john.id_string(), [ACL::ReadItems])
        .await
        .unwrap();
    assert_eq!(
        john_client
            .set_default_account_id(jane.id_string())
            .mailbox_get(&inbox_id, [mailbox::Property::MyRights].into())
            .await
            .unwrap()
            .unwrap()
            .my_rights()
            .unwrap()
            .acl_list(),
        vec![ACL::ReadItems]
    );

    // Try to add items using import and copy
    let blob_id = john_client
        .set_default_account_id(john.id_string())
        .upload(
            Some(john.id_string()),
            concat!(
                "From: acl_test@example.com\r\n",
                "To: jane.smith@example.com\r\n",
                "Subject: Created by john in jane's inbox\r\n",
                "\r\n",
                "This message is owned by jane.",
            )
            .as_bytes()
            .to_vec(),
            None,
        )
        .await
        .unwrap()
        .take_blob_id();
    let mut request = john_client.set_default_account_id(jane.id_string()).build();
    let email_id = request
        .import_email()
        .email(&blob_id)
        .mailbox_ids([&inbox_id])
        .create_id();
    assert_forbidden(
        request
            .send_single::<EmailImportResponse>()
            .await
            .unwrap()
            .created(&email_id),
    );
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .email_copy(
                john.id_string(),
                email_ids.get("john").unwrap().last().unwrap(),
                [&inbox_id],
                None::<Vec<&str>>,
                None,
            )
            .await,
    );

    // Grant access and try again
    jane_client
        .mailbox_update_acl(&inbox_id, john.id_string(), [ACL::ReadItems, ACL::AddItems])
        .await
        .unwrap();

    let mut request = john_client.set_default_account_id(jane.id_string()).build();
    let email_id = request
        .import_email()
        .email(&blob_id)
        .mailbox_ids([&inbox_id])
        .create_id();
    let email_id = request
        .send_single::<EmailImportResponse>()
        .await
        .unwrap()
        .created(&email_id)
        .unwrap()
        .take_id();
    let email_id_2 = john_client
        .set_default_account_id(jane.id_string())
        .email_copy(
            john.id_string(),
            email_ids.get("john").unwrap().last().unwrap(),
            [&inbox_id],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_id();

    assert_eq!(
        jane_client
            .email_get(&email_id, [Property::Subject].into(),)
            .await
            .unwrap()
            .unwrap()
            .subject()
            .unwrap(),
        "Created by john in jane's inbox"
    );
    assert_eq!(
        jane_client
            .email_get(&email_id_2, [Property::Subject].into(),)
            .await
            .unwrap()
            .unwrap()
            .subject()
            .unwrap(),
        "Owned by john in trash"
    );

    // Try removing items
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .email_destroy(&email_id)
            .await,
    );
    jane_client
        .mailbox_update_acl(
            &inbox_id,
            john.id_string(),
            [ACL::ReadItems, ACL::AddItems, ACL::RemoveItems],
        )
        .await
        .unwrap();
    john_client
        .set_default_account_id(jane.id_string())
        .email_destroy(&email_id)
        .await
        .unwrap();

    // Try to set keywords
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .email_set_keyword(&email_id_2, "$seen", true)
            .await,
    );
    jane_client
        .mailbox_update_acl(
            &inbox_id,
            john.id_string(),
            [
                ACL::ReadItems,
                ACL::AddItems,
                ACL::RemoveItems,
                ACL::SetKeywords,
            ],
        )
        .await
        .unwrap();
    john_client
        .set_default_account_id(jane.id_string())
        .email_set_keyword(&email_id_2, "$seen", true)
        .await
        .unwrap();
    john_client
        .set_default_account_id(jane.id_string())
        .email_set_keyword(&email_id_2, "my-keyword", true)
        .await
        .unwrap();

    // Try to create a child
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .mailbox_create("John's mailbox", None::<&str>, Role::None)
            .await,
    );
    jane_client
        .mailbox_update_acl(
            &inbox_id,
            john.id_string(),
            [
                ACL::ReadItems,
                ACL::AddItems,
                ACL::RemoveItems,
                ACL::SetKeywords,
                ACL::CreateChild,
            ],
        )
        .await
        .unwrap();
    let mailbox_id = john_client
        .set_default_account_id(jane.id_string())
        .mailbox_create("John's mailbox", Some(&inbox_id), Role::None)
        .await
        .unwrap()
        .take_id();

    // Try renaming a mailbox
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .mailbox_rename(&mailbox_id, "John's private mailbox")
            .await,
    );
    jane_client
        .mailbox_update_acl(&mailbox_id, john.id_string(), [ACL::ReadItems, ACL::Rename])
        .await
        .unwrap();
    john_client
        .set_default_account_id(jane.id_string())
        .mailbox_rename(&mailbox_id, "John's private mailbox")
        .await
        .unwrap();

    // Try moving a message
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .email_set_mailbox(&email_id_2, &mailbox_id, true)
            .await,
    );
    jane_client
        .mailbox_update_acl(
            &mailbox_id,
            john.id_string(),
            [ACL::ReadItems, ACL::Rename, ACL::AddItems],
        )
        .await
        .unwrap();
    john_client
        .set_default_account_id(jane.id_string())
        .email_set_mailbox(&email_id_2, &mailbox_id, true)
        .await
        .unwrap();

    // Try deleting a mailbox
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .mailbox_destroy(&mailbox_id, true)
            .await,
    );
    jane_client
        .mailbox_update_acl(
            &mailbox_id,
            john.id_string(),
            [ACL::ReadItems, ACL::Rename, ACL::AddItems, ACL::Delete],
        )
        .await
        .unwrap();
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .mailbox_destroy(&mailbox_id, true)
            .await,
    );
    jane_client
        .mailbox_update_acl(
            &mailbox_id,
            john.id_string(),
            [
                ACL::ReadItems,
                ACL::Rename,
                ACL::AddItems,
                ACL::Delete,
                ACL::RemoveItems,
            ],
        )
        .await
        .unwrap();
    john_client
        .set_default_account_id(jane.id_string())
        .mailbox_destroy(&mailbox_id, true)
        .await
        .unwrap();

    // Try changing ACL
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .mailbox_update_acl(&inbox_id, bill.id_string(), [ACL::ReadItems])
            .await,
    );
    assert_forbidden(
        bill_client
            .set_default_account_id(jane.id_string())
            .email_query(None::<Filter>, None::<Vec<_>>)
            .await,
    );
    jane_client
        .mailbox_update_acl(
            &inbox_id,
            john.id_string(),
            [
                ACL::ReadItems,
                ACL::AddItems,
                ACL::RemoveItems,
                ACL::SetKeywords,
                ACL::CreateChild,
                ACL::Rename,
                ACL::Administer,
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        john_client
            .set_default_account_id(jane.id_string())
            .mailbox_get(&inbox_id, [mailbox::Property::MyRights].into())
            .await
            .unwrap()
            .unwrap()
            .my_rights()
            .unwrap()
            .acl_list(),
        vec![
            ACL::ReadItems,
            ACL::AddItems,
            ACL::RemoveItems,
            ACL::SetSeen,
            ACL::SetKeywords,
            ACL::CreateChild,
            ACL::Rename
        ]
    );
    john_client
        .set_default_account_id(jane.id_string())
        .mailbox_update_acl(&inbox_id, bill.id_string(), [ACL::ReadItems])
        .await
        .unwrap();
    assert_eq!(
        bill_client
            .set_default_account_id(jane.id_string())
            .email_query(
                None::<Filter>,
                vec![email::query::Comparator::subject()].into()
            )
            .await
            .unwrap()
            .ids(),
        [
            email_ids.get("jane").unwrap().first().unwrap().as_str(),
            &email_id_2
        ]
    );

    // Revoke all access to John
    jane_client
        .mailbox_update_acl(&inbox_id, john.id_string(), [])
        .await
        .unwrap();
    assert_forbidden(
        john_client
            .set_default_account_id(jane.id_string())
            .email_get(
                email_ids.get("jane").unwrap().first().unwrap(),
                [Property::Subject].into(),
            )
            .await,
    );
    john_client.refresh_session().await.unwrap();
    assert!(john_client.session().account(jane.id_string()).is_none());
    assert_eq!(
        bill_client
            .set_default_account_id(jane.id_string())
            .email_get(
                email_ids.get("jane").unwrap().first().unwrap(),
                [Property::Subject].into(),
            )
            .await
            .unwrap()
            .unwrap()
            .subject()
            .unwrap(),
        "Owned by jane in inbox"
    );

    // Add John and Jane to the Sales group
    for name in ["jdoe@example.com", "jane.smith@example.com"] {
        server
            .invalidate_principal_caches(
                server
                    .core
                    .storage
                    .data
                    .add_to_group(name, "sales@example.com")
                    .await,
            )
            .await;
    }
    john_client.refresh_session().await.unwrap();
    jane_client.refresh_session().await.unwrap();
    bill_client.refresh_session().await.unwrap();
    assert_eq!(
        john_client
            .session()
            .account(sales.id_string())
            .unwrap()
            .name(),
        "sales@example.com"
    );
    assert!(
        !john_client
            .session()
            .account(sales.id_string())
            .unwrap()
            .is_personal()
    );
    assert_eq!(
        jane_client
            .session()
            .account(sales.id_string())
            .unwrap()
            .name(),
        "sales@example.com"
    );
    assert!(bill_client.session().account(sales.id_string()).is_none());

    // Insert a message in Sales's inbox
    let blob_id = john_client
        .set_default_account_id(sales.id_string())
        .upload(
            Some(sales.id_string()),
            concat!(
                "From: acl_test@example.com\r\n",
                "To: sales@example.com\r\n",
                "Subject: Created by john in sales\r\n",
                "\r\n",
                "This message is owned by sales.",
            )
            .as_bytes()
            .to_vec(),
            None,
        )
        .await
        .unwrap()
        .take_blob_id();
    let mut request = john_client.build();
    let email_id = request
        .import_email()
        .email(&blob_id)
        .mailbox_ids([&inbox_id])
        .create_id();
    let email_id = request
        .send_single::<EmailImportResponse>()
        .await
        .unwrap()
        .created(&email_id)
        .unwrap()
        .take_id();

    // Both Jane and John should be able to see this message, but not Bill
    assert_eq!(
        john_client
            .set_default_account_id(sales.id_string())
            .email_get(&email_id, [Property::Subject].into(),)
            .await
            .unwrap()
            .unwrap()
            .subject()
            .unwrap(),
        "Created by john in sales"
    );
    assert_eq!(
        jane_client
            .set_default_account_id(sales.id_string())
            .email_get(&email_id, [Property::Subject].into(),)
            .await
            .unwrap()
            .unwrap()
            .subject()
            .unwrap(),
        "Created by john in sales"
    );
    assert_forbidden(
        bill_client
            .set_default_account_id(sales.id_string())
            .email_get(&email_id, [Property::Subject].into())
            .await,
    );

    // Remove John from the sales group
    server
        .invalidate_principal_caches(
            server
                .core
                .storage
                .data
                .remove_from_group("jdoe@example.com", "sales@example.com")
                .await,
        )
        .await;
    assert_forbidden(
        john_client
            .set_default_account_id(sales.id_string())
            .email_get(&email_id, [Property::Subject].into())
            .await,
    );

    // Destroy test account data
    for id in [john, bill, jane, sales] {
        params.destroy_all_mailboxes(id).await;
    }
    params.assert_is_empty().await;
}

pub fn assert_forbidden<T: Debug>(result: Result<T, jmap_client::Error>) {
    if !matches!(
        result,
        Err(jmap_client::Error::Method(MethodError {
            p_type: MethodErrorType::Forbidden
        })) | Err(jmap_client::Error::Set(SetError {
            type_: SetErrorType::BlobNotFound | SetErrorType::Forbidden,
            ..
        }))
    ) {
        panic!("Expected forbidden, got {:?}", result);
    }
}
