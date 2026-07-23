/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::utils::{
    imap::{AssertResult, ImapConnection, Type},
    jmap::JmapUtils,
    server::TestServer,
};
use imap_proto::ResponseType;
use jmap_proto::error::set::SetErrorType;
use registry::schema::{
    enums::{AccountType, ArchivedItemStatus, TaskStoreMaintenanceType},
    prelude::{ObjectType, Property},
    structs::{
        Account, Action, ArchivedItem, DataRetention, Task, TaskStatus, TaskStoreMaintenance,
    },
};
use serde_json::json;
use types::id::Id;

pub async fn test(test: &mut TestServer) {
    println!("Running Archiving tests...");

    // Add test settings
    let admin = test.account("admin@example.org");
    admin
        .registry_update_setting(
            DataRetention {
                archive_deleted_accounts_for: Some(3600u64.into()),
                archive_deleted_items_for: Some(1u64.into()),
                ..Default::default()
            },
            &[
                Property::ArchiveDeletedAccountsFor,
                Property::ArchiveDeletedItemsFor,
            ],
        )
        .await;
    admin.reload_settings().await;

    // Create test account
    let mut john = test
        .create_user_account(
            "admin@example.org",
            "jdoe@example.org",
            "this is a very strong password",
            &[],
            "jdoe@example.org",
        )
        .await;
    let jane = test
        .create_user_account(
            "admin@example.org",
            "jane@example.org",
            "this is a very strong password",
            &[],
            "jane@example.org",
        )
        .await;
    let mut john_imap = john.imap_client().await;
    let mut jane_imap = jane.imap_client().await;

    for (account, imap) in [(&john, &mut john_imap), (&jane, &mut jane_imap)] {
        let message = RAW_MESSAGE.replace("NAME", account.name());

        // Insert test message
        imap.send("STATUS INBOX (MESSAGES)").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .assert_contains("MESSAGES 0");
        imap.send(&format!("APPEND INBOX {{{}}}", message.len()))
            .await;
        imap.assert_read(Type::Continuation, ResponseType::Ok).await;
        imap.send_untagged(&message).await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;

        // Make sure the message is there
        imap.send("STATUS INBOX (MESSAGES)").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .assert_contains("MESSAGES 1");
        imap.send("SELECT INBOX").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;

        // Fetch message body
        imap.send("FETCH 1 BODY[]").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .assert_contains(&format!("Subject: undelete test for {}", account.name()));

        // Delete and expunge message
        imap.send("STORE 1 +FLAGS (\\Deleted)").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;
        imap.send("EXPUNGE").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;

        // Logout and reconnect
        imap.send("LOGOUT").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;
        *imap = ImapConnection::connect(b"_x ").await;
        imap.authenticate(account.name(), account.secret()).await;

        // Make sure the message is gone
        imap.send("STATUS INBOX (MESSAGES)").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .assert_contains("MESSAGES 0");
    }

    // Expunge messages
    admin
        .registry_create_object(Task::StoreMaintenance(TaskStoreMaintenance {
            maintenance_type: TaskStoreMaintenanceType::PurgeAccounts,
            shard_index: None,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;

    // Fetch archived items
    let mut john_archive_id = Id::singleton();
    let mut jane_archive_id = Id::singleton();
    for (account, archive_id) in [(&john, &mut john_archive_id), (&jane, &mut jane_archive_id)] {
        let ids = account
            .registry_query(
                ObjectType::ArchivedItem,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 1);
        *archive_id = ids[0];

        let response = account
            .registry_get_many(ObjectType::ArchivedItem, Vec::<&str>::new())
            .await;
        let archives = response.list();
        assert_eq!(archives.len(), 1);
        assert_eq!(archives[0].object_id(), *archive_id);

        let archive = account.registry_get::<ArchivedItem>(*archive_id).await;
        if let ArchivedItem::Email(archive) = archive {
            assert_eq!(
                archive.subject,
                format!("undelete test for {}", account.name())
            );
            assert_eq!(archive.from, format!("{}@example.org", account.name()));
            assert_eq!(
                archive.blob_id.class.account_id(),
                account.id().document_id()
            );
            assert!(archive.size > 0);
        } else {
            panic!("Unexpected archived item type: {:?}", archive);
        }
    }

    // John should not be able to get, update or destroy Jane's archived item and vice versa
    assert_eq!(
        john.registry_get_many(ObjectType::ArchivedItem, [jane_archive_id])
            .await
            .not_found()
            .count(),
        1
    );
    john.registry_update_object_expect_err(
        ObjectType::ArchivedItem,
        jane_archive_id,
        json!({
            Property::Status: ArchivedItemStatus::RequestRestore,
        }),
    )
    .await
    .assert_type(SetErrorType::NotFound);
    john.registry_destroy_object_expect_err(ObjectType::ArchivedItem, jane_archive_id)
        .await
        .assert_type(SetErrorType::NotFound);

    // Admin should be able to see both archived items
    assert_eq!(
        admin
            .registry_query(
                ObjectType::ArchivedItem,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new()
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        vec![john_archive_id, jane_archive_id]
    );
    assert_eq!(
        admin
            .registry_query(
                ObjectType::ArchivedItem,
                [(Property::AccountId, jane.id().to_string())],
                Vec::<&str>::new()
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        vec![jane_archive_id]
    );

    // Request restore for John's archived item
    john.registry_update_object(
        ObjectType::ArchivedItem,
        john_archive_id,
        json!({
            Property::Status: ArchivedItemStatus::RequestRestore,
        }),
    )
    .await;
    test.wait_for_tasks().await;

    // Make sure the message is back
    john_imap.send("STATUS INBOX (MESSAGES)").await;
    john_imap
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 1");

    john_imap.send("SELECT INBOX").await;
    john_imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Fetch message body
    john_imap.send("FETCH 1 BODY[]").await;
    john_imap
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!("Subject: undelete test for {}", john.name()));

    // Jane's archived item should be deleted on the next purge
    admin
        .registry_create_object(Task::StoreMaintenance(TaskStoreMaintenance {
            maintenance_type: TaskStoreMaintenanceType::PurgeBlob,
            shard_index: None,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    assert_eq!(
        jane.registry_get_many(ObjectType::ArchivedItem, [jane_archive_id])
            .await
            .not_found()
            .count(),
        1
    );

    // Delete John's account
    john_imap.send("LOGOUT").await;
    john_imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let domain_id = admin.find_or_create_domain("example.org").await;
    admin
        .registry_destroy(ObjectType::Account, [john.id()])
        .await
        .assert_destroyed(&[john.id()]);
    assert!(
        test.server
            .rcpt_id_from_email("jdoe@example.org")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        test.server
            .try_account(john.id().document_id())
            .await
            .unwrap()
            .is_none()
    );

    // Make sure the deletion task is created
    let task_ids = admin
        .registry_query(
            ObjectType::Task,
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
        .await
        .object_ids()
        .collect::<Vec<_>>();
    assert_eq!(
        task_ids.len(),
        1,
        "Expected exactly one task, found {:?}",
        task_ids
    );
    let task = admin.registry_get::<Task>(task_ids[0]).await;
    if let Task::DestroyAccount(task) = task {
        assert_eq!(task.account_id, john.id());
        assert_eq!(task.account_domain_id, domain_id);
        assert_eq!(task.account_name, "jdoe");
        assert_eq!(task.account_type, AccountType::User)
    } else {
        panic!("Unexpected task type: {:?}", task);
    }

    // Delete task to trigger restore
    admin
        .registry_destroy(ObjectType::Task, [task_ids[0]])
        .await
        .assert_destroyed(&[task_ids[0]]);
    test.wait_for_tasks().await;

    // Make sure the account is back and set a new password
    let _john_account = admin.registry_get::<Account>(john.id()).await;
    admin
        .registry_update_object(
            ObjectType::Account,
            john.id(),
            json!({
                "credentials/0": {
                    Property::Type: "Password",
                    Property::Secret: "brand new secret"
                }
            }),
        )
        .await;

    // Reset cache
    admin.registry_create_object(Action::InvalidateCaches).await;

    // Authenticate with the new password and fetch the message again
    let mut john_imap = ImapConnection::connect(b"_x ").await;
    john_imap
        .authenticate("jdoe@example.org", "brand new secret")
        .await;
    john_imap.send("SELECT INBOX").await;
    john_imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    john_imap.send("FETCH 1 BODY[]").await;
    john_imap
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!("Subject: undelete test for {}", john.name()));

    // Delete spam samples
    john.update_secret("brand new secret");
    john.registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    jane.registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;

    // Restore settings
    admin
        .registry_update_setting(
            DataRetention::default(),
            &[
                Property::ArchiveDeletedAccountsFor,
                Property::ArchiveDeletedItemsFor,
            ],
        )
        .await;
    admin.reload_settings().await;

    // Delete accounts
    admin.destroy_account(john).await;
    admin.destroy_account(jane).await;

    test.cleanup().await;
}

const RAW_MESSAGE: &str = "From: NAME@example.org
To: NAME@example.org
Subject: undelete test for NAME

test
";
