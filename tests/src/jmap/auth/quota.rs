/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    directory::internal::TestInternalDirectory,
    jmap::{JMAPTest, mail::delivery::SmtpConnection, wait_for_index},
    smtp::queue::QueuedEvents,
    store::cleanup::store_blob_expire_all,
};
use common::config::smtp::queue::QueueName;
use email::{cache::MessageCacheFetch, mailbox::INBOX_ID};
use http::management::stores::recalculate_quota;
use jmap::blob::upload::DISABLE_UPLOAD_QUOTA;
use jmap_client::{
    core::set::{SetErrorType, SetObject},
    email::EmailBodyPart,
};
use serde_json::json;
use smtp::queue::spool::SmtpSpool;
use types::id::Id;

pub async fn test(params: &mut JMAPTest) {
    println!("Running quota tests...");
    let server = params.server.clone();

    let account = params.account("robert@example.com");
    let other_account = params.account("jdoe@example.com");

    server
        .core
        .storage
        .data
        .set_test_quota("robert@example.com", 1024)
        .await;
    server
        .core
        .storage
        .data
        .add_to_group("robert@example.com", "jdoe@example.com")
        .await;
    server.inner.cache.access_tokens.clear();

    // Delete temporary blobs from previous tests
    store_blob_expire_all(&server.core.storage.data).await;

    // Test temporary blob quota (3 files)
    DISABLE_UPLOAD_QUOTA.store(false, std::sync::atomic::Ordering::Relaxed);
    let client = account.client();
    for i in 0..3 {
        assert_eq!(
            client
                .upload(None, vec![b'A' + i; 1024], None)
                .await
                .unwrap()
                .size(),
            1024
        );
    }
    match client
        .upload(None, vec![b'Z'; 1024], None)
        .await
        .unwrap_err()
    {
        jmap_client::Error::Problem(err) if err.detail().unwrap().contains("quota") => (),
        other => panic!("Unexpected error: {:?}", other),
    }
    store_blob_expire_all(&server.core.storage.data).await;

    // Test temporary blob quota (50000 bytes)
    for i in 0..2 {
        assert_eq!(
            client
                .upload(None, vec![b'a' + i; 25000], None)
                .await
                .unwrap()
                .size(),
            25000
        );
    }
    match client
        .upload(None, vec![b'z'; 1024], None)
        .await
        .unwrap_err()
    {
        jmap_client::Error::Problem(err) if err.detail().unwrap().contains("quota") => (),
        other => panic!("Unexpected error: {:?}", other),
    }
    store_blob_expire_all(&server.core.storage.data).await;

    // Test JMAP Quotas extension
    let response = account
        .jmap_method_call(
            "Quota/get",
            json!({
                "ids": null
            }),
        )
        .await
        .to_string();
    assert!(response.contains("\"used\":0"), "{}", response);
    assert!(response.contains("\"hardLimit\":1024"), "{}", response);
    assert!(response.contains("\"scope\":\"account\""), "{}", response);
    assert!(
        response.contains("\"name\":\"robert@example.com\""),
        "{}",
        response
    );

    // Test Email/import quota
    let inbox_id = Id::new(INBOX_ID as u64).to_string();
    let mut message_ids = Vec::new();
    for i in 0..2 {
        message_ids.push(
            client
                .email_import(
                    create_message_with_size(
                        "jdoe@example.com",
                        "robert@example.com",
                        &format!("Test {i}"),
                        512,
                    ),
                    vec![&inbox_id],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }

    assert_over_quota(
        client
            .email_import(
                create_message_with_size("test@example.com", "jdoe@example.com", "Test 3", 100),
                vec![&inbox_id],
                None::<Vec<String>>,
                None,
            )
            .await,
    );

    // Test JMAP Quotas extension
    let response = account
        .jmap_method_call(
            "Quota/get",
            json!({
                "ids": null
            }),
        )
        .await
        .to_string();
    assert!(response.contains("\"used\":1024"), "{}", response);
    assert!(response.contains("\"hardLimit\":1024"), "{}", response);

    // Delete messages and check available quota
    for message_id in message_ids {
        client.email_destroy(&message_id).await.unwrap();
    }

    // Wait for pending index tasks
    wait_for_index(&server).await;
    assert_eq!(
        server
            .get_used_quota(account.id().document_id())
            .await
            .unwrap(),
        0
    );

    // Test Email/set quota
    let mut message_ids = Vec::new();
    for i in 0..2 {
        let mut request = client.build();
        let create_item = request.set_email().create();
        create_item
            .mailbox_ids([&inbox_id])
            .subject(format!("Test {i}"))
            .from(["jdoe@example.com"])
            .to(["robert@example.com"])
            .body_value("a".to_string(), String::from_utf8(vec![b'A'; 200]).unwrap())
            .text_body(EmailBodyPart::new().part_id("a"));
        let create_id = create_item.create_id().unwrap();
        message_ids.push(
            request
                .send_set_email()
                .await
                .unwrap()
                .created(&create_id)
                .unwrap()
                .take_id(),
        );
    }
    let mut request = client.build();
    let create_item = request.set_email().create();
    create_item
        .mailbox_ids([&inbox_id])
        .subject("Test 3")
        .from(["jdoe@example.com"])
        .to(["robert@example.com"])
        .body_value("a".to_string(), String::from_utf8(vec![b'A'; 400]).unwrap())
        .text_body(EmailBodyPart::new().part_id("a"));
    let create_id = create_item.create_id().unwrap();
    assert_over_quota(request.send_set_email().await.unwrap().created(&create_id));

    // Recalculate quota
    let prev_quota = server
        .get_used_quota(account.id().document_id())
        .await
        .unwrap();
    recalculate_quota(&server, account.id().document_id())
        .await
        .unwrap();
    assert_eq!(
        server
            .get_used_quota(account.id().document_id())
            .await
            .unwrap(),
        prev_quota
    );

    // Delete messages and check available quota
    for message_id in message_ids {
        client.email_destroy(&message_id).await.unwrap();
    }
    // Wait for pending index tasks
    wait_for_index(&server).await;
    assert_eq!(
        server
            .get_used_quota(account.id().document_id())
            .await
            .unwrap(),
        0
    );

    // Test Email/copy quota
    let other_client = other_account.client();
    let mut other_message_ids = Vec::new();
    let mut message_ids = Vec::new();
    for i in 0..3 {
        other_message_ids.push(
            other_client
                .email_import(
                    create_message_with_size(
                        "jane@example.com",
                        "jdoe@example.com",
                        &format!("Other Test {i}"),
                        512,
                    ),
                    vec![&inbox_id],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }
    for id in other_message_ids.iter().take(2) {
        message_ids.push(
            client
                .email_copy(
                    other_account.id_string(),
                    id,
                    vec![&inbox_id],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }
    assert_over_quota(
        client
            .email_copy(
                other_account.id_string(),
                &other_message_ids[2],
                vec![&inbox_id],
                None::<Vec<String>>,
                None,
            )
            .await,
    );

    // Delete messages and check available quota
    for message_id in message_ids {
        client.email_destroy(&message_id).await.unwrap();
    }
    // Wait for pending index tasks
    wait_for_index(&server).await;
    assert_eq!(
        server
            .get_used_quota(account.id().document_id())
            .await
            .unwrap(),
        0
    );

    // Test delivery quota
    let mut lmtp = SmtpConnection::connect().await;
    for i in 0..2 {
        lmtp.ingest(
            "jane@example.com",
            &["robert@example.com"],
            &String::from_utf8(create_message_with_size(
                "jane@example.com",
                "robert@example.com",
                &format!("Ingest test {i}"),
                513,
            ))
            .unwrap(),
        )
        .await;
    }
    let quota = server
        .get_used_quota(account.id().document_id())
        .await
        .unwrap();
    assert!(quota > 0 && quota <= 1024, "Quota is {}", quota);
    assert_eq!(
        server
            .get_cached_messages(account.id().document_id())
            .await
            .unwrap()
            .emails
            .items
            .len(),
        1,
    );

    DISABLE_UPLOAD_QUOTA.store(true, std::sync::atomic::Ordering::Relaxed);

    // Remove test data
    params.destroy_all_mailboxes(account).await;
    params.destroy_all_mailboxes(other_account).await;

    for event in server.all_queued_messages().await.messages {
        server
            .read_message(event.queue_id, QueueName::default())
            .await
            .unwrap()
            .remove(&server, event.due.into())
            .await;
    }
    params.assert_is_empty().await;
}

fn assert_over_quota<T: std::fmt::Debug>(result: Result<T, jmap_client::Error>) {
    match result {
        Ok(result) => panic!("Expected error, got {:?}", result),
        Err(jmap_client::Error::Set(err)) if err.error() == &SetErrorType::OverQuota => (),
        Err(err) => panic!("Expected OverQuota SetError, got {:?}", err),
    }
}

fn create_message_with_size(from: &str, to: &str, subject: &str, size: usize) -> Vec<u8> {
    let mut message = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n",
        from, to, subject
    );
    for _ in 0..size - message.len() {
        message.push('A');
    }

    message.into_bytes()
}
