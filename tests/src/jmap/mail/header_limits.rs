/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use ::email::mailbox::INBOX_ID;
use jmap_proto::{error::set::SetErrorType, request::method::MethodObject};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::Email,
};
use serde_json::{Map, Value, json};
use types::id::Id;

const MAX_HEADER_SIZE: u64 = 1024;
const MAX_HEADER_COUNT: u64 = 100;
const TOO_MANY_FIELDS: usize = MAX_HEADER_COUNT as usize + 50;
const LONG_SUBJECT: usize = MAX_HEADER_SIZE as usize + 100;
const COUNT_ERROR: &str = "more than 100 fields";
const SIZE_ERROR: &str = "cannot exceed 1024 bytes";

pub async fn test(test: &TestServer) {
    println!("Running Email header limit tests...");
    let admin = test.account("admin@example.com");
    set_header_limits(
        admin,
        Email {
            max_header_size: MAX_HEADER_SIZE,
            max_header_count: MAX_HEADER_COUNT,
            ..Default::default()
        },
    )
    .await;

    let account = test.account("jdoe@example.com");
    let inbox_id = Id::from(INBOX_ID).to_string();

    email_import(account, &inbox_id).await;
    email_create(account, &inbox_id).await;

    set_header_limits(admin, Email::default()).await;
    test.destroy_all_mailboxes(account).await;
    admin
        .registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    test.assert_is_empty().await;
}

async fn email_import(account: &Account, inbox_id: &str) {
    let client = account.jmap_client().await;
    let messages = [
        format!(
            "Subject: count\r\n{}\r\nbody\r\n",
            "X: y\r\n".repeat(TOO_MANY_FIELDS)
        ),
        format!("Subject: {}\r\n\r\nbody\r\n", "s".repeat(LONG_SUBJECT)),
        format!(
            concat!(
                "Subject: nested\r\n",
                "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
                "\r\n",
                "--b\r\n",
                "{}",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "part\r\n",
                "--b--\r\n"
            ),
            "X: y\r\n".repeat(TOO_MANY_FIELDS)
        ),
    ];

    let mut emails = Map::with_capacity(messages.len());
    for (idx, message) in messages.into_iter().enumerate() {
        let blob_id = client
            .upload(None, message.into_bytes(), None)
            .await
            .expect("blob upload succeeds")
            .take_blob_id();
        emails.insert(
            format!("i{idx}"),
            json!({
                "blobId": blob_id,
                "mailboxIds": { inbox_id: true },
            }),
        );
    }

    let response = account
        .jmap_method_call(
            "Email/import",
            json!({
                "accountId": account.id_string(),
                "emails": emails,
            }),
        )
        .await;
    response
        .not_created(0)
        .to_set_error()
        .assert_type(SetErrorType::TooLarge)
        .assert_description_contains(COUNT_ERROR);
    response
        .not_created(1)
        .to_set_error()
        .assert_type(SetErrorType::TooLarge)
        .assert_description_contains(SIZE_ERROR);
    response.created(2);
}

async fn email_create(account: &Account, inbox_id: &str) {
    let mut too_many_fields = json!({
        "mailboxIds": { inbox_id: true },
        "subject": "count",
    });
    too_many_fields
        .as_object_mut()
        .expect("email is an object")
        .extend(
            (0..TOO_MANY_FIELDS)
                .map(|idx| (format!("header:X-Count-{idx}:asText"), Value::from("value"))),
        );

    let response = account
        .jmap_create(
            MethodObject::Email,
            [
                too_many_fields,
                json!({
                    "mailboxIds": { inbox_id: true },
                    "subject": "s".repeat(LONG_SUBJECT),
                }),
                json!({
                    "mailboxIds": { inbox_id: true },
                    "subject": "within limits",
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response
        .not_created(0)
        .to_set_error()
        .assert_type(SetErrorType::TooLarge)
        .assert_description_contains(COUNT_ERROR);
    response
        .not_created(1)
        .to_set_error()
        .assert_type(SetErrorType::TooLarge)
        .assert_description_contains(SIZE_ERROR);
    response.created(2);
}

async fn set_header_limits(admin: &Account, limits: Email) {
    admin
        .registry_update_setting(limits, &[Property::MaxHeaderSize, Property::MaxHeaderCount])
        .await;
    admin.reload_settings().await;
}
