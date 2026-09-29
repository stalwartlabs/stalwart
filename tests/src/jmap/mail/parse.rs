/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{mail::get::all_headers, replace_blob_ids},
    utils::server::TestServer,
};
use jmap_client::{
    client::Client,
    email::{self, Email, Header, HeaderForm},
    mailbox::Role,
};
use std::{fs, path::PathBuf, str::FromStr};
use types::blob::BlobId;

pub async fn test(test: &TestServer) {
    println!("Running Email Parse tests...");
    let account = test.account("jdoe@example.com");
    let client = account.jmap_client().await;

    let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("resources");
    test_dir.push("jmap");
    test_dir.push("email_parse");

    let mailbox_id = client
        .mailbox_create("JMAP Parse", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    // Test parsing an email attachment
    for test_name in [
        "attachment.eml",
        "attachment_b64.eml",
        "attachment_b64_nested.eml",
    ] {
        let mut test_file = test_dir.clone();
        test_file.push(test_name);

        let email = client
            .email_import(
                fs::read(&test_file).unwrap(),
                [mailbox_id.clone()],
                None::<Vec<String>>,
                None,
            )
            .await
            .unwrap();

        let blob_id = client
            .email_get(email.id().unwrap(), Some([email::Property::Attachments]))
            .await
            .unwrap()
            .unwrap()
            .attachments()
            .unwrap()
            .first()
            .unwrap()
            .blob_id()
            .unwrap()
            .to_string();

        let email = parse_and_compare(&client, &blob_id, test_file).await;

        if test_name == "attachment_b64_nested.eml" {
            let nested_blob_id = email
                .attachments()
                .unwrap()
                .iter()
                .find(|part| part.content_type() == Some("message/rfc822"))
                .unwrap()
                .blob_id()
                .unwrap()
                .to_string();
            let inner = parse_and_compare(
                &client,
                &nested_blob_id,
                test_dir.join("attachment_b64_nested_inner.eml"),
            )
            .await;

            let containers = |blob_id: &str| {
                BlobId::from_str(blob_id)
                    .ok()
                    .and_then(|blob_id| blob_id.section)
                    .map(|section| section.containers().len())
            };
            assert_eq!(containers(&nested_blob_id), Some(1), "{nested_blob_id}");
            for part in inner
                .text_body()
                .unwrap()
                .iter()
                .chain(inner.html_body().unwrap())
            {
                let part_blob_id = part.blob_id().unwrap();
                assert_eq!(containers(part_blob_id), Some(2), "{part_blob_id}");
            }

            let other = test.account("jane.smith@example.com").jmap_client().await;
            let mut blob_ids = vec![blob_id, nested_blob_id];
            for parts in [
                inner.text_body().unwrap(),
                inner.html_body().unwrap(),
                email.text_body().unwrap(),
            ] {
                blob_ids.extend(parts.iter().map(|part| part.blob_id().unwrap().to_string()));
            }
            for blob_id in &blob_ids {
                assert!(client.download(blob_id).await.is_ok(), "{blob_id}");
                assert!(other.download(blob_id).await.is_err(), "{blob_id}");
            }
        }
    }

    // Test header parsing on a temporary blob
    let mut test_file = test_dir;
    test_file.push("headers.eml");
    let blob_id = client
        .upload(None, fs::read(&test_file).unwrap(), None)
        .await
        .unwrap()
        .take_blob_id();

    let mut email = client
        .email_parse(
            &blob_id,
            [
                email::Property::Id,
                email::Property::MessageId,
                email::Property::InReplyTo,
                email::Property::References,
                email::Property::Sender,
                email::Property::From,
                email::Property::To,
                email::Property::Cc,
                email::Property::Bcc,
                email::Property::ReplyTo,
                email::Property::Subject,
                email::Property::SentAt,
                email::Property::Preview,
                email::Property::TextBody,
                email::Property::HtmlBody,
                email::Property::Attachments,
            ]
            .into(),
            [
                email::BodyProperty::Size,
                email::BodyProperty::Name,
                email::BodyProperty::Type,
                email::BodyProperty::Charset,
                email::BodyProperty::Disposition,
                email::BodyProperty::Cid,
                email::BodyProperty::Language,
                email::BodyProperty::Location,
                email::BodyProperty::Header(Header {
                    name: "X-Custom-Header".into(),
                    form: HeaderForm::Raw,
                    all: false,
                }),
                email::BodyProperty::Header(Header {
                    name: "X-Custom-Header-2".into(),
                    form: HeaderForm::Raw,
                    all: false,
                }),
            ]
            .into(),
            100.into(),
        )
        .await
        .unwrap()
        .into_test();

    for property in all_headers() {
        email.headers.extend(
            client
                .email_parse(&blob_id, [property].into(), [].into(), None)
                .await
                .unwrap()
                .into_test()
                .headers,
        );
    }

    test_file.set_extension("json");

    let result = replace_blob_ids(serde_json::to_string_pretty(&email).unwrap());

    if fs::read(&test_file).unwrap() != result.as_bytes() {
        test_file.set_extension("failed");
        fs::write(&test_file, result.as_bytes()).unwrap();
        panic!("Test failed, output saved to {}", test_file.display());
    }

    test.destroy_all_mailboxes(account).await;
    test.assert_is_empty().await;
}

async fn parse_and_compare(client: &Client, blob_id: &str, mut test_file: PathBuf) -> Email {
    let email = client
        .email_parse(
            blob_id,
            [
                email::Property::Id,
                email::Property::BlobId,
                email::Property::ThreadId,
                email::Property::MailboxIds,
                email::Property::Keywords,
                email::Property::Size,
                email::Property::ReceivedAt,
                email::Property::MessageId,
                email::Property::InReplyTo,
                email::Property::References,
                email::Property::Sender,
                email::Property::From,
                email::Property::To,
                email::Property::Cc,
                email::Property::Bcc,
                email::Property::ReplyTo,
                email::Property::Subject,
                email::Property::SentAt,
                email::Property::HasAttachment,
                email::Property::Preview,
                email::Property::BodyValues,
                email::Property::TextBody,
                email::Property::HtmlBody,
                email::Property::Attachments,
                email::Property::BodyStructure,
            ]
            .into(),
            [
                email::BodyProperty::PartId,
                email::BodyProperty::BlobId,
                email::BodyProperty::Size,
                email::BodyProperty::Name,
                email::BodyProperty::Type,
                email::BodyProperty::Charset,
                email::BodyProperty::Headers,
                email::BodyProperty::Disposition,
                email::BodyProperty::Cid,
                email::BodyProperty::Language,
                email::BodyProperty::Location,
            ]
            .into(),
            100.into(),
        )
        .await
        .unwrap();

    for parts in [
        email.text_body().unwrap(),
        email.html_body().unwrap(),
        email.attachments().unwrap(),
    ] {
        for part in parts {
            let inner_blob = client.download(part.blob_id().unwrap()).await.unwrap();

            test_file.set_extension(format!("part{}", part.part_id().unwrap()));

            let expected_inner_blob = fs::read(&test_file).unwrap();

            assert_eq!(
                inner_blob,
                expected_inner_blob,
                "file: {}",
                test_file.display()
            );
        }
    }

    test_file.set_extension("json");

    let result =
        replace_blob_ids(serde_json::to_string_pretty(&email.clone().into_test()).unwrap());

    if fs::read(&test_file).ok().as_deref() != Some(result.as_bytes()) {
        test_file.set_extension("failed");
        fs::write(&test_file, result.as_bytes()).unwrap();
        panic!("Test failed, output saved to {}", test_file.display());
    }

    email
}
