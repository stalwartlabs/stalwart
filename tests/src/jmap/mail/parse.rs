/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{JMAPTest, mail::get::all_headers, replace_blob_ids};
use jmap_client::{
    email::{self, Header, HeaderForm},
    mailbox::Role,
};
use std::{fs, path::PathBuf};

pub async fn test(params: &mut JMAPTest) {
    println!("Running Email Parse tests...");
    let account = params.account("jdoe@example.com");
    let client = account.client();

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
    for test_name in ["attachment.eml", "attachment_b64.eml"] {
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

        let email = client
            .email_parse(
                &blob_id,
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

        if !test_name.contains("_b64") {
            for parts in [
                email.text_body().unwrap(),
                email.html_body().unwrap(),
                email.attachments().unwrap(),
            ] {
                for part in parts {
                    let blob_id = part.blob_id().unwrap();

                    let inner_blob = client.download(blob_id).await.unwrap();

                    test_file.set_extension(format!("part{}", part.part_id().unwrap()));

                    //fs::write(&test_file, inner_blob).unwrap();
                    let expected_inner_blob = fs::read(&test_file).unwrap();

                    assert_eq!(
                        inner_blob,
                        expected_inner_blob,
                        "file: {}",
                        test_file.display()
                    );
                }
            }
        }

        test_file.set_extension("json");

        let result = replace_blob_ids(serde_json::to_string_pretty(&email.into_test()).unwrap());

        if fs::read(&test_file).unwrap() != result.as_bytes() {
            test_file.set_extension("failed");
            fs::write(&test_file, result.as_bytes()).unwrap();
            panic!("Test failed, output saved to {}", test_file.display());
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

    params.destroy_all_mailboxes(account).await;
    params.assert_is_empty().await;
}
