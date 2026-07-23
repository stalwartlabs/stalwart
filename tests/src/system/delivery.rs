/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    account::Account, imap::AssertResult, jmap::JmapUtils, server::TestServer, smtp::SmtpConnection,
};
use common::{Server, auth::BuildAccessToken};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::{INBOX_ID, JUNK_ID, SENT_ID},
    message::metadata::MessageMetadata,
};
use groupware::DavResourceName;
use jmap::blob::download::BlobDownload;
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::StorageQuota,
        prelude::{ObjectType, Property},
        structs::{
            EmailAlias, Expression, MailingList, MtaExtensions, SpamTag, SpamTagScore,
            SpamTrainingSample,
        },
    },
    types::{EnumImpl, datetime::UTCDateTime, float::Float, list::List, map::Map},
};
use serde_json::json;
use std::time::Duration;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, now},
};
use types::{
    blob::{BlobClass, BlobId},
    collection::Collection,
    field::EmailField,
    id::Id,
};
use utils::chained_bytes::ChainedBytes;

pub async fn test(test: &mut TestServer) {
    println!("Running Email delivery tests...");
    let admin = test.account("admin@example.org");

    // Prepare tests
    admin
        .registry_create_object(SpamTag::Score(SpamTagScore {
            score: Float::new(1000.0),
            tag: "GTUBE_TEST".to_string(),
        }))
        .await;
    admin
        .registry_update_setting(
            MtaExtensions {
                expn: Expression {
                    else_: "true".to_string(),
                    ..Default::default()
                },
                vrfy: Expression {
                    else_: "true".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            &[Property::Expn, Property::Vrfy],
        )
        .await;
    admin.reload_settings().await;

    // Create a domain name and a test account
    let john = test
        .create_user_account(
            "admin@example.org",
            "jdoe@example.org",
            "this is a very strong password",
            &["john.doe@example.org"],
            "jdoe@example.org",
        )
        .await;
    let jane = test
        .create_user_account(
            "admin@example.org",
            "jane.smith@example.org",
            "this is a very strong password",
            &[],
            "jane.smith@example.org",
        )
        .await;
    let bill = test
        .create_user_account(
            "admin@example.org",
            "bill@example.org",
            "this is a very strong password",
            &[],
            "bill@example.org",
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            john.id(),
            json!({
                Property::Quotas: {StorageQuota::MaxMaskedAddresses.as_str(): 2}
            }),
        )
        .await;

    // Create a mailing list
    let domain_id = admin.find_or_create_domain("example.org").await;
    let list_id = admin
        .registry_create_object(MailingList {
            name: "members".to_string(),
            recipients: Map::new(vec![
                "jdoe@example.org".to_string(),
                "jane.smith@example.org".to_string(),
                "bill@example.org".to_string(),
            ]),
            aliases: List::from_iter([EmailAlias {
                name: "corporate".to_string(),
                domain_id,
                enabled: true,
                ..Default::default()
            }]),
            domain_id,
            ..Default::default()
        })
        .await;

    // Delivering to individuals
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.org",
        &["jdoe@example.org"],
        concat!(
            "From: bill@example.org\r\n",
            "To: jdoe@example.org\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;

    let john_cache = test
        .server
        .get_cached_messages(john.id().document_id())
        .await
        .unwrap();

    assert_eq!(john_cache.emails.items.len(), 1);
    assert_eq!(john_cache.in_mailbox(INBOX_ID).count(), 1);
    assert_eq!(john_cache.in_mailbox(JUNK_ID).count(), 0);

    // Make sure there are no spam training samples
    admin
        .registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    assert!(
        admin
            .registry_query(
                ObjectType::SpamTrainingSample,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .ids()
            .next()
            .is_none()
    );

    // Masked email tests
    john.registry_create_many(
        ObjectType::MaskedEmail,
        [json!({
            Property::EmailDomain: "invalid.org"
        })],
    )
    .await
    .not_created(0)
    .to_set_error()
    .assert_type(SetErrorType::Forbidden)
    .assert_description_contains("The specified domain is not valid for this account.");

    let response = john
        .registry_create_many(
            ObjectType::MaskedEmail,
            [json!({
                Property::EmailDomain: "example.org",
                Property::EmailPrefix: "secretive",
                Property::ExpiresAt: UTCDateTime::from_timestamp((now() + 1) as i64)
            })],
        )
        .await;
    let masked = response.created(0);
    let masked_prefix_id = masked.object_id();
    let masked_prefix_email = masked.text_field("email").to_string();
    assert!(
        masked_prefix_email.starts_with("secretive")
            && masked_prefix_email.ends_with("@example.org"),
        "Unexpected masked email: {masked_prefix_email}"
    );

    let response = john
        .registry_create_many(
            ObjectType::MaskedEmail,
            [json!({
                Property::EmailDomain: "example.org",
            })],
        )
        .await;
    let masked = response.created(0);
    let masked_random_id = masked.object_id();
    let masked_random_email = masked.text_field("email").to_string();
    assert!(
        masked_random_email.contains(".") && masked_random_email.ends_with("@example.org"),
        "Unexpected masked email: {masked_random_email}"
    );

    john.registry_create_many(
        ObjectType::MaskedEmail,
        [json!({
            Property::EmailDomain: "example.org",
        })],
    )
    .await
    .not_created(0)
    .to_set_error()
    .assert_type(SetErrorType::OverQuota);

    // Test spam filtering using masked email
    lmtp.ingest(
        "bill@example.org",
        &[masked_prefix_email.as_str()],
        concat!(
            "From: bill@example.org\r\n",
            "To: john.doe@example.org\r\n",
            "Subject: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n",
            "\r\n",
            "--- Forwarded Message ---\r\n\r\n ",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    let john_cache = test
        .server
        .get_cached_messages(john.id().document_id())
        .await
        .unwrap();
    let inbox_ids = john_cache
        .in_mailbox(INBOX_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    let junk_ids = john_cache
        .in_mailbox(JUNK_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    assert_eq!(john_cache.emails.items.len(), 2);
    assert_eq!(inbox_ids.len(), 1);
    assert_eq!(junk_ids.len(), 1);
    assert_message_headers_contains(
        &test.server,
        john.id().document_id(),
        junk_ids.min().unwrap(),
        "X-Spam-Status: Yes",
    )
    .await;
    assert_eq!(john.spam_training_samples().await, vec![]);

    // CardDAV spam override, using masked email
    let dav_client = john.webdav_client();
    dav_client
        .request(
            "PUT",
            &format!(
                "{}/jdoe%40example.org/default/bill.vcf",
                DavResourceName::Card.base_path()
            ),
            r#"BEGIN:VCARD
VERSION:4.0
FN:Bill Foobar
EMAIL;TYPE=WORK:dmarc-bill@example.org
UID:urn:uuid:e1ee798b-3d4c-41b0-b217-b9c918e4686f
END:VCARD
"#,
        )
        .await
        .with_status(hyper::StatusCode::CREATED);
    lmtp.ingest(
        "dmarc-bill@example.org",
        &[masked_random_email.as_str()],
        concat!(
            "From: dmarc-bill@example.org\r\n",
            "To: john.doe@example.org\r\n",
            "Subject: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n",
            "\r\n",
            "--- Forwarded Message ---\r\n\r\n ",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    let john_cache = test
        .server
        .get_cached_messages(john.id().document_id())
        .await
        .unwrap();
    let inbox_ids = john_cache
        .in_mailbox(INBOX_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    let junk_ids = john_cache
        .in_mailbox(JUNK_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    assert_eq!(john_cache.emails.items.len(), 3);
    assert_eq!(inbox_ids.len(), 2);
    assert_eq!(junk_ids.len(), 1);
    dav_client.delete_default_containers().await;
    assert_message_headers_contains(
        &test.server,
        john.id().document_id(),
        inbox_ids.max().unwrap(),
        "X-Spam-Status: No, reason=card-exists",
    )
    .await;
    let samples = john.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 1);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 0);

    // Test trusted reply override
    john.jmap_client()
        .await
        .email_import(
            concat!(
                "From: john.doe@example.org\r\n",
                "To: dmarc-bill@example.org\r\n",
                "Message-ID: <trusted@message-id.example.org>\r\n",
                "Subject: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n",
                "\r\n",
                "This is a trusted reply."
            )
            .as_bytes()
            .to_vec(),
            vec![Id::from(SENT_ID).to_string()],
            None::<Vec<String>>,
            None,
        )
        .await
        .unwrap()
        .take_id();
    assert_eq!(
        test.server
            .get_cached_messages(john.id().document_id())
            .await
            .unwrap()
            .emails
            .items
            .len(),
        4
    );
    lmtp.ingest(
        "dmarc-bill@example.org",
        &["john.doe@example.org"],
        concat!(
            "From: dmarc-bill@example.org\r\n",
            "To: john.doe@example.org\r\n",
            "Message-ID: <other@message-id.example.org>\r\n",
            "References: <trusted@message-id.example.org>\r\n",
            "Subject: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n",
            "\r\n",
            "--- Forwarded Message ---\r\n\r\n ",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    let john_cache = test
        .server
        .get_cached_messages(john.id().document_id())
        .await
        .unwrap();
    let inbox_ids = john_cache
        .in_mailbox(INBOX_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    let junk_ids = john_cache
        .in_mailbox(JUNK_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    assert_eq!(john_cache.emails.items.len(), 5);
    assert_eq!(inbox_ids.len(), 3);
    assert_eq!(junk_ids.len(), 1);
    assert_message_headers_contains(
        &test.server,
        john.id().document_id(),
        inbox_ids.max().unwrap(),
        "X-Spam-Status: No, reason=trusted-reply",
    )
    .await;
    let samples = john.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 2);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 0);

    // EXPN and VRFY
    lmtp.expn("members@example.org", 2)
        .await
        .assert_contains("jdoe@example.org")
        .assert_contains("jane.smith@example.org")
        .assert_contains("bill@example.org");
    lmtp.expn("non_existant@example.org", 5).await;
    lmtp.expn("jdoe@example.org", 5).await;
    lmtp.vrfy("jdoe@example.org", 2).await;
    lmtp.vrfy("members@example.org", 5).await;
    lmtp.vrfy("non_existant@example.org", 5).await;
    lmtp.vrfy(masked_random_email.as_str(), 2).await;
    lmtp.vrfy(masked_prefix_email.as_str(), 5).await; // Should have expired

    // Delivering to a mailing list
    lmtp.ingest(
        "bill@example.org",
        &["members@example.org"],
        concat!(
            "From: bill@example.org\r\n",
            "To: members@example.org\r\n",
            "Subject: WFH policy\r\n",
            "\r\n",
            "We need the entire staff back in the office, ",
            "TPS reports cannot be filed properly from home."
        ),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    for (account, num_messages) in [(&john, 6), (&jane, 1), (&bill, 1)] {
        assert_eq!(
            test.server
                .get_cached_messages(account.id().document_id())
                .await
                .unwrap()
                .emails
                .items
                .len(),
            num_messages,
            "for {}",
            account.id_string()
        );
    }

    // Removing members from the mailing list and chunked ingest
    admin
        .registry_update_object(
            ObjectType::MailingList,
            list_id,
            json!({
                "recipients/jdoe@example.org": false
            }),
        )
        .await;
    lmtp.ingest_chunked(
        "bill@example.org",
        &["members@example.org"],
        concat!(
            "From: bill@example.org\r\n",
            "To: members@example.org\r\n",
            "Subject: WFH policy (reminder)\r\n",
            "\r\n",
            "This is a reminder that we need the entire staff back in the office, ",
            "TPS reports cannot be filed properly from home."
        ),
        10,
    )
    .await;

    for (account, num_messages) in [(&john, 6), (&jane, 2), (&bill, 2)] {
        assert_eq!(
            test.server
                .get_cached_messages(account.id().document_id())
                .await
                .unwrap()
                .emails
                .items
                .len(),
            num_messages,
            "for {}",
            account.id_string()
        );
    }

    // Deduplication of recipients
    lmtp.ingest(
        "bill@example.org",
        &[
            "members@example.org",
            "jdoe@example.org",
            "john.doe@example.org",
            "jane.smith@example.org",
            "bill@example.org",
        ],
        concat!(
            "From: bill@example.org\r\n",
            "Bcc: Undisclosed recipients;\r\n",
            "Subject: Holidays\r\n",
            "\r\n",
            "Remember to file your TPS reports before ",
            "going on holidays."
        ),
    )
    .await;

    // Make sure blobs are properly linked
    test.blob_expire_all().await;

    for (account, num_messages) in [(&john, 7), (&jane, 3), (&bill, 3)] {
        let account_id = account.id().document_id();
        let cache = test.server.get_cached_messages(account_id).await.unwrap();
        assert_eq!(
            cache.emails.items.len(),
            num_messages,
            "for {}",
            account.id_string()
        );
        let access_token = test.server.access_token(account_id).await.unwrap().build();

        for document_id in cache.in_mailbox(INBOX_ID).map(|e| e.document_id) {
            let metadata = message_metadata(&test.server, account_id, document_id).await;
            let partial_message = test
                .server
                .blob_store()
                .get_blob(metadata.blob_hash.0.as_ref(), 0..usize::MAX)
                .await
                .unwrap()
                .unwrap();

            assert_ne!(metadata.blob_body_offset, 0);
            let expected_full_message = String::from_utf8(
                ChainedBytes::new(metadata.raw_headers.as_ref())
                    .with_last(
                        partial_message
                            .get(metadata.blob_body_offset as usize..)
                            .unwrap_or_default(),
                    )
                    .to_bytes(),
            )
            .unwrap();
            assert!(
                expected_full_message.contains("Delivered-To:")
                    && expected_full_message.contains("Subject:"),
                "for {account_id}: {expected_full_message}"
            );
            let full_message = String::from_utf8(
                test.server
                    .blob_download(
                        &BlobId {
                            hash: metadata.blob_hash,
                            class: BlobClass::Linked {
                                account_id,
                                collection: Collection::Email.into(),
                                document_id,
                            },
                            section: None,
                        },
                        &access_token,
                    )
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(full_message, expected_full_message, "for {account_id}");
        }
    }

    // Remove test data
    john.registry_destroy(
        ObjectType::MaskedEmail,
        [masked_prefix_id, masked_random_id],
    )
    .await
    .assert_destroyed(&[masked_prefix_id, masked_random_id]);
    for account in [&john, &jane, &bill] {
        test.destroy_all_mailboxes(account).await;
    }
    admin.registry_destroy_all(ObjectType::MailingList).await;
    admin
        .registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    admin.registry_destroy_all(ObjectType::SpamTag).await;
    test.assert_is_empty().await;

    for account in [john, jane, bill] {
        admin.destroy_account(account).await;
    }

    test.cleanup().await;
}

impl Account {
    pub async fn spam_training_sample_ids(&self) -> Vec<Id> {
        self.registry_query_ids(
            ObjectType::SpamTrainingSample,
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
        .await
    }

    pub async fn spam_training_samples(&self) -> Vec<(Id, SpamTrainingSample)> {
        self.registry_get_all().await
    }
}

async fn assert_message_headers_contains(
    server: &Server,
    account_id: u32,
    document_id: u32,
    value: &str,
) {
    let headers = message_headers(server, account_id, document_id).await;
    assert!(
        headers.contains(value),
        "Expected message headers to contain {:?}, got {:?}",
        value,
        headers
    );
}

async fn message_headers(server: &Server, account_id: u32, document_id: u32) -> String {
    std::str::from_utf8(
        message_metadata(server, account_id, document_id)
            .await
            .raw_headers
            .as_ref(),
    )
    .unwrap()
    .to_string()
}

async fn message_metadata(server: &Server, account_id: u32, document_id: u32) -> MessageMetadata {
    server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await
        .unwrap()
        .unwrap()
        .deserialize::<MessageMetadata>()
        .unwrap()
}
