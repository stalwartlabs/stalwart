/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{jmap::JmapUtils, server::TestServer, smtp::SmtpConnection};
use common::{
    auth::{
        ACCOUNT_FLAG_ENCRYPT_ALGO_AES128, ACCOUNT_FLAG_ENCRYPT_ALGO_AES256,
        ACCOUNT_FLAG_ENCRYPT_METHOD_PGP, ACCOUNT_FLAG_ENCRYPT_METHOD_SMIME,
    },
    storage::encryption::{EncryptionMethod, parse_public_key},
};
use email::message::crypto::EncryptMessage;
use mail_parser::{MessageParser, MimeHeaders};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{EncryptionAtRest, EncryptionSettings, PublicKey},
};
use serde_json::json;
use std::path::PathBuf;
use types::id::Id;

pub async fn test(test: &mut TestServer) {
    println!("Running Encryption-at-rest tests...");

    // Check encryption
    check_is_encrypted();
    import_certs_and_encrypt().await;

    // Create test account
    let account = test
        .create_user_account(
            "admin@example.org",
            "jdoe@example.org",
            "this is a very strong password",
            &[],
            "jdoe@example.org",
        )
        .await;
    let client = account.jmap_client().await;

    // Import all certs
    let mut cert_ids = Vec::new();
    let mut certs_parsed = Vec::new();
    for cert_file in ["cert_smime.pem", "cert_pgp.pem"] {
        let certs = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("crypto")
                .join(cert_file),
        )
        .unwrap();

        let params = parse_public_key(&PublicKey {
            description: cert_file.to_string(),
            key: certs.clone(),
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        certs_parsed.push(params.certs);

        let cert_id = account
            .registry_create_many(
                ObjectType::PublicKey,
                [json!({
                    Property::Description: "This is a public key",
                    Property::Key: certs
                })],
            )
            .await
            .created(0)
            .object_id();

        cert_ids.push(cert_id);
    }

    // Update encryption at rest settings
    account
        .registry_update_object(
            ObjectType::AccountSettings,
            Id::singleton(),
            json!({
                Property::EncryptionAtRest: EncryptionAtRest::Aes256(EncryptionSettings {
                    allow_spam_training: true,
                    encrypt_on_append: true,
                    public_key: cert_ids[1],
                })
            }),
        )
        .await;
    assert_eq!(
        test.server
            .account(account.id().document_id())
            .await
            .unwrap()
            .encryption_key
            .as_ref()
            .unwrap(),
        &certs_parsed[1]
    );

    // Send a new message, which should be encrypted
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.org",
        &["jdoe@example.org"],
        concat!(
            "From: bill@example.org\r\n",
            "To: jdoe@example.org\r\n",
            "Subject: TPS Report (should be encrypted)\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;

    // Send an encrypted message
    lmtp.ingest(
        "bill@example.org",
        &["jdoe@example.org"],
        concat!(
            "From: bill@example.org\r\n",
            "To: jdoe@example.org\r\n",
            "Subject: TPS Report (already encrypted)\r\n",
            "Content-Type: application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data\r\n",
            "\r\n",
            "xjMEZMYfNhYJKwYBBAHaRw8BAQdAYyTN1HzqapLw8xwkCGwa0OjsgT/JqhcB/+Dy",
            "Ga1fsBrNG0pvaG4gRG9lIDxqb2huQGV4YW1wbGUub3JnPsKJBBMWCAAxFiEEg836",
            "pwbXpuQ/THMtpJwd4oBfIrUFAmTGHzYCGwMECwkIBwUVCAkKCwUWAgMBAAAKCRCk",
            "nB3igF8itYhyAQD2jEdeYa3gyQ47X9YWZTK1wEJkN8W9//V1fYl2XQwqlQEA0qBv",
            "Ai6nUh99oDw+/zQ8DFIKdeb5Ti4tu/X58PdpiQ7OOARkxh82EgorBgEEAZdVAQUB",
            "AQdAvXz2FbFN0DovQF/ACnZyczTsSIQp0mvmF1PE+aijbC8DAQgHwngEGBYIACAW",
            "IQSDzfqnBtem5D9Mcy2knB3igF8itQUCZMYfNgIbDAAKCRCknB3igF8itRnoAQC3",
            "GzPmgx7TnB+SexPuJV/DoKSMJ0/X+hbEFcZkulxaDQEAh+xiJCvf+ZNAKw6kFhsL",
            "UuZhEDktxnY6Ehz3aB7FawA=",
            "=KGrr",
        ),
    )
    .await;

    // Disable encryption
    account
        .registry_update_object(
            ObjectType::AccountSettings,
            Id::singleton(),
            json!({
                Property::EncryptionAtRest: EncryptionAtRest::Disabled
            }),
        )
        .await;

    // Send a new message, which should NOT be encrypted
    lmtp.ingest(
        "bill@example.org",
        &["jdoe@example.org"],
        concat!(
            "From: bill@example.org\r\n",
            "To: jdoe@example.org\r\n",
            "Subject: TPS Report (plain text)\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;

    // Check messages
    let mut request = client.build();
    request.get_email();
    let emails = request.send_get_email().await.unwrap().take_list();
    assert_eq!(emails.len(), 3, "3 messages were expected: {:#?}.", emails);

    for email in emails {
        let message =
            String::from_utf8(client.download(email.blob_id().unwrap()).await.unwrap()).unwrap();
        if message.contains("should be encrypted") {
            assert!(
                message.contains("Content-Type: multipart/encrypted"),
                "got message {message}, expected encrypted message"
            );
        } else if message.contains("already encrypted") {
            assert!(
                message.contains("Content-Type: application/pkcs7-mime")
                    && message.contains("xjMEZMYfNhYJKwYBBAHaRw8BAQdAYy"),
                "got message {message}, expected message to be left intact"
            );
        } else if message.contains("plain text") {
            assert!(
                message.contains("I'm going to need those TPS reports ASAP."),
                "got message {message}, expected plain text message"
            );
        } else {
            panic!("Unexpected message: {:#?}", message)
        }
    }

    test.account("admin@example.org")
        .destroy_account(account)
        .await;
    test.cleanup().await;
}

pub async fn import_certs_and_encrypt() {
    for (name, method) in [
        ("cert_pgp.pem", EncryptionMethod::PGP),
        //("cert_pgp.der", EncryptionMethod::PGP),
        ("cert_smime.pem", EncryptionMethod::SMIME),
        //("cert_smime.der", EncryptionMethod::SMIME),
    ] {
        let pk = PublicKey {
            description: name.to_string(),
            key: String::from_utf8(
                std::fs::read(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("resources")
                        .join("crypto")
                        .join(name),
                )
                .unwrap(),
            )
            .unwrap(),
            ..Default::default()
        };

        let params = parse_public_key(&pk).unwrap().unwrap();
        assert_eq!(params.method, method);

        for mut flags in [
            ACCOUNT_FLAG_ENCRYPT_ALGO_AES128,
            ACCOUNT_FLAG_ENCRYPT_ALGO_AES256,
        ] {
            let message = MessageParser::new()
                .parse(b"Subject: test\r\ntest\r\n")
                .unwrap();
            assert!(!message.is_encrypted());
            flags |= match method {
                EncryptionMethod::PGP => ACCOUNT_FLAG_ENCRYPT_METHOD_PGP,
                EncryptionMethod::SMIME => ACCOUNT_FLAG_ENCRYPT_METHOD_SMIME,
            };
            message.encrypt(&params.certs, flags).await.unwrap();
        }
    }

    // S/MIME and PGP should not be allowed mixed
    assert!(
        parse_public_key(&PublicKey {
            description: "err".into(),
            key: String::from_utf8(
                std::fs::read(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("resources")
                        .join("crypto")
                        .join("cert_mixed.pem"),
                )
                .unwrap()
            )
            .unwrap(),
            ..Default::default()
        })
        .is_err()
    );
}

pub fn check_is_encrypted() {
    let messages = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("crypto")
            .join("is_encrypted.txt"),
    )
    .unwrap();

    for raw_message in messages.split("!!!") {
        let is_encrypted = raw_message.contains("TRUE");
        let message = MessageParser::new()
            .parse(raw_message.trim().as_bytes())
            .unwrap();
        assert!(message.content_type().is_some());
        assert_eq!(
            message.is_encrypted(),
            is_encrypted,
            "failed for {raw_message}"
        );
    }
}
