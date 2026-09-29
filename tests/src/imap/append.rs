/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AssertResult, ImapConnection, Type, resources_dir};
use crate::utils::server::TestServer;
use imap_proto::ResponseType;
use registry::schema::{prelude::Property, structs::Email};
use std::{fs, io};

const APPEND_INTERNALDATE: &str = "01-Jan-2024 00:00:00 +0000";
const MAX_HEADER_SIZE: u64 = 1024;
const MAX_HEADER_COUNT: u64 = 100;

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection, test: &TestServer) {
    println!("Running APPEND tests...");

    // Invalid APPEND commands
    imap.send("APPEND \"Does not exist\" {1+}\r\na").await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("TRYCREATE");

    header_limits(test).await;

    // Import test messages
    let mut entries = fs::read_dir(resources_dir())
        .unwrap()
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()
        .unwrap();

    entries.sort();

    let mut expected_uid = 1;
    for file_name in entries.into_iter().take(20) {
        if file_name.extension().is_none_or(|e| e != "txt") {
            continue;
        }
        let raw_message = fs::read(&file_name).unwrap();

        imap.send(&format!(
            "APPEND INBOX (Flag_{}) \"{}\" {{{}}}",
            file_name
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .split_once('.')
                .unwrap()
                .0,
            APPEND_INTERNALDATE,
            raw_message.len()
        ))
        .await;
        imap.assert_read(Type::Continuation, ResponseType::Ok).await;
        imap.send_untagged(std::str::from_utf8(&raw_message).unwrap())
            .await;
        let result = imap
            .assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_response_code();
        let mut code = result.split(' ');
        assert_eq!(code.next(), Some("APPENDUID"));
        assert_ne!(code.next(), Some("0"));
        assert_eq!(code.next(), Some(expected_uid.to_string().as_str()));
        expected_uid += 1;
    }

    test.wait_for_tasks().await;
}

async fn header_limits(test: &TestServer) {
    let admin = test.account("admin@example.com");
    admin
        .registry_update_setting(
            Email {
                max_header_size: MAX_HEADER_SIZE,
                max_header_count: MAX_HEADER_COUNT,
                ..Default::default()
            },
            &[Property::MaxHeaderSize, Property::MaxHeaderCount],
        )
        .await;
    admin.reload_settings().await;

    let account = test.account("jdoe@example.com");
    let mut imap = ImapConnection::connect(b"_h ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    imap.authenticate(account.name(), account.secret()).await;

    let within = "Subject: within\r\n\r\nbody\r\n";
    let too_many_fields = format!(
        "Subject: count\r\n{}\r\nbody\r\n",
        "X: y\r\n".repeat(MAX_HEADER_COUNT as usize)
    );
    let too_large = format!(
        "Subject: {}\r\n\r\nbody\r\n",
        "s".repeat(MAX_HEADER_SIZE as usize)
    );
    for (message, details) in [
        (too_many_fields.as_str(), "more than 100 fields"),
        (too_large.as_str(), "cannot exceed 1024 bytes"),
    ] {
        imap.send(&format!("APPEND INBOX {{{}+}}\r\n{message}", message.len()))
            .await;
        imap.assert_read(Type::Tagged, ResponseType::No)
            .await
            .assert_response_code("LIMIT")
            .assert_contains(details);
    }
    imap.send(&format!(
        "APPEND INBOX {{{}+}}\r\n{too_large} {{{}+}}\r\n{within}",
        too_large.len(),
        within.len()
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("LIMIT");
    imap.send("STATUS INBOX (MESSAGES)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 0");

    admin
        .registry_update_setting(
            Email::default(),
            &[Property::MaxHeaderSize, Property::MaxHeaderCount],
        )
        .await;
    admin.reload_settings().await;
}

pub async fn assert_append_message(
    imap: &mut ImapConnection,
    folder: &str,
    message: &str,
    expected_response: ResponseType,
) -> Vec<String> {
    imap.send(&format!("APPEND \"{}\" {{{}}}", folder, message.len()))
        .await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged(message).await;
    imap.assert_read(Type::Tagged, expected_response).await
}

fn build_message(message: usize, in_reply_to: Option<usize>, thread_num: usize) -> String {
    if let Some(in_reply_to) = in_reply_to {
        format!(
            "Message-ID: <{}@domain>\nReferences: <{}@domain>\nSubject: re: T{}\n\nreply\n",
            message, in_reply_to, thread_num
        )
    } else {
        format!(
            "Message-ID: <{}@domain>\nSubject: T{}\n\nmsg\n",
            message, thread_num
        )
    }
}

pub fn build_messages() -> Vec<String> {
    let mut messages = Vec::new();
    for parent in 0..3 {
        messages.push(build_message(parent, None, parent));
        for child in 0..3 {
            messages.push(build_message(
                ((parent + 1) * 10) + child,
                parent.into(),
                parent,
            ));
        }
    }
    messages
}
