/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::smtp::{QueueReceiver, TestSMTP, inbound::sign::SIGNATURES};
use common::config::smtp::queue::{QueueExpiry, QueueName};
use smtp::queue::{
    Error, ErrorDetails, HostResponse, Message, MessageWrapper, Recipient, Schedule, Status,
    UnexpectedResponse, dsn::SendDsn,
};
use smtp_proto::{RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_SUCCESS, Response};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::SystemTime,
};
use store::write::now;
use types::blob_hash::BlobHash;

const CONFIG: &str = r#"
[report]
submitter = "'mx.example.org'"

[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

[report.dsn]
from-name = "'Mail Delivery Subsystem'"
from-address = "'MAILER-DAEMON@example.org'"
sign = "['rsa']"

"#;

#[tokio::test]
async fn generate_dsn() {
    // Enable logging
    crate::enable_logging();

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("smtp");
    path.push("dsn");
    path.push("original.txt");
    let size = fs::metadata(&path).unwrap().len() as u64;
    let dsn_original = fs::read_to_string(&path).unwrap();

    let flags = RCPT_NOTIFY_FAILURE | RCPT_NOTIFY_DELAY | RCPT_NOTIFY_SUCCESS;
    let mut message = MessageWrapper {
        queue_id: 0,
        span_id: 0,
        is_multi_queue: false,
        queue_name: QueueName::default(),
        message: Message {
            size,
            created: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            return_path: "sender@foobar.org".into(),
            recipients: vec![Recipient {
                address: "foobar@example.org".into(),
                status: Status::PermanentFailure(ErrorDetails {
                    entity: "mx.example.org".into(),
                    details: Error::UnexpectedResponse(UnexpectedResponse {
                        command: "RCPT TO:<foobar@example.org>".into(),
                        response: Response {
                            code: 550,
                            esc: [5, 1, 2],
                            message: "User does not exist".into(),
                        },
                    }),
                }),
                flags: 0,
                orcpt: None,
                retry: Schedule::now(),
                notify: Schedule::now(),
                expires: QueueExpiry::Ttl(10),
                queue: QueueName::default(),
            }],
            flags: 0,
            env_id: None,
            priority: 0,
            blob_hash: BlobHash::generate(dsn_original.as_bytes()),
            quota_keys: Default::default(),
            received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_via_port: 0,
        },
    };

    // Load config
    let mut local = TestSMTP::new("smtp_dsn_test", CONFIG.to_string() + SIGNATURES).await;
    let core = local.build_smtp();
    let qr = &mut local.queue_receiver;

    // Create temp dir for queue
    qr.blob_store
        .put_blob(
            message.message.blob_hash.as_slice(),
            dsn_original.as_bytes(),
        )
        .await
        .unwrap();

    // Disabled DSN
    core.send_dsn(&mut message).await;
    qr.assert_no_events();
    qr.assert_queue_is_empty().await;

    // Failure DSN
    message.message.recipients[0].flags = flags;
    core.send_dsn(&mut message).await;
    let dsn_message = qr.expect_message().await;
    qr.compare_dsn(dsn_message.message, "failure.eml").await;

    // Success DSN
    message.message.recipients.push(Recipient {
        address: "jane@example.org".into(),
        status: Status::Completed(HostResponse {
            hostname: "mx2.example.org".into(),
            response: Response {
                code: 250,
                esc: [2, 1, 5],
                message: "Message accepted for delivery".into(),
            },
        }),
        flags,
        orcpt: None,
        retry: Schedule::now(),
        notify: Schedule::now(),
        expires: QueueExpiry::Ttl(10),
        queue: QueueName::default(),
    });
    core.send_dsn(&mut message).await;
    let dsn_message = qr.expect_message().await;
    qr.compare_dsn(dsn_message.message, "success.eml").await;

    // Delay DSN
    message.message.recipients.push(Recipient {
        address: "john.doe@example.org".into(),
        status: Status::TemporaryFailure(ErrorDetails {
            entity: "mx.domain.org".into(),
            details: Error::ConnectionError("Connection timeout".into()),
        }),
        flags,
        orcpt: Some("jdoe@example.org".into()),
        retry: Schedule::now(),
        notify: Schedule::now(),
        expires: QueueExpiry::Ttl(10),
        queue: QueueName::default(),
    });
    core.send_dsn(&mut message).await;
    let dsn_message = qr.expect_message().await;
    qr.compare_dsn(dsn_message.message, "delay.eml").await;

    // Mixed DSN
    for rcpt in &mut message.message.recipients {
        rcpt.flags = flags;
    }
    message.message.recipients.last_mut().unwrap().notify.due = now();
    core.send_dsn(&mut message).await;
    let dsn_message = qr.expect_message().await;
    qr.compare_dsn(dsn_message.message, "mixed.eml").await;

    // Load queue
    let queue = qr.read_queued_messages().await;
    assert_eq!(queue.len(), 4);
}

impl QueueReceiver {
    async fn compare_dsn(&self, message: Message, test: &str) {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources");
        path.push("smtp");
        path.push("dsn");
        path.push(test);

        let bytes = self
            .blob_store
            .get_blob(message.blob_hash.as_slice(), 0..usize::MAX)
            .await
            .unwrap()
            .unwrap();

        let dsn = remove_ids(bytes);
        let dsn_expected = fs::read_to_string(&path).unwrap();

        if dsn != dsn_expected {
            let mut failed = PathBuf::from(&path);
            failed.set_extension("failed");
            fs::write(&failed, dsn.as_bytes()).unwrap();
            panic!(
                "Failed for {}, output saved to {}",
                path.display(),
                failed.display()
            );
        }
    }
}

fn remove_ids(message: Vec<u8>) -> String {
    let old_message = String::from_utf8(message).unwrap();
    let mut message = String::with_capacity(old_message.len());
    let mut found_dkim = false;
    let mut skip = false;

    let mut boundary = "";
    for line in old_message.split("\r\n") {
        if skip {
            if line.chars().next().unwrap().is_ascii_whitespace() {
                continue;
            } else {
                skip = false;
            }
        }
        if line.starts_with("Date:") || line.starts_with("Message-ID:") {
            continue;
        } else if !found_dkim && line.starts_with("DKIM-Signature:") {
            found_dkim = true;
            skip = true;
            continue;
        } else if line.starts_with("--") {
            message.push_str(&line.replace(boundary, "mime_boundary"));
        } else if let Some((_, boundary_)) = line.split_once("boundary=\"") {
            boundary = boundary_.split_once('"').unwrap().0;
            message.push_str(&line.replace(boundary, "mime_boundary"));
        } else if line.starts_with("Arrival-Date:") {
            message.push_str("Arrival-Date: <date goes here>");
        } else if line.starts_with("Will-Retry-Until:") {
            message.push_str("Will-Retry-Until: <date goes here>");
        } else {
            message.push_str(line);
        }
        message.push_str("\r\n");
    }

    if !found_dkim {
        panic!("No DKIM signature found in: {old_message}");
    }

    message
}
