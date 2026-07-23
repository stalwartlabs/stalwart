/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::{TestServer, TestServerBuilder};
use common::config::smtp::queue::{QueueExpiry, QueueName};
use registry::schema::{
    enums::CompressionAlgo,
    structs::{DsnReportSettings, Expression, ReportSettings},
};
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

#[tokio::test]
async fn generate_dsn() {
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
            metadata: Default::default(),
            received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_via_port: 0,
        },
    };

    let mut local = TestServerBuilder::new("smtp_queue_dsn")
        .await
        .with_http_listener(19039)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let local_admin = local.account("admin");
    local_admin
        .registry_create_object(ReportSettings {
            outbound_report_submitter: Expression {
                else_: "'mx.example.org'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    local_admin
        .registry_create_object(DsnReportSettings {
            dkim_sign_domain: Expression {
                else_: "'example.org'".into(),
                ..Default::default()
            },
            from_address: Expression {
                else_: "'MAILER-DAEMON@example.org'".into(),
                ..Default::default()
            },
            from_name: Expression {
                else_: "'Mail Delivery Subsystem'".into(),
                ..Default::default()
            },
        })
        .await;
    let domain_id = local_admin.find_or_create_domain("example.org").await;
    local_admin.create_dkim_signatures(domain_id).await;
    local_admin.mta_allow_non_fqdn().await;
    local_admin.mta_allow_relaying().await;
    local_admin.reload_settings().await;
    local_admin.mta_allow_relaying().await;
    local.reload_core();
    local.expect_reload_settings().await;

    // Create temp dir for queue
    local
        .server
        .blob_store()
        .put_blob(
            message.message.blob_hash.as_slice(),
            dsn_original.as_bytes(),
            CompressionAlgo::Lz4,
        )
        .await
        .unwrap();

    // Disabled DSN
    local.server.send_dsn(&mut message).await;
    local.assert_no_events();
    local.assert_queue_is_empty().await;

    // Failure DSN
    message.message.recipients[0].flags = flags;
    local.server.send_dsn(&mut message).await;
    let dsn_message = local.expect_message().await;
    local.compare_dsn(dsn_message.message, "failure.eml").await;

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
    local.server.send_dsn(&mut message).await;
    let dsn_message = local.expect_message().await;
    local.compare_dsn(dsn_message.message, "success.eml").await;

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
    local.server.send_dsn(&mut message).await;
    let dsn_message = local.expect_message().await;
    local.compare_dsn(dsn_message.message, "delay.eml").await;

    // Mixed DSN
    for rcpt in &mut message.message.recipients {
        rcpt.flags = flags;
    }
    message.message.recipients.last_mut().unwrap().notify.due = now();
    local.server.send_dsn(&mut message).await;
    let dsn_message = local.expect_message().await;
    local.compare_dsn(dsn_message.message, "mixed.eml").await;

    // Load queue
    let queue = local.read_queued_messages().await;
    assert_eq!(queue.len(), 4);
}

impl TestServer {
    async fn compare_dsn(&self, message: Message, test: &str) {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources");
        path.push("smtp");
        path.push("dsn");
        path.push(test);

        let bytes = self
            .server
            .blob_store()
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
    let mut found_dkim = 0;
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
        } else if found_dkim < 2 && line.starts_with("DKIM-Signature:") {
            found_dkim += 1;
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

    if found_dkim == 0 {
        panic!("No DKIM signature found in: {old_message}");
    }

    message
}
