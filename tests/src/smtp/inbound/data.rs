/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::TestMessage,
        session::{TestSession, VerifyResponse, load_test_message},
    },
    utils::server::TestServerBuilder,
};
use registry::{
    schema::{
        enums::MtaQueueQuotaKey,
        prelude::ObjectType,
        structs::{
            Expression, ExpressionMatch, MtaQueueQuota, MtaStageData, SenderAuth, SpamSettings,
        },
    },
    types::{list::List, map::Map},
};

#[tokio::test]
async fn data() {
    let mut test = TestServerBuilder::new("smtp_data_test")
        .await
        .with_http_listener(19004)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    // Create test users
    let admin = test.account("admin");
    for (name, secret, description, aliases) in [
        ("john@foobar.org", "12345 + extra safety", "John Doe", &[]),
        ("jane@domain.net", "abcde + extra safety", "Jane Smith", &[]),
        (
            "bill@foobar.org",
            "p4ssw0rd + extra safety",
            "Bill Foobar",
            &[],
        ),
        (
            "mike@test.com",
            "p4ssw0rd + extra safety",
            "Mike Foobar",
            &[],
        ),
    ] {
        admin
            .create_user_account(name, secret, description, aliases, vec![])
            .await;
    }

    // Add test settings
    admin.mta_no_auth().await;
    admin
        .registry_create_object(SpamSettings {
            enable: false,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(SenderAuth {
            dmarc_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            reverse_ip_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            spf_ehlo_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            spf_from_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageData {
            add_auth_results_header: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.3'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            add_date_header: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.3'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            add_message_id_header: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.3'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            add_received_header: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.3'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            add_received_spf_header: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.3'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            add_return_path_header: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.3'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            max_messages: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "1".into(),
                }]),
                else_: "100".into(),
            },
            max_received_headers: Expression {
                else_: "3".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaQueueQuota {
            description: None,
            enable: true,
            key: Map::new(vec![MtaQueueQuotaKey::Sender]),
            match_: Expression {
                else_: "sender = 'john@doe.org'".into(),
                ..Default::default()
            },
            messages: Some(1),
            size: None,
        })
        .await;
    admin
        .registry_create_object(MtaQueueQuota {
            description: None,
            enable: true,
            key: Map::new(vec![MtaQueueQuotaKey::RcptDomain]),
            match_: Expression {
                else_: "rcpt_domain = 'foobar.org'".into(),
                ..Default::default()
            },
            messages: None,
            size: Some(450),
        })
        .await;
    admin
        .registry_create_object(MtaQueueQuota {
            description: None,
            enable: true,
            key: Map::new(vec![MtaQueueQuotaKey::Rcpt]),
            match_: Expression {
                else_: "rcpt = 'jane@domain.net'".into(),
                ..Default::default()
            },
            messages: None,
            size: Some(450),
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;

    // Test queue message builder
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.test_builder().await;

    // Send DATA without RCPT
    session.ehlo("mx.doe.org").await;
    session.ingest(b"DATA\r\n").await.unwrap();
    session.response().assert_code("503 5.5.1");

    // Send broken message
    session
        .send_message("john@doe.org", &["bill@foobar.org"], "invalid", "550 5.7.7")
        .await;

    // Naive Loop detection
    session
        .send_message(
            "john@doe.org",
            &["bill@foobar.org"],
            "test:loop",
            "450 4.4.6",
        )
        .await;

    // No headers should be added to messages from 10.0.0.1
    session
        .send_message("john@test.org", &["mike@test.com"], "test:no_msgid", "250")
        .await;
    assert_eq!(
        test.expect_message().await.read_message(&test).await,
        format!("{}\r\n", load_test_message("no_msgid", "messages"))
    );

    // Maximum one message per session is allowed for 10.0.0.1
    session.mail_from("john@doe.org", "250").await;
    session.rcpt_to("bill@foobar.org", "250").await;
    session.ingest(b"DATA\r\n").await.unwrap();
    session.response().assert_code("452 4.4.5");
    session.rset().await;

    // Headers should be added to messages from 10.0.0.3
    session.data.remote_ip_str = "10.0.0.3".into();
    session.eval_session_params().await;
    session
        .send_message("bill@doe.org", &["mike@test.com"], "test:no_msgid", "250")
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("From: ")
        .assert_contains("To: ")
        .assert_contains("Subject: ")
        .assert_contains("Date: ")
        .assert_contains("Message-ID: ")
        .assert_contains("Return-Path: ")
        .assert_contains("Received: ")
        .assert_contains("Authentication-Results: ")
        .assert_contains("Received-SPF: ");

    // Only one message is allowed in the queue from john@doe.org
    session.data.remote_ip_str = "10.0.0.2".into();
    session.eval_session_params().await;
    session
        .send_message("john@doe.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    session
        .send_message(
            "john@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "452 4.3.1",
        )
        .await;

    // Release quota
    test.clear_queue().await;

    // Only 1500 bytes are allowed in the queue to domain foobar.org
    session
        .send_message(
            "jane@foobar.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250",
        )
        .await;
    session
        .send_message(
            "jane@foobar.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "452 4.3.1",
        )
        .await;

    // Only 1500 bytes are allowed in the queue to recipient jane@domain.net
    session
        .send_message(
            "jane@foobar.org",
            &["jane@domain.net"],
            "test:no_dkim",
            "250",
        )
        .await;
    session
        .send_message(
            "jane@foobar.org",
            &["jane@domain.net"],
            "test:no_dkim",
            "452 4.3.1",
        )
        .await;

    // Make sure store is empty
    test.clear_queue().await;
    let admin = test.account("admin");
    admin.registry_destroy_all(ObjectType::MtaQueueQuota).await;
    admin
        .registry_destroy_all(ObjectType::MtaInboundThrottle)
        .await;
    test.assert_is_empty().await;
}
