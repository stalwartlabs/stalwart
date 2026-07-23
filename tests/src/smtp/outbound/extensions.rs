/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::{TestMessage, TestQueueEvent},
        session::{TestSession, VerifyResponse},
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use mail_auth::{DnssecStatus, MX};
use registry::schema::structs::{Expression, MtaStageData};
use smtp_proto::{MAIL_REQUIRETLS, MAIL_RET_HDRS, MAIL_SMTPUTF8, RCPT_NOTIFY_NEVER};
use std::time::{Duration, Instant};

#[tokio::test]
#[serial_test::serial]
async fn extensions() {
    let mut local = TestServerBuilder::new("smtp_ext_local")
        .await
        .with_http_listener(19020)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_ext_remote")
        .await
        .with_http_listener(19021)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_no_auth().await;
    local_admin.mta_all_extensions().await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_all_extensions().await;
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_no_auth().await;
    remote_admin
        .registry_create_object(MtaStageData {
            max_message_size: Expression {
                else_: "1500".into(),
                ..Default::default()
            },
            add_date_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_message_id_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_received_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_received_spf_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_auth_results_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_return_path_header: Expression {
                else_: "false".into(),
                ..Default::default()
            },
            enable_spam_filter: Expression {
                else_: "false".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    // Add mock DNS entries
    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(10),
    );
    local.server.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(
            "john@test.org",
            &["<bill@foobar.org> NOTIFY=SUCCESS,FAILURE"],
            "test:no_dkim",
            "250",
        )
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());

    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (delivered to")
        .assert_contains("Final-Recipient: rfc822;bill@foobar.org")
        .assert_contains("Action: delivered");
    local.read_event().await.assert_done();
    remote
        .expect_message()
        .await
        .read_lines(&remote)
        .await
        .assert_contains("using TLSv1.3 with cipher");

    // Test SIZE extension
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:arc", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (host 'mx.foobar.org' rejected command 'MAIL FROM:")
        .assert_contains("Action: failed")
        .assert_contains("Diagnostic-Code: smtp;552")
        .assert_contains("Status: 5.3.4");
    local.read_event().await.assert_done();
    remote.assert_no_events();

    // Test DSN, SMTPUTF8 and REQUIRETLS extensions
    session
        .send_message(
            "<john@test.org> ENVID=abc123 RET=HDRS REQUIRETLS SMTPUTF8",
            &["<bill@foobar.org> NOTIFY=NEVER"],
            "test:no_dkim",
            "250",
        )
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local.read_event().await.assert_done();
    let message = remote.expect_message().await;
    assert_eq!(message.message.env_id, Some("abc123".into()));
    assert!((message.message.flags & MAIL_RET_HDRS) != 0);
    assert!((message.message.flags & MAIL_REQUIRETLS) != 0);
    assert!((message.message.flags & MAIL_SMTPUTF8) != 0);
    assert!((message.message.recipients.last().unwrap().flags & RCPT_NOTIFY_NEVER) != 0);
}
