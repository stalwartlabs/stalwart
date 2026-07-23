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
    utils::server::TestServerBuilder,
};
use core::panic;
use registry::schema::structs::{
    CertificateManagement, DkimManagement, DnsManagement, Domain, Expression, LookupStore,
    MtaStageConnect, MtaStageData, MtaStageEhlo, MtaStageMail, MtaStageRcpt,
    SieveSystemInterpreter, SieveSystemScript, SqliteStore, StoreLookup,
};
use smtp::scripts::{ScriptResult, event_loop::RunScript};
use std::{fs, path::PathBuf};

#[tokio::test]
async fn sieve_scripts() {
    let mut test = TestServerBuilder::new("smtp_sieve_test")
        .await
        .with_http_listener(19008)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    // Create test data
    let admin = test.account("admin");
    let domain_id = admin
        .registry_create_object(Domain {
            name: "foobar.org".into(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            allow_relaying: true,
            ..Default::default()
        })
        .await;
    admin.create_dkim_signatures(domain_id).await;
    admin.mta_no_auth().await;
    admin
        .registry_create_object(SieveSystemInterpreter {
            default_from_address: Expression {
                else_: "'sieve@foobar.org'".into(),
                ..Default::default()
            },

            default_from_name: Expression {
                else_: "'Sieve Daemon'".into(),
                ..Default::default()
            },
            default_return_path: Expression {
                else_: "''".into(),
                ..Default::default()
            },
            message_id_hostname: Some("'mx.foobar.org'".into()),
            dkim_sign_domain: Expression {
                else_: "'foobar.org'".into(),
                ..Default::default()
            },
            duplicate_expiry: (86_400u64 * 100 * 7).into(),
            max_cpu_cycles: 10000,
            max_nested_includes: 5,
            max_out_messages: 5,
            max_received_headers: 50,
            max_redirects: 3,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(StoreLookup {
            namespace: "sql".into(),
            store: LookupStore::Sqlite(SqliteStore {
                path: format!("{}/smtp_sieve.db", test.tmp_dir()),
                pool_max_connections: 10,
                pool_workers: None,
            }),
        })
        .await;
    admin
        .registry_create_object(MtaStageConnect {
            script: Expression {
                else_: "'stage_connect'".into(),
                ..Default::default()
            },
            smtp_greeting: Expression {
                else_: "'mx.example.org at your service'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageEhlo {
            script: Expression {
                else_: "'stage_ehlo'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageMail {
            script: Expression {
                else_: "'stage_mail'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageRcpt {
            script: Expression {
                else_: "'stage_rcpt'".into(),
                ..Default::default()
            },
            allow_relaying: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageData {
            script: Expression {
                else_: "'stage_data'".into(),
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

    // Add test scripts
    for entry in fs::read_dir(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("smtp")
            .join("sieve"),
    )
    .unwrap()
    {
        let entry = entry.unwrap();
        admin
            .registry_create_object(SieveSystemScript {
                contents: fs::read_to_string(entry.path()).unwrap(),
                description: None,
                is_active: true,
                name: entry
                    .file_name()
                    .to_str()
                    .unwrap()
                    .split_once('.')
                    .unwrap()
                    .0
                    .to_string(),
            })
            .await;
    }
    admin.reload_settings().await;
    admin.reload_lookup_stores().await;
    test.reload_core();
    test.expect_reload_settings().await;

    // Build session
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.88".parse().unwrap();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    assert!(!session.init_conn().await);

    // Run tests
    for (name, script) in &test.server.core.sieve.trusted_scripts {
        if name.starts_with("stage_") || name.ends_with("_include") {
            continue;
        }
        let script = script.clone();
        let params = session
            .build_script_parameters("data")
            .set_variable("from", "john.doe@example.org")
            .with_envelope(&test.server, &session, 0)
            .await;
        match test.server.run_script(name.into(), script, params).await {
            ScriptResult::Accept { .. } => (),
            ScriptResult::Reject(message) => panic!("{}", message),
            err => {
                panic!("Unexpected script result {err:?}");
            }
        }
    }

    // Test connect script
    session
        .response()
        .assert_contains("503 5.5.3 Your IP '10.0.0.88' is not welcomed here");
    session.data.remote_ip_str = "10.0.0.5".parse().unwrap();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    assert!(session.init_conn().await);
    session
        .response()
        .assert_contains("220 mx.example.org at your service");

    // Test EHLO script
    session
        .cmd(
            "EHLO spammer.org",
            "551 5.1.1 Your domain 'spammer.org' has been blocklisted",
        )
        .await;
    session.cmd("EHLO foobar.net", "250").await;

    // Test MAIL-FROM script
    session
        .mail_from("spammer@domain.com", "450 4.1.1 Invalid address")
        .await;
    session
        .mail_from(
            "marketing@spam-domain.com",
            "503 5.5.3 Your address has been blocked",
        )
        .await;
    session.mail_from("bill@foobar.org", "250").await;

    // Test RCPT-TO script
    session
        .rcpt_to(
            "jane@foobar.org",
            "422 4.2.2 You have been greylisted '10.0.0.5.bill@foobar.org.jane@foobar.org'.",
        )
        .await;
    session.rcpt_to("jane@foobar.org", "250").await;

    // Expect a modified message
    session.data("test:multipart", "250").await;

    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("X-Part-Number: 5")
        .assert_contains("THIS IS A PIECE OF HTML TEXT");
    test.assert_no_events();

    // Expect rejection for bill@foobar.net
    session
        .send_message(
            "test@example.net",
            &["bill@foobar.net"],
            "test:multipart",
            "503 5.5.3 Bill cannot receive messages",
        )
        .await;
    test.assert_no_events();
    test.clear_queue().await;

    // Expect message delivery plus a notification
    session
        .send_message(
            "test@example.net",
            &["john@foobar.net"],
            "test:multipart",
            "250",
        )
        .await;
    test.read_event().await.assert_refresh();
    test.read_event().await.assert_refresh();
    let messages = test.read_queued_messages().await;
    assert_eq!(messages.len(), 2);
    let mut messages = messages.into_iter();
    let notification = messages.next().unwrap();
    assert_eq!(notification.message.return_path.as_ref(), "");
    assert_eq!(notification.message.recipients.len(), 2);
    assert_eq!(
        notification.message.recipients.first().unwrap().address(),
        "john@example.net"
    );
    assert_eq!(
        notification.message.recipients.last().unwrap().address(),
        "jane@example.org"
    );
    notification
        .read_lines(&test)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=foobar.org;")
        .assert_contains("From: \"Sieve Daemon\" <sieve@foobar.org>")
        .assert_contains("To: <john@example.net>")
        .assert_contains("Cc: <jane@example.org>")
        .assert_contains("Subject: You have got mail")
        .assert_contains("One Two Three Four");

    messages
        .next()
        .unwrap()
        .read_lines(&test)
        .await
        .assert_contains("One Two Three Four")
        .assert_contains("multi-part message in MIME format")
        .assert_not_contains("X-Part-Number: 5")
        .assert_not_contains("THIS IS A PIECE OF HTML TEXT");
    test.assert_no_events();
    test.clear_queue().await;

    // Expect a modified message delivery plus a notification
    session
        .send_message(
            "test@example.net",
            &["jane@foobar.net"],
            "test:multipart",
            "250",
        )
        .await;
    test.read_event().await.assert_refresh();
    test.read_event().await.assert_refresh();
    let messages = test.read_queued_messages().await;
    assert_eq!(messages.len(), 2);
    let mut messages = messages.into_iter();

    messages
        .next()
        .unwrap()
        .read_lines(&test)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=foobar.org;")
        .assert_contains("From: \"Sieve Daemon\" <sieve@foobar.org>")
        .assert_contains("To: <john@example.net>")
        .assert_contains("Cc: <jane@example.org>")
        .assert_contains("Subject: You have got mail")
        .assert_contains("One Two Three Four");

    messages
        .next()
        .unwrap()
        .read_lines(&test)
        .await
        .assert_contains("X-Part-Number: 5")
        .assert_contains("THIS IS A PIECE OF HTML TEXT")
        .assert_not_contains("X-My-Header: true");
    test.clear_queue().await;

    // Expect a modified redirected message
    session
        .send_message(
            "test@example.net",
            &["thomas@foobar.gov"],
            "test:no_dkim",
            "250",
        )
        .await;

    let redirect = test.expect_message().await;
    assert_eq!(redirect.message.return_path.as_ref(), "");
    assert_eq!(redirect.message.recipients.len(), 1);
    assert_eq!(
        redirect.message.recipients.first().unwrap().address(),
        "redirect@here.email"
    );
    redirect
        .read_lines(&test)
        .await
        .assert_contains("From: no-reply@my.domain")
        .assert_contains("To: Suzie Q <suzie@shopping.example.net>")
        .assert_contains("Subject: Is dinner ready?")
        .assert_contains("Message-ID: <20030712040037.46341.5F8J@football.example.com>")
        .assert_contains("Received: ")
        .assert_not_contains("From: Joe SixPack <joe@football.example.com>");
    test.assert_no_events();

    // Expect an intact redirected message
    session
        .send_message(
            "test@example.net",
            &["bob@foobar.gov"],
            "test:no_dkim",
            "250",
        )
        .await;

    let redirect = test.expect_message().await;
    assert_eq!(redirect.message.return_path.as_ref(), "");
    assert_eq!(redirect.message.recipients.len(), 1);
    assert_eq!(
        redirect.message.recipients.first().unwrap().address(),
        "redirect@somewhere.email"
    );
    redirect
        .read_lines(&test)
        .await
        .assert_not_contains("From: no-reply@my.domain")
        .assert_contains("To: Suzie Q <suzie@shopping.example.net>")
        .assert_contains("Subject: Is dinner ready?")
        .assert_contains("Message-ID: <20030712040037.46341.5F8J@football.example.com>")
        .assert_contains("From: Joe SixPack <joe@football.example.com>")
        .assert_contains("Received: ")
        .assert_contains("Authentication-Results: ");
    test.assert_no_events();
}
