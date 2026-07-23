/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::session::{TestSession, VerifyResponse},
    utils::server::TestServerBuilder,
};
use registry::{
    schema::structs::{Expression, ExpressionMatch, MtaExtensions, MtaStageAuth},
    types::list::List,
};
use smtp::core::State;

#[tokio::test]
async fn auth() {
    let mut test = TestServerBuilder::new("smtp_auth_test")
        .await
        .with_http_listener(19001)
        .await
        .disable_services()
        .build()
        .await;

    // Create test users
    let admin = test.account("admin");
    for (name, secret, description, aliases) in [
        (
            "john@example.org",
            "12345 + extra safety",
            "John Doe",
            &["john.doe@example.org"][..],
        ),
        (
            "jane@example.org",
            "abcde + extra safety",
            "Jane Smith",
            &["jane@example.org"],
        ),
    ] {
        admin
            .create_user_account(name, secret, description, aliases, vec![])
            .await;
    }

    // Add test settings
    admin
        .registry_create_object(MtaStageAuth {
            max_failures: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "2".into(),
                }]),
                else_: "3".into(),
            },
            must_match_sender: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            require: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            sasl_mechanisms: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1' && is_tls".into(),
                    then: "[plain, login]".into(),
                }]),
                else_: "0".into(),
            },
            wait_on_fail: Expression {
                else_: "100ms".into(),
                ..Default::default()
            },
        })
        .await;
    admin
        .registry_create_object(MtaExtensions {
            future_release: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "!is_empty(authenticated_as)".into(),
                    then: "1d".into(),
                }]),
                else_: "false".into(),
            },
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();

    // EHLO should not advertise plain text auth without TLS
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.stream.tls = false;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains(" PLAIN")
        .assert_not_contains(" LOGIN");

    // EHLO should advertise AUTH for 10.0.0.1
    session.stream.tls = true;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("AUTH ")
        .assert_contains(" PLAIN")
        .assert_contains(" LOGIN")
        .assert_not_contains("FUTURERELEASE");

    // Invalid password should be rejected
    session
        .auth_plain("john@example.org", "wrong pass", "535 5.7.8")
        .await;

    // Session should be disconnected after second invalid auth attempt
    session
        .ingest(b"AUTH PLAIN AGpvaG4AY2hpbWljaGFuZ2Fz\r\n")
        .await
        .unwrap_err();
    session.response().assert_code("455 4.3.0");

    // Should not be able to send without authenticating
    session.state = State::default();
    session.mail_from("bill@foobar.org", "503 5.5.1").await;

    // Successful PLAIN authentication
    session.data.auth_errors = 0;
    session
        .auth_plain("john@example.org", "12345 + extra safety", "235 2.7.0")
        .await;

    // Users should be able to send emails only from their own email addresses
    session.mail_from("bill@foobar.org", "501 5.5.4").await;
    session.mail_from("john@example.org", "250").await;
    session.data.mail_from.take();

    // Should not be able to authenticate twice
    session
        .auth_plain("john@example.org", "12345 + extra safety", "503 5.5.1")
        .await;

    // FUTURERELEASE extension should be available after authenticating
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("AUTH ")
        .assert_not_contains(" PLAIN")
        .assert_not_contains(" LOGIN")
        .assert_contains("FUTURERELEASE 86400");

    // Successful LOGIN authentication
    session.data.authenticated_as.take();
    session
        .auth_login("john@example.org", "12345 + extra safety", "235 2.7.0")
        .await;

    // Login should not be advertised to 10.0.0.2
    session.data.remote_ip_str = "10.0.0.2".into();
    session.eval_session_params().await;
    session.stream.tls = true;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("AUTH ")
        .assert_not_contains(" PLAIN")
        .assert_not_contains(" LOGIN");
    session
        .auth_plain("john@example.org", "12345 + extra safety", "503 5.5.1")
        .await;
}
