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
    schema::structs::{Expression, ExpressionMatch, MailingList, MtaExtensions},
    types::{list::List, map::Map},
};

#[tokio::test]
async fn vrfy_expn() {
    let mut test = TestServerBuilder::new("smtp_vrfy_test")
        .await
        .with_http_listener(19006)
        .await
        .disable_services()
        .build()
        .await;

    // Create test users
    let admin = test.account("admin");
    for (name, secret, description, aliases) in [
        ("john@foobar.org", "12345 + extra safety", "John Doe", &[]),
        ("jane@foobar.org", "abcde + extra safety", "Jane Smith", &[]),
        (
            "bill@foobar.org",
            "p4ssw0rd + extra safety",
            "Bill Foobar",
            &[],
        ),
    ] {
        admin
            .create_user_account(name, secret, description, aliases, vec![])
            .await;
    }
    let domain_id = admin.find_or_create_domain("foobar.org").await;
    admin
        .registry_create_object(MailingList {
            domain_id,
            name: "sales".into(),
            recipients: Map::new(vec![
                "john@foobar.org".into(),
                "jane@foobar.org".into(),
                "bill@foobar.org".into(),
            ]),
            ..Default::default()
        })
        .await;

    // Add test settings
    admin.mta_no_auth().await;
    admin
        .registry_create_object(MtaExtensions {
            vrfy: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            expn: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();

    // EHLO should not advertise VRFY/EXPN to 10.0.0.2
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.2".into();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("EXPN")
        .assert_not_contains("VRFY");
    session.cmd("VRFY john@foobar.org", "252 2.5.1").await;
    session.cmd("EXPN sales@foobar.org", "252 2.5.1").await;

    // EHLO should advertise VRFY/EXPN for 10.0.0.1
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("EXPN")
        .assert_contains("VRFY");

    // Successful VRFY
    session
        .cmd("VRFY john@foobar.org", "250 john@foobar.org")
        .await;

    // Successful EXPN
    session
        .cmd("EXPN sales@foobar.org", "250")
        .await
        .assert_contains("250-john@foobar.org")
        .assert_contains("250-jane@foobar.org")
        .assert_contains("250 bill@foobar.org");

    // Non-existent VRFY
    session.cmd("VRFY robert", "550 5.1.2").await;

    // Non-existent EXPN
    session.cmd("EXPN procurement", "550 5.1.2").await;
}
