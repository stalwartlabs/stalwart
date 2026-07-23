/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::session::{TestSession, VerifyResponse},
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use mail_auth::{SpfResult, common::parse::TxtRecordParser, spf::Spf};
use registry::{
    schema::structs::{
        Expression, ExpressionMatch, MtaExtensions, MtaStageData, MtaStageEhlo, SenderAuth,
    },
    types::list::List,
};
use std::time::{Duration, Instant};

#[tokio::test]
async fn ehlo() {
    let mut test = TestServerBuilder::new("smtp_ehlo_test")
        .await
        .with_http_listener(19005)
        .await
        .disable_services()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    admin
        .registry_create_object(MtaExtensions {
            future_release: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "1h".into(),
                }]),
                else_: "false".into(),
            },
            mt_priority: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "nsep".into(),
                }]),
                else_: "false".into(),
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageEhlo {
            reject_non_fqdn: Expression {
                else_: "starts_with(remote_ip, '10.0.0.')".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageData {
            max_message_size: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "1024".into(),
                }]),
                else_: "2048".into(),
            },
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
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "strict".into(),
                }]),
                else_: "relaxed".into(),
            },
            spf_from_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();

    test.server.txt_add(
        "mx1.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "mx2.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );

    // Reject non-FQDN domains
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    session.stream.tls = false;
    session.eval_session_params().await;
    session.cmd("EHLO domain", "550 5.5.0").await;

    // EHLO capabilities evaluation
    session
        .cmd("EHLO mx1.foobar.org", "250")
        .await
        .assert_contains("SIZE 1024")
        .assert_contains("MT-PRIORITY NSEP")
        .assert_contains("FUTURERELEASE 3600")
        .assert_contains("STARTTLS");

    // SPF should be a Pass for 10.0.0.1
    assert_eq!(
        session.data.spf_ehlo.as_ref().unwrap().result(),
        SpfResult::Pass
    );

    // Test SPF strict mode
    session.data.helo_domain = "".into();
    session.data.remote_ip_str = "10.0.0.2".into();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    session.stream.tls = true;
    session.eval_session_params().await;
    session.ingest(b"EHLO mx1.foobar.org\r\n").await.unwrap();
    session.response().assert_code("550 5.7.23");

    // EHLO capabilities evaluation
    session.ingest(b"EHLO mx2.foobar.org\r\n").await.unwrap();
    assert_eq!(
        session.data.spf_ehlo.as_ref().unwrap().result(),
        SpfResult::Pass
    );
    session
        .response()
        .assert_code("250")
        .assert_contains("SIZE 2048")
        .assert_not_contains("MT-PRIORITY")
        .assert_not_contains("FUTURERELEASE")
        .assert_not_contains("STARTTLS");
}
