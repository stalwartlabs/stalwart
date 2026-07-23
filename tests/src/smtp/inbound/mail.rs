/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::session::{TestSession, VerifyResponse},
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use mail_auth::{IprevResult, SpfResult, common::parse::TxtRecordParser, spf::Spf};
use registry::{
    schema::{
        enums::MtaInboundThrottleKey,
        structs::{
            Expression, ExpressionMatch, MtaExtensions, MtaInboundThrottle, MtaStageData,
            MtaStageEhlo, MtaStageMail, Rate, SenderAuth,
        },
    },
    types::{list::List, map::Map},
};
use smtp_proto::{MAIL_BY_NOTIFY, MAIL_BY_RETURN, MAIL_REQUIRETLS};
use std::time::{Duration, Instant, SystemTime};

#[tokio::test]
async fn mail() {
    let mut test = TestServerBuilder::new("smtp_mail_from_test")
        .await
        .with_http_listener(19003)
        .await
        .disable_services()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    admin
        .registry_create_object(MtaStageEhlo {
            require: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin.mta_no_auth().await;
    admin
        .registry_create_object(SenderAuth {
            reverse_ip_verify: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "strict".into(),
                }]),
                else_: "relaxed".into(),
            },
            spf_ehlo_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            spf_from_verify: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "strict".into(),
                }]),
                else_: "relaxed".into(),
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaExtensions {
            deliver_by: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "1d".into(),
                }]),
                else_: "false".into(),
            },
            future_release: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "1d".into(),
                }]),
                else_: "false".into(),
            },
            mt_priority: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "nsep".into(),
                }]),
                else_: "false".into(),
            },
            require_tls: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "true".into(),
                }]),
                else_: "false".into(),
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageMail {
            is_sender_allowed: Expression {
                else_: "sender_domain != 'blocked.com'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageData {
            max_message_size: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "2048".into(),
                }]),
                else_: "1024".into(),
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaInboundThrottle {
            description: "Test throttle".into(),
            enable: true,
            key: Map::new(vec![MtaInboundThrottleKey::Sender]),
            match_: Expression {
                else_: "remote_ip = '10.0.0.1'".into(),
                ..Default::default()
            },
            rate: Rate {
                count: 2,
                period: 1000u64.into(),
            },
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();

    test.server.txt_add(
        "foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "mx1.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.ptr_add(
        "10.0.0.1".parse().unwrap(),
        vec!["mx1.foobar.org.".to_string()],
        Instant::now() + Duration::from_secs(5),
    );
    test.server.ipv4_add(
        "mx1.foobar.org.",
        vec!["10.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(5),
    );
    test.server.ptr_add(
        "10.0.0.2".parse().unwrap(),
        vec!["mx2.foobar.org.".to_string()],
        Instant::now() + Duration::from_secs(5),
    );

    // Be rude and do not say EHLO
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    session.eval_session_params().await;
    session
        .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("503 5.5.1");

    // Test sender not allowed
    session.ingest(b"EHLO mx1.foobar.org\r\n").await.unwrap();
    session.response().assert_code("250");
    session
        .ingest(b"MAIL FROM:<bill@blocked.com>\r\n")
        .await
        .unwrap();
    session.response().assert_code("550 5.7.1");

    // Both IPREV and SPF should pass
    session
        .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert_eq!(
        session.data.spf_ehlo.as_ref().unwrap().result(),
        SpfResult::Pass
    );
    assert_eq!(
        session.data.spf_mail_from.as_ref().unwrap().result(),
        SpfResult::Pass
    );
    assert_eq!(
        session.data.iprev.as_ref().unwrap().result(),
        &IprevResult::Pass
    );

    // Multiple MAIL FROMs should not be allowed
    session
        .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("503 5.5.1");

    // Test rate limit
    for n in 0..2 {
        session.rset().await;
        session
            .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
            .await
            .unwrap();
        session
            .response()
            .assert_code(if n == 0 { "250" } else { "452 4.4.5" });
    }

    // Test disabled extensions
    for param in [
        "HOLDFOR=123",
        "HOLDUNTIL=49374347",
        "MT-PRIORITY=3",
        "BY=120;R",
        "REQUIRETLS",
    ] {
        session
            .ingest(format!("MAIL FROM:<params@foobar.org> {param}\r\n").as_bytes())
            .await
            .unwrap();
        session.response().assert_code("501 5.5.4");
    }

    // Test size with a large value
    session
        .ingest(b"MAIL FROM:<bill@foobar.org> SIZE=1512\r\n")
        .await
        .unwrap();
    session.response().assert_code("552 5.3.4");

    // Test strict IPREV
    session.data.remote_ip_str = "10.0.0.2".into();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    session.data.iprev = None;
    session.eval_session_params().await;
    session
        .ingest(b"MAIL FROM:<jane@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("550 5.7.25");
    session.data.iprev = None;
    test.server.ipv4_add(
        "mx2.foobar.org.",
        vec!["10.0.0.2".parse().unwrap()],
        Instant::now() + Duration::from_secs(5),
    );

    // Test strict SPF
    session
        .ingest(b"MAIL FROM:<jane@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("550 5.7.23");
    test.server.txt_add(
        "foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    session
        .ingest(b"MAIL FROM:<Jane@FooBar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    let mail_from = session.data.mail_from.as_ref().unwrap();
    assert_eq!(mail_from.domain, "foobar.org");
    assert_eq!(mail_from.address, "Jane@FooBar.org");
    assert_eq!(mail_from.address_lcase, "jane@foobar.org");
    session.rset().await;

    // Test SIZE extension
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> SIZE=1023\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    session.rset().await;

    // Test MT-PRIORITY extension
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> MT-PRIORITY=-3\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert_eq!(session.data.priority, -3);
    session.rset().await;

    // Test REQUIRETLS extension
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> REQUIRETLS\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert!((session.data.mail_from.as_ref().unwrap().flags & MAIL_REQUIRETLS) != 0);
    session.rset().await;

    // Test DELIVERBY extension with by-mode=R
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> BY=120;R\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert!((session.data.mail_from.as_ref().unwrap().flags & MAIL_BY_RETURN) != 0);
    assert_eq!(session.data.delivery_by, 120);
    session.rset().await;

    // Test DELIVERBY extension with by-mode=N
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> BY=-456;N\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert!((session.data.mail_from.as_ref().unwrap().flags & MAIL_BY_NOTIFY) != 0);
    assert_eq!(session.data.delivery_by, -456);
    session.rset().await;

    // Test DELIVERBY extension with invalid by-mode=R
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> BY=-1;R\r\n")
        .await
        .unwrap();
    session.response().assert_code("501 5.5.4");
    session.rset().await;

    session
        .ingest(b"MAIL FROM:<jane@foobar.org> BY=99999;R\r\n")
        .await
        .unwrap();
    session.response().assert_code("501 5.5.4");
    session.rset().await;

    // Test FUTURERELEASE extension with HOLDFOR
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> HOLDFOR=1234\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert_eq!(session.data.future_release, 1234);
    session.rset().await;

    // Test FUTURERELEASE extension with invalid HOLDFOR falue
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> HOLDFOR=99999\r\n")
        .await
        .unwrap();
    session.response().assert_code("501 5.5.4");
    session.rset().await;

    // Test FUTURERELEASE extension with HOLDUNTIL
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    session
        .ingest(format!("MAIL FROM:<jane@foobar.org> HOLDUNTIL={}\r\n", now + 10).as_bytes())
        .await
        .unwrap();
    session.response().assert_code("250");
    assert_eq!(session.data.future_release, 10);
    session.rset().await;

    // Test FUTURERELEASE extension with invalid HOLDUNTIL value
    session
        .ingest(format!("MAIL FROM:<jane@foobar.org> HOLDUNTIL={}\r\n", now + 99999).as_bytes())
        .await
        .unwrap();
    session.response().assert_code("501 5.5.4");
    session.rset().await;
}
