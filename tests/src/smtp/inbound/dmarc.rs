/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::{TestMessage, TestReportingEvent},
        session::{TestSession, VerifyResponse},
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::config::smtp::report::AggregateFrequency;
use mail_auth::{
    common::{parse::TxtRecordParser, verify::DomainKey},
    dkim::DomainKeyReport,
    dmarc::Dmarc,
    report::DmarcResult,
    spf::Spf,
};
use registry::{
    schema::structs::{
        CertificateManagement, DkimManagement, DkimReportSettings, DmarcReportSettings,
        DnsManagement, Domain, Expression, ExpressionMatch, SenderAuth, SpfReportSettings,
    },
    types::list::List,
};
use std::time::{Duration, Instant};

#[tokio::test]
async fn dmarc() {
    let mut test = TestServerBuilder::new("smtp_dmarc_test")
        .await
        .with_http_listener(19012)
        .await
        .disable_services()
        .capture_queue()
        .capture_reporting()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    let domain_id = admin
        .registry_create_object(Domain {
            name: "localdomain.org".into(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            allow_relaying: true,
            ..Default::default()
        })
        .await;
    admin.create_dkim_signatures(domain_id).await;
    admin.mta_no_auth().await;
    admin.mta_add_all_headers().await;
    admin
        .registry_create_object(SenderAuth {
            dmarc_verify: Expression {
                else_: "strict".into(),
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
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "strict".into(),
                }]),
                else_: "relaxed".into(),
            },
            arc_verify: Expression {
                else_: "strict".into(),
                ..Default::default()
            },
            dkim_sign_domain: Expression {
                else_: "'localdomain.org'".into(),
                ..Default::default()
            },
            dkim_verify: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "sender_domain = 'test.net'".into(),
                    then: "relaxed".into(),
                }]),
                else_: "strict".into(),
            },
            dkim_strict: false,
        })
        .await;
    admin
        .registry_create_object(DkimReportSettings {
            dkim_sign_domain: Expression {
                else_: "'localdomain.org'".into(),
                ..Default::default()
            },
            send_frequency: Expression {
                else_: "[1, 1s]".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(SpfReportSettings {
            dkim_sign_domain: Expression {
                else_: "'localdomain.org'".into(),
                ..Default::default()
            },
            send_frequency: Expression {
                else_: "[1, 1s]".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(DmarcReportSettings {
            failure_dkim_sign_domain: Expression {
                else_: "'localdomain.org'".into(),
                ..Default::default()
            },
            failure_send_frequency: Expression {
                else_: "[1, 1s]".into(),
                ..Default::default()
            },
            aggregate_send_frequency: Expression {
                else_: "daily".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;

    // Add SPF, DKIM and DMARC records
    test.server.txt_add(
        "mx.example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all ra=spf-failures rr=e:f:s:n").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "foobar.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "ed._domainkey.example.com",
        DomainKey::parse(
            concat!(
                "v=DKIM1; k=ed25519; ",
                "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "default._domainkey.example.com",
        DomainKey::parse(
            concat!(
                "v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
                "KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt",
                "IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v",
                "/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi",
                "tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB",
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "_report._domainkey.example.com",
        DomainKeyReport::parse(b"ra=dkim-failures; rp=100; rr=d:o:p:s:u:v:x;").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "_dmarc.example.com",
        Dmarc::parse(
            concat!(
                "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo=1;",
                "rua=mailto:dmarc-feedback@example.com;",
                "ruf=mailto:dmarc-failures@example.com"
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );

    // SPF must pass
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.2".into();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.example.com").await;
    session.mail_from("bill@example.com", "550 5.7.23").await;

    // Expect SPF auth failure report
    let message = test.expect_message().await;
    assert_eq!(
        message.message.recipients.last().unwrap().address(),
        "spf-failures@example.com"
    );
    message
        .read_lines(&test)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=localdomain.org;")
        .assert_contains("To: spf-failures@example.com")
        .assert_contains("Feedback-Type: auth-failure")
        .assert_contains("Auth-Failure: spf");

    // Second DKIM failure report should be rate limited
    session.mail_from("bill@example.com", "550 5.7.23").await;
    test.assert_no_events();

    // Invalid DKIM signatures should be rejected
    session.data.remote_ip_str = "10.0.0.1".into();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    session.eval_session_params().await;
    session
        .send_message(
            "bill@example.com",
            &["jdoe@localdomain.org"],
            "test:invalid_dkim",
            "550 5.7.20",
        )
        .await;

    // Expect DKIM auth failure report
    let message = test.expect_message().await;
    assert_eq!(
        message.message.recipients.last().unwrap().address(),
        "dkim-failures@example.com"
    );
    message
        .read_lines(&test)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=localdomain.org;")
        .assert_contains("To: dkim-failures@example.com")
        .assert_contains("Feedback-Type: auth-failure")
        .assert_contains("Auth-Failure: bodyhash");

    // Second DKIM failure report should be rate limited
    session
        .send_message(
            "bill@example.com",
            &["jdoe@localdomain.org"],
            "test:invalid_dkim",
            "550 5.7.20",
        )
        .await;
    test.assert_no_events();

    // Invalid ARC should be rejected
    session
        .send_message(
            "bill@example.com",
            &["jdoe@localdomain.org"],
            "test:invalid_arc",
            "550 5.7.29",
        )
        .await;
    test.assert_no_events();

    // Unaligned DMARC should be rejected
    test.server.txt_add(
        "test.net",
        Spf::parse(b"v=spf1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    session
        .send_message(
            "joe@test.net",
            &["jdoe@localdomain.org"],
            "test:invalid_dkim",
            "550 5.7.1",
        )
        .await;

    // Expect DMARC auth failure report
    let message = test.expect_message().await;
    assert_eq!(
        message.message.recipients.last().unwrap().address(),
        "dmarc-failures@example.com"
    );
    message
        .read_lines(&test)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=localdomain.org;")
        .assert_contains("To: dmarc-failures@example.com")
        .assert_contains("Feedback-Type: auth-failure")
        .assert_contains("Auth-Failure: dmarc")
        .assert_contains("dmarc=3Dnone");

    // Expect DMARC aggregate report
    let report = test.read_report().await.unwrap_dmarc();
    assert_eq!(report.domain, "example.com");
    assert_eq!(report.interval, AggregateFrequency::Daily);
    assert_eq!(report.dmarc_record.rua().len(), 1);
    assert_eq!(report.report_record.dmarc_spf_result(), DmarcResult::Fail);

    // Second DMARC failure report should be rate limited
    session
        .send_message(
            "joe@test.net",
            &["jdoe@localdomain.org"],
            "test:invalid_dkim",
            "550 5.7.1",
        )
        .await;
    test.assert_no_events();

    // Messages passing DMARC should be accepted
    session
        .send_message(
            "bill@example.com",
            &["jdoe@localdomain.org"],
            "test:dkim",
            "250",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("dkim=pass")
        .assert_contains("spf=pass")
        .assert_contains("dmarc=pass")
        .assert_contains("Received-SPF: pass");
}
