/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::{TestMessage, TestQueueEvent, TestReportingEvent},
        session::{TestSession, VerifyResponse},
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::{config::smtp::resolver::Policy, ipc::PolicyType};
use mail_auth::{
    DnssecStatus, MX,
    common::parse::TxtRecordParser,
    mta_sts::{MtaSts, ReportUri, TlsRpt},
    report::tlsrpt::ResultType,
};
use registry::schema::{
    enums::MtaRequiredOrOptional,
    prelude::ObjectType,
    structs::{Expression, MtaTlsStrategy, TlsReportSettings},
};
use smtp::outbound::mta_sts::{lookup::STS_TEST_POLICY, parse::ParsePolicy};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[tokio::test]
#[serial_test::serial]
async fn mta_sts_verify() {
    let mut local = TestServerBuilder::new("smtp_mta_sts_local")
        .await
        .with_http_listener(19028)
        .await
        .disable_services()
        .capture_queue()
        .capture_reporting()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_mta_sts_remote")
        .await
        .with_http_listener(19029)
        .await
        .with_smtp_listener(9925)
        .await
        .with_dummy_tls_cert(["*.foobar.org"])
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_no_auth().await;
    local_admin
        .registry_create_object(TlsReportSettings {
            send_frequency: Expression {
                else_: "weekly".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    let (tls_strategy_id, mut tls_strategy) = local_admin
        .registry_get_all::<MtaTlsStrategy>()
        .await
        .into_iter()
        .find(|(_, s)| s.name == "default")
        .unwrap();
    tls_strategy.mta_sts = MtaRequiredOrOptional::Require;
    tls_strategy.allow_invalid_certs = false;
    let mut tls_strategy = serde_json::to_value(tls_strategy).unwrap();
    tls_strategy
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k != "name");
    local_admin
        .registry_update_object(ObjectType::MtaTlsStrategy, tls_strategy_id, tls_strategy)
        .await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_no_auth().await;
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.mta_add_all_headers().await;
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
    local.server.txt_add(
        "_smtp._tls.foobar.org",
        TlsRpt::parse(b"v=TLSRPTv1; rua=mailto:reports@foobar.org").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
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
        .assert_contains("<bill@foobar.org> (MTA-STS failed to authenticate")
        .assert_contains("Record not f=")
        .assert_contains("ound");
    local.read_event().await.assert_done();

    // Expect TLS failure report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.domain, "foobar.org");
    assert_eq!(report.policy, PolicyType::Sts(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::Other
    );
    assert_eq!(
        report.tls_record.rua,
        vec![ReportUri::Mail("reports@foobar.org".to_string())]
    );

    // MTA-STS policy fetch failure
    local.server.txt_add(
        "_mta-sts.foobar.org",
        MtaSts::parse(b"v=STSv1; id=policy_will_fail;").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
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
        .assert_contains("<bill@foobar.org> (MTA-STS failed to authenticate")
        .assert_contains("No 'mx' entries found");
    local.read_event().await.assert_done();

    // Expect TLS failure report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Sts(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::StsPolicyInvalid
    );

    // MTA-STS policy does not authorize mx.foobar.org
    let policy = concat!(
        "version: STSv1\n",
        "mode: enforce\n",
        "mx: mail.foobar.net\n",
        "max_age: 604800\n"
    );
    STS_TEST_POLICY.lock().extend_from_slice(policy.as_bytes());
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
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
        .assert_contains("<bill@foobar.org> (MTA-STS failed to authenticate")
        .assert_contains("not authorized by policy");
    local.read_event().await.assert_done();

    // Expect TLS failure report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(
        report.policy,
        PolicyType::Sts(
            Arc::new(Policy::parse(policy, "policy_will_fail".to_string()).unwrap()).into()
        )
    );
    assert_eq!(
        report.failure.as_ref().unwrap().receiving_mx_hostname,
        Some("mx.foobar.org".to_string())
    );
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::ValidationFailure
    );
    remote.assert_no_events();

    // MTA-STS successful validation
    local.server.txt_add(
        "_mta-sts.foobar.org",
        MtaSts::parse(b"v=STSv1; id=policy_will_work;").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );
    let policy = concat!(
        "version: STSv1\n",
        "mode: enforce\n",
        "mx: *.foobar.org\n",
        "max_age: 604800\n"
    );
    STS_TEST_POLICY.lock().clear();
    STS_TEST_POLICY.lock().extend_from_slice(policy.as_bytes());
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local.read_event().await.assert_done();
    remote
        .expect_message()
        .await
        .read_lines(&remote)
        .await
        .assert_contains("using TLSv1.3 with cipher");

    // Expect TLS success report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(
        report.policy,
        PolicyType::Sts(
            Arc::new(Policy::parse(policy, "policy_will_work".to_string()).unwrap()).into()
        )
    );
    assert!(report.failure.is_none());
}
