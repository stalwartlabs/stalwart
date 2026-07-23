/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{inbound::TestMessage, session::VerifyResponse},
    utils::server::TestServerBuilder,
};
use common::{config::smtp::report::AggregateFrequency, ipc::TlsEvent};
use mail_auth::{
    common::parse::TxtRecordParser,
    flate2::read::GzDecoder,
    mta_sts::TlsRpt,
    report::tlsrpt::{FailureDetails, PolicyType, ResultType, TlsReport},
};
use registry::schema::structs::{Expression, ReportSettings, TlsInternalReport, TlsReportSettings};
use smtp::reporting::tls::{TLS_HTTP_REPORT, TlsReporting};
use std::{io::Read, sync::Arc, time::Duration};

#[tokio::test]
async fn report_tls() {
    let mut test = TestServerBuilder::new("smtp_report_tls_test")
        .await
        .with_http_listener(19047)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let admin = test.account("admin");
    let domain_id = admin.find_or_create_domain("example.org").await;
    admin.create_dkim_signatures(domain_id).await;
    admin
        .registry_create_object(ReportSettings {
            outbound_report_submitter: Expression {
                else_: "'mx.example.org'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(TlsReportSettings {
            contact_info: Expression {
                else_: "'https://foobar.org/contact'".into(),
                ..Default::default()
            },
            dkim_sign_domain: Expression {
                else_: "'example.org'".into(),
                ..Default::default()
            },
            from_address: Expression {
                else_: "'reports@example.org'".into(),
                ..Default::default()
            },
            from_name: Expression {
                else_: "'Report Subsystem'".into(),
                ..Default::default()
            },
            org_name: Expression {
                else_: "'Foobar, Inc.'".into(),
                ..Default::default()
            },
            send_frequency: Expression {
                else_: "daily".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin.mta_no_auth().await;
    admin.mta_allow_non_fqdn().await;
    admin.mta_allow_relaying().await;
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;

    // Schedule TLS reports to be delivered via email
    let tls_record = Arc::new(TlsRpt::parse(b"v=TLSRPTv1;rua=mailto:reports@foobar.org").unwrap());

    for _ in 0..2 {
        // Add two successful records
        test.server
            .schedule_tls(Box::new(TlsEvent {
                domain: "foobar.org".to_string(),
                policy: common::ipc::PolicyType::None,
                failure: None,
                tls_record: tls_record.clone(),
                interval: AggregateFrequency::Daily,
                span_id: 0,
            }))
            .await;
    }

    for (policy, rt) in [
        (
            common::ipc::PolicyType::None, // Quota limited at 1532 bytes, this should not be included in the report.
            ResultType::CertificateExpired,
        ),
        (common::ipc::PolicyType::Tlsa(None), ResultType::TlsaInvalid),
        (
            common::ipc::PolicyType::Sts(None),
            ResultType::StsPolicyFetchError,
        ),
        (
            common::ipc::PolicyType::Sts(None),
            ResultType::StsPolicyInvalid,
        ),
        (
            common::ipc::PolicyType::Sts(None),
            ResultType::StsWebpkiInvalid,
        ),
    ] {
        test.server
            .schedule_tls(Box::new(TlsEvent {
                domain: "foobar.org".to_string(),
                policy,
                failure: FailureDetails::new(rt).into(),
                tls_record: tls_record.clone(),
                interval: AggregateFrequency::Daily,
                span_id: 0,
            }))
            .await;
    }

    // Wait for flush
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reports = test.read_report_events::<TlsInternalReport>().await;
    assert_eq!(reports.len(), 1);
    let (report_id, report) = reports.into_iter().next().unwrap();
    assert_eq!(report.report.policies.len(), 3);
    test.server
        .send_tls_aggregate_report(report_id.id())
        .await
        .unwrap();

    // Expect report
    let message = test.expect_message().await;
    assert_eq!(
        message.message.recipients.last().unwrap().address(),
        "reports@foobar.org"
    );
    assert_eq!(message.message.return_path.as_ref(), "reports@example.org");
    message
        .read_lines(&test)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.org;")
        .assert_contains("To: <reports@foobar.org>")
        .assert_contains("Report Domain: foobar.org")
        .assert_contains("Submitter: mx.example.org");

    // Verify generated report
    let report = TlsReport::parse_rfc5322(message.read_message(&test).await.as_bytes()).unwrap();
    assert_eq!(report.organization_name.unwrap(), "Foobar, Inc.");
    assert_eq!(report.contact_info.unwrap(), "https://foobar.org/contact");
    assert_eq!(report.policies.len(), 3);
    let mut seen = [false; 3];
    for policy in report.policies {
        match policy.policy.policy_type {
            PolicyType::Tlsa => {
                seen[0] = true;
                assert_eq!(policy.summary.total_failure, 1);
                assert_eq!(policy.summary.total_success, 0);
                assert_eq!(policy.policy.policy_domain, "foobar.org");
                assert_eq!(policy.failure_details.len(), 1);
                assert_eq!(
                    policy.failure_details.first().unwrap().result_type,
                    ResultType::TlsaInvalid
                );
            }
            PolicyType::Sts => {
                seen[1] = true;
                assert_eq!(policy.summary.total_failure, 3);
                assert_eq!(policy.summary.total_success, 0);
                assert_eq!(policy.policy.policy_domain, "foobar.org");
                assert_eq!(policy.failure_details.len(), 3);
                assert!(
                    policy
                        .failure_details
                        .iter()
                        .any(|d| d.result_type == ResultType::StsPolicyFetchError)
                );
                assert!(
                    policy
                        .failure_details
                        .iter()
                        .any(|d| d.result_type == ResultType::StsPolicyInvalid)
                );
                assert!(
                    policy
                        .failure_details
                        .iter()
                        .any(|d| d.result_type == ResultType::StsWebpkiInvalid)
                );
            }
            PolicyType::NoPolicyFound => {
                seen[2] = true;
                assert_eq!(policy.summary.total_failure, 1);
                assert_eq!(policy.summary.total_success, 2);
                assert_eq!(policy.policy.policy_domain, "foobar.org");
                assert_eq!(policy.failure_details.len(), 1);
                /*assert_eq!(
                    policy.failure_details.first().unwrap().result_type,
                    ResultType::CertificateExpired
                );*/
            }
            PolicyType::Other => unreachable!(),
        }
    }

    assert!(seen[0]);
    assert!(seen[1]);
    assert!(seen[2]);

    // Schedule TLS reports to be delivered via https
    let tls_record = Arc::new(TlsRpt::parse(b"v=TLSRPTv1;rua=https://127.0.0.1/tls").unwrap());

    for _ in 0..2 {
        // Add two successful records
        test.server
            .schedule_tls(Box::new(TlsEvent {
                domain: "foobar.org".to_string(),
                policy: common::ipc::PolicyType::None,
                failure: None,
                tls_record: tls_record.clone(),
                interval: AggregateFrequency::Daily,
                span_id: 0,
            }))
            .await;
    }

    let reports = test.read_report_events::<TlsInternalReport>().await;
    assert_eq!(reports.len(), 1);
    test.server
        .send_tls_aggregate_report(reports.first().unwrap().0.id())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Uncompress report
    {
        let gz_report = TLS_HTTP_REPORT.lock();
        let mut file = GzDecoder::new(&gz_report[..]);
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        let report = TlsReport::parse_json(&buf).unwrap();
        assert_eq!(report.organization_name.unwrap(), "Foobar, Inc.");
        assert_eq!(report.contact_info.unwrap(), "https://foobar.org/contact");
        assert_eq!(report.policies.len(), 1);
    }
    test.assert_report_is_empty::<TlsInternalReport>().await;
}
