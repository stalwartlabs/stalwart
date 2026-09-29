/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{inbound::TestMessage, reporting::TestRecord, session::VerifyResponse},
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::{config::smtp::report::AggregateFrequency, ipc::DmarcEvent};
use mail_auth::{
    dmarc::{DmarcRecord, Policy},
    dns::TxtRecordParser,
    report::dmarc::{AggregateReport, Disposition, DmarcStatus, Record},
};
use registry::schema::structs::{
    DmarcInternalReport, DmarcReportSettings, Expression, ReportSettings,
};
use smtp::reporting::{dmarc::DmarcReporting, send::MtaReportSend};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

#[tokio::test]
async fn report_dmarc() {
    let mut test = TestServerBuilder::new("smtp_report_dmarc_test")
        .await
        .with_http_listener(19045)
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
        .registry_create_object(DmarcReportSettings {
            aggregate_contact_info: Expression {
                else_: "'https://foobar.org/contact'".into(),
                ..Default::default()
            },
            aggregate_dkim_sign_domain: Expression {
                else_: "'example.org'".into(),
                ..Default::default()
            },
            aggregate_from_address: Expression {
                else_: "'reports@' + system('domain')".into(),
                ..Default::default()
            },
            aggregate_from_name: Expression {
                else_: "'DMARC Report'".into(),
                ..Default::default()
            },
            aggregate_max_report_size: Expression {
                else_: "4096".into(),
                ..Default::default()
            },
            aggregate_org_name: Expression {
                else_: "'Foobar, Inc.'".into(),
                ..Default::default()
            },
            aggregate_send_frequency: Expression {
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

    // Authorize external report for foobar.org
    test.server.txt_add(
        "foobar.org._report._dmarc.foobar.net",
        DmarcRecord::parse(b"v=DMARC1;").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );

    // Schedule two events with a same policy and another one with a different policy
    let dmarc_record = Arc::new(
        DmarcRecord::parse(
            concat!(
                "v=DMARC1; p=quarantine; rua=mailto:reports@foobar.net,mailto:reports@example.net,",
                "mailto:rep<orts@foobar.net,mailto:rep>orts@foobar.net,",
                "mailto:rep%2Corts@foobar.net,mailto:rep\"orts@foobar.net"
            )
            .as_bytes(),
        )
        .unwrap(),
    );
    assert_eq!(dmarc_record.rua().len(), 6);
    for _ in 0..2 {
        test.server
            .schedule_dmarc(Box::new(DmarcEvent {
                domain: "foobar.org".to_string(),
                report_record: Record::evaluated(
                    "192.168.1.2",
                    Disposition::Pass,
                    DmarcStatus::Pass,
                    DmarcStatus::Fail,
                )
                .with_identifiers(
                    "hello@example.org",
                    "other@example.org",
                    "bye@example.org",
                ),
                dmarc_record: dmarc_record.clone(),
                interval: AggregateFrequency::Weekly,
                span_id: 0,
            }))
            .await;
    }
    test.server
        .schedule_dmarc(Box::new(DmarcEvent {
            domain: "foobar.org".to_string(),
            report_record: Record::evaluated(
                "a:b:c::e:f",
                Disposition::Reject,
                DmarcStatus::Fail,
                DmarcStatus::Pass,
            ),
            dmarc_record: dmarc_record.clone(),
            interval: AggregateFrequency::Weekly,
            span_id: 0,
        }))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reports = test.read_report_events::<DmarcInternalReport>().await;
    assert_eq!(reports.len(), 1);
    test.server
        .send_dmarc_aggregate_report(reports.first().unwrap().0.id())
        .await
        .unwrap();

    // Expect report
    let message = test.expect_message().await;
    test.assert_no_events();
    assert_eq!(message.message.recipients.len(), 1);
    assert_eq!(
        message.message.recipients.last().unwrap().address(),
        "reports@foobar.net"
    );
    assert_eq!(message.message.return_path.as_ref(), "reports@example.org");
    message
        .read_lines(&test)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.org;")
        .assert_contains("To: <reports@foobar.net>")
        .assert_contains("Report Domain: foobar.org")
        .assert_contains("Submitter: mx.example.org");

    // Verify generated report
    let report =
        AggregateReport::parse_rfc5322(message.read_message(&test).await.as_bytes(), usize::MAX)
            .unwrap();
    assert_eq!(report.policy_published.domain, "foobar.org");
    assert_eq!(report.report_metadata.email, "reports@example.org");
    assert_eq!(report.report_metadata.org_name, "Foobar, Inc.");
    assert_eq!(
        report
            .report_metadata
            .extra_contact_info
            .as_deref()
            .unwrap(),
        "https://foobar.org/contact"
    );
    assert_eq!(report.policy_published.p, Policy::Quarantine);
    assert_eq!(report.records.len(), 2, "records: {:?}", report.records);
    for record in &report.records {
        let source_ip = record.row.source_ip.unwrap();
        if source_ip == "192.168.1.2".parse::<IpAddr>().unwrap() {
            assert_eq!(record.row.count, 2);
            assert_eq!(record.row.policy_evaluated.disposition, Disposition::Pass);
            assert_eq!(record.identifiers.envelope_from, "hello@example.org");
            assert_eq!(record.identifiers.header_from, "bye@example.org");
            assert_eq!(
                record.identifiers.envelope_to.as_deref().unwrap(),
                "other@example.org"
            );
        } else if source_ip == "a:b:c::e:f".parse::<IpAddr>().unwrap() {
            assert_eq!(record.row.count, 1);
            assert_eq!(record.row.policy_evaluated.disposition, Disposition::Reject);
        } else {
            panic!("unexpected ip {source_ip}");
        }
    }
    test.assert_report_is_empty::<DmarcInternalReport>().await;

    test.server
        .send_report(
            "reports@example.org",
            [
                "rep<orts@foobar.net",
                "rep>orts@foobar.net",
                "rep,orts@foobar.net",
                "rep\"orts@foobar.net",
                "reports@foobar.net",
            ]
            .into_iter(),
            b"Subject: report\r\n\r\nreport\r\n".to_vec(),
            &test.server.core.smtp.report.dmarc_aggregate.sign,
            true,
            0,
        )
        .await;
    let message = test.expect_message().await;
    test.assert_no_events();
    assert_eq!(
        message
            .message
            .recipients
            .iter()
            .map(|rcpt| rcpt.address())
            .collect::<Vec<_>>(),
        ["reports@foobar.net"]
    );
}
