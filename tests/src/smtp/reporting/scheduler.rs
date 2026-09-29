/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{smtp::reporting::TestRecord, utils::server::TestServerBuilder};
use common::{
    config::smtp::report::AggregateFrequency,
    ipc::{DmarcEvent, PolicyType, TlsEvent},
};
use mail_auth::{
    dmarc::DmarcRecord,
    dns::TxtRecordParser,
    mta_sts::TlsRptRecord,
    report::dmarc::{Disposition, DmarcStatus, Record},
};
use registry::schema::structs::{
    DmarcInternalReport, DmarcReportSettings, Expression, TlsInternalReport, TlsReportSettings,
};
use smtp::reporting::{dmarc::DmarcReporting, tls::TlsReporting};
use std::sync::Arc;

#[tokio::test]
async fn report_scheduler() {
    let mut test = TestServerBuilder::new("smtp_report_queue_test")
        .await
        .with_http_listener(19046)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let admin = test.account("admin");
    admin
        .registry_create_object(DmarcReportSettings {
            aggregate_max_report_size: Expression {
                else_: "500".into(),
                ..Default::default()
            },
            aggregate_send_frequency: Expression {
                else_: "daily".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(TlsReportSettings {
            max_report_size: Expression {
                else_: "550".into(),
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

    // Schedule two events with a same policy and another one with a different policy
    let dmarc_record = Arc::new(
        DmarcRecord::parse(b"v=DMARC1; p=quarantine; rua=mailto:dmarc@foobar.org").unwrap(),
    );
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

    // No records should be added once the 550 bytes max size is reached
    for _ in 0..10 {
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
    let dmarc_record =
        Arc::new(DmarcRecord::parse(b"v=DMARC1; p=reject; rua=mailto:dmarc@foobar.org").unwrap());
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

    // Schedule TLS event
    let tls_record =
        Arc::new(TlsRptRecord::parse(b"v=TLSRPTv1;rua=mailto:reports@foobar.org").unwrap());
    test.server
        .schedule_tls(Box::new(TlsEvent {
            domain: "foobar.org".to_string(),
            policy: PolicyType::Tlsa(None),
            failure: None,
            tls_record: tls_record.clone(),
            interval: AggregateFrequency::Daily,
            span_id: 0,
        }))
        .await;
    test.server
        .schedule_tls(Box::new(TlsEvent {
            domain: "foobar.org".to_string(),
            policy: PolicyType::Tlsa(None),
            failure: None,
            tls_record: tls_record.clone(),
            interval: AggregateFrequency::Daily,
            span_id: 0,
        }))
        .await;
    test.server
        .schedule_tls(Box::new(TlsEvent {
            domain: "foobar.org".to_string(),
            policy: PolicyType::Sts(None),
            failure: None,
            tls_record: tls_record.clone(),
            interval: AggregateFrequency::Daily,
            span_id: 0,
        }))
        .await;
    test.server
        .schedule_tls(Box::new(TlsEvent {
            domain: "foobar.org".to_string(),
            policy: PolicyType::None,
            failure: None,
            tls_record: tls_record.clone(),
            interval: AggregateFrequency::Daily,
            span_id: 0,
        }))
        .await;

    // Verify sizes and counts
    let mut total_tls = 0;
    let mut total_tls_policies = 0;
    let mut total_dmarc_policies = 0;
    for (_, report) in test.read_report_events::<DmarcInternalReport>().await {
        total_dmarc_policies += 1;
        assert_eq!(
            report.deliver_at.timestamp() - report.created_at.timestamp(),
            7 * 86400
        );
    }
    for (_, report) in test.read_report_events::<TlsInternalReport>().await {
        total_tls += 1;
        total_tls_policies += report.report.policies.len();
        assert_eq!(
            report.deliver_at.timestamp() - report.created_at.timestamp(),
            86400
        );
    }
    assert_eq!(total_tls, 1);
    assert_eq!(total_tls_policies, 3);
    assert_eq!(total_dmarc_policies, 2);
}
