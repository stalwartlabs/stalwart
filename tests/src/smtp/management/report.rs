/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServerBuilder;
use ahash::AHashMap;
use common::{
    config::smtp::report::AggregateFrequency,
    ipc::{DmarcEvent, PolicyType, TlsEvent},
};
use mail_auth::{
    common::parse::TxtRecordParser,
    dmarc::Dmarc,
    mta_sts::TlsRpt,
    report::{
        ActionDisposition, DmarcResult, Record,
        tlsrpt::{FailureDetails, ResultType},
    },
};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{
        DmarcInternalReport, DmarcReportSettings, Expression, TlsInternalReport, TlsReportSettings,
    },
};
use smtp::reporting::send::MtaReportSend;
use std::sync::Arc;

#[tokio::test]
#[serial_test::serial]
async fn manage_reports() {
    let mut test = TestServerBuilder::new("smtp_report_manage")
        .await
        .with_http_listener(19048)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let admin = test.account("admin");
    admin
        .registry_create_object(TlsReportSettings {
            max_report_size: Expression {
                else_: "1024".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(DmarcReportSettings {
            aggregate_max_report_size: Expression {
                else_: "1024".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin.mta_allow_relaying().await;
    admin.mta_no_auth().await;
    admin.mta_allow_non_fqdn().await;
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;
    let admin = test.account("admin");

    // Send test reporting events
    test.server
        .schedule_report(DmarcEvent {
            domain: "foobar.org".to_string(),
            report_record: Record::new()
                .with_source_ip("192.168.1.2".parse().unwrap())
                .with_action_disposition(ActionDisposition::Pass)
                .with_dmarc_dkim_result(DmarcResult::Pass)
                .with_dmarc_spf_result(DmarcResult::Fail)
                .with_envelope_from("hello@example.org")
                .with_envelope_to("other@example.org")
                .with_header_from("bye@example.org"),
            dmarc_record: Arc::new(
                Dmarc::parse(b"v=DMARC1; p=reject; rua=mailto:reports@foobar.org").unwrap(),
            ),
            interval: AggregateFrequency::Daily,
            span_id: 0,
        })
        .await;
    test.server
        .schedule_report(DmarcEvent {
            domain: "foobar.net".to_string(),
            report_record: Record::new()
                .with_source_ip("a:b:c::e:f".parse().unwrap())
                .with_action_disposition(ActionDisposition::Reject)
                .with_dmarc_dkim_result(DmarcResult::Fail)
                .with_dmarc_spf_result(DmarcResult::Pass),
            dmarc_record: Arc::new(
                Dmarc::parse(
                    concat!(
                        "v=DMARC1; p=quarantine; rua=mailto:reports",
                        "@foobar.net,mailto:reports@example.net"
                    )
                    .as_bytes(),
                )
                .unwrap(),
            ),
            interval: AggregateFrequency::Weekly,
            span_id: 0,
        })
        .await;
    test.server
        .schedule_report(TlsEvent {
            domain: "foobar.org".to_string(),
            policy: PolicyType::None,
            failure: None,
            tls_record: Arc::new(
                TlsRpt::parse(b"v=TLSRPTv1;rua=mailto:reports@foobar.org").unwrap(),
            ),
            interval: AggregateFrequency::Daily,
            span_id: 0,
        })
        .await;
    test.server
        .schedule_report(TlsEvent {
            domain: "foobar.net".to_string(),
            policy: PolicyType::Sts(None),
            failure: FailureDetails::new(ResultType::StsPolicyInvalid).into(),
            tls_record: Arc::new(
                TlsRpt::parse(b"v=TLSRPTv1;rua=mailto:reports@foobar.net").unwrap(),
            ),
            interval: AggregateFrequency::Weekly,
            span_id: 0,
        })
        .await;

    // List DMARC reports
    let mut dmarc_name_to_id = AHashMap::new();
    let mut dmarc_id_to_name = AHashMap::new();
    for (id, report) in admin.registry_get_all::<DmarcInternalReport>().await {
        let diff =
            report.report.date_range_end.timestamp() - report.report.date_range_begin.timestamp();
        if report.domain == "foobar.org" {
            assert_eq!(diff, 86400);
        } else {
            assert_eq!(diff, 7 * 86400);
        }
        dmarc_name_to_id.insert(report.domain.clone(), id);
        dmarc_id_to_name.insert(id, report.domain);
    }
    assert_eq!(dmarc_name_to_id.len(), 2);

    // List TLS reports
    let mut tls_name_to_id = AHashMap::new();
    let mut tls_id_to_name = AHashMap::new();
    for (id, report) in admin.registry_get_all::<TlsInternalReport>().await {
        let diff =
            report.report.date_range_end.timestamp() - report.report.date_range_start.timestamp();
        if report.domain == "foobar.org" {
            assert_eq!(diff, 86400);
        } else {
            assert_eq!(diff, 7 * 86400);
        }
        tls_name_to_id.insert(report.domain.clone(), id);
        tls_id_to_name.insert(id, report.domain);
    }
    assert_eq!(tls_name_to_id.len(), 2);

    // Test list search
    for (object, query, expected_ids) in [
        (
            ObjectType::DmarcInternalReport,
            vec![],
            vec![
                dmarc_name_to_id["foobar.org"],
                dmarc_name_to_id["foobar.net"],
            ],
        ),
        (
            ObjectType::TlsInternalReport,
            vec![],
            vec![tls_name_to_id["foobar.org"], tls_name_to_id["foobar.net"]],
        ),
        (
            ObjectType::DmarcInternalReport,
            vec![(Property::Domain, "foobar.org".to_string())],
            vec![dmarc_name_to_id["foobar.org"]],
        ),
        (
            ObjectType::DmarcInternalReport,
            vec![(Property::Domain, "foobar.net".to_string())],
            vec![dmarc_name_to_id["foobar.net"]],
        ),
        (
            ObjectType::TlsInternalReport,
            vec![(Property::Domain, "foobar.org".to_string())],
            vec![tls_name_to_id["foobar.org"]],
        ),
        (
            ObjectType::TlsInternalReport,
            vec![(Property::Domain, "foobar.net".to_string())],
            vec![tls_name_to_id["foobar.net"]],
        ),
    ] {
        assert_eq!(
            admin
                .registry_query_ids(object, query.clone(), Vec::<&str>::new())
                .await,
            expected_ids,
            "failed for {object:?} with query {query:?}"
        );
    }

    // Cancel reports
    for (object, id) in [
        (
            ObjectType::DmarcInternalReport,
            dmarc_name_to_id["foobar.org"],
        ),
        (ObjectType::TlsInternalReport, tls_name_to_id["foobar.org"]),
    ] {
        admin
            .registry_destroy(object, vec![id])
            .await
            .assert_destroyed(&[id]);
    }
    for (object, id) in [
        (
            ObjectType::DmarcInternalReport,
            dmarc_name_to_id["foobar.net"],
        ),
        (ObjectType::TlsInternalReport, tls_name_to_id["foobar.net"]),
    ] {
        assert_eq!(
            admin
                .registry_query_ids(object, Vec::<(&str, &str)>::new(), Vec::<&str>::new())
                .await,
            vec![id],
            "failed for {object:?}"
        );
    }

    // Cancel all reports
    admin
        .registry_destroy_all(ObjectType::DmarcInternalReport)
        .await;
    admin
        .registry_destroy_all(ObjectType::TlsInternalReport)
        .await;
    assert_eq!(
        admin.registry_get_all::<DmarcInternalReport>().await,
        Vec::new()
    );
    assert_eq!(
        admin.registry_get_all::<TlsInternalReport>().await,
        Vec::new()
    );
}
