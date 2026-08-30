/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::session::TestSession,
    utils::server::TestServerBuilder,
};
use ahash::AHashMap;
use flate2::{Compression, Crc, write::GzEncoder};
use mail_builder::{
    MessageBuilder,
    mime::{BodyPart, MimePart},
};
use registry::{
    schema::{
        enums::TaskStoreMaintenanceType,
        structs::{
            ArfExternalReport, DataRetention, DmarcExternalReport, Expression, MtaStageData,
            ReportSettings, Task, TaskStatus, TaskStoreMaintenance, TlsExternalReport,
        },
    },
    types::map::Map,
};
use std::{io::Write, time::Duration};

const MAX_REPORT_SIZE: i64 = 65536;

const DMARC_REPORT: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata>"#,
    r#"<org_name>Example</org_name><email>dmarc@example.org</email>"#,
    r#"<report_id>1</report_id><date_range><begin>1</begin><end>2</end></date_range>"#,
    r#"</report_metadata><policy_published><domain>foobar.org</domain>"#,
    r#"</policy_published></feedback>"#
);

fn report_message(content_type: &str, file_name: &str, payload: &[u8]) -> String {
    MessageBuilder::new()
        .from(("Reporter", "reporter@test.org"))
        .to("reports@foobar.org")
        .subject("Report Domain: foobar.org")
        .body(MimePart::new(
            "multipart/report",
            BodyPart::Multipart(vec![
                MimePart::new("text/plain", BodyPart::Text("Report attached.".into())),
                MimePart::new(content_type, BodyPart::Binary(payload.into())).attachment(file_name),
            ]),
        ))
        .write_to_string()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn report_analyze() {
    let mut test = TestServerBuilder::new("smtp_analyze_report_test")
        .await
        .with_http_listener(19044)
        .await
        .capture_queue()
        .build()
        .await;

    let admin = test.account("admin");
    admin
        .registry_create_object(MtaStageData {
            max_messages: Expression {
                else_: "100".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(ReportSettings {
            inbound_report_addresses: Map::new(vec![
                "reports@*".to_string(),
                "*@dmarc.foobar.org".to_string(),
                "feedback@foobar.org".to_string(),
            ]),
            inbound_report_forwarding: false,
            inbound_report_max_size: MAX_REPORT_SIZE,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(DataRetention {
            hold_mta_reports_for: Some(1u64.into()),
            ..Default::default()
        })
        .await;
    admin.mta_no_auth().await;
    admin.mta_allow_non_fqdn().await;
    admin.mta_allow_relaying().await;
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;

    // Create test message
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;

    let addresses = [
        "reports@foobar.org",
        "rep@dmarc.foobar.org",
        "feedback@foobar.org",
    ];
    let mut ac = 0;
    let mut total_reports_received: AHashMap<&str, usize> = AHashMap::new();
    for (test_name, num_tests) in [("arf", 5), ("dmarc", 5), ("tls", 2)] {
        for num_test in 1..=num_tests {
            *total_reports_received.entry(test_name).or_insert(0) += 1;
            session
                .send_message(
                    "john@test.org",
                    &[addresses[ac % addresses.len()]],
                    &format!("report:{test_name}{num_test}"),
                    "250",
                )
                .await;
            test.assert_no_events();
            ac += 1;
        }
    }

    // Report ingestion is asynchronous, poll until the reports are stored
    let admin = test.account("admin");
    for _ in 0..50 {
        if admin.registry_get_all::<DmarcExternalReport>().await.len()
            == total_reports_received["dmarc"]
            && admin.registry_get_all::<TlsExternalReport>().await.len()
                == total_reports_received["tls"]
            && admin.registry_get_all::<ArfExternalReport>().await.len()
                == total_reports_received["arf"]
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Purging the database shouldn't remove the reports
    admin
        .registry_create_object(Task::StoreMaintenance(TaskStoreMaintenance {
            maintenance_type: TaskStoreMaintenanceType::PurgeData,
            shard_index: None,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;

    // Make sure the reports are in the store
    assert_eq!(
        admin.registry_get_all::<DmarcExternalReport>().await.len(),
        total_reports_received["dmarc"]
    );
    assert_eq!(
        admin.registry_get_all::<TlsExternalReport>().await.len(),
        total_reports_received["tls"]
    );
    assert_eq!(
        admin.registry_get_all::<ArfExternalReport>().await.len(),
        total_reports_received["arf"]
    );

    // Wait one second, purge, and make sure they are gone
    tokio::time::sleep(Duration::from_secs(1)).await;
    admin
        .registry_create_object(Task::StoreMaintenance(TaskStoreMaintenance {
            maintenance_type: TaskStoreMaintenanceType::PurgeData,
            shard_index: None,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    assert_eq!(
        admin.registry_get_all::<DmarcExternalReport>().await,
        vec![]
    );
    assert_eq!(admin.registry_get_all::<TlsExternalReport>().await, vec![]);
    assert_eq!(admin.registry_get_all::<ArfExternalReport>().await, vec![]);

    // Reports that lie about their size or exceed the limit must not be ingested
    let attachment_name = "mx.test.org!foobar.org!1!2.xml";
    for payload in [
        report_message(
            "application/zip",
            &format!("{attachment_name}.zip"),
            &zip("report.xml", DMARC_REPORT.as_bytes(), None, Some(u32::MAX)),
        ),
        report_message(
            "application/gzip",
            &format!("{attachment_name}.gz"),
            &gzip(&vec![b' '; MAX_REPORT_SIZE as usize * 2]),
        ),
    ] {
        session
            .send_message("john@test.org", &["reports@foobar.org"], &payload, "250")
            .await;
        test.assert_no_events();
    }

    // A report within the limit is still ingested
    session
        .send_message(
            "john@test.org",
            &["reports@foobar.org"],
            &report_message(
                "application/zip",
                &format!("{attachment_name}.zip"),
                &zip("report.xml", DMARC_REPORT.as_bytes(), None, None),
            ),
            "250",
        )
        .await;
    test.assert_no_events();

    let admin = test.account("admin");
    for _ in 0..50 {
        if !admin
            .registry_get_all::<DmarcExternalReport>()
            .await
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        admin.registry_get_all::<DmarcExternalReport>().await.len(),
        1
    );

    // Test delivery to non-report addresses
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    test.expect_refresh().await;
    test.last_queued_message().await;

    // Messages sent to a report address that contain no report must be delivered
    session
        .send_message(
            "john@test.org",
            &["reports@foobar.org"],
            concat!(
                "From: john@test.org\r\n",
                "To: reports@foobar.org\r\n",
                "Subject: Your MX is refusing my connections\r\n",
                "\r\n",
                "Could you have a look at this?"
            ),
            "250",
        )
        .await;
    let message = test.expect_message().await;
    assert_eq!(
        message.message.recipients.last().unwrap().address(),
        "reports@foobar.org"
    );

    // Reports addressed to both a report address and a regular mailbox are
    // discarded only for the report address
    session
        .send_message(
            "john@test.org",
            &["reports@foobar.org", "bill@foobar.org"],
            &report_message(
                "application/zip",
                &format!("{attachment_name}.zip"),
                &zip("report.xml", DMARC_REPORT.as_bytes(), None, None),
            ),
            "250",
        )
        .await;
    let message = test.expect_message().await;
    assert_eq!(
        message
            .message
            .recipients
            .iter()
            .map(|rcpt| rcpt.address())
            .collect::<Vec<_>>(),
        vec!["bill@foobar.org"]
    );
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn zip(
    name: &str,
    data: &[u8],
    compressed_size: Option<u32>,
    uncompressed_size: Option<u32>,
) -> Vec<u8> {
    let mut crc = Crc::new();
    crc.update(data);
    let crc = crc.sum();
    let compressed_size = compressed_size.unwrap_or(data.len() as u32);
    let uncompressed_size = uncompressed_size.unwrap_or(data.len() as u32);
    let name = name.as_bytes();

    let mut out = Vec::new();
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&compressed_size.to_le_bytes());
    out.extend_from_slice(&uncompressed_size.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(data);

    let central_offset = out.len() as u32;
    out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&compressed_size.to_le_bytes());
    out.extend_from_slice(&uncompressed_size.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name);

    let central_size = out.len() as u32 - central_offset;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    out
}
