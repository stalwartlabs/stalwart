/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{inbound::TestQueueEvent, session::TestSession},
    utils::server::TestServerBuilder,
};
use ahash::AHashMap;
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
use std::time::Duration;

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

    // Test delivery to non-report addresses
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    test.read_event().await.assert_refresh();
    test.last_queued_message().await;
}
