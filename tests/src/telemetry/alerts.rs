/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::BuildServer;
use registry::{
    schema::{
        prelude::ObjectType,
        structs::{
            Alert, AlertEmail, AlertEmailProperties, AlertEvent, AlertEventProperties, Expression,
        },
    },
    types::map::Map,
};
use trc::{ClusterEvent, Collector, EventType, MetricType};

pub async fn test(test: &TestServer) {
    println!("Running Alerts tests...");

    // Create alerts
    let admin = test.account("admin@example.org");
    admin
        .registry_create_object(Alert {
            enable: true,
            condition: Expression {
                else_: "metric('domain.count') > 1 && metric('cluster.publisher-error') > 3".into(),
                ..Default::default()
            },
            email_alert: AlertEmail::Enabled(AlertEmailProperties {
                body: concat!(
                    "Sorry for the bad news, but we found %{domain.count}% ",
                    "domains and %{cluster.publisher-error}% cluster errors."
                )
                .to_string(),
                from_address: "alert@example.com".to_string(),
                from_name: "Alert Subsystem".to_string().into(),
                subject: "Found %{cluster.publisher-error}% cluster errors".to_string(),
                to: Map::new(vec!["jdoe@example.com".to_string()]),
            }),
            event_alert: AlertEvent::Enabled(AlertEventProperties {
                event_message: "Yikes! Found %{cluster.publisher-error}% cluster errors!"
                    .to_string()
                    .into(),
            }),
        })
        .await;
    admin
        .registry_create_object(Alert {
            enable: true,
            condition: Expression {
                else_: "metric('domain.count') < 1 || metric('cluster.publisher-error') < 3".into(),
                ..Default::default()
            },
            email_alert: AlertEmail::Disabled,
            event_alert: AlertEvent::Enabled(AlertEventProperties {
                event_message: "this should not have happened".to_string().into(),
            }),
        })
        .await;
    admin.reload_settings().await;

    // Make sure the required metrics are set to 0
    assert_eq!(
        Collector::read_metric(MetricType::ClusterPublisherError),
        0.0
    );
    assert_eq!(Collector::read_metric(MetricType::DomainCount), 1.0);
    assert_eq!(Collector::read_metric(MetricType::TelemetryAlertEvent), 0.0);

    // Increment metrics to trigger alerts
    Collector::update_event_counter(EventType::Cluster(ClusterEvent::PublisherError), 5);
    Collector::update_gauge(MetricType::DomainCount, 3);

    // Make sure the values were set
    assert_eq!(
        Collector::read_metric(MetricType::ClusterPublisherError),
        5.0
    );
    assert_eq!(Collector::read_metric(MetricType::DomainCount), 3.0);

    // Process alerts
    let message = test
        .server
        .inner
        .build_server()
        .process_alerts()
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(message.from, "alert@example.com");
    assert_eq!(message.to, vec!["jdoe@example.com".to_string()]);
    let body = String::from_utf8(message.body).unwrap();
    assert!(
        body.contains("Sorry for the bad news, but we found 3 domains and 5 cluster errors."),
        "{body:?}"
    );
    assert!(body.contains("Subject: Found 5 cluster errors"), "{body:?}");
    assert!(
        body.contains("From: \"Alert Subsystem\" <alert@example.com>"),
        "{body:?}"
    );
    assert!(body.contains("To: <jdoe@example.com>"), "{body:?}");

    // Make sure the event was triggered
    assert_eq!(Collector::read_metric(MetricType::TelemetryAlertEvent), 1.0);

    // Cleanup
    admin.registry_destroy_all(ObjectType::Alert).await;
    admin.reload_settings().await;
    test.cleanup().await;
}
