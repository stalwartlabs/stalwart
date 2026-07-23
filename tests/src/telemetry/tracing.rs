/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{server::TestServer, smtp::SmtpConnection};
use common::telemetry::tracers::store::TracingStore;
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::Trace,
};
use std::time::Duration;
use trc::{DeliveryEvent, EventType, SmtpEvent};
use types::id::Id;

pub async fn test(test: &TestServer) {
    println!("Running Tracing tests...");

    // Create test accounts
    let admin = test.account("admin@example.org");
    let account = test
        .create_user_account(
            "admin@example.org",
            "admin@example.org",
            "this is a very strong password",
            &[],
            "admin@example.org",
        )
        .await;

    // Make sure there are no span entries in the db
    test.server
        .tracing_store()
        .purge_spans(Duration::from_secs(0), test.server.search_store().into())
        .await
        .unwrap();
    assert_eq!(
        admin
            .registry_query(
                ObjectType::Trace,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        Vec::<Id>::new()
    );

    // Send an email
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.org",
        &["jdoe@example.org"],
        concat!(
            "From: bill@example.org\r\n",
            "To: jdoe@example.org\r\n",
            "Subject: TPS Report\r\n",
            "X-Spam-Status: No\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    lmtp.quit().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    test.server.notify_task_queue();
    test.wait_for_tasks().await;

    // There should be 2 spans
    assert_eq!(
        admin
            .registry_query(
                ObjectType::Trace,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .count(),
        2
    );

    // Purge should not delete anything at this point
    test.server
        .tracing_store()
        .purge_spans(Duration::from_secs(2), test.server.search_store().into())
        .await
        .unwrap();

    // There should be 2 spans
    assert_eq!(
        admin
            .registry_query(
                ObjectType::Trace,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .count(),
        2
    );

    // Search by spam type
    for span_type in [
        EventType::Delivery(DeliveryEvent::AttemptStart),
        EventType::Smtp(SmtpEvent::ConnectionStart),
    ] {
        let span_ids = admin
            .registry_query(
                ObjectType::Trace,
                [(Property::Event, span_type.as_str())],
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();

        assert_eq!(span_ids.len(), 1, "{span_type:?}");
        let trace = admin.registry_get::<Trace>(span_ids[0]).await;

        assert_eq!(trace.events.iter().next().unwrap().event, span_type);
    }

    // Try searching
    for keyword in ["bill@example.org", "jdoe@example.org", "example.org"] {
        let span_ids = admin
            .registry_query(
                ObjectType::Trace,
                [(Property::Text, keyword)],
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();

        assert_eq!(span_ids.len(), 2, "keyword: {keyword}");

        let trace_1 = admin.registry_get::<Trace>(span_ids[0]).await;
        let trace_2 = admin.registry_get::<Trace>(span_ids[1]).await;

        assert!(trace_1 != trace_2, "keyword: {keyword}");
    }

    // Purge should delete the span entries
    tokio::time::sleep(Duration::from_millis(800)).await;
    test.server
        .tracing_store()
        .purge_spans(Duration::from_secs(1), test.server.search_store().into())
        .await
        .unwrap();

    assert_eq!(
        admin
            .registry_query(
                ObjectType::Trace,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        Vec::<Id>::new()
    );

    admin.destroy_account(account).await;
    test.cleanup().await;
}
