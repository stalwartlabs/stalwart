/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::telemetry::metrics::store::MetricsStore;
use registry::{schema::prelude::ObjectType, types::datetime::UTCDateTime};
use std::time::Duration;
use store::write::now;
use types::id::Id;

pub async fn test(test: &TestServer) {
    println!("Running Metrics tests...");

    // Make sure there are no span entries in the db
    let admin = test.account("admin@example.org");
    assert_eq!(
        admin
            .registry_query(
                ObjectType::Metric,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        Vec::<Id>::new()
    );

    // Insert test metrics
    test.server.insert_test_metrics().await;

    // Fetch all metrics
    let metric_ids = admin
        .registry_query(
            ObjectType::Metric,
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
        .await
        .object_ids()
        .collect::<Vec<_>>();
    let response = admin
        .registry_get_many(ObjectType::Metric, Vec::<&str>::new())
        .await;
    let metrics = response.list();
    assert!(
        metrics.len() > 2000,
        "Found {} metrics, expected more than 2000",
        metrics.len()
    );
    assert_eq!(metrics.len(), metric_ids.len());

    // Fetch the last 48 hours of metrics
    let metric_ids = admin
        .registry_query(
            ObjectType::Metric,
            [(
                "timestampIsGreaterThan",
                UTCDateTime::from_timestamp((now() - (2 * 86400)) as i64).to_string(),
            )],
            Vec::<&str>::new(),
        )
        .await
        .object_ids()
        .collect::<Vec<_>>();
    assert!(
        metric_ids.len() > 20 && metric_ids.len() < 2000,
        "Found {} metrics, expected more than 20 and less than 2000",
        metric_ids.len()
    );

    // Test pagination (forward and reverse)
    let asc_order: Vec<Id> = admin
        .registry_query_paginated(
            ObjectType::Metric,
            "timestamp",
            true,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .object_ids()
        .collect();
    assert!(asc_order.len() > 100, "expected >100 metrics, got {}", asc_order.len());
    let desc_order: Vec<Id> = asc_order.iter().rev().copied().collect();
    let total = asc_order.len();
    let limit = 25usize;

    for chunk_start in [0usize, limit, total - limit] {
        let asc = admin
            .registry_query_paginated(
                ObjectType::Metric,
                "timestamp",
                true,
                Some(chunk_start as i32),
                Some(limit),
                None,
                None,
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            asc,
            asc_order[chunk_start..chunk_start + limit],
            "ascending position={chunk_start} limit={limit}",
        );

        let desc = admin
            .registry_query_paginated(
                ObjectType::Metric,
                "timestamp",
                false,
                Some(chunk_start as i32),
                Some(limit),
                None,
                None,
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            desc,
            desc_order[chunk_start..chunk_start + limit],
            "descending position={chunk_start} limit={limit}",
        );
    }

    for anchor_idx in [limit - 1, total - limit - 1] {
        let asc = admin
            .registry_query_paginated(
                ObjectType::Metric,
                "timestamp",
                true,
                None,
                Some(limit),
                Some(asc_order[anchor_idx]),
                Some(1),
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        let asc_size = std::cmp::min(limit, total - anchor_idx - 1);
        assert_eq!(
            asc,
            asc_order[anchor_idx + 1..anchor_idx + 1 + asc_size],
            "ascending anchor={} offset=1 limit={limit}",
            asc_order[anchor_idx],
        );

        let desc = admin
            .registry_query_paginated(
                ObjectType::Metric,
                "timestamp",
                false,
                None,
                Some(limit),
                Some(desc_order[anchor_idx]),
                Some(1),
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        let desc_size = std::cmp::min(limit, total - anchor_idx - 1);
        assert_eq!(
            desc,
            desc_order[anchor_idx + 1..anchor_idx + 1 + desc_size],
            "descending anchor={} offset=1 limit={limit}",
            desc_order[anchor_idx],
        );
    }

    // Purge metrics and make sure they are gone
    test.server
        .metrics_store()
        .purge_metrics(Duration::from_secs(0))
        .await
        .unwrap();
    assert_eq!(
        admin
            .registry_query(
                ObjectType::Metric,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        Vec::<Id>::new()
    );
}
