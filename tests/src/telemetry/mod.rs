/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod alerts;
pub mod metrics;
pub mod tracing;
pub mod webhooks;

use crate::utils::server::TestServerBuilder;
use registry::schema::structs::{Expression, Jmap, MetricsStore, MtaStageAuth, TracingStore};

#[tokio::test(flavor = "multi_thread")]
pub async fn telemetry_tests() {
    let mut test = TestServerBuilder::new("telemetry_tests")
        .await
        .with_logging()
        .with_default_listeners()
        .await
        .with_object(MetricsStore::Default)
        .await
        .with_object(TracingStore::Default)
        .await
        .with_object(Jmap {
            get_max_results: 100_000,
            query_max_results: 100_000,
            ..Default::default()
        })
        .await
        .with_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;

    // Create admin account
    let admin = test
        .create_user_account(
            "admin",
            "admin@example.org",
            "these_pretzels_are_making_me_thirsty",
            &[],
            "Admin",
        )
        .await;
    test.account("admin")
        .assign_roles_to_account(admin.id(), &["user", "system"])
        .await;
    test.insert_account(admin);

    alerts::test(&test).await;
    metrics::test(&test).await;
    tracing::test(&test).await;
    webhooks::test(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}
