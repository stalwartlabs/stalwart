/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{inbound::TestQueueEvent, session::TestSession},
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use mail_auth::{DnssecStatus, MX};
use registry::{
    schema::{
        enums::MtaIpStrategy,
        prelude::{ObjectType, Property},
        structs::MtaRoute,
    },
    types::EnumImpl,
};
use serde_json::json;
use std::time::{Duration, Instant};

#[tokio::test]
#[serial_test::serial]
async fn ip_lookup_strategy() {
    let mut local = TestServerBuilder::new("smtp_iplookup_local")
        .await
        .with_http_listener(19024)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_iplookup_remote")
        .await
        .with_http_listener(19025)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_no_auth().await;
    local_admin.reload_settings().await;
    let (mx_route_id, _) = local_admin
        .registry_get_all::<MtaRoute>()
        .await
        .into_iter()
        .find(|(_, s)| matches!(s, MtaRoute::Mx(_)))
        .unwrap();
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_no_auth().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    for strategy in [MtaIpStrategy::V6Only, MtaIpStrategy::V6ThenV4] {
        local
            .account("admin")
            .registry_update_object(
                ObjectType::MtaRoute,
                mx_route_id,
                json!({
                    Property::IpLookupStrategy: strategy.as_str(),
                }),
            )
            .await;
        local.account("admin").reload_settings().await;
        local.expect_reload_settings().await;

        println!("-> Strategy: {:?}", strategy);
        // Add mock DNS entries
        local.server.mx_add(
            "foobar.org",
            vec![MX {
                exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
                preference: 10,
            }],
            DnssecStatus::Secure,
            Instant::now() + Duration::from_secs(10),
        );
        if matches!(strategy, MtaIpStrategy::V6ThenV4) {
            local.server.ipv4_add(
                "mx.foobar.org",
                vec!["127.0.0.1".parse().unwrap()],
                Instant::now() + Duration::from_secs(10),
            );
        }
        local.server.ipv6_add(
            "mx.foobar.org",
            vec!["::1".parse().unwrap()],
            Instant::now() + Duration::from_secs(10),
        );

        // Retry on failed STARTTLS
        let mut session = local.new_mta_session();
        session.data.remote_ip_str = "10.0.0.1".into();
        session.eval_session_params().await;
        session.ehlo("mx.test.org").await;
        session
            .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
            .await;
        local
            .expect_message_then_deliver()
            .await
            .try_deliver(local.server.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;
        if matches!(strategy, MtaIpStrategy::V6ThenV4) {
            remote.expect_message().await;
        } else {
            let message = local.last_queued_message().await;
            let status = message.message.recipients[0].status.to_string();
            assert!(
                status.contains("Connection refused"),
                "Message: {:?}",
                message
            );
            local.read_event().await.assert_refresh();
        }
    }
}
