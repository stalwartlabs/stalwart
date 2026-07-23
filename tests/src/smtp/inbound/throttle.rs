/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServerBuilder;
use registry::{
    schema::{
        enums::MtaInboundThrottleKey,
        structs::{Expression, MtaInboundThrottle, Rate},
    },
    types::map::Map,
};
use smtp::core::SessionAddress;
use std::time::Duration;

#[tokio::test]
async fn throttle_inbound() {
    let mut test = TestServerBuilder::new("smtp_inbound_throttle_test")
        .await
        .with_http_listener(19009)
        .await
        .disable_services()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    admin
        .registry_create_object(MtaInboundThrottle {
            description: "Test throttle".into(),
            enable: true,
            key: Map::new(vec![MtaInboundThrottleKey::RemoteIp]),
            match_: Expression {
                else_: "remote_ip = '10.0.0.1'".into(),
                ..Default::default()
            },
            rate: Rate {
                count: 2,
                period: 1000u64.into(),
            },
        })
        .await;

    admin
        .registry_create_object(MtaInboundThrottle {
            description: "Test throttle".into(),
            enable: true,
            key: Map::new(vec![MtaInboundThrottleKey::Sender]),
            rate: Rate {
                count: 2,
                period: 1000u64.into(),
            },
            ..Default::default()
        })
        .await;

    admin
        .registry_create_object(MtaInboundThrottle {
            enable: true,
            key: Map::new(vec![
                MtaInboundThrottleKey::RemoteIp,
                MtaInboundThrottleKey::Rcpt,
            ]),
            rate: Rate {
                count: 2,
                period: 1000u64.into(),
            },
            description: "Test throttle".into(),
            ..Default::default()
        })
        .await;

    admin.reload_settings().await;
    test.reload_core();

    // Test connection rate limit
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        session.is_allowed().await,
        "Rate limiter did not restore quota."
    );

    // Test mail from rate limit
    session.data.mail_from = SessionAddress {
        address: "sender@test.org".into(),
        address_lcase: "sender@test.org".into(),
        domain: "test.org".into(),
        flags: 0,
        dsn_info: None,
    }
    .into();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.data.mail_from = SessionAddress {
        address: "other-sender@test.org".into(),
        address_lcase: "other-sender@test.org".into(),
        domain: "test.org".into(),
        flags: 0,
        dsn_info: None,
    }
    .into();
    assert!(session.is_allowed().await, "Rate limiter failed.");

    // Test recipient rate limit
    session.data.rcpt_to.push(SessionAddress {
        address: "recipient@example.org".into(),
        address_lcase: "recipient@example.org".into(),
        domain: "example.org".into(),
        flags: 0,
        dsn_info: None,
    });
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.data.remote_ip_str = "10.0.0.2".into();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
}
