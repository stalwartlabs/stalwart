/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::TestQueueEvent,
        queue::{build_rcpt, new_message},
        session::TestSession,
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::config::smtp::queue::QueueName;
use mail_auth::{DnssecStatus, MX};
use registry::{
    schema::{
        enums::MtaOutboundThrottleKey,
        structs::{
            Expression, MtaDeliveryExpiration, MtaDeliveryExpirationTtl, MtaDeliverySchedule,
            MtaDeliveryScheduleInterval, MtaDeliveryScheduleIntervals,
            MtaDeliveryScheduleIntervalsOrDefault, MtaOutboundStrategy, MtaOutboundThrottle,
            MtaVirtualQueue, Rate,
        },
    },
    types::{list::List, map::Map},
};
use smtp::queue::{Message, QueueEnvelope, Recipient, throttle::IsAllowed};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};
use store::write::now;

#[tokio::test]
async fn throttle_outbound() {
    let mut local = TestServerBuilder::new("smtp_throttle_outbound")
        .await
        .with_http_listener(19032)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let admin = local.account("admin");
    let queue_id = admin
        .registry_create_object(MtaVirtualQueue {
            name: "default".into(),
            threads_per_node: 25,
            description: None,
        })
        .await;
    admin
        .registry_create_object(MtaDeliverySchedule {
            name: "default".into(),
            retry: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 3_600_000u64.into(),
                }]),
            }),
            notify: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 3_600_000u64.into(),
                }]),
            }),
            expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                expire: 3_600_000u64.into(),
            }),
            queue_id,
            description: None,
        })
        .await;
    admin
        .registry_create_object(MtaOutboundStrategy {
            schedule: Expression {
                else_: "'default'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;

    for (expr, key, rate_count, rate_duration) in [
        (
            "sender_domain = 'foobar.net'",
            MtaOutboundThrottleKey::SenderDomain,
            1,
            30 * 60 * 1000,
        ),
        (
            "rcpt_domain = 'example.net'",
            MtaOutboundThrottleKey::RcptDomain,
            1,
            40 * 60 * 1000,
        ),
        ("mx = 'mx.test.org'", MtaOutboundThrottleKey::Mx, 1, 99999),
        (
            "mx = 'mx.test.net'",
            MtaOutboundThrottleKey::Mx,
            1,
            50 * 60 * 1000,
        ),
    ] {
        admin
            .registry_create_object(MtaOutboundThrottle {
                enable: true,
                key: Map::new(vec![key]),
                match_: Expression {
                    else_: expr.into(),
                    ..Default::default()
                },
                rate: Rate {
                    count: rate_count,
                    period: rate_duration.into(),
                },
                description: "Test throttle".into(),
            })
            .await;
    }
    admin.mta_no_auth().await;
    admin.mta_allow_relaying().await;
    admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    // Build test message
    let mut test_message = new_message(0).message;
    test_message.return_path = "test@foobar.org".into();
    test_message
        .recipients
        .push(build_rcpt("bill@test.org", 0, 0, 0));

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@foobar.org", &["bill@test.org"], "test:no_dkim", "250")
        .await;
    assert_eq!(local.last_queued_due().await as i64 - now() as i64, 0);

    // Throttle sender
    let core = local.server.core.clone();
    let throttle = &core.smtp.queue.outbound_limiters;
    for t in &throttle.sender {
        local
            .server
            .is_allowed(
                t,
                &QueueEnvelope::test(&test_message, &test_message.recipients[0], ""),
                0,
            )
            .await
            .unwrap();
    }

    // Expect rate limit throttle for sender domain 'foobar.net'
    test_message.return_path = "test@foobar.net".into();
    for t in &throttle.sender {
        local
            .server
            .is_allowed(
                t,
                &QueueEnvelope::test(&test_message, &test_message.recipients[0], ""),
                0,
            )
            .await
            .unwrap();
    }
    test_message.recipients.clear();

    session
        .send_message("john@foobar.net", &["bill@test.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_for_queue_then_deliver("default")
        .await
        .try_deliver(local.server.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    local.read_event().await.assert_refresh();
    let due = local.last_queued_due().await - now();
    assert!(due > 0, "Due: {}", due);

    // Expect concurrency throttle for recipient domain 'example.org'
    test_message.return_path = "test@test.net".into();
    test_message
        .recipients
        .push(build_rcpt("test@example.org", 0, 0, 0));
    for t in &throttle.rcpt {
        local
            .server
            .is_allowed(
                t,
                &QueueEnvelope::test(&test_message, &test_message.recipients[0], ""),
                0,
            )
            .await
            .unwrap();
    }

    // Expect rate limit throttle for recipient domain 'example.net'
    test_message
        .recipients
        .push(build_rcpt("test@example.net", 0, 0, 0));
    for t in &throttle.rcpt {
        local
            .server
            .is_allowed(
                t,
                &QueueEnvelope::test(&test_message, &test_message.recipients[1], ""),
                0,
            )
            .await
            .unwrap();
    }

    session
        .send_message(
            "john@test.net",
            &["jane@example.net"],
            "test:no_dkim",
            "250",
        )
        .await;
    local
        .expect_message_for_queue_then_deliver("default")
        .await
        .try_deliver(local.server.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    local.read_event().await.assert_refresh();
    let due = local.last_queued_due().await - now();
    assert!(due > 0, "Due: {}", due);

    // Expect concurrency throttle for mx 'mx.test.org'
    local.server.mx_add(
        "test.org",
        vec![MX {
            exchanges: vec!["mx.test.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(10),
    );
    local.server.ipv4_add(
        "mx.test.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    test_message
        .recipients
        .push(build_rcpt("test@test.org", 0, 0, 0));

    for t in &throttle.remote {
        local
            .server
            .is_allowed(
                t,
                &QueueEnvelope::test(&test_message, &test_message.recipients[2], "mx.test.org"),
                0,
            )
            .await
            .unwrap();
    }

    // Expect rate limit throttle for mx 'mx.test.net'
    local.server.mx_add(
        "test.net",
        vec![MX {
            exchanges: vec!["mx.test.net".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(10),
    );
    local.server.ipv4_add(
        "mx.test.net",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    for t in &throttle.remote {
        local
            .server
            .is_allowed(
                t,
                &QueueEnvelope::test(&test_message, &test_message.recipients[1], "mx.test.net"),
                0,
            )
            .await
            .unwrap();
    }

    session
        .send_message("john@test.net", &["jane@test.net"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_for_queue_then_deliver("default")
        .await
        .try_deliver(local.server.clone());

    tokio::time::sleep(Duration::from_millis(100)).await;
    local.read_event().await.assert_refresh();
    let due = local.last_queued_due().await - now();
    assert!(due > 0, "Due: {}", due);
}

#[tokio::test]
async fn throttle_outbound_queue_name() {
    let mut local = TestServerBuilder::new("smtp_throttle_outbound_queue_name")
        .await
        .with_http_listener(19033)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let admin = local.account("admin");
    let queue_id = admin
        .registry_create_object(MtaVirtualQueue {
            name: "default".into(),
            threads_per_node: 25,
            description: None,
        })
        .await;
    admin
        .registry_create_object(MtaDeliverySchedule {
            name: "default".into(),
            retry: MtaDeliveryScheduleIntervalsOrDefault::Default,
            notify: MtaDeliveryScheduleIntervalsOrDefault::Default,
            expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                expire: 3_600_000u64.into(),
            }),
            queue_id,
            description: None,
        })
        .await;
    admin
        .registry_create_object(MtaOutboundStrategy {
            schedule: Expression {
                else_: "'default'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaOutboundThrottle {
            enable: true,
            key: Map::new(vec![MtaOutboundThrottleKey::SenderDomain]),
            match_: Expression {
                else_: "queue_name == 'default'".into(),
                ..Default::default()
            },
            rate: Rate {
                count: 1,
                period: (30u64 * 60 * 1000).into(),
            },
            description: "queue_name throttle".into(),
        })
        .await;
    admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let core = local.server.core.clone();
    let throttle = &core.smtp.queue.outbound_limiters;
    assert_eq!(throttle.sender.len(), 1);
    assert!(throttle.rcpt.is_empty());
    assert!(throttle.remote.is_empty());

    let matching = new_message(0);
    assert_eq!(matching.queue_name, QueueName::default());
    local
        .server
        .is_allowed(&throttle.sender[0], &matching, 0)
        .await
        .unwrap();
    assert!(
        local
            .server
            .is_allowed(&throttle.sender[0], &matching, 0)
            .await
            .is_err(),
        "sender-bucket throttle failed to resolve queue_name and never engaged"
    );

    let mut other_queue = new_message(0);
    other_queue.queue_name = QueueName::new("remote").unwrap();
    local
        .server
        .is_allowed(&throttle.sender[0], &other_queue, 0)
        .await
        .unwrap();
}

pub trait TestQueueEnvelope<'x> {
    fn test(message: &'x Message, rcpt: &'x Recipient, mx: &'x str) -> Self;
}

impl<'x> TestQueueEnvelope<'x> for QueueEnvelope<'x> {
    fn test(message: &'x Message, rcpt: &'x Recipient, mx: &'x str) -> Self {
        QueueEnvelope {
            message,
            mx,
            remote_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            local_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            domain: rcpt.domain_part(),
            rcpt,
        }
    }
}
