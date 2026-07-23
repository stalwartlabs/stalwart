/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::session::TestSession,
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::{BuildServer, config::smtp::queue::QueueName, ipc::QueueEvent};
use mail_auth::{DnssecStatus, MX};
use registry::{
    schema::{
        enums::NetworkListenerProtocol,
        prelude::ObjectType,
        structs::{
            Expression, ExpressionMatch, MtaDeliveryExpiration, MtaDeliveryExpirationTtl,
            MtaDeliverySchedule, MtaDeliveryScheduleInterval, MtaDeliveryScheduleIntervals,
            MtaDeliveryScheduleIntervalsOrDefault, MtaOutboundStrategy, MtaStageData,
            MtaVirtualQueue,
        },
    },
    types::list::List,
};
use smtp::queue::manager::Queue;
use std::time::{Duration, Instant};

const NUM_MESSAGES: usize = 100;
const NUM_QUEUES: usize = 10;

#[tokio::test(flavor = "multi_thread", worker_threads = 18)]
#[serial_test::serial]
async fn virtual_queue() {
    let mut local = TestServerBuilder::new("smtp_virtual_queue_local")
        .await
        .with_http_listener(19042)
        .await
        .disable_services()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_virtual_queue_remote")
        .await
        .with_http_listener(19043)
        .await
        .with_listener(NetworkListenerProtocol::Smtp, "smtp-debug", 9925, false)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin
        .registry_create_object(MtaOutboundStrategy {
            schedule: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "rcpt == 'delay-random@foobar.org'".into(),
                    then: "'q2'".into(),
                }]),
                else_: "'q1'".into(),
            },
            ..Default::default()
        })
        .await;
    local_admin
        .registry_create_object(MtaStageData {
            max_messages: Expression {
                else_: "2000".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    let queue1_id = local_admin
        .registry_create_object(MtaVirtualQueue {
            name: "q1".into(),
            threads_per_node: 5,
            description: None,
        })
        .await;
    let queue2_id = local_admin
        .registry_create_object(MtaVirtualQueue {
            name: "q2".into(),
            threads_per_node: 4,
            description: None,
        })
        .await;
    local_admin
        .registry_create_object(MtaDeliverySchedule {
            name: "q1".into(),
            retry: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 1_000u64.into(),
                }]),
            }),
            notify: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 86_400_000u64.into(),
                }]),
            }),
            expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                expire: 86_400_000u64.into(),
            }),
            queue_id: queue1_id,
            description: None,
        })
        .await;
    local_admin
        .registry_create_object(MtaDeliverySchedule {
            name: "q2".into(),
            retry: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 1_000u64.into(),
                }]),
            }),
            notify: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 86_400_000u64.into(),
                }]),
            }),
            expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                expire: 86_400_000u64.into(),
            }),
            queue_id: queue2_id,
            description: None,
        })
        .await;
    local_admin.mta_allow_relaying().await;
    local_admin.mta_disable_spam_filter().await;
    local_admin.mta_allow_non_fqdn().await;
    local_admin.mta_no_auth().await;
    local_admin
        .registry_destroy_all(ObjectType::MtaInboundThrottle)
        .await;
    local_admin.reload_settings().await;
    local.reload_core();

    let remote_admin = remote.account("admin");
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_disable_spam_filter().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.mta_no_auth().await;
    remote_admin
        .registry_destroy_all(ObjectType::MtaInboundThrottle)
        .await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    // Validate parsing
    for value in ["a", "ab", "abcdefgh"] {
        let queue_name = QueueName::new(value).unwrap();
        assert_eq!(queue_name.to_string(), value);
    }
    assert_eq!(
        local
            .server
            .core
            .smtp
            .queue
            .virtual_queues
            .get(&QueueName::new("q1").unwrap())
            .unwrap()
            .threads,
        5
    );
    assert_eq!(
        local
            .server
            .core
            .smtp
            .queue
            .virtual_queues
            .get(&QueueName::new("q2").unwrap())
            .unwrap()
            .threads,
        4
    );

    // Add mock DNS entries
    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(100),
    );
    local.server.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(100),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;

    // Spawn concurrent queues
    let mut inners = vec![];
    for _ in 0..NUM_QUEUES {
        let (inner, rxs) = local.inner_with_rxs().await;
        let server = inner.build_server();
        server.mx_add(
            "foobar.org",
            vec![MX {
                exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
                preference: 10,
            }],
            DnssecStatus::Secure,
            Instant::now() + Duration::from_secs(100),
        );
        server.ipv4_add(
            "mx.foobar.org",
            vec!["127.0.0.1".parse().unwrap()],
            Instant::now() + Duration::from_secs(100),
        );
        inners.push(inner.clone());
        tokio::spawn(async move {
            Queue::new(inner, rxs.queue_rx.unwrap()).start().await;
        });
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send 1000 test messages
    for _ in 0..(NUM_MESSAGES / 2) {
        session
            .send_message(
                "john@test.org",
                &["bill@foobar.org", "delay-random@foobar.org"],
                "test:no_dkim",
                "250",
            )
            .await;
    }

    // Wake up all queues
    for inner in &inners {
        inner.ipc.queue_tx.send(QueueEvent::Refresh).await.unwrap();
    }
    for _ in 0..(NUM_MESSAGES / 2) {
        session
            .send_message(
                "john@test.org",
                &["bill@foobar.org", "delay-random@foobar.org"],
                "test:no_dkim",
                "250",
            )
            .await;
    }

    loop {
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let m = local.read_queued_messages().await;
        let e = local.read_queued_events().await;

        if m.len() + e.len() != 0 {
            println!(
                "Queue still has {} messages and {} events",
                m.len(),
                e.len()
            );
            /*for inner in &inners {
                inner.ipc.queue_tx.send(QueueEvent::Refresh).await.unwrap();
            }*/
        } else {
            break;
        }
    }

    local.assert_queue_is_empty().await;
    let remote_messages = remote.read_queued_messages().await;
    assert_eq!(remote_messages.len(), NUM_MESSAGES * 2);

    // Make sure local store is queue
    local
        .account("admin")
        .registry_destroy_all(ObjectType::MtaConnectionStrategy)
        .await;
    local.assert_is_empty().await;
}
