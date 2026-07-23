/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::TestMessage,
        session::{TestSession, VerifyResponse},
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::{config::smtp::queue::QueueName, ipc::QueueEvent};
use registry::{
    schema::{
        enums::{MtaProtocol, NetworkListenerProtocol},
        structs::{
            Expression, ExpressionMatch, MtaConnectionStrategy, MtaDeliveryExpiration,
            MtaDeliveryExpirationTtl, MtaDeliverySchedule, MtaDeliveryScheduleInterval,
            MtaDeliveryScheduleIntervals, MtaDeliveryScheduleIntervalsOrDefault,
            MtaOutboundStrategy, MtaRoute, MtaRouteRelay, MtaStageRcpt, MtaVirtualQueue,
        },
    },
    types::list::List,
};
use smtp::queue::spool::{QUEUE_REFRESH, SmtpSpool};
use std::time::{Duration, Instant};
use store::write::now;

#[tokio::test]
#[serial_test::serial]
async fn lmtp_delivery() {
    let mut local = TestServerBuilder::new("lmtp_delivery_local")
        .await
        .with_http_listener(19026)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("lmtp_delivery_remote")
        .await
        .with_http_listener(19027)
        .await
        .with_listener(NetworkListenerProtocol::Lmtp, "lmtp-debug", 9924, true)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin
        .registry_create_object(MtaStageRcpt {
            max_recipients: Expression {
                else_: "100".into(),

                ..Default::default()
            },
            allow_relaying: Expression {
                else_: "true".into(),

                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    local_admin
        .registry_create_object(MtaOutboundStrategy {
            route: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "rcpt_domain = 'foobar.org'".into(),
                    then: "'lmtp'".into(),
                }]),
                else_: "'mx'".into(),
            },
            schedule: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "rcpt_domain = 'foobar.org'".into(),
                    then: "'foobar'".into(),
                }]),
                else_: "'default'".into(),
            },
            connection: Expression {
                else_: "'impatient'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    local_admin
        .registry_create_object(MtaRoute::Relay(MtaRouteRelay {
            address: "lmtp.foobar.org".into(),
            allow_invalid_certs: true,
            implicit_tls: true,
            name: "lmtp".into(),
            port: 9924,
            protocol: MtaProtocol::Lmtp,
            ..Default::default()
        }))
        .await;
    let queue_id = local_admin
        .registry_create_object(MtaVirtualQueue {
            name: "default".into(),
            threads_per_node: 25,
            description: None,
        })
        .await;
    local_admin
        .registry_create_object(MtaDeliverySchedule {
            name: "foobar".into(),
            retry: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 1_000u64.into(),
                }]),
            }),
            notify: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([
                    MtaDeliveryScheduleInterval {
                        duration: 1_000u64.into(),
                    },
                    MtaDeliveryScheduleInterval {
                        duration: 2_000u64.into(),
                    },
                ]),
            }),
            expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                expire: 4_000u64.into(),
            }),
            queue_id,
            description: None,
        })
        .await;
    local_admin
        .registry_create_object(MtaDeliverySchedule {
            name: "default".into(),
            retry: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 1_000u64.into(),
                }]),
            }),
            notify: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 1_000u64.into(),
                }]),
            }),
            expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                expire: 5_000u64.into(),
            }),
            queue_id,
            description: None,
        })
        .await;
    local_admin
        .registry_create_object(MtaConnectionStrategy {
            name: "impatient".into(),
            connect_timeout: 1_000u64.into(),
            data_timeout: 50u64.into(),
            ..Default::default()
        })
        .await;
    local_admin.mta_no_auth().await;
    local_admin.mta_all_extensions().await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_no_auth().await;
    remote_admin.mta_all_extensions().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    // Add mock DNS entries
    local.server.ipv4_add(
        "lmtp.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(
            "john@test.org",
            &[
                "<bill@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<jane@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<john@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<invalid@domain.org> NOTIFY=SUCCESS,DELAY,FAILURE",
            ],
            "test:no_dkim",
            "250",
        )
        .await;
    local
        .expect_message_for_queue_then_deliver("default")
        .await
        .try_deliver(local.server.clone());
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut dsn = Vec::new();
    loop {
        match local.try_read_event().await {
            Some(QueueEvent::Refresh | QueueEvent::WorkerDone { .. }) => {}
            Some(QueueEvent::Paused(_)) | Some(QueueEvent::ReloadSettings) => unreachable!(),
            None | Some(QueueEvent::Stop) => break,
        }

        let mut events = local.all_queued_messages().await;
        if events.messages.is_empty() {
            let now = now();
            if events.next_refresh < now + QUEUE_REFRESH {
                tokio::time::sleep(Duration::from_secs(events.next_refresh - now)).await;
                events = local.all_queued_messages().await;
            } else {
                break;
            }
        }
        for event in events.messages {
            let message = local
                .server
                .read_message(event.queue_id, QueueName::default())
                .await
                .unwrap();
            if message.message.return_path.is_empty() {
                message
                    .clone()
                    .remove(&local.server, event.due.into())
                    .await;
                dsn.push(message);
            } else {
                event.try_deliver(local.server.clone());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    local.assert_queue_is_empty().await;
    assert_eq!(dsn.len(), 4);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (delivered to")
        .assert_contains("<jane@foobar.org> (delivered to")
        .assert_contains("<john@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.org> (host 'lmtp.foobar.org' rejected command");

    dsn.next()
        .unwrap()
        .read_lines(&local)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: failed");

    assert_eq!(
        remote
            .expect_message()
            .await
            .message
            .recipients
            .into_iter()
            .map(|r| r.address().to_string())
            .collect::<Vec<_>>(),
        vec![
            "bill@foobar.org".to_string(),
            "jane@foobar.org".to_string(),
            "john@foobar.org".to_string()
        ]
    );
    remote.assert_no_events();
}
