/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::{TestMessage, TestQueueEvent},
        session::{TestSession, VerifyResponse},
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::{config::smtp::queue::QueueName, ipc::QueueEvent};
use mail_auth::{DnssecStatus, MX};
use registry::{
    schema::{
        enums::NetworkListenerProtocol,
        structs::{
            Expression, ExpressionMatch, MtaDeliveryExpiration, MtaDeliveryExpirationTtl,
            MtaDeliverySchedule, MtaDeliveryScheduleInterval, MtaDeliveryScheduleIntervals,
            MtaDeliveryScheduleIntervalsOrDefault, MtaExtensions, MtaOutboundStrategy,
            MtaStageRcpt, MtaVirtualQueue,
        },
    },
    types::list::List,
};
use smtp::queue::spool::{QUEUE_REFRESH, SmtpSpool};
use std::time::{Duration, Instant};
use store::write::now;

const SMUGGLER: &str = r#"From: Joe SixPack <john@foobar.net>
To: Suzie Q <suzie@foobar.org>
Subject: Is dinner ready?

Hi.

We lost the game. Are you hungry yet?
.hey
Joe.

<SEP>.
MAIL FROM:<admin@foobar.net>
RCPT TO:<ok@foobar.org>
DATA
From: Joe SixPack <admin@foobar.net>
To: Suzie Q <suzie@foobar.org>
Subject: smuggled message

This is a smuggled message
"#;

#[tokio::test]
#[serial_test::serial]
async fn smtp_delivery() {
    let mut local = TestServerBuilder::new("smtp_delivery_local")
        .await
        .with_http_listener(19030)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_delivery_remote")
        .await
        .with_http_listener(19031)
        .await
        .with_listener(NetworkListenerProtocol::Smtp, "smtp-debug", 9925, false)
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
            schedule: Expression {
                match_: List::from_iter([
                    ExpressionMatch {
                        if_: "rcpt_domain == 'foobar.org'".into(),
                        then: "'foobar-org'".into(),
                    },
                    ExpressionMatch {
                        if_: "rcpt_domain == 'foobar.com'".into(),
                        then: "'foobar-com'".into(),
                    },
                ]),
                else_: "'default'".into(),
            },
            ..Default::default()
        })
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
                expire: 7_000u64.into(),
            }),
            queue_id,
            description: None,
        })
        .await;
    local_admin
        .registry_create_object(MtaDeliverySchedule {
            name: "foobar-org".into(),
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
                expire: 6_000u64.into(),
            }),
            queue_id,
            description: None,
        })
        .await;
    local_admin
        .registry_create_object(MtaDeliverySchedule {
            name: "foobar-com".into(),
            retry: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 1_000u64.into(),
                }]),
            }),
            notify: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([
                    MtaDeliveryScheduleInterval {
                        duration: 5_000u64.into(),
                    },
                    MtaDeliveryScheduleInterval {
                        duration: 6_000u64.into(),
                    },
                ]),
            }),
            expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                expire: 7_000u64.into(),
            }),
            queue_id,
            description: None,
        })
        .await;
    local_admin.mta_no_auth().await;
    local_admin.mta_all_extensions().await;
    local_admin.mta_disable_spam_filter().await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_no_auth().await;
    remote_admin.mta_disable_spam_filter().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin
        .registry_create_object(MtaExtensions {
            chunking: Expression {
                else_: "false".into(),
                ..Default::default()
            },
            dsn: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    // Add mock DNS entries
    for domain in ["foobar.org", "foobar.net", "foobar.com"] {
        local.server.mx_add(
            domain,
            vec![MX {
                exchanges: vec![
                    format!("mx1.{domain}").into(),
                    format!("mx2.{domain}").into(),
                ]
                .into_boxed_slice(),
                preference: 10,
            }],
            DnssecStatus::Secure,
            Instant::now() + Duration::from_secs(10),
        );
        local.server.ipv4_add(
            format!("mx1.{domain}"),
            vec!["127.0.0.1".parse().unwrap()],
            Instant::now() + Duration::from_secs(30),
        );
        local.server.ipv4_add(
            format!("mx2.{domain}"),
            vec!["127.0.0.1".parse().unwrap()],
            Instant::now() + Duration::from_secs(30),
        );
    }

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(
            "john@test.org",
            &[
                "<ok@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<ok@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<invalid@domain.org> NOTIFY=SUCCESS,DELAY,FAILURE",
            ],
            "test:no_dkim",
            "250",
        )
        .await;
    let message = local.expect_message().await;
    let num_recipients = message.message.recipients.len();
    assert_eq!(num_recipients, 7);
    local
        .delivery_attempt_for_queue(message.queue_id, "default")
        .await
        .try_deliver(local.server.clone());
    let mut dsn = Vec::new();
    let mut rcpt_retries = vec![0; num_recipients];
    loop {
        match local.try_read_event().await {
            Some(QueueEvent::Refresh | QueueEvent::WorkerDone { .. }) => {}
            Some(QueueEvent::Paused(_)) | Some(QueueEvent::ReloadSettings) => unreachable!(),
            None | Some(QueueEvent::Stop) => {
                break;
            }
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
                for (idx, rcpt) in message.message.recipients.iter().enumerate() {
                    rcpt_retries[idx] = rcpt.retry.inner;
                }
                event.try_deliver(local.server.clone());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    assert_eq!(rcpt_retries[0], 0, "retries {rcpt_retries:?}");
    assert!(rcpt_retries[1] >= 5, "retries {rcpt_retries:?}");
    assert_eq!(rcpt_retries[2], 0, "retries {rcpt_retries:?}");
    assert_eq!(rcpt_retries[3], 0, "retries {rcpt_retries:?}");
    assert!(rcpt_retries[4] >= 5, "retries {rcpt_retries:?}");
    assert_eq!(rcpt_retries[5], 0, "retries {rcpt_retries:?}");
    assert_eq!(rcpt_retries[6], 0, "retries {rcpt_retries:?}");
    assert!(
        rcpt_retries[1] >= rcpt_retries[4],
        "retries {rcpt_retries:?}"
    );

    local.assert_queue_is_empty().await;
    assert_eq!(dsn.len(), 5);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines(&local)
        .await
        .assert_contains("<ok@foobar.net> (delivered to")
        .assert_contains("<ok@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.net> (host ")
        .assert_contains("<fail@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines(&local)
        .await
        .assert_contains("<delay@foobar.net> (host ")
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local)
        .await
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local)
        .await
        .assert_contains("<delay@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines(&local)
        .await
        .assert_contains("<delay@foobar.net> (host ")
        .assert_contains("Action: failed");

    let mut recipients = remote
        .consume_message()
        .await
        .message
        .recipients
        .into_iter()
        .map(|r| r.address().to_string())
        .collect::<Vec<_>>();
    recipients.extend(
        remote
            .consume_message()
            .await
            .message
            .recipients
            .into_iter()
            .map(|r| r.address().to_string()),
    );
    recipients.sort();
    assert_eq!(
        recipients,
        vec!["ok@foobar.net".to_string(), "ok@foobar.org".to_string()]
    );

    remote.assert_no_events();

    // SMTP smuggling
    for separator in ["\n", "\r"].iter() {
        session.data.remote_ip_str = "10.0.0.2".into();
        session.eval_session_params().await;
        session.ehlo("mx.test.org").await;

        let out_message = SMUGGLER
            .replace('\r', "")
            .replace('\n', "\r\n")
            .replace("<SEP>", separator);

        session
            .send_message("john@doe.org", &["bill@foobar.com"], &out_message, "250")
            .await;
        local
            .expect_message_for_queue_then_deliver("default")
            .await
            .try_deliver(local.server.clone());
        local.read_event().await.assert_refresh_or_done();

        let message = remote.consume_message().await.read_message(&remote).await;

        assert!(
            message.contains("This is a smuggled message"),
            "message: {:?}",
            message
        );
        assert!(
            message.contains("We lost the game."),
            "message: {:?}",
            message
        );
        assert!(
            message.contains(&format!("{separator}..\r\nMAIL FROM:<",)),
            "Message {message:?} does not contain separator {:?}",
            format!("{separator}..\r\nMAIL FROM:<",)
        );
    }
}
