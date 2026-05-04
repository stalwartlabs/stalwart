/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::session::TestSession,
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use ahash::{AHashMap, HashMap, HashSet};
use mail_auth::MX;
use registry::{
    schema::{
        enums::NetworkListenerProtocol,
        prelude::{ObjectType, Property},
        structs::{
            Expression, MtaDeliveryExpiration, MtaDeliveryExpirationTtl, MtaDeliverySchedule,
            MtaDeliveryScheduleInterval, MtaDeliveryScheduleIntervals,
            MtaDeliveryScheduleIntervalsOrDefault, MtaExtensions, MtaOutboundStrategy,
            MtaStageRcpt, MtaVirtualQueue, QueueExpiry, QueuedMessage, RecipientStatus,
        },
    },
    types::{EnumImpl, datetime::UTCDateTime, list::List},
};
use serde_json::json;
use std::time::{Duration, Instant};
use types::id::Id;

#[tokio::test]
#[serial_test::serial]
async fn manage_queue() {
    let mut local = TestServerBuilder::new("smtp_manage_queue_local")
        .await
        .with_http_listener(19049)
        .await
        .disable_services()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_manage_queue_remote")
        .await
        .with_dummy_tls_cert(["*.foobar.org"])
        .await
        .with_http_listener(19050)
        .await
        .with_listener(NetworkListenerProtocol::Smtp, "smtp-debug", 9925, false)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_no_auth().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    let admin = local.account("admin");
    admin
        .registry_create_object(MtaExtensions {
            dsn: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            future_release: Expression {
                else_: "1h".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
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
                    duration: 1_000_000u64.into(),
                }]),
            }),
            notify: MtaDeliveryScheduleIntervalsOrDefault::Custom(MtaDeliveryScheduleIntervals {
                intervals: List::from_iter([MtaDeliveryScheduleInterval {
                    duration: 2_000_000u64.into(),
                }]),
            }),
            expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                expire: 3_000_000u64.into(),
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
    admin.mta_no_auth().await;
    admin.mta_allow_non_fqdn().await;
    admin.reload_settings().await;
    local.reload_core();
    let admin = local.account("admin");

    // Add mock DNS entries
    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx1.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );

    local.server.ipv4_add(
        "mx1.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // Send test messages
    let envelopes = HashMap::from_iter([
        (
            "a",
            (
                "bill1@foobar.net",
                vec![
                    "rcpt1@example1.org",
                    "rcpt1@example2.org",
                    "rcpt2@example2.org",
                ],
            ),
        ),
        (
            "b",
            (
                "bill2@foobar.net",
                vec!["rcpt3@example1.net", "rcpt4@example1.net"],
            ),
        ),
        (
            "c",
            (
                "bill3@foobar.net",
                vec![
                    "rcpt5@example1.com",
                    "rcpt6@example2.com",
                    "rcpt7@example2.com",
                    "rcpt8@example3.com",
                    "rcpt9@example4.com",
                ],
            ),
        ),
        ("d", ("bill4@foobar.net", vec!["delay@foobar.org"])),
        ("e", ("bill5@foobar.net", vec!["john@foobar.org"])),
        ("f", ("", vec!["success@foobar.org", "delay@foobar.org"])),
    ]);
    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("foobar.net").await;
    for test_num in 0..6 {
        let env_id = char::from(b'a' + test_num).to_string();
        let hold_for = ((test_num + 1) as u32) * 100;
        let (sender, recipients) = envelopes.get(env_id.as_str()).unwrap();
        session
            .send_message(
                &if env_id != "f" {
                    format!("<{sender}> ENVID={env_id} HOLDFOR={hold_for}")
                } else {
                    format!("<{sender}> ENVID={env_id}")
                },
                recipients,
                "test:no_dkim",
                "250",
            )
            .await;
    }

    // Expect delivery to success@foobar.org
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        remote
            .consume_message()
            .await
            .message
            .recipients
            .into_iter()
            .map(|r| r.address().to_string())
            .collect::<Vec<_>>(),
        vec!["success@foobar.org"]
    );

    // Fetch and validate messages
    assert_eq!(
        admin
            .registry_query_ids(
                ObjectType::QueuedMessage,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new()
            )
            .await
            .len(),
        6
    );
    let messages = admin.registry_get_all::<QueuedMessage>().await;
    assert_eq!(messages.len(), 6);
    let mut id_map = AHashMap::new();
    let mut id_map_rev = AHashMap::new();
    let mut test_search = String::new();
    for (id, message) in messages {
        let env_id = message.env_id.as_ref().unwrap().clone();

        // Validate return path and recipients
        let (sender, recipients) = envelopes.get(env_id.as_str()).unwrap();
        assert_eq!(
            &message.return_path,
            if !sender.is_empty() { sender } else { "<>" }
        );
        'outer: for recipient in recipients {
            for (address, _) in message.recipients.iter() {
                if address == recipient {
                    continue 'outer;
                }
            }
            panic!("Recipient {recipient} not found in message.");
        }

        // Validate status and datetimes
        let created = message.created_at.timestamp();
        let hold_for = (env_id.as_bytes().first().unwrap() - b'a' + 1) as i64 * 100;
        let next_retry = created + hold_for;
        let next_notify = created + 2000 + hold_for;
        let expires = created + 3000 + hold_for;
        for (rcpt_address, rcpt) in message.recipients.iter() {
            if env_id == "c" {
                let mut dt = rcpt.retry_due;
                dt.add_seconds(-1);
                test_search = dt.to_string();
            }
            if env_id != "f" {
                // HOLDFOR messages
                assert_eq!(rcpt.retry_count, 0);
                assert_timestamp(rcpt.retry_due.timestamp(), next_retry, "retry", &message);
                assert_timestamp(rcpt.notify_due.timestamp(), next_notify, "notify", &message);
                assert_timestamp(
                    match &rcpt.expires {
                        QueueExpiry::Ttl(ttl) => ttl.expires_at.timestamp(),
                        QueueExpiry::Attempts(_) => unreachable!(),
                    },
                    expires,
                    "expires",
                    &message,
                );
                assert_eq!(&rcpt.status, &RecipientStatus::Scheduled, "{message:#?}");
            } else if rcpt_address == "success@foobar.org" {
                assert_eq!(rcpt.retry_count, 0);
                assert!(
                    matches!(&rcpt.status, RecipientStatus::Completed(_)),
                    "{:?}",
                    rcpt.status
                );
            } else {
                assert_eq!(rcpt.retry_count, 1);
                assert!(
                    matches!(&rcpt.status, RecipientStatus::TemporaryFailure(_)),
                    "{:?}",
                    rcpt.status
                );
            }
        }

        id_map.insert(env_id.clone(), id);
        id_map_rev.insert(id, env_id);
    }
    assert_eq!(id_map.len(), 6);

    // Test list search
    for (query, expected_ids) in [
        (
            vec![(Property::ReturnPath.as_str(), "bill1@foobar.net")],
            vec!["a"],
        ),
        (
            vec![(Property::To.as_str(), "foobar.org")],
            vec!["d", "e", "f"],
        ),
        (
            vec![
                (Property::ReturnPath.as_str(), "bill3@foobar.net"),
                (Property::To.as_str(), "rcpt5@example1.com"),
            ],
            vec!["c"],
        ),
        (
            vec![("dueIsLessThan", test_search.as_str())],
            vec!["a", "b"],
        ),
        (
            vec![("dueIsGreaterThan", test_search.as_str())],
            vec!["d", "e", "f", "c"],
        ),
    ] {
        let ids = admin
            .registry_query_ids(ObjectType::QueuedMessage, query.clone(), Vec::<&str>::new())
            .await;
        assert_eq!(
            HashSet::from_iter(ids.iter().map(|id| id_map_rev.get(id).unwrap().as_str())),
            HashSet::from_iter(expected_ids.into_iter()),
            "failed for query {query:?}"
        );
    }

    // Test pagination (forward and reverse)
    let asc_order: Vec<Id> = admin
        .registry_query_paginated(
            ObjectType::QueuedMessage,
            "due",
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
    assert_eq!(asc_order.len(), 6, "expected 6 messages, got {asc_order:?}");
    let desc_order: Vec<Id> = asc_order.iter().rev().copied().collect();

    for chunk_start in [0usize, 2, 4] {
        let asc = admin
            .registry_query_paginated(
                ObjectType::QueuedMessage,
                "due",
                true,
                Some(chunk_start as i32),
                Some(2),
                None,
                None,
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            asc,
            asc_order[chunk_start..chunk_start + 2],
            "ascending position={chunk_start} limit=2",
        );

        let desc = admin
            .registry_query_paginated(
                ObjectType::QueuedMessage,
                "due",
                false,
                Some(chunk_start as i32),
                Some(2),
                None,
                None,
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            desc,
            desc_order[chunk_start..chunk_start + 2],
            "descending position={chunk_start} limit=2",
        );
    }

    for anchor_idx in [1usize, 3] {
        let asc = admin
            .registry_query_paginated(
                ObjectType::QueuedMessage,
                "due",
                true,
                None,
                Some(2),
                Some(asc_order[anchor_idx]),
                Some(1),
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            asc,
            asc_order[anchor_idx + 1..anchor_idx + 3],
            "ascending anchor={} offset=1 limit=2",
            asc_order[anchor_idx],
        );

        let desc = admin
            .registry_query_paginated(
                ObjectType::QueuedMessage,
                "due",
                false,
                None,
                Some(2),
                Some(desc_order[anchor_idx]),
                Some(1),
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            desc,
            desc_order[anchor_idx + 1..anchor_idx + 3],
            "descending anchor={} offset=1 limit=2",
            desc_order[anchor_idx],
        );
    }

    // Retry delivery
    admin
        .registry_update_object(
            ObjectType::QueuedMessage,
            id_map["e"],
            json!({
                "recipients/john@foobar.org/retryDue": UTCDateTime::now()
            }),
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::QueuedMessage,
            id_map["f"],
            json!({
                "recipients/delay@foobar.org/retryDue": UTCDateTime::now()
            }),
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::QueuedMessage,
            id_map["a"],
            json!({
                "recipients/rcpt1@example1.org/retryDue": "2200-01-01T00:00:00Z",
            }),
        )
        .await;

    // Expect delivery to john@foobar.org
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        remote
            .consume_message()
            .await
            .message
            .recipients
            .into_iter()
            .map(|r| r.address().to_string())
            .collect::<Vec<_>>(),
        vec!["john@foobar.org".to_string()]
    );

    // Message 'e' should be gone, 'f' should have retry_count == 2
    // while 'a' should have a retry time of 2200-01-01T00:00:00Z
    assert_eq!(
        admin
            .registry_get_many(ObjectType::QueuedMessage, [id_map["e"]])
            .await
            .not_found()
            .next()
            .unwrap(),
        id_map["e"].to_string()
    );
    assert_eq!(
        admin
            .registry_get::<QueuedMessage>(id_map["f"])
            .await
            .recipients
            .values()
            .next()
            .unwrap()
            .retry_count,
        2
    );
    for (rcpt_address, rcpt) in admin
        .registry_get::<QueuedMessage>(id_map["a"])
        .await
        .recipients
    {
        let next_retry = rcpt.retry_due.to_string();
        let matched =
            ["2200-01-01T00:00:00Z", "2199-12-31T23:59:59Z"].contains(&next_retry.as_str());
        if rcpt_address.ends_with("example1.org") {
            assert!(matched, "{next_retry}");
        } else {
            assert!(!matched, "{next_retry}");
        }
    }

    // Cancel deliveries
    for (id, filter) in [
        ("a", &["rcpt1@example2.org", "rcpt2@example2.org"][..]),
        ("b", &["rcpt3@example1.net", "rcpt4@example1.net"][..]),
        ("c", &["rcpt6@example2.com"][..]),
    ] {
        let mut map = serde_json::Map::new();
        for i in filter {
            map.insert(format!("recipients/{i}"), serde_json::Value::Null);
        }

        admin
            .registry_update_object(
                ObjectType::QueuedMessage,
                id_map[id],
                serde_json::Value::Object(map),
            )
            .await;
    }

    admin
        .registry_destroy(ObjectType::QueuedMessage, [id_map["d"]])
        .await
        .assert_destroyed(&[id_map["d"]]);

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(admin.registry_get_all::<QueuedMessage>().await.len(), 3);
    assert_eq!(
        admin
            .registry_query_ids(
                ObjectType::QueuedMessage,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new()
            )
            .await
            .len(),
        3
    );
    for id in ["b", "d"] {
        assert_eq!(
            admin
                .registry_get_many(ObjectType::QueuedMessage, [id_map[id]])
                .await
                .not_found()
                .next()
                .unwrap(),
            id_map[id].to_string()
        );
    }
    for id in ["a", "c"] {
        let message = admin.registry_get::<QueuedMessage>(id_map[id]).await;

        assert!(!message.recipients.is_empty());
        for (rcpt_address, rcpt) in message.recipients {
            match id {
                "a" => {
                    if rcpt_address.ends_with("example2.org") {
                        assert!(matches!(&rcpt.status, RecipientStatus::PermanentFailure(_)));
                    } else {
                        assert!(matches!(&rcpt.status, RecipientStatus::Scheduled));
                    }
                }
                "c" => {
                    if rcpt_address.ends_with("example2.com") {
                        if rcpt_address == "rcpt6@example2.com" {
                            assert!(matches!(&rcpt.status, RecipientStatus::PermanentFailure(_)));
                        } else {
                            assert!(matches!(&rcpt.status, RecipientStatus::Scheduled));
                        }
                    } else {
                        assert!(matches!(&rcpt.status, RecipientStatus::Scheduled));
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    // Bulk cancel
    admin.registry_destroy_all(ObjectType::QueuedMessage).await;
    assert_eq!(
        admin
            .registry_query_ids(
                ObjectType::QueuedMessage,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new()
            )
            .await
            .len(),
        0
    );
}

fn assert_timestamp(timestamp: i64, expected: i64, ctx: &str, message: &QueuedMessage) {
    let diff = timestamp - expected;
    if ![-2, -1, 0, 1, 2].contains(&diff) {
        panic!(
            "Got timestamp {timestamp}, expected {expected} (diff {diff} for {ctx}) for {message:?}"
        );
    }
}
