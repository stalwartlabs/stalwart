/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use futures::StreamExt;
use jmap_client::{
    CalendarAlert, PushObject, client_ws::WebSocketMessage, event_source::PushNotification,
};
use jmap_proto::request::method::MethodObject;
use mail_parser::DateTime;
use serde_json::json;
use std::time::Instant;
use store::write::now;
use tokio::sync::mpsc;

use crate::jmap::{IntoJmapSet, JMAPTest, JmapUtils};

pub async fn test(params: &mut JMAPTest) {
    println!("Running Calendar Alarm tests...");
    let account = params.account("jdoe@example.com");
    let account_id = account.id_string();
    let client = account.client();
    let client_ws = account.client_owned().await;

    // Create test calendar
    let response = account
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Alarming Calendar",
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let calendar_id = response.created(0).id().to_string();

    // Connect to EventSource
    let (event_tx, mut event_rx) = mpsc::channel::<PushNotification>(100);
    let mut notifications = client
        .event_source(None::<Vec<_>>, false, 1.into(), None)
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Some(notification) = notifications.next().await {
            if let Err(_err) = event_tx.send(notification.unwrap()).await {
                break;
            }
        }
    });

    // Connect to WebSocket
    let mut ws_stream = client_ws.connect_ws().await.unwrap();
    let (stream_tx, mut stream_rx) = mpsc::channel::<WebSocketMessage>(100);
    tokio::spawn(async move {
        while let Some(change) = ws_stream.next().await {
            if stream_tx.send(change.unwrap()).await.is_err() {
                break;
            }
        }
    });
    client_ws
        .enable_push_ws(None::<Vec<_>>, None::<&str>)
        .await
        .unwrap();

    // Create test event
    let response = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
              "@type": "Event",
              "calendarIds": ([calendar_id.as_str()].into_jmap_set()),
              "description": "What mirror where?!",
              "timeZone": "Etc/UTC",
              "start": DateTime::from_timestamp(now() as i64 + 5)
                        .to_rfc3339().trim_end_matches("Z").to_string(),
              "title": "See the pretty girl in that mirror there",
              "alerts": {
                "k1": {
                  "@type": "Alert",
                  "trigger": {
                    "@type": "OffsetTrigger",
                    "offset": "-PT2S"
                  },
                  "action": "display"
                },
                "k2": {
                  "trigger": {
                    "@type": "OffsetTrigger",
                    "offset": "-PT4S"
                  },
                  "action": "display",
                  "@type": "Alert"
                }
              },
              "locations": {
                "0b7168ae-ed3e-5eae-9540-89ba3a469b16": {
                  "name": "West Side",
                  "@type": "Location"
                }
              },
              "uid": "2371c2d9-a136-43b0-bba3-f6ab249ad46e",
              "duration": "P1D"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let event_id = response.created(0).id().to_string();

    // Wait for alarm notifications
    let start = Instant::now();
    let mut ws_events = Vec::new();
    let mut es_events = Vec::new();

    while start.elapsed().as_secs() < 7 && (ws_events.len() < 2 || es_events.len() < 2) {
        tokio::select! {
            Some(notification) = event_rx.recv() => {
                if let PushNotification::CalendarAlert(alert) = notification {
                    es_events.push(alert);
                }
            }
            Some(message) = stream_rx.recv() => {
                match message {
                    WebSocketMessage::PushNotification(PushObject::CalendarAlert(alert)) => {
                        ws_events.push(alert);
                    }
                    WebSocketMessage::PushNotification(PushObject::Group {entries} ) => {
                        ws_events.extend(entries.into_iter().filter_map(|entry| {
                            if let PushObject::CalendarAlert(alert) = entry {
                                Some(alert)
                            } else {
                                None
                            }
                        }));
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(6)) => {
                break;
            }
        }
    }

    let expected_alerts = vec![
        CalendarAlert {
            account_id: account_id.to_string(),
            calendar_event_id: event_id.clone(),
            uid: "2371c2d9-a136-43b0-bba3-f6ab249ad46e".to_string(),
            recurrence_id: None,
            alert_id: "k2".to_string(),
        },
        CalendarAlert {
            account_id: account_id.to_string(),
            calendar_event_id: event_id.clone(),
            uid: "2371c2d9-a136-43b0-bba3-f6ab249ad46e".to_string(),
            recurrence_id: None,
            alert_id: "k1".to_string(),
        },
    ];

    assert_eq!(
        es_events, expected_alerts,
        "EventSource alarms do not match"
    );
    assert_eq!(ws_events, expected_alerts, "WebSocket alarms do not match");

    // Cleanup
    account.destroy_all_calendars().await;
    params.assert_is_empty().await;
}
