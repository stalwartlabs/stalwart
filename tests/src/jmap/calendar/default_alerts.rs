/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use common::NO_ID;
use email::cache::MessageCacheFetch;
use futures::StreamExt;
use groupware::{
    cache::GroupwareCache,
    calendar::{CALENDAR_SUBSCRIBED, Calendar, alarm::AlarmTarget, storage::ItipAutoExpunge},
};
use hyper::StatusCode;
use jmap_client::{CalendarAlert, event_source::PushNotification};
use jmap_proto::request::method::MethodObject;
use mail_parser::{DateTime, MessageParser};
use registry::{schema::properties::ObjectType, schema::structs::Task};
use serde_json::{Map, Value, json};
use std::{
    str::FromStr,
    time::{Duration, Instant},
};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, TaskId, TaskQueueClass, ValueClass, now},
};
use tokio::sync::mpsc;
use types::{
    collection::{Collection, SyncCollection},
    id::Id,
};

pub async fn test(test: &TestServer) {
    println!("Running Calendar default alerts tests...");
    let john = test.account("jdoe@example.com");
    let john_id = john.id_string().to_string();

    sharee_alert_fires(test, john).await;
    per_user_alarm_tasks(test, john).await;
    group_account_alerts(test).await;
    alert_limit_ignores_defaults(test, john).await;
    floating_alerts_use_calendar_time_zone(test, john).await;
    acknowledged_alert_is_skipped(john).await;
    moved_occurrence_alert(john).await;
    sharee_email_alert(test, john).await;
    sharee_snoozed_default_alert_fires(test, john).await;
    caldav_snooze_survives_jmap_update(test, john).await;
    alerts_do_not_widen_the_query_range(john).await;

    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Defaults",
                "defaultAlertsWithTime": {
                    "timed-1": {
                        "action": "display",
                        "trigger": { "relativeTo": "start", "offset": "-PT15M" }
                    }
                },
                "defaultAlertsWithoutTime": {
                    "allday-1": {
                        "action": "display",
                        "trigger": { "relativeTo": "start", "offset": "-PT12H" }
                    }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({
                    "uid": "default-alerts-timed",
                    "title": "Timed",
                    "start": "2030-01-10T10:00:00",
                    "timeZone": "Etc/UTC",
                    "duration": "PT1H",
                    "useDefaultAlerts": true,
                    "alerts": {
                        "own": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT1H" } }
                    },
                    "calendarIds": { &calendar_id: true },
                }),
                json!({
                    "uid": "default-alerts-allday",
                    "title": "All day",
                    "start": "2030-01-11T00:00:00",
                    "showWithoutTime": true,
                    "duration": "P1D",
                    "useDefaultAlerts": true,
                    "calendarIds": { &calendar_id: true },
                }),
                json!({
                    "uid": "default-alerts-recurring",
                    "title": "Recurring",
                    "start": "2030-01-14T09:00:00",
                    "timeZone": "Etc/UTC",
                    "duration": "PT30M",
                    "recurrenceRule": { "@type": "RecurrenceRule", "frequency": "daily", "count": 3 },
                    "useDefaultAlerts": true,
                    "calendarIds": { &calendar_id: true },
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let timed_id = response.created(0).id().to_string();
    let allday_id = response.created(1).id().to_string();
    let recurring_id = response.created(2).id().to_string();

    // Default alerts replace the event alerts
    assert_eq!(
        alert_ids(&alerts(john, &john_id, &timed_id).await),
        ["timed-1"]
    );
    assert_eq!(
        alert_ids(&alerts(john, &john_id, &allday_id).await),
        ["allday-1"]
    );

    // Changing the calendar defaults applies to existing events without modifying them
    let event_state = john
        .jmap_method_call(
            "CalendarEvent/get",
            json!({ "accountId": &john_id, "ids": [], "properties": ["id"] }),
        )
        .await
        .state()
        .to_string();
    john.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": {
                &calendar_id: {
                    "defaultAlertsWithTime": {
                        "timed-2": {
                            "action": "display",
                            "trigger": { "relativeTo": "start", "offset": "-PT30M" }
                        }
                    }
                }
            }
        }),
    )
    .await
    .updated(&calendar_id);
    let timed_alerts = alerts(john, &john_id, &timed_id).await;
    assert_eq!(alert_ids(&timed_alerts), ["timed-2"]);
    assert_eq!(
        timed_alerts["timed-2"]["trigger"]["offset"],
        json!("-PT30M")
    );
    assert_eq!(
        john.jmap_method_call(
            "CalendarEvent/changes",
            json!({ "accountId": &john_id, "sinceState": &event_state }),
        )
        .await
        .method_response()["updated"],
        json!([])
    );

    // Acknowledging a default alert stores the acknowledgement only
    john.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": {
                &timed_id: { "alerts/timed-2/acknowledged": "2030-01-10T09:31:00Z" }
            }
        }),
    )
    .await
    .updated(&timed_id);
    let timed_alerts = alerts(john, &john_id, &timed_id).await;
    assert_eq!(alert_ids(&timed_alerts), ["timed-2"]);
    assert_eq!(
        timed_alerts["timed-2"]["acknowledged"],
        json!("2030-01-10T09:31:00Z")
    );

    // Acknowledging an occurrence alert must not create a recurrence override
    const RID: &str = "2030-01-15T09:00:00";
    let update_recurring = async |patch: Value| {
        john.jmap_method_call(
            "CalendarEvent/set",
            json!({ "accountId": &john_id, "update": { &recurring_id: patch } }),
        )
        .await
    };
    let recurring_event = async || {
        john.jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": &john_id,
                "ids": [&recurring_id],
                "properties": ["alerts", "recurrenceOverrides"]
            }),
        )
        .await
        .list()[0]
            .clone()
    };
    update_recurring(json!({ "recurrenceOverrides": { RID: { "title": "Moved" } } }))
        .await
        .updated(&recurring_id);
    update_recurring(json!({
        format!("recurrenceOverrides/{RID}/alerts~1timed-2~1acknowledged"): "2030-01-15T08:31:00Z"
    }))
    .await
    .updated(&recurring_id);
    let recurring = recurring_event().await;
    assert_eq!(
        recurring["recurrenceOverrides"],
        json!({ RID: { "title": "Moved" } }),
        "{recurring:#?}"
    );
    assert_eq!(
        recurring["alerts"]["timed-2"]["acknowledged"],
        json!("2030-01-15T08:31:00Z")
    );

    // A pointer below the override patch needs the path to exist in the patch
    let pointer = format!("recurrenceOverrides/{RID}/alerts/timed-2/acknowledged");
    assert_eq!(
        update_recurring(json!({ &pointer: "2030-01-15T08:45:00Z" }))
            .await
            .not_updated(&recurring_id)
            .typ(),
        "invalidPatch",
        "{pointer}"
    );
    assert_eq!(recurring_event().await, recurring);

    // Occurrences without an override acknowledge the alert of the base event
    update_recurring(json!({
        "recurrenceOverrides/2030-01-16T09:00:00/alerts~1timed-2~1acknowledged":
            "2030-01-15T08:45:00Z"
    }))
    .await
    .updated(&recurring_id);
    let acknowledged = recurring_event().await;
    assert_eq!(
        acknowledged["recurrenceOverrides"], recurring["recurrenceOverrides"],
        "{acknowledged:#?}"
    );
    assert_eq!(
        acknowledged["alerts"]["timed-2"]["acknowledged"],
        json!("2030-01-15T08:45:00Z"),
        "{acknowledged:#?}"
    );

    // CalDAV clients see the resolved default alarms
    let timed_path = event_dav_path(test, john, &timed_id).await;
    let dav_client = john.webdav_client();
    let body = dav_client
        .request("GET", &timed_path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert!(body.contains("JSID:timed-2"), "{body}");
    assert!(body.contains("TRIGGER:-PT30M"), "{body}");
    assert!(body.contains("ACKNOWLEDGED:20300110T093100Z"), "{body}");
    assert!(body.contains("DESCRIPTION:Timed"), "{body}");
    assert!(!body.contains("TRIGGER:-PT1H"), "{body}");
    let multiget = dav_client
        .multiget_calendar(
            timed_path
                .rsplit_once('/')
                .map(|(folder, _)| folder)
                .unwrap(),
            &[timed_path.as_str()],
        )
        .await;
    let properties = multiget.properties(&timed_path);
    let calendar_data = properties.calendar_data();
    let calendar_data = calendar_data.value();
    assert!(calendar_data.contains("JSID:timed-2"), "{calendar_data}");
    assert!(!calendar_data.contains("TRIGGER:-PT1H"), "{calendar_data}");

    // Writing the resolved view back over CalDAV does not store the default alarms
    dav_client
        .request(
            "PUT",
            &timed_path,
            body.replace("SUMMARY:Timed", "SUMMARY:Timed (CalDAV)"),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    let timed_alerts = alerts(john, &john_id, &timed_id).await;
    assert_eq!(alert_ids(&timed_alerts), ["timed-2"]);
    assert_eq!(
        timed_alerts["timed-2"]["acknowledged"],
        json!("2030-01-10T09:31:00Z")
    );
    john.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": {
                &calendar_id: {
                    "defaultAlertsWithTime": {
                        "timed-3": {
                            "action": "display",
                            "trigger": { "relativeTo": "start", "offset": "-PT5M" }
                        }
                    }
                }
            }
        }),
    )
    .await
    .updated(&calendar_id);
    let body = dav_client
        .request("GET", &timed_path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert!(body.contains("SUMMARY:Timed (CalDAV)"), "{body}");
    assert!(body.contains("JSID:timed-3"), "{body}");
    assert!(!body.contains("JSID:timed-2"), "{body}");

    // Turning off default alerts shows the event alerts again
    john.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &timed_id: { "useDefaultAlerts": false } }
        }),
    )
    .await
    .updated(&timed_id);
    let timed_alerts = alerts(john, &john_id, &timed_id).await;
    assert!(
        alert_ids(&timed_alerts).contains(&"own"),
        "{timed_alerts:#?}"
    );
    assert!(
        !alert_ids(&timed_alerts).contains(&"timed-3"),
        "{timed_alerts:#?}"
    );

    default_alert_fires(john, &calendar_id).await;

    john.destroy_all_calendars().await;
    test.assert_is_empty().await;
}

async fn alerts_do_not_widen_the_query_range(john: &Account) {
    let john_id = john.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Range",
                "defaultAlertsWithTime": {
                    "far-1": {
                        "action": "display",
                        "trigger": { "relativeTo": "start", "offset": "-P2D" }
                    }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "range-not-widened",
                "title": "Range",
                "start": "2030-04-10T10:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "useDefaultAlerts": true,
                "alerts": {
                    "own-far": { "trigger": { "@type": "OffsetTrigger", "offset": "-P1D" } }
                },
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    for (after, before, expected) in [
        ("2030-04-07T00:00:00", "2030-04-10T00:00:00", vec![]),
        ("2030-04-09T00:00:00", "2030-04-10T09:00:00", vec![]),
        (
            "2030-04-10T00:00:00",
            "2030-04-11T00:00:00",
            vec![event_id.as_str()],
        ),
    ] {
        let response = john
            .jmap_method_call(
                "CalendarEvent/query",
                json!({
                    "accountId": &john_id,
                    "expandRecurrences": false,
                    "filter": {"inCalendar": &calendar_id, "after": after, "before": before}
                }),
            )
            .await;
        assert_eq!(
            response.ids().collect::<Vec<_>>(),
            expected,
            "{after} - {before}: {response:?}"
        );
    }
}

async fn caldav_snooze_survives_jmap_update(test: &TestServer, john: &Account) {
    let john_id = john.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "CalDAV snooze",
                "defaultAlertsWithTime": {
                    "snooze-default": {
                        "action": "display",
                        "trigger": { "relativeTo": "start", "offset": "-PT15M" }
                    }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "caldav-snooze",
                "title": "Snoozed over CalDAV",
                "start": "2030-05-01T10:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "useDefaultAlerts": true,
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    let path = event_dav_path(test, john, &event_id).await;
    let dav_client = john.webdav_client();
    let body = dav_client
        .request("GET", &path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert!(body.contains("JSID:snooze-default\r\n"), "{body}");
    let snoozed = body
        .replace(
            "JSID:snooze-default\r\n",
            "JSID:snooze-default\r\nUID:original-alarm\r\nACKNOWLEDGED:20300501T094600Z\r\n",
        )
        .replace(
            "END:VEVENT",
            concat!(
                "BEGIN:VALARM\r\n",
                "UID:snooze-alarm\r\n",
                "ACTION:DISPLAY\r\n",
                "DESCRIPTION:Snoozed\r\n",
                "TRIGGER;VALUE=DATE-TIME:20300501T095500Z\r\n",
                "RELATED-TO;RELTYPE=SNOOZE:original-alarm\r\n",
                "END:VALARM\r\n",
                "END:VEVENT"
            ),
        );
    dav_client
        .request("PUT", &path, snoozed)
        .await
        .with_status(StatusCode::NO_CONTENT);

    john.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &event_id: { "title": "Snoozed and renamed" } }
        }),
    )
    .await
    .updated(&event_id);
    let body = dav_client
        .request("GET", &path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert!(body.contains("SUMMARY:Snoozed and renamed"), "{body}");
    assert!(
        body.contains("TRIGGER;VALUE=DATE-TIME:20300501T095500Z"),
        "{body}"
    );
    assert!(body.contains("RELATED-TO;RELTYPE=SNOOZE:"), "{body}");
    assert!(body.contains("ACKNOWLEDGED:20300501T094600Z"), "{body}");

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn alert_limit_ignores_defaults(test: &TestServer, john: &Account) {
    let john_id = john.id_string().to_string();
    let default_alerts = |prefix: &str, action: &str| {
        Value::Object(
            (1..=17)
                .map(|idx| {
                    (
                        format!("{prefix}-{idx}"),
                        json!({
                            "action": action,
                            "trigger": { "relativeTo": "start", "offset": format!("-PT{idx}M") }
                        }),
                    )
                })
                .collect::<Map<_, _>>(),
        )
    };
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({ "name": "Limit A", "defaultAlertsWithTime": default_alerts("limit-a", "display") }),
                json!({ "name": "Limit B", "defaultAlertsWithTime": default_alerts("limit-b", "email") }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let calendar_a = response.created(0).id().to_string();
    let calendar_b = response.created(1).id().to_string();
    let own_alerts = Value::Object(
        (1..=30)
            .map(|idx| {
                (
                    format!("own-{idx}"),
                    json!({ "trigger": { "@type": "OffsetTrigger", "offset": format!("-PT{idx}H") } }),
                )
            })
            .collect::<Map<_, _>>(),
    );
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "default-alerts-limit",
                "title": "Limit",
                "start": "2030-02-01T10:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "useDefaultAlerts": true,
                "alerts": own_alerts,
                "calendarIds": { &calendar_a: true, &calendar_b: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    john.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &event_id: { "title": "Limit (renamed)" } }
        }),
    )
    .await
    .updated(&event_id);
    assert_eq!(
        alert_ids(&alerts(john, &john_id, &event_id).await).len(),
        34
    );

    let path = event_dav_path(test, john, &event_id).await;
    let dav_client = john.webdav_client();
    let body = dav_client
        .request("GET", &path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert_eq!(body.matches("BEGIN:VALARM").count(), 34, "{body}");
    assert_eq!(
        body.matches("DESCRIPTION:Limit (renamed)").count(),
        34,
        "{body}"
    );
    assert_eq!(
        body.matches("ATTENDEE:mailto:jdoe@example.com").count(),
        17,
        "{body}"
    );
    dav_client
        .request(
            "PUT",
            &path,
            body.replace("SUMMARY:Limit (renamed)", "SUMMARY:Limit (CalDAV)"),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    john.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &event_id: { "useDefaultAlerts": false } }
        }),
    )
    .await
    .updated(&event_id);
    let own_alerts = alerts(john, &john_id, &event_id).await;
    assert_eq!(alert_ids(&own_alerts).len(), 30, "{own_alerts:#?}");
    assert!(
        alert_ids(&own_alerts)
            .iter()
            .all(|id| id.starts_with("own-")),
        "{own_alerts:#?}"
    );

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_a, &calendar_b],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn floating_alerts_use_calendar_time_zone(test: &TestServer, john: &Account) {
    let john_id = john.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Los Angeles",
                "timeZone": "America/Los_Angeles",
                "defaultAlertsWithoutTime": {
                    "la-noon": {
                        "action": "display",
                        "trigger": { "relativeTo": "start", "offset": "-PT12H" }
                    }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "default-alerts-time-zone",
                "title": "All day",
                "start": "2030-01-11T00:00:00",
                "showWithoutTime": true,
                "duration": "P1D",
                "useDefaultAlerts": true,
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    assert_eq!(
        queued_alarm_due(test, john, &event_id).await,
        Some(utc_timestamp("2030-01-10T20:00:00Z"))
    );

    john.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": { &calendar_id: { "timeZone": "Australia/Sydney" } }
        }),
    )
    .await
    .updated(&calendar_id);
    assert_eq!(
        queued_alarm_due(test, john, &event_id).await,
        Some(utc_timestamp("2030-01-10T01:00:00Z"))
    );

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
    assert_eq!(queued_alarm_due(test, john, &event_id).await, None);
}

async fn acknowledged_alert_is_skipped(john: &Account) {
    let john_id = john.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({ "name": "Acknowledged" })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let mut john_rx = push_listener(john).await;

    let start = now() as i64 + 14;
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "default-alerts-acknowledged",
                "title": "Acknowledged",
                "start": local_date_time(start),
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "alerts": {
                    "dismissed": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT6S" } },
                    "pending": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT2S" } }
                },
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    john.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": {
                &event_id: { "alerts/dismissed/acknowledged": utc_date_time(start - 5) }
            }
        }),
    )
    .await
    .updated(&event_id);

    let fired = next_alert(&mut john_rx, &event_id, Duration::from_secs(25))
        .await
        .expect("pending alert did not fire");
    assert_eq!(fired.alert_id, "pending");

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn moved_occurrence_alert(john: &Account) {
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({ "name": "Moved occurrence" })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let mut john_rx = push_listener(john).await;

    let second_occurrence = now() as i64 + 60;
    let recurrence_id = local_date_time(second_occurrence);
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "default-alerts-moved",
                "title": "Moved",
                "start": local_date_time(second_occurrence - 86400),
                "timeZone": "Etc/UTC",
                "duration": "PT30M",
                "recurrenceRule": { "@type": "RecurrenceRule", "frequency": "daily", "count": 2 },
                "alerts": {
                    "moved": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT4S" } }
                },
                "recurrenceOverrides": {
                    &recurrence_id: { "start": local_date_time(now() as i64 + 12) }
                },
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    let fired = next_alert(&mut john_rx, &event_id, Duration::from_secs(20))
        .await
        .expect("moved occurrence alert did not fire");
    assert_eq!(fired.alert_id, "moved");
    assert_eq!(fired.recurrence_id.as_deref(), Some(recurrence_id.as_str()));

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn sharee_email_alert(test: &TestServer, john: &Account) {
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Hidden guests",
                "shareWith": {
                    &jane_id: { "mayReadItems": true, "mayUpdatePrivate": true }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    jane.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": { &calendar_id: { "isSubscribed": true } }
        }),
    )
    .await
    .updated(&calendar_id);

    let participants = json!({
        "owner": {
            "@type": "Participant",
            "name": "John Doe",
            "calendarAddress": "mailto:jdoe@example.com",
            "roles": { "owner": true },
            "participationStatus": "accepted"
        },
        "guest": {
            "@type": "Participant",
            "name": "Hidden Guest",
            "calendarAddress": "mailto:hidden.guest@example.net",
            "roles": { "attendee": true },
            "participationStatus": "needs-action"
        }
    });
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({
                    "uid": "sharee-email-alert",
                    "title": "Sharee email reminder",
                    "start": local_date_time(now() as i64 + 20),
                    "timeZone": "Etc/UTC",
                    "duration": "PT1H",
                    "hideAttendees": true,
                    "participants": participants.clone(),
                    "calendarIds": { &calendar_id: true },
                }),
                json!({
                    "uid": "sharee-alert-destroy",
                    "title": "Destroyed with a sharee alert",
                    "start": "2030-03-01T10:00:00",
                    "timeZone": "Etc/UTC",
                    "duration": "PT1H",
                    "calendarIds": { &calendar_id: true },
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let event_id = response.created(0).id().to_string();
    let destroy_id = response.created(1).id().to_string();
    let response = jane
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": {
                    &event_id: {
                        "alerts": {
                            "jane-email": {
                                "action": "email",
                                "trigger": { "@type": "OffsetTrigger", "offset": "-PT15S" }
                            }
                        }
                    },
                    &destroy_id: {
                        "alerts": {
                            "jane-later": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT5M" } }
                        }
                    }
                }
            }),
        )
        .await;
    response.updated(&event_id);
    response.updated(&destroy_id);

    let jane_account_id = jane.id().document_id();
    assert!(
        queued_alarm_due_for(
            test,
            john,
            &destroy_id,
            AlarmTarget::Sharee(jane_account_id)
        )
        .await
        .is_some()
    );
    john.jmap_destroy(
        MethodObject::CalendarEvent,
        [&destroy_id],
        Vec::<(&str, &str)>::new(),
    )
    .await;
    assert_eq!(
        queued_alarm_due_for(
            test,
            john,
            &destroy_id,
            AlarmTarget::Sharee(jane_account_id)
        )
        .await,
        None
    );

    let start = Instant::now();
    let message = loop {
        let messages = test
            .server
            .get_cached_messages(jane_account_id)
            .await
            .unwrap();
        if let Some(message) = messages.emails.iter().next() {
            break test
                .fetch_email(jane_account_id, message.document_id())
                .await;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "sharee email alert was not delivered"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let message = MessageParser::new().parse(&message).unwrap();
    let html = message
        .html_bodies()
        .next()
        .and_then(|body| body.text_contents())
        .unwrap_or_default()
        .to_string();
    assert!(html.contains("Sharee email reminder"), "{html}");
    assert!(html.contains("jdoe@example.com"), "{html}");
    assert!(!html.contains("hidden.guest@example.net"), "{html}");
    assert!(!html.contains("Hidden Guest"), "{html}");

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
    test.destroy_all_mailboxes(jane).await;
    jane.destroy_all_event_notifications().await;
    john.destroy_all_event_notifications().await;
}

async fn sharee_snoozed_default_alert_fires(test: &TestServer, john: &Account) {
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Snoozed defaults",
                "shareWith": {
                    &jane_id: { "mayReadItems": true, "mayUpdatePrivate": true }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    jane.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": {
                &calendar_id: {
                    "isSubscribed": true,
                    "defaultAlertsWithTime": {
                        "jane-default": {
                            "action": "display",
                            "trigger": { "relativeTo": "start", "offset": "-PT1H" }
                        }
                    }
                }
            }
        }),
    )
    .await
    .updated(&calendar_id);
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "sharee-snoozed-default",
                "title": "Snoozed",
                "start": local_date_time(now() as i64 + 7200),
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &event_id: { "useDefaultAlerts": true } }
        }),
    )
    .await
    .updated(&event_id);
    let mut jane_rx = push_listener(jane).await;

    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": {
                &event_id: {
                    "alerts/jane-default/acknowledged": utc_date_time(now() as i64),
                    "alerts/jane-snooze": {
                        "trigger": { "@type": "AbsoluteTrigger", "when": utc_date_time(now() as i64 + 6) },
                        "relatedTo": {
                            "jane-default": { "@type": "Relation", "relation": { "snooze": true } }
                        }
                    }
                }
            }
        }),
    )
    .await
    .updated(&event_id);
    let jane_alerts = alerts(jane, &john_id, &event_id).await;
    assert_eq!(
        alert_ids(&jane_alerts),
        ["jane-default", "jane-snooze"],
        "{jane_alerts:#?}"
    );
    let fired = next_alert(&mut jane_rx, &event_id, Duration::from_secs(20))
        .await
        .expect("snoozed default alert did not fire");
    assert_eq!(fired.alert_id, "jane-snooze");
    assert_eq!(fired.account_id, john_id);

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
    jane.destroy_all_event_notifications().await;
    john.destroy_all_event_notifications().await;
}

async fn push_listener(account: &Account) -> mpsc::Receiver<PushNotification> {
    let (tx, rx) = mpsc::channel::<PushNotification>(100);
    let mut notifications = account
        .jmap_client()
        .await
        .event_source(None::<Vec<_>>, false, 1.into(), None)
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Some(notification) = notifications.next().await {
            if tx.send(notification.unwrap()).await.is_err() {
                break;
            }
        }
    });
    rx
}

async fn next_alert(
    rx: &mut mpsc::Receiver<PushNotification>,
    event_id: &str,
    timeout: Duration,
) -> Option<CalendarAlert> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(PushNotification::CalendarAlert(alert)))
                if alert.calendar_event_id == event_id =>
            {
                return Some(alert);
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return None,
        }
    }
}

async fn queued_alarm_due(test: &TestServer, account: &Account, event_id: &str) -> Option<u64> {
    queued_alarm_due_for(test, account, event_id, AlarmTarget::Owner).await
}

async fn queued_alarm_due_for(
    test: &TestServer,
    account: &Account,
    event_id: &str,
    target: AlarmTarget,
) -> Option<u64> {
    let document_id = Id::from_str(event_id).unwrap().document_id();
    test.server
        .store()
        .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
            TaskQueueClass::Task {
                id: TaskId::Assigned(
                    target
                        .task_id()
                        .resolve(account.id().document_id(), document_id),
                ),
            },
        )))
        .await
        .unwrap()
        .map(|task| task.due_timestamp())
}

fn local_date_time(timestamp: i64) -> String {
    DateTime::from_timestamp(timestamp)
        .to_rfc3339()
        .trim_end_matches('Z')
        .to_string()
}

fn utc_date_time(timestamp: i64) -> String {
    DateTime::from_timestamp(timestamp).to_rfc3339()
}

fn utc_timestamp(date_time: &str) -> u64 {
    DateTime::parse_rfc3339(date_time).unwrap().to_timestamp() as u64
}

async fn sharee_alert_fires(test: &TestServer, john: &Account) {
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Shared alerts",
                "isSubscribed": false,
                "shareWith": {
                    &jane_id: { "mayReadItems": true, "mayUpdatePrivate": true }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    jane.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": { &calendar_id: { "isSubscribed": true } }
        }),
    )
    .await
    .updated(&calendar_id);

    let mut jane_rx = push_listener(jane).await;
    let mut john_rx = push_listener(john).await;

    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "sharee-alert-fire",
                "title": "Shared soon",
                "start": local_date_time(now() as i64 + 20),
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "alerts": {
                    "owner": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT15S" } }
                },
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": {
                &event_id: {
                    "alerts": {
                        "jane": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT15S" } }
                    }
                }
            }
        }),
    )
    .await
    .updated(&event_id);

    let fired = next_alert(&mut jane_rx, &event_id, Duration::from_secs(25))
        .await
        .expect("sharee alert did not fire");
    assert_eq!(fired.calendar_event_id, event_id);
    assert_eq!(fired.account_id, john_id);
    assert_eq!(fired.alert_id, "jane");

    // The owner is not subscribed to the calendar, so their alert does not fire
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(notification) = john_rx.try_recv() {
        assert!(
            !matches!(notification, PushNotification::CalendarAlert(ref alert)
                if alert.calendar_event_id == event_id),
            "owner alert fired while unsubscribed"
        );
    }

    // Alerts of the owner and a sharee firing at the same time are both delivered
    john.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": { &calendar_id: { "isSubscribed": true } }
        }),
    )
    .await
    .updated(&calendar_id);
    let tie_event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "sharee-alert-tie",
                "title": "Shared tie",
                "start": local_date_time(now() as i64 + 20),
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "alerts": {
                    "owner": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT15S" } }
                },
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": {
                &tie_event_id: {
                    "alerts": {
                        "jane": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT15S" } }
                    }
                }
            }
        }),
    )
    .await
    .updated(&tie_event_id);
    let start = Instant::now();
    let (mut john_fired, mut jane_fired) = (None, None);
    while start.elapsed().as_secs() < 25 && (john_fired.is_none() || jane_fired.is_none()) {
        let (notification, is_jane) = tokio::select! {
            Some(notification) = jane_rx.recv() => (notification, true),
            Some(notification) = john_rx.recv() => (notification, false),
            _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
        };
        if let PushNotification::CalendarAlert(alert) = notification
            && alert.calendar_event_id == tie_event_id
        {
            if is_jane {
                jane_fired = Some(alert);
            } else {
                john_fired = Some(alert);
            }
        }
    }
    assert_eq!(
        john_fired.map(|alert| alert.alert_id).as_deref(),
        Some("owner")
    );
    assert_eq!(
        jane_fired.map(|alert| alert.alert_id).as_deref(),
        Some("jane")
    );

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
    jane.destroy_all_event_notifications().await;
    john.destroy_all_event_notifications().await;
    jane.destroy_all_calendars().await;
}

async fn default_alert_fires(john: &Account, calendar_id: &str) {
    let mut event_rx = push_listener(john).await;

    let john_id = john.id_string().to_string();
    john.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": {
                calendar_id: {
                    "defaultAlertsWithTime": {
                        "soon": {
                            "action": "display",
                            "trigger": { "relativeTo": "start", "offset": "-PT6S" }
                        }
                    }
                }
            }
        }),
    )
    .await
    .updated(calendar_id);
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "default-alerts-fire",
                "title": "Soon",
                "start": local_date_time(now() as i64 + 10),
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "useDefaultAlerts": true,
                "calendarIds": { calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    let fired = next_alert(&mut event_rx, &event_id, Duration::from_secs(20))
        .await
        .expect("default alert did not fire");
    assert_eq!(fired.calendar_event_id, event_id);
    assert_eq!(fired.alert_id, "soon");
}

async fn event_dav_path(test: &TestServer, account: &Account, event_id: &str) -> String {
    let account_id = account.id().document_id();
    let document_id = Id::from_str(event_id).unwrap().document_id();
    let resources = test
        .server
        .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .unwrap();
    let path = resources
        .paths
        .iter()
        .find(|(_, path)| path.parent_id != NO_ID && path.document_id == document_id)
        .map(|(chunk, path)| std::str::from_utf8(&chunk.bytes[path.path.range()]).unwrap())
        .unwrap();
    format!("{}{path}", resources.base_path)
}

async fn alerts(account: &Account, account_id: &str, event_id: &str) -> Value {
    account
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": account_id,
                "ids": [event_id],
                "properties": ["alerts"]
            }),
        )
        .await
        .list()[0]["alerts"]
        .clone()
}

fn alert_ids(alerts: &Value) -> Vec<&str> {
    let mut ids = alerts
        .as_object()
        .into_iter()
        .flat_map(|alerts| alerts.keys().map(String::as_str))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

async fn per_user_alarm_tasks(test: &TestServer, john: &Account) {
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Per user tasks",
                "shareWith": {
                    &jane_id: { "mayReadItems": true, "mayUpdatePrivate": true }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    jane.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": { &calendar_id: { "isSubscribed": true } }
        }),
    )
    .await
    .updated(&calendar_id);

    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "per-user-alarm-tasks",
                "title": "Two users",
                "start": "2030-03-01T10:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "alerts": {
                    "owner": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT30M" } }
                },
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": {
                &event_id: {
                    "alerts": {
                        "jane": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT10M" } }
                    }
                }
            }
        }),
    )
    .await
    .updated(&event_id);

    assert_eq!(
        queued_alarm_due(test, john, &event_id).await,
        Some(utc_timestamp("2030-03-01T09:30:00Z"))
    );
    assert_eq!(
        queued_alarm_due_for(
            test,
            john,
            &event_id,
            AlarmTarget::Sharee(jane.id().document_id())
        )
        .await,
        Some(utc_timestamp("2030-03-01T09:50:00Z"))
    );

    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &event_id: { "alerts": null } }
        }),
    )
    .await
    .updated(&event_id);
    assert_eq!(
        queued_alarm_due_for(
            test,
            john,
            &event_id,
            AlarmTarget::Sharee(jane.id().document_id())
        )
        .await,
        None
    );
    assert_eq!(
        queued_alarm_due(test, john, &event_id).await,
        Some(utc_timestamp("2030-03-01T09:30:00Z"))
    );

    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": {
                &event_id: {
                    "alerts": {
                        "jane": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT10M" } }
                    }
                }
            }
        }),
    )
    .await
    .updated(&event_id);
    assert!(
        queued_alarm_due_for(
            test,
            john,
            &event_id,
            AlarmTarget::Sharee(jane.id().document_id())
        )
        .await
        .is_some()
    );
    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
    assert_eq!(queued_alarm_due(test, john, &event_id).await, None);
    assert_eq!(
        queued_alarm_due_for(
            test,
            john,
            &event_id,
            AlarmTarget::Sharee(jane.id().document_id())
        )
        .await,
        None
    );
    destroy_event_notifications(jane, &john_id).await;
    destroy_event_notifications(john, &john_id).await;
}

async fn group_account_alerts(test: &TestServer) {
    let admin = test.account("admin@example.com");
    let robert = test.account("robert@example.com");
    let sales = test.account("sales@example.com");
    let sales_id = sales.id_string().to_string();

    admin
        .registry_update_object(
            ObjectType::Account,
            robert.id(),
            json!({ "memberGroupIds": { &sales_id: true } }),
        )
        .await;
    wait_for_account_access(robert, &sales_id).await;

    let calendar_id = robert
        .jmap_method_call(
            "Calendar/set",
            json!({
                "accountId": &sales_id,
                "create": {
                    "i0": {
                        "name": "Team",
                        "defaultAlertsWithTime": {
                            "team-default": {
                                "action": "display",
                                "trigger": { "relativeTo": "start", "offset": "-PT6S" }
                            }
                        }
                    }
                }
            }),
        )
        .await
        .created(0)
        .id()
        .to_string();

    let calendar = robert
        .jmap_method_call(
            "Calendar/get",
            json!({
                "accountId": &sales_id,
                "ids": [&calendar_id],
                "properties": ["name", "isSubscribed", "defaultAlertsWithTime"]
            }),
        )
        .await
        .list()[0]
        .clone();
    assert_eq!(calendar["name"], json!("Team"));
    assert_eq!(calendar["isSubscribed"], json!(true));
    assert!(calendar["defaultAlertsWithTime"]["team-default"].is_object());

    let group_settings = group_calendar_settings(test, sales, &calendar_id).await;
    assert_eq!(group_settings.0, "Team");
    assert!(group_settings.1, "group entry is not subscribed");
    assert_eq!(group_settings.2, vec!["team-default"]);

    let mut robert_rx = push_listener(robert).await;
    let stored_alarm_id = robert
        .jmap_create_account(
            sales,
            MethodObject::CalendarEvent,
            [json!({
                "uid": "group-stored-alarm",
                "title": "Group stored",
                "start": local_date_time(now() as i64 + 10),
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "alerts": {
                    "stored": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT6S" } }
                },
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let default_alarm_id = robert
        .jmap_create_account(
            sales,
            MethodObject::CalendarEvent,
            [json!({
                "uid": "group-default-alarm",
                "title": "Group defaults",
                "start": local_date_time(now() as i64 + 12),
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "useDefaultAlerts": true,
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    assert!(
        queued_alarm_due(test, sales, &stored_alarm_id)
            .await
            .is_some(),
        "stored alarm was not scheduled for the group account"
    );
    assert!(
        queued_alarm_due_for(
            test,
            sales,
            &default_alarm_id,
            AlarmTarget::Sharee(robert.id().document_id())
        )
        .await
        .is_some(),
        "default alert was not scheduled for the member"
    );

    let fired = next_alert(&mut robert_rx, &stored_alarm_id, Duration::from_secs(25))
        .await
        .expect("group stored alarm did not fire");
    assert_eq!(fired.alert_id, "stored");
    assert_eq!(fired.account_id, sales_id);
    let fired = next_alert(&mut robert_rx, &default_alarm_id, Duration::from_secs(25))
        .await
        .expect("member default alert did not fire");
    assert_eq!(fired.alert_id, "team-default");
    assert_eq!(fired.account_id, sales_id);

    let bill = test.account("bill@example.com");
    let bill_id = bill.id().document_id();
    admin
        .registry_update_object(
            ObjectType::Account,
            bill.id(),
            json!({ "memberGroupIds": { &sales_id: true } }),
        )
        .await;
    wait_for_account_access(bill, &sales_id).await;
    let mut bill_rx = push_listener(bill).await;
    let comember_alarm_id = bill
        .jmap_create_account(
            sales,
            MethodObject::CalendarEvent,
            [json!({
                "uid": "group-comember-alarm",
                "title": "Co-member defaults",
                "start": local_date_time(now() as i64 + 10),
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "useDefaultAlerts": true,
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    let comember_calendar = bill
        .jmap_method_call(
            "Calendar/get",
            json!({
                "accountId": &sales_id,
                "ids": [&calendar_id],
                "properties": ["isSubscribed"]
            }),
        )
        .await
        .list()[0]["isSubscribed"]
        .clone();
    assert_eq!(comember_calendar, json!(true));
    assert_eq!(
        alert_ids(&alerts(bill, &sales_id, &comember_alarm_id).await),
        ["team-default"]
    );
    assert!(
        queued_alarm_due_for(
            test,
            sales,
            &comember_alarm_id,
            AlarmTarget::Sharee(bill_id)
        )
        .await
        .is_some(),
        "default alert was not scheduled for a member without preferences"
    );
    let fired = next_alert(&mut bill_rx, &comember_alarm_id, Duration::from_secs(25))
        .await
        .expect("co-member default alert did not fire");
    assert_eq!(fired.alert_id, "team-default");
    assert_eq!(fired.account_id, sales_id);

    robert
        .jmap_destroy_account(
            sales,
            MethodObject::CalendarEvent,
            [&stored_alarm_id, &default_alarm_id, &comember_alarm_id],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    destroy_all_calendars_in(robert, &sales_id).await;
    bill.destroy_all_calendars().await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    test.server
        .itip_auto_expunge(sales.id().document_id(), 0)
        .await
        .unwrap();
    for member in [robert, bill] {
        admin
            .registry_update_object(
                ObjectType::Account,
                member.id(),
                json!({ "memberGroupIds": {} }),
            )
            .await;
    }
}

async fn destroy_all_calendars_in(actor: &Account, account_id: &str) {
    actor
        .jmap_method_calls(json!([
            [
                "Calendar/get",
                { "accountId": account_id, "ids": (), "properties": ["id"] },
                "R1"
            ],
            [
                "Calendar/set",
                {
                    "accountId": account_id,
                    "#destroy": {
                        "resultOf": "R1",
                        "name": "Calendar/get",
                        "path": "/list/*/id"
                    },
                    "onDestroyRemoveEvents": true
                },
                "R2"
            ]
        ]))
        .await;
}

async fn destroy_event_notifications(actor: &Account, account_id: &str) {
    actor
        .jmap_method_calls(json!([
            [
                "CalendarEventNotification/get",
                { "accountId": account_id, "ids": (), "properties": ["id"] },
                "R1"
            ],
            [
                "CalendarEventNotification/set",
                {
                    "accountId": account_id,
                    "#destroy": {
                        "resultOf": "R1",
                        "name": "CalendarEventNotification/get",
                        "path": "/list/*/id"
                    }
                },
                "R2"
            ]
        ]))
        .await;
}

async fn wait_for_account_access(account: &Account, account_id: &str) {
    for _ in 0..50 {
        let response = account
            .jmap_method_calls(json!([[
                "Calendar/get",
                { "accountId": account_id, "ids": [], "properties": ["id"] },
                "0"
            ]]))
            .await;
        if !response.is_error_at(0) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("Account {account_id} did not become accessible");
}

async fn group_calendar_settings(
    test: &TestServer,
    account: &Account,
    calendar_id: &str,
) -> (String, bool, Vec<String>) {
    let account_id = account.id().document_id();
    let document_id = Id::from_str(calendar_id).unwrap().document_id();
    let calendar_ = test
        .server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            Collection::Calendar,
            document_id,
        ))
        .await
        .unwrap()
        .expect("calendar not found");
    let calendar = calendar_.unarchive::<Calendar>().unwrap();
    let preferences = calendar
        .personal_preferences(account_id)
        .expect("group account has no preferences entry");
    (
        preferences.name.to_string(),
        preferences.flags.to_native() & CALENDAR_SUBSCRIBED != 0,
        preferences
            .default_alerts
            .iter()
            .map(|alert| alert.id.to_string())
            .collect(),
    )
}
