/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::conformance::{dav_get, event_dav_path};
use crate::utils::{
    account::Account,
    jmap::{JmapResponse, JmapUtils},
    server::TestServer,
};
use hyper::StatusCode;
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running Calendar privacy tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();

    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Privacy",
                "shareWith": {
                    &jane_id: {
                        "mayReadItems": true,
                        "mayWriteAll": true,
                        "mayDelete": true,
                    }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let jane_calendar_id = jane
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Jane's",
                "shareWith": {
                    &john_id: { "mayReadItems": true, "mayWriteAll": true }
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
                event(&calendar_id, "privacy-public", "Public lunch", "public"),
                event(&calendar_id, "privacy-private", "Doctor", "private"),
                event(&calendar_id, "privacy-secret", "Interview", "secret"),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let public_id = response.created(0).id().to_string();
    let private_id = response.created(1).id().to_string();
    let secret_id = response.created(2).id().to_string();

    // Sharees do not see secret events
    let mut listed = jane
        .jmap_method_call(
            "CalendarEvent/get",
            json!({ "accountId": &john_id, "properties": ["id"] }),
        )
        .await
        .list()
        .iter()
        .map(|item| item.id().to_string())
        .collect::<Vec<_>>();
    listed.sort();
    let mut expected = vec![public_id.clone(), private_id.clone()];
    expected.sort();
    assert_eq!(listed, expected);
    assert_eq!(
        jane.jmap_method_call(
            "CalendarEvent/get",
            json!({ "accountId": &john_id, "ids": [&secret_id] }),
        )
        .await
        .not_found()
        .collect::<Vec<_>>(),
        [secret_id.as_str()]
    );

    // Sharees only see the allowed properties of private events
    jane.jmap_method_call(
        "CalendarEvent/get",
        json!({
            "accountId": &john_id,
            "ids": [&private_id],
            "properties": [
                "id", "uid", "calendarIds", "title", "description", "locations",
                "start", "duration", "timeZone", "privacy", "alerts", "mayInviteSelf"
            ]
        }),
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
            "id": &private_id,
            "uid": "privacy-private",
            "calendarIds": { &calendar_id: true },
            "start": "2024-03-01T10:00:00",
            "duration": "PT1H",
            "timeZone": "Europe/Berlin",
            "privacy": "private",
        }));

    // Owners see everything
    let owner_view = john
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": &john_id,
                "ids": [&secret_id],
                "properties": ["id", "title", "privacy"]
            }),
        )
        .await;
    owner_view.list()[0].assert_is_equal(json!({
        "id": &secret_id,
        "title": "Interview",
        "privacy": "secret",
    }));

    // Queries exclude secret events for sharees
    let mut queried = jane
        .jmap_method_call("CalendarEvent/query", json!({ "accountId": &john_id }))
        .await
        .ids()
        .map(str::to_string)
        .collect::<Vec<_>>();
    queried.sort();
    assert_eq!(queried, expected);

    // Text conditions never match the hidden properties of private events
    test.wait_for_tasks().await;
    for (filter, expected) in [
        (json!({"title": "doctor"}), vec![]),
        (json!({"text": "doctor"}), vec![]),
        (json!({"title": "lunch"}), vec![public_id.clone()]),
        (
            json!({"operator": "NOT", "conditions": [{"title": "doctor"}]}),
            expected.clone(),
        ),
    ] {
        let mut queried = jane
            .jmap_method_call(
                "CalendarEvent/query",
                json!({ "accountId": &john_id, "filter": filter }),
            )
            .await
            .ids()
            .map(str::to_string)
            .collect::<Vec<_>>();
        queried.sort();
        assert_eq!(queried, expected, "{filter}");
    }
    assert_eq!(
        john.jmap_method_call(
            "CalendarEvent/query",
            json!({ "accountId": &john_id, "filter": {"title": "doctor"} }),
        )
        .await
        .ids()
        .collect::<Vec<_>>(),
        [private_id.as_str()]
    );

    // Sharees cannot modify or destroy private or secret events
    let response = jane
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": {
                    &private_id: { "title": "Changed" },
                    &secret_id: { "title": "Changed" },
                    &public_id: { "privacy": "private" }
                }
            }),
        )
        .await;
    assert_eq!(response.not_updated(&private_id).typ(), "forbidden");
    assert_eq!(response.not_updated(&secret_id).typ(), "notFound");
    assert_eq!(response.not_updated(&public_id).typ(), "invalidProperties");
    let response = jane
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "destroy": [&private_id, &secret_id]
            }),
        )
        .await;
    assert_eq!(response.not_destroyed(&private_id).typ(), "forbidden");
    assert_eq!(response.not_destroyed(&secret_id).typ(), "notFound");

    // Sharees cannot create non-public events
    let response = jane
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "create": {
                    "i0": event(&calendar_id, "privacy-jane", "Jane's", "private")
                }
            }),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "invalidProperties");

    // Sharees cannot copy private or secret events out of the account
    let response = jane
        .jmap_method_call(
            "CalendarEvent/copy",
            json!({
                "fromAccountId": &john_id,
                "accountId": &jane_id,
                "create": {
                    &private_id: { "id": &private_id, "calendarIds": { &jane_calendar_id: true } },
                    &secret_id: { "id": &secret_id, "calendarIds": { &jane_calendar_id: true } }
                }
            }),
        )
        .await;
    assert_eq!(not_created(&response, &private_id), "forbidden");
    assert_eq!(not_created(&response, &secret_id), "notFound");

    // Owners cannot put non-public events into calendars they do not own
    let response = john
        .jmap_method_call(
            "CalendarEvent/copy",
            json!({
                "fromAccountId": &john_id,
                "accountId": &jane_id,
                "create": {
                    &private_id: { "id": &private_id, "calendarIds": { &jane_calendar_id: true } }
                }
            }),
        )
        .await;
    assert_eq!(not_created(&response, &private_id), "invalidProperties");

    // Public events remain writable by sharees
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &public_id: { "title": "Public dinner" } }
        }),
    )
    .await
    .updated(&public_id);

    // Rejected changes to private and secret events create no notifications
    let notifications = john
        .jmap_method_call(
            "CalendarEventNotification/get",
            json!({
                "accountId": &john_id,
                "ids": null,
                "properties": ["calendarEventId", "type"]
            }),
        )
        .await;
    assert!(!notifications.list().is_empty(), "{notifications:?}");
    assert!(
        notifications
            .list()
            .iter()
            .all(|notification| notification["calendarEventId"] == json!(&public_id)),
        "{notifications:?}"
    );

    // Sharees cannot change their personal properties of private events
    for patch in [
        json!({ "keywords": { "mine": true } }),
        json!({ "color": "blue" }),
        json!({ "alerts/a1/acknowledged": "2024-03-01T09:50:00Z" }),
        json!({ "useDefaultAlerts": true }),
    ] {
        let response = jane
            .jmap_method_call(
                "CalendarEvent/set",
                json!({ "accountId": &john_id, "update": { &private_id: patch } }),
            )
            .await;
        assert_eq!(
            response.not_updated(&private_id).typ(),
            "forbidden",
            "{patch}"
        );
    }

    sharee_changes(john, jane, &calendar_id).await;
    private_view_details(test, john, jane, &calendar_id).await;
    uid_privacy_consistency(john, &calendar_id).await;

    john.destroy_all_calendars().await;
    jane.destroy_all_calendars().await;
    john.destroy_all_event_notifications().await;
    jane.destroy_all_event_notifications().await;

    // Destroying a shared calendar revokes access to the owner's account
    let session = john.jmap_session_object().await.into_inner();
    assert!(session["accounts"].get(&jane_id).is_none(), "{session:#?}");
    test.assert_is_empty().await;
}

async fn sharee_changes(john: &Account, jane: &Account, calendar_id: &str) {
    let john_id = john.id_string().to_string();
    let hidden_calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({ "name": "Hidden" })],
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
                event(calendar_id, "changes-updated", "Standup", "public"),
                event(calendar_id, "changes-secret", "Offer", "public"),
                event(calendar_id, "changes-destroyed", "Retro", "public"),
                event(calendar_id, "changes-moved", "Review", "public"),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let updated_id = response.created(0).id().to_string();
    let secret_id = response.created(1).id().to_string();
    let destroyed_id = response.created(2).id().to_string();
    let moved_id = response.created(3).id().to_string();

    let since_state = jane
        .jmap_method_call(
            "CalendarEvent/get",
            json!({ "accountId": &john_id, "ids": [] }),
        )
        .await
        .state()
        .to_string();
    let since_query_state = jane
        .jmap_method_call("CalendarEvent/query", json!({ "accountId": &john_id }))
        .await
        .pointer("/methodResponses/0/1/queryState")
        .and_then(|state| state.as_str())
        .expect("query state")
        .to_string();

    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": {
                    &updated_id: { "title": "Standup moved" },
                    &secret_id: { "privacy": "secret" },
                    &moved_id: { "calendarIds": { &hidden_calendar_id: true } }
                },
                "destroy": [&destroyed_id]
            }),
        )
        .await;
    for id in [&updated_id, &secret_id, &moved_id] {
        response.updated(id);
    }
    assert_eq!(
        response.destroyed().collect::<Vec<_>>(),
        [destroyed_id.as_str()],
        "{response:?}"
    );

    let changes = jane
        .jmap_method_call(
            "CalendarEvent/changes",
            json!({ "accountId": &john_id, "sinceState": &since_state }),
        )
        .await;
    assert_eq!(
        changes.changes_by_type("updated").collect::<Vec<_>>(),
        [updated_id.as_str()],
        "{changes:?}"
    );
    let mut destroyed = changes.changes_by_type("destroyed").collect::<Vec<_>>();
    destroyed.sort_unstable();
    let mut expected = vec![secret_id.as_str(), destroyed_id.as_str(), moved_id.as_str()];
    expected.sort_unstable();
    assert_eq!(destroyed, expected, "{changes:?}");

    let query_changes = jane
        .jmap_method_call(
            "CalendarEvent/queryChanges",
            json!({ "accountId": &john_id, "sinceQueryState": &since_query_state }),
        )
        .await;
    let removed = query_changes
        .pointer("/methodResponses/0/1/removed")
        .and_then(|removed| removed.as_array())
        .expect("removed ids")
        .iter()
        .filter_map(|id| id.as_str())
        .collect::<Vec<_>>();
    for id in [&secret_id, &destroyed_id, &moved_id] {
        assert!(removed.contains(&id.as_str()), "{query_changes:?}");
    }

    john.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "destroy": [&updated_id, &secret_id, &moved_id]
        }),
    )
    .await;
    john.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "destroy": [&hidden_calendar_id],
            "onDestroyRemoveEvents": true
        }),
    )
    .await;
}

async fn private_view_details(
    test: &TestServer,
    john: &Account,
    jane: &Account,
    calendar_id: &str,
) {
    let john_id = john.id_string().to_string();
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "privacy-details",
                "title": "Lawyer",
                "description": "Details",
                "start": "2024-05-06T09:00:00",
                "timeZone": "Europe/Berlin",
                "duration": "PT30M",
                "recurrenceRule": { "@type": "RecurrenceRule", "frequency": "weekly", "count": 4 },
                "recurrenceOverrides": {
                    "2024-05-13T09:00:00": { "title": "Lawyer again" },
                    "2024-05-20T09:00:00": { "start": "2024-05-20T10:00:00" }
                },
                "calendarIds": { calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    // Personal values set while the event was public
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": {
                &event_id: {
                    "keywords": { "divorce": true },
                    "color": "red",
                    "freeBusyStatus": "free",
                    "alerts": {
                        "j1": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT1H" } }
                    },
                    "recurrenceOverrides/2024-05-27T09:00:00": { "color": "blue" }
                }
            }
        }),
    )
    .await
    .updated(&event_id);

    // The owner marks the event private and adds a vendor parameter
    let path = event_dav_path(test, john, &event_id).await;
    let client = john.webdav_client();
    let ical = dav_get(&client, &path).await;
    assert!(
        ical.contains("DTSTART;TZID=Europe/Berlin:20240506T090000"),
        "{ical}"
    );
    client
        .request(
            "PUT",
            &path,
            ical.replacen(
                "DTSTART;TZID=Europe/Berlin:20240506T090000",
                "DTSTART;X-NOTE=Lawyer about divorce;TZID=Europe/Berlin:20240506T090000",
                1,
            )
            .replace("END:VEVENT", "CLASS:PRIVATE\r\nEND:VEVENT"),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);

    let private_view = jane
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": &john_id,
                "ids": [&event_id],
                "properties": [
                    "id", "title", "iCalendar", "recurrenceOverrides", "keywords",
                    "color", "alerts", "freeBusyStatus", "start", "privacy"
                ]
            }),
        )
        .await
        .list()[0]
        .clone();
    private_view.assert_is_equal(json!({
        "id": &event_id,
        "start": "2024-05-06T09:00:00",
        "privacy": "private",
        "freeBusyStatus": "free",
        "recurrenceOverrides": {
            "2024-05-20T09:00:00": { "start": "2024-05-20T10:00:00" }
        },
    }));
    let full_view = jane
        .jmap_method_call(
            "CalendarEvent/get",
            json!({ "accountId": &john_id, "ids": [&event_id] }),
        )
        .await
        .list()[0]
        .to_string();
    for hidden in ["Lawyer", "divorce", "iCalendar", "Details", "PT1H"] {
        assert!(!full_view.contains(hidden), "{hidden} leaked: {full_view}");
    }

    // Occurrences of private events cannot be changed by sharees either
    let occurrence_id = jane
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": &john_id,
                "filter": {
                    "after": "2024-05-01T00:00:00",
                    "before": "2024-06-01T00:00:00"
                },
                "expandRecurrences": true
            }),
        )
        .await
        .ids()
        .next()
        .map(str::to_string)
        .expect("expanded occurrence");
    let response = jane
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": { &occurrence_id: { "color": "green" } }
            }),
        )
        .await;
    assert_eq!(response.not_updated(&occurrence_id).typ(), "forbidden");

    assert_eq!(
        john.jmap_method_call(
            "CalendarEvent/set",
            json!({ "accountId": &john_id, "destroy": [&event_id] }),
        )
        .await
        .destroyed()
        .collect::<Vec<_>>(),
        [event_id.as_str()]
    );
}

async fn uid_privacy_consistency(john: &Account, calendar_id: &str) {
    let instances_calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Split instances"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let base_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "privacy-split",
                "recurrenceId": "2024-04-01T10:00:00",
                "title": "First instance",
                "start": "2024-04-01T10:00:00",
                "timeZone": "Europe/Berlin",
                "duration": "PT1H",
                "calendarIds": { calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let instance = |privacy: &str| {
        json!({
            "uid": "privacy-split",
            "recurrenceId": "2024-04-08T10:00:00",
            "title": "Moved instance",
            "start": "2024-04-08T11:00:00",
            "timeZone": "Europe/Berlin",
            "duration": "PT1H",
            "privacy": privacy,
            "calendarIds": { &instances_calendar_id: true },
        })
    };

    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": john.id_string(),
                "create": {
                    "i0": instance("public").with_property(
                        "calendarIds", json!({ calendar_id: true })
                    )
                }
            }),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "invalidProperties");
    assert_eq!(
        response.not_created(0)["properties"],
        json!(["calendarIds"]),
        "{response:?}"
    );

    // A new event with the same uid must match the existing privacy
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({ "accountId": john.id_string(), "create": { "i0": instance("secret") } }),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "invalidProperties");
    assert_eq!(response.not_created(0)["properties"], json!(["privacy"]));
    let instance_id = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({ "accountId": john.id_string(), "create": { "i0": instance("public") } }),
        )
        .await
        .created(0)
        .id()
        .to_string();

    // Changing the privacy of only one event with the uid fails
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": john.id_string(),
                "update": { &base_id: { "privacy": "private" } }
            }),
        )
        .await;
    assert_eq!(response.not_updated(&base_id).typ(), "invalidProperties");

    // Changing all of them in the same request succeeds
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": john.id_string(),
                "update": {
                    &instance_id: { "privacy": "private" },
                    &base_id: { "privacy": "private" }
                }
            }),
        )
        .await;
    response.updated(&base_id);
    response.updated(&instance_id);

    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": john.id_string(),
                "create": {
                    "base": {
                        "uid": "privacy-split",
                        "title": "Whole series",
                        "start": "2024-04-01T10:00:00",
                        "timeZone": "Europe/Berlin",
                        "duration": "PT1H",
                        "privacy": "private",
                        "recurrenceRule": { "frequency": "weekly", "count": 4 },
                        "calendarIds": { calendar_id: true },
                    }
                },
                "destroy": [&base_id, &instance_id]
            }),
        )
        .await;
    response.method_response()["created"]["base"].id();
    assert_eq!(response.destroyed().count(), 2);

    john.jmap_destroy(
        MethodObject::Calendar,
        [&instances_calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

fn event(calendar_id: &str, uid: &str, title: &str, privacy: &str) -> Value {
    json!({
        "uid": uid,
        "title": title,
        "description": "Details",
        "start": "2024-03-01T10:00:00",
        "timeZone": "Europe/Berlin",
        "duration": "PT1H",
        "privacy": privacy,
        "locations": { "l1": { "name": "Room 7" } },
        "alerts": {
            "a1": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT15M" } }
        },
        "calendarIds": { calendar_id: true },
    })
}

fn not_created<'x>(response: &'x JmapResponse, id: &str) -> &'x str {
    response.method_response()["notCreated"][id]["type"]
        .as_str()
        .unwrap_or_default()
}
