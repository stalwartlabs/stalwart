/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use common::NO_ID;
use groupware::{
    cache::GroupwareCache,
    calendar::itip::{ItipIngest, ItipIngestError},
};
use hyper::StatusCode;
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};
use std::str::FromStr;
use types::{collection::SyncCollection, id::Id};

const PERSONAL_PROPERTIES: &[&str] = &[
    "id",
    "title",
    "keywords",
    "color",
    "freeBusyStatus",
    "alerts",
    "updated",
    "useDefaultAlerts",
];

pub async fn test(test: &TestServer) {
    println!("Running Calendar personal properties tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let bill = test.account("bill@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let bill_id = bill.id_string().to_string();

    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Personal",
                "shareWith": {
                    &jane_id: { "mayReadItems": true, "mayWriteAll": true },
                    &bill_id: { "mayReadItems": true }
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
                "uid": "personal-properties",
                "title": "Team sync",
                "start": "2024-05-06T09:00:00",
                "timeZone": "Europe/Berlin",
                "duration": "PT30M",
                "updated": "2024-01-01T00:00:00Z",
                "recurrenceRule": { "@type": "RecurrenceRule", "frequency": "weekly", "count": 4 },
                "keywords": { "owner": true },
                "color": "red",
                "freeBusyStatus": "free",
                "alerts": {
                    "o1": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT10M" } }
                },
                "calendarIds": { &calendar_id: true },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let owner_view = get_event(john, &john_id, &event_id).await;
    let owner_updated = owner_view["updated"].clone();

    // Sharees start with default personal properties
    for sharee in [jane, bill] {
        let sharee_view = get_event(sharee, &john_id, &event_id).await;
        assert_eq!(sharee_view["title"], json!("Team sync"));
        assert_default_personal_properties(&sharee_view);
    }

    // Sharees store their own personal properties
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let response = jane
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": {
                    &event_id: {
                        "keywords": { "jane": true },
                        "color": "#00ff00",
                        "freeBusyStatus": "free",
                        "alerts": {
                            "j1": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT1H" } }
                        },
                        "recurrenceOverrides": { "2024-05-13T09:00:00": { "color": "blue" } }
                    }
                }
            }),
        )
        .await;
    let server_set_updated = response.updated(&event_id)["updated"].clone();

    let sharee_view = get_event(jane, &john_id, &event_id).await;
    assert_eq!(sharee_view["keywords"], json!({ "jane": true }));
    assert_eq!(sharee_view["color"], json!("#00ff00"));
    assert_eq!(sharee_view["freeBusyStatus"], json!("free"));
    assert_eq!(alert_offsets(&sharee_view), ["-PT1H"]);
    assert!(
        sharee_view["updated"].as_str() > owner_updated.as_str(),
        "{sharee_view:#?}"
    );
    assert_eq!(server_set_updated, sharee_view["updated"], "{response:?}");
    assert_eq!(
        sharee_overrides(jane, &john_id, &event_id).await,
        json!({ "2024-05-13T09:00:00": { "color": "blue" } })
    );

    // Other sharees keep the default values
    let other_sharee = get_event(bill, &john_id, &event_id).await;
    assert_default_personal_properties(&other_sharee);
    assert!(
        sharee_overrides(bill, &john_id, &event_id).await.is_null(),
        "{other_sharee:#?}"
    );

    // The owner keeps their own values and the shared event was not modified
    let owner_after = get_event(john, &john_id, &event_id).await;
    assert_eq!(owner_after["keywords"], json!({ "owner": true }));
    assert_eq!(owner_after["color"], json!("red"));
    assert_eq!(owner_after["freeBusyStatus"], json!("free"));
    assert_eq!(alert_offsets(&owner_after), ["-PT10M"]);
    assert_eq!(owner_after["updated"], owner_updated);

    // Changing a shared property together with a personal one
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &event_id: { "title": "Team sync (moved)", "keywords/extra": true } }
        }),
    )
    .await
    .updated(&event_id);
    let owner_after = get_event(john, &john_id, &event_id).await;
    assert_eq!(owner_after["title"], json!("Team sync (moved)"));
    assert_eq!(owner_after["keywords"], json!({ "owner": true }));
    let sharee_view = get_event(jane, &john_id, &event_id).await;
    assert_eq!(
        sharee_view["keywords"],
        json!({ "jane": true, "extra": true })
    );

    // Keyword limits are enforced
    let too_many = (0..65)
        .map(|i| (format!("k{i}"), Value::Bool(true)))
        .collect::<serde_json::Map<_, _>>();
    let too_long = json!({ "k".repeat(129): true });
    for keywords in [Value::Object(too_many), too_long] {
        for account in [john, jane] {
            let response = account
                .jmap_method_call(
                    "CalendarEvent/set",
                    json!({
                        "accountId": &john_id,
                        "update": { &event_id: { "keywords": keywords.clone() } }
                    }),
                )
                .await;
            assert_eq!(
                response.not_updated(&event_id).typ(),
                "invalidProperties",
                "{response:?}"
            );
        }
    }

    // Sharees see their per-occurrence properties when fetching an occurrence
    let occurrences = sharee_occurrences(jane, &john_id).await;
    assert_eq!(occurrences.len(), 4, "{occurrences:#?}");
    assert_eq!(
        occurrences[0]["color"],
        json!("#00ff00"),
        "{occurrences:#?}"
    );
    assert_eq!(occurrences[1]["color"], json!("blue"), "{occurrences:#?}");
    assert_eq!(alert_offsets(&occurrences[1]), ["-PT1H"]);

    // Per-occurrence personal changes on events with DTEND and owner overrides
    let event_path = event_dav_path(test, john, &event_id).await;
    john.webdav_client()
        .request("PUT", &event_path, DTEND_EVENT)
        .await
        .with_status(StatusCode::NO_CONTENT);
    let owner_before = get_event_ical(john, &event_path).await;
    let occurrences = sharee_occurrences(jane, &john_id).await;
    assert_eq!(occurrences[2]["title"], json!("Team sync (late)"));
    let last_id = occurrences[3]["id"].as_str().unwrap().to_string();
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &last_id: { "color": "green", "keywords": { "last": true } } }
        }),
    )
    .await
    .updated(&last_id);
    assert_eq!(get_event_ical(john, &event_path).await, owner_before);
    let occurrences = sharee_occurrences(jane, &john_id).await;
    assert_eq!(occurrences[3]["color"], json!("green"), "{occurrences:#?}");
    assert_eq!(occurrences[3]["keywords"], json!({ "last": true }));
    assert_eq!(
        occurrences[2]["color"],
        json!("#00ff00"),
        "{occurrences:#?}"
    );
    let owner_overrides = john
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": &john_id,
                "ids": [&event_id],
                "properties": ["recurrenceOverrides"]
            }),
        )
        .await;
    assert_eq!(
        owner_overrides.list()[0]["recurrenceOverrides"]
            .as_object()
            .map(|overrides| overrides.keys().cloned().collect::<Vec<_>>()),
        Some(vec!["2024-05-20T09:00:00".to_string()]),
        "{owner_overrides:?}"
    );

    // CalDAV writes by sharees keep the alarms hidden by their default alerts
    jane.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": &john_id,
            "update": {
                &calendar_id: {
                    "defaultAlertsWithTime": {
                        "jane-default": {
                            "action": "display",
                            "trigger": { "relativeTo": "start", "offset": "-PT2M" }
                        }
                    }
                }
            }
        }),
    )
    .await
    .updated(&calendar_id);
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &event_id: { "useDefaultAlerts": true } }
        }),
    )
    .await
    .updated(&event_id);
    let sharee_ical = get_event_ical(jane, &event_path).await;
    assert!(sharee_ical.contains("TRIGGER:-PT2M"), "{sharee_ical}");
    assert!(!sharee_ical.contains("TRIGGER:-PT1H"), "{sharee_ical}");
    jane.webdav_client()
        .request("PUT", &event_path, sharee_ical.as_str())
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_eq!(get_event_ical(john, &event_path).await, owner_before);

    // CalDAV writes by sharees keep the personal values set over JMAP
    let sharee_view = get_event(jane, &john_id, &event_id).await;
    assert_eq!(
        sharee_view["keywords"],
        json!({ "jane": true, "extra": true })
    );
    assert_eq!(sharee_view["color"], json!("#00ff00"));
    assert_eq!(sharee_view["freeBusyStatus"], json!("free"));
    let overrides = sharee_overrides(jane, &john_id, &event_id).await;
    assert_eq!(
        overrides["2024-05-13T09:00:00"],
        json!({ "color": "blue" }),
        "{overrides:#}"
    );
    assert_eq!(
        overrides["2024-05-27T09:00:00"],
        json!({ "color": "green", "keywords": { "last": true } }),
        "{overrides:#}"
    );
    assert_eq!(
        overrides["2024-05-20T09:00:00"]["title"],
        json!("Team sync (late)"),
        "{overrides:#}"
    );
    assert!(
        overrides.as_object().is_some_and(|overrides| overrides
            .values()
            .filter_map(Value::as_object)
            .flat_map(|patch| patch.values())
            .all(|value| !value.is_null())),
        "{overrides:#}"
    );

    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": { &event_id: { "useDefaultAlerts": false } }
        }),
    )
    .await
    .updated(&event_id);
    assert_eq!(
        alert_offsets(&get_event(jane, &john_id, &event_id).await),
        ["-PT1H"]
    );

    // Personal values of occurrences that no longer exist are not returned
    john.webdav_client()
        .request(
            "PUT",
            &event_path,
            DTEND_EVENT
                .replace("COUNT=4", "COUNT=2")
                .split_once("BEGIN:VEVENT\r\nUID:personal-properties\r\nDTSTAMP:20240101T000000Z\r\nRECURRENCE-ID")
                .map(|(series, _)| format!("{series}END:VCALENDAR\r\n"))
                .unwrap(),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_eq!(
        sharee_overrides(jane, &john_id, &event_id).await,
        json!({ "2024-05-13T09:00:00": { "color": "blue" } })
    );

    personal_updated(john, jane, &calendar_id).await;
    reencoded_personal_changes(test, john, jane, &calendar_id).await;
    ingested_event_limits(test, jane).await;

    john.destroy_all_calendars().await;
    jane.destroy_all_calendars().await;
    john.destroy_all_event_notifications().await;
    jane.destroy_all_event_notifications().await;
    test.assert_is_empty().await;
}

const DTEND_EVENT: &str = concat!(
    "BEGIN:VCALENDAR\r\n",
    "VERSION:2.0\r\n",
    "PRODID:-//Stalwart//Test//EN\r\n",
    "BEGIN:VEVENT\r\n",
    "UID:personal-properties\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "DTSTART;TZID=Europe/Berlin:20240506T090000\r\n",
    "DTEND;TZID=Europe/Berlin:20240506T093000\r\n",
    "RRULE:FREQ=WEEKLY;COUNT=4\r\n",
    "SUMMARY:Team sync\r\n",
    "COLOR:red\r\n",
    "END:VEVENT\r\n",
    "BEGIN:VEVENT\r\n",
    "UID:personal-properties\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "RECURRENCE-ID;TZID=Europe/Berlin:20240520T090000\r\n",
    "DTSTART;TZID=Europe/Berlin:20240520T100000\r\n",
    "DTEND;TZID=Europe/Berlin:20240520T103000\r\n",
    "SUMMARY:Team sync (late)\r\n",
    "COLOR:red\r\n",
    "END:VEVENT\r\n",
    "END:VCALENDAR\r\n"
);

async fn ingested_event_limits(test: &TestServer, jane: &Account) {
    let uid = "ingested-categories";
    let jane_id = jane.id_string().to_string();
    jane.jmap_create(
        MethodObject::Calendar,
        [json!({"name": "Invitations"})],
        [("onSuccessSetIsDefault", "#i0")],
    )
    .await
    .created(0);
    let account_info = test
        .server
        .account_info(jane.id().document_id())
        .await
        .unwrap();
    let categories = (0..70)
        .map(|i| format!("c{i}"))
        .collect::<Vec<_>>()
        .join(",");
    match test
        .server
        .itip_ingest(
            &account_info,
            "jdoe@example.com",
            "jane.smith@example.com",
            &format!(
                concat!(
                    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nMETHOD:REQUEST\r\n",
                    "BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20300101T000000Z\r\nSEQUENCE:0\r\n",
                    "DTSTART:20300601T090000Z\r\nDURATION:PT1H\r\nSUMMARY:Ingested\r\n",
                    "CATEGORIES:{categories}\r\nORGANIZER:mailto:jdoe@example.com\r\n",
                    "ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:jane.smith@example.com\r\n",
                    "END:VEVENT\r\nEND:VCALENDAR\r\n"
                ),
                uid = uid,
                categories = categories
            ),
        )
        .await
    {
        Ok(_) => {}
        Err(ItipIngestError::Message(err)) => panic!("iTIP message rejected: {err}"),
        Err(ItipIngestError::Internal(err)) => panic!("iTIP message not ingested: {err:?}"),
    }
    let event_id = jane
        .jmap_method_call(
            "CalendarEvent/query",
            json!({ "accountId": &jane_id, "filter": { "uid": uid } }),
        )
        .await
        .method_response()["ids"][0]
        .as_str()
        .unwrap_or_else(|| panic!("no copy of {uid}"))
        .to_string();
    let event = get_event(jane, &jane_id, &event_id).await;
    assert_eq!(
        event["keywords"].as_object().map(|keywords| keywords.len()),
        Some(70),
        "{event}"
    );

    // Owner edits only validate the personal data they change
    jane.jmap_update(
        MethodObject::CalendarEvent,
        [(&event_id, json!({ "title": "Ingested and renamed" }))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&event_id);
    assert_eq!(
        get_event(jane, &jane_id, &event_id).await["title"],
        json!("Ingested and renamed")
    );
    let response = jane
        .jmap_update(
            MethodObject::CalendarEvent,
            [(&event_id, json!({ "keywords/c70": true }))],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let error = response.not_updated(&event_id);
    assert_eq!(error["type"], json!("invalidProperties"), "{response:?}");
    assert_eq!(error["properties"], json!(["keywords"]), "{response:?}");
}

async fn personal_updated(john: &Account, jane: &Account, calendar_id: &str) {
    let john_id = john.id_string().to_string();
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({
                    "uid": "personal-updated",
                    "title": "Updated rules",
                    "start": "2024-06-03T09:00:00",
                    "timeZone": "Europe/Berlin",
                    "duration": "PT30M",
                    "calendarIds": { calendar_id: true },
                }),
                json!({
                    "uid": "personal-updated-invitation",
                    "title": "Invitation",
                    "start": "2024-06-04T09:00:00",
                    "timeZone": "Europe/Berlin",
                    "duration": "PT30M",
                    "updated": "2024-01-01T00:00:00Z",
                    "organizerCalendarAddress": "mailto:organizer@remote.example.org",
                    "participants": {
                        "o1": {
                            "@type": "Participant",
                            "calendarAddress": "mailto:organizer@remote.example.org",
                            "roles": { "owner": true }
                        },
                        "j1": {
                            "@type": "Participant",
                            "calendarAddress": "mailto:jdoe@example.com",
                            "roles": { "attendee": true },
                            "participationStatus": "accepted"
                        }
                    },
                    "calendarIds": { calendar_id: true },
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let event_id = response.created(0).id().to_string();
    let invitation_id = response.created(1).id().to_string();
    let shared_updated = get_event(john, &john_id, &event_id).await["updated"].clone();
    let update = async |event_id: &str, patch: Value| {
        let response = jane
            .jmap_method_call(
                "CalendarEvent/set",
                json!({ "accountId": &john_id, "update": { event_id: patch } }),
            )
            .await;
        let server_set = response.updated(event_id)["updated"].clone();
        let updated = get_event(jane, &john_id, event_id).await["updated"].clone();
        (updated, server_set)
    };

    // Origin events stamp the personal updated time, which never goes backwards
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (colored, server_set) = update(&event_id, json!({ "color": "blue" })).await;
    assert!(colored.as_str() > shared_updated.as_str(), "{colored}");
    assert_eq!(server_set, colored);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (cleared, server_set) = update(&event_id, json!({ "color": null })).await;
    assert!(cleared.as_str() > colored.as_str(), "{cleared}");
    assert_eq!(server_set, cleared);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (toggled, server_set) = update(&event_id, json!({ "useDefaultAlerts": true })).await;
    assert!(toggled.as_str() > cleared.as_str(), "{toggled}");
    assert_eq!(server_set, toggled);
    assert_eq!(
        get_event(john, &john_id, &event_id).await["updated"],
        shared_updated
    );

    // Other origins keep the updated time chosen by the client
    let (updated, server_set) = update(&invitation_id, json!({ "color": "green" })).await;
    assert_eq!(updated, json!("2024-01-01T00:00:00Z"));
    assert!(server_set.is_null(), "{server_set}");
    let (updated, server_set) = update(
        &invitation_id,
        json!({ "color": "blue", "updated": "2025-06-01T00:00:00Z" }),
    )
    .await;
    assert_eq!(updated, json!("2025-06-01T00:00:00Z"));
    assert!(server_set.is_null(), "{server_set}");
    assert_eq!(
        get_event(john, &john_id, &invitation_id).await["updated"],
        json!("2024-01-01T00:00:00Z")
    );
}

const REENCODED_EVENT: &str = concat!(
    "BEGIN:VCALENDAR\r\n",
    "VERSION:2.0\r\n",
    "PRODID:-//Stalwart//Test//EN\r\n",
    "BEGIN:VEVENT\r\n",
    "UID:reencoded\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "DTSTART;TZID=Europe/Berlin:20300601T090000\r\n",
    "DTEND:20300601T070000Z\r\n",
    "RRULE:FREQ=DAILY;COUNT=5\r\n",
    "SEQUENCE:3\r\n",
    "SUMMARY:Standup\r\n",
    "COLOR:red\r\n",
    "END:VEVENT\r\n",
    "BEGIN:VEVENT\r\n",
    "UID:reencoded\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "RECURRENCE-ID:20300602T070000Z\r\n",
    "DTSTART;TZID=Europe/Berlin:20300602T110000\r\n",
    "DTEND:20300602T100000Z\r\n",
    "SEQUENCE:3\r\n",
    "SUMMARY:Standup (late)\r\n",
    "END:VEVENT\r\n",
    "END:VCALENDAR\r\n"
);

async fn reencoded_personal_changes(
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
                "uid": "reencoded",
                "title": "Standup",
                "start": "2030-06-01T09:00:00",
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
    let event_path = event_dav_path(test, john, &event_id).await;
    john.webdav_client()
        .request("PUT", &event_path, REENCODED_EVENT)
        .await
        .with_status(StatusCode::NO_CONTENT);
    let stored = get_event_ical(john, &event_path).await;
    assert!(stored.contains("DTEND:20300601T070000Z"), "{stored}");
    assert!(stored.contains("SEQUENCE:3"), "{stored}");
    john.destroy_all_event_notifications().await;
    jane.destroy_all_event_notifications().await;

    let update = async |account: &Account, patch: Value| -> Value {
        account
            .jmap_method_call(
                "CalendarEvent/set",
                json!({ "accountId": &john_id, "update": { &event_id: patch } }),
            )
            .await
            .updated(&event_id)
            .clone()
    };
    update(
        jane,
        json!({ "color": "blue", "keywords": { "jane": true } }),
    )
    .await;
    assert_eq!(get_event_ical(john, &event_path).await, stored);
    assert_eq!(
        get_event(jane, &john_id, &event_id).await["color"],
        json!("blue")
    );
    assert_eq!(notification_count(john).await, 0);

    update(
        john,
        json!({ "color": "azure", "keywords": { "john": true } }),
    )
    .await;
    let owner_stored = get_event_ical(john, &event_path).await;
    assert!(owner_stored.contains("COLOR:azure"), "{owner_stored}");
    assert!(owner_stored.contains("CATEGORIES:john"), "{owner_stored}");
    assert_eq!(
        shared_lines(&owner_stored),
        shared_lines(&stored),
        "{owner_stored}"
    );
    assert_eq!(notification_count(jane).await, 0);

    update(
        john,
        json!({ "recurrenceOverrides/2030-06-02T09:00:00/color": "beige" }),
    )
    .await;
    let occurrence_stored = get_event_ical(john, &event_path).await;
    assert!(
        occurrence_stored.contains("COLOR:beige"),
        "{occurrence_stored}"
    );
    assert_eq!(
        shared_lines(&occurrence_stored),
        shared_lines(&stored),
        "{occurrence_stored}"
    );
    update(
        jane,
        json!({ "recurrenceOverrides/2030-06-02T09:00:00/color": "brown" }),
    )
    .await;
    assert_eq!(get_event_ical(john, &event_path).await, occurrence_stored);
    assert_eq!(
        sharee_overrides(jane, &john_id, &event_id).await["2030-06-02T09:00:00"]["color"],
        json!("brown")
    );

    let server_set = update(
        john,
        json!({ "recurrenceOverrides/2030-06-03T09:00:00": { "color": "olive" } }),
    )
    .await;
    assert!(
        server_set
            .get("recurrenceOverrides/2030-06-03T09:00:00")
            .is_some_and(Value::is_null),
        "{server_set}"
    );
    assert!(
        sharee_overrides(john, &john_id, &event_id)
            .await
            .get("2030-06-03T09:00:00")
            .is_none(),
        "{event_id}"
    );
    let dropped_stored = get_event_ical(john, &event_path).await;
    assert_eq!(shared_lines(&dropped_stored), shared_lines(&stored));
    assert!(!dropped_stored.contains("COLOR:olive"), "{dropped_stored}");
    assert!(dropped_stored.contains("COLOR:azure"), "{dropped_stored}");
    assert!(dropped_stored.contains("COLOR:beige"), "{dropped_stored}");
    update(
        jane,
        json!({ "recurrenceOverrides/2030-06-03T09:00:00": { "color": "olive" } }),
    )
    .await;
    assert_eq!(get_event_ical(john, &event_path).await, dropped_stored);
    assert_eq!(
        sharee_overrides(jane, &john_id, &event_id).await["2030-06-03T09:00:00"]["color"],
        json!("olive")
    );
    assert_eq!(notification_count(john).await, 0);
    assert_eq!(notification_count(jane).await, 0);

    john.jmap_destroy(
        MethodObject::CalendarEvent,
        [&event_id],
        Vec::<(&str, &str)>::new(),
    )
    .await;
    john.destroy_all_event_notifications().await;
    jane.destroy_all_event_notifications().await;
}

fn shared_lines(ical: &str) -> Vec<&str> {
    ical.split("\r\n")
        .filter(|line| !line.starts_with("COLOR:") && !line.starts_with("CATEGORIES:"))
        .collect()
}

async fn notification_count(account: &Account) -> usize {
    account
        .jmap_method_call(
            "CalendarEventNotification/get",
            json!({ "accountId": account.id_string(), "ids": null, "properties": ["type"] }),
        )
        .await
        .list()
        .len()
}

async fn sharee_overrides(account: &Account, account_id: &str, event_id: &str) -> Value {
    account
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": account_id,
                "ids": [event_id],
                "properties": ["recurrenceOverrides"]
            }),
        )
        .await
        .list()[0]["recurrenceOverrides"]
        .clone()
}

fn assert_default_personal_properties(event: &Value) {
    for property in ["keywords", "color", "alerts"] {
        assert!(
            event.get(property).is_none_or(Value::is_null),
            "{property} leaked: {event:#?}"
        );
    }
    assert!(
        event
            .get("freeBusyStatus")
            .is_none_or(|status| status.is_null() || status == "busy"),
        "freeBusyStatus leaked: {event:#?}"
    );
    assert_eq!(event["useDefaultAlerts"], json!(false), "{event:#?}");
}

async fn sharee_occurrences(account: &Account, account_id: &str) -> Vec<Value> {
    let ids = account
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": account_id,
                "filter": { "after": "2024-05-01T00:00:00", "before": "2024-06-01T00:00:00" },
                "sort": [{ "property": "start" }],
                "expandRecurrences": true
            }),
        )
        .await
        .ids()
        .map(|id| id.to_string())
        .collect::<Vec<_>>();
    account
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": account_id,
                "ids": ids,
                "properties": PERSONAL_PROPERTIES
            }),
        )
        .await
        .list()
        .to_vec()
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

async fn get_event_ical(account: &Account, path: &str) -> String {
    account
        .webdav_client()
        .request("GET", path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string()
}

async fn get_event(account: &Account, account_id: &str, event_id: &str) -> Value {
    account
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": account_id,
                "ids": [event_id],
                "properties": PERSONAL_PROPERTIES
            }),
        )
        .await
        .list()[0]
        .clone()
}

fn alert_offsets(event: &Value) -> Vec<&str> {
    event["alerts"]
        .as_object()
        .into_iter()
        .flat_map(|alerts| alerts.values())
        .filter_map(|alert| alert["trigger"]["offset"].as_str())
        .collect()
}
