/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::conformance::{dav_get, event_dav_path};
use crate::utils::{
    account::Account,
    jmap::{IntoJmapSet, JmapUtils},
    server::TestServer,
};
use calcard::jscalendar::JSCalendarProperty;
use hyper::StatusCode;
use jmap_proto::{
    object::calendar_event_notification::CalendarEventNotificationProperty,
    request::method::MethodObject,
};
use mail_parser::DateTime;
use registry::{
    schema::{
        enums::{Permission, StorageQuota},
        prelude::{ObjectType, Property},
    },
    types::EnumImpl,
};
use serde_json::{Value, json};
use std::str::FromStr;
use store::write::now;
use types::{collection::Collection, id::Id};

pub async fn test(test: &TestServer) {
    println!("Running Calendar Event Notification tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let bill = test.account("bill@example.com");

    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let bill_id = bill.id_string().to_string();

    let mut john_change_id = String::new();
    let mut jane_change_id = String::new();
    let mut bill_change_id = String::new();

    // Obtain share notification change ids for all accounts
    for (change_id, client) in [
        (&mut john_change_id, john),
        (&mut jane_change_id, jane),
        (&mut bill_change_id, bill),
    ] {
        let response = client
            .jmap_get(
                MethodObject::CalendarEventNotification,
                [CalendarEventNotificationProperty::Id],
                Vec::<&str>::new(),
            )
            .await;
        response.list_array().assert_is_equal(json!([]));
        *change_id = response.state().to_string();

        let response = client
            .jmap_changes(MethodObject::CalendarEventNotification, &change_id)
            .await;
        assert_eq!(response.changes().next(), None);
        assert_eq!(response.new_state(), change_id.as_str());
    }

    // Create test calendars
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Test Calendar",
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let john_calendar_id = response.created(0).id().to_string();

    // Sent invitation to Jane and Bill
    let john_event = test_event();
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [john_event.clone().with_property(
                JSCalendarProperty::<Id>::CalendarIds,
                [john_calendar_id.as_str()].into_jmap_set(),
            )],
            [("sendSchedulingMessages", true)],
        )
        .await;
    let john_event_id = response.created(0).id().to_string();

    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    test.wait_for_tasks().await;

    // Verify Jane and Bill received the share notification
    let mut jane_event_id = String::new();
    let mut bill_event_id = String::new();
    for (change_id, event_id, client) in [
        (&mut jane_change_id, &mut jane_event_id, jane),
        (&mut bill_change_id, &mut bill_event_id, bill),
    ] {
        // Obtain changes
        let response = client
            .jmap_changes(MethodObject::CalendarEventNotification, &change_id)
            .await;
        let changes = response.changes().collect::<Vec<_>>();
        assert_eq!(changes.len(), 1);
        *change_id = response.new_state().to_string();
        let notification_id = changes[0].as_created();

        // Obtain and verify notification
        let response = client
            .jmap_get(
                MethodObject::CalendarEventNotification,
                [
                    CalendarEventNotificationProperty::Id,
                    CalendarEventNotificationProperty::Created,
                    CalendarEventNotificationProperty::ChangedBy,
                    CalendarEventNotificationProperty::Comment,
                    CalendarEventNotificationProperty::Type,
                    CalendarEventNotificationProperty::CalendarEventId,
                    CalendarEventNotificationProperty::IsDraft,
                    CalendarEventNotificationProperty::Event,
                    CalendarEventNotificationProperty::EventPatch,
                ],
                [notification_id],
            )
            .await;
        let notification = &response.list()[0];
        *event_id = notification.text_field("calendarEventId").to_string();
        notification.assert_is_equal(json!({
          "id": &notification_id,
          "created": &notification.text_field("created"),
          "changedBy": {
            "name": "John Doe",
            "email": "jdoe@example.com",
            "calendarAddress": "mailto:jdoe@example.com",
            "principalId": &john_id
          },
          "comment": null,
          "type": "created",
          "calendarEventId": event_id,
          "isDraft": false,
          "eventPatch": null,
          "event": john_event
            .clone()
            .with_property(
                "updated",
                notification
                    .text_field("event/updated")
            )
            .with_property(
                "created",
                notification
                    .text_field("event/created")
            )
        }));

        // Verify the event exists
        let response = client
            .jmap_get(
                MethodObject::CalendarEvent,
                [JSCalendarProperty::<Id>::Id, JSCalendarProperty::Title],
                [&event_id],
            )
            .await;
        response.list()[0].assert_is_equal(json!({
          "id": &event_id,
          "title": "Lunch"
        }));
    }

    // Jane and Bill accept the invitation
    let response = jane
        .jmap_update(
            MethodObject::CalendarEvent,
            [(
                &jane_event_id,
                json!({
             "participants/a0171748-fe8d-57d8-879e-56036a5251d1/participationStatus":
             "accepted"}),
            )],
            [("sendSchedulingMessages", true)],
        )
        .await;
    response.updated(&jane_event_id);
    let response = bill
        .jmap_update(
            MethodObject::CalendarEvent,
            [(
                &bill_event_id,
                json!({
             "participants/86720268-d67c-58c3-9217-03df7d7ee4d8/participationStatus":
             "accepted"}),
            )],
            [("sendSchedulingMessages", true)],
        )
        .await;
    response.updated(&bill_event_id);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Verify John received two share notifications
    let response = john
        .jmap_changes(MethodObject::CalendarEventNotification, &john_change_id)
        .await;
    let changes = response.changes().collect::<Vec<_>>();
    assert_eq!(changes.len(), 2);
    for (i, change) in changes.into_iter().enumerate() {
        let notification_id = change.as_created();

        // Obtain and verify notification
        let response = john
            .jmap_get(
                MethodObject::CalendarEventNotification,
                [
                    CalendarEventNotificationProperty::Id,
                    CalendarEventNotificationProperty::ChangedBy,
                    CalendarEventNotificationProperty::Comment,
                    CalendarEventNotificationProperty::Type,
                    CalendarEventNotificationProperty::CalendarEventId,
                    CalendarEventNotificationProperty::IsDraft,
                ],
                [notification_id],
            )
            .await;
        let changed_by = if i == 0 {
            json!({
                "name": "Jane Smith",
                "email": "jane.smith@example.com",
                "calendarAddress": "mailto:jane.smith@example.com",
                "principalId": &jane_id,
            })
        } else {
            json!({
                "name": "Bill Foobar",
                "email": "bill@example.com",
                "calendarAddress": "mailto:bill@example.com",
                "principalId": &bill_id,
            })
        };

        response.list()[0].assert_is_equal(json!({
            "id": &notification_id,
            "changedBy": changed_by,
            "comment": null,
            "type": "updated",
            "calendarEventId": &john_event_id,
            "isDraft": false
        }));
    }

    // Verify the event was updated
    let response = john
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::Title,
                JSCalendarProperty::Participants,
            ],
            [&john_event_id],
        )
        .await;
    response.list()[0].assert_is_equal(json!({
        "participants": {
        "8584f8f9-5414-55e3-8a1c-ad6fc2f3ffb6": {
            "calendarAddress": "mailto:jdoe@example.com",
            "@type": "Participant",
            "roles": {
                "chair": true,
                "owner": true
            },
            "participationStatus": "accepted"
        },
        "a0171748-fe8d-57d8-879e-56036a5251d1": {
            "calendarAddress": "mailto:jane.smith@example.com",
            "@type": "Participant",
            "participationStatus": "accepted",
            "kind": "individual"
        },
        "86720268-d67c-58c3-9217-03df7d7ee4d8": {
            "calendarAddress": "mailto:bill@example.com",
            "@type": "Participant",
            "kind": "individual",
            "participationStatus": "accepted"
        }
        },
        "title": "Lunch",
        "id": &john_event_id
    }));

    // Jane later declines the invitation
    let response = jane
        .jmap_update(
            MethodObject::CalendarEvent,
            [(
                &jane_event_id,
                json!({
             "participants/a0171748-fe8d-57d8-879e-56036a5251d1/participationStatus":
             "declined"}),
            )],
            [("sendSchedulingMessages", true)],
        )
        .await;
    response.updated(&jane_event_id);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Make sure John received the update
    let response = john
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::Title,
                JSCalendarProperty::Participants,
            ],
            [&john_event_id],
        )
        .await;
    response.list()[0].assert_is_equal(json!({
        "participants": {
        "8584f8f9-5414-55e3-8a1c-ad6fc2f3ffb6": {
            "calendarAddress": "mailto:jdoe@example.com",
            "@type": "Participant",
            "roles": {
                "chair": true,
                "owner": true
            },
            "participationStatus": "accepted"
        },
        "a0171748-fe8d-57d8-879e-56036a5251d1": {
            "calendarAddress": "mailto:jane.smith@example.com",
            "@type": "Participant",
            "participationStatus": "declined",
            "kind": "individual"
        },
        "86720268-d67c-58c3-9217-03df7d7ee4d8": {
            "calendarAddress": "mailto:bill@example.com",
            "@type": "Participant",
            "kind": "individual",
            "participationStatus": "accepted"
        }
        },
        "title": "Lunch",
        "id": &john_event_id
    }));

    // John deletes the event
    let response = john
        .jmap_destroy(
            MethodObject::CalendarEvent,
            [&john_event_id],
            [("sendSchedulingMessages", true)],
        )
        .await;
    assert_eq!(response.destroyed().collect::<Vec<_>>(), [&john_event_id]);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Verify that only Bill received the cancellation
    let response = jane
        .jmap_changes(MethodObject::CalendarEventNotification, &jane_change_id)
        .await;
    assert_eq!(response.changes().next(), None);
    let response = bill
        .jmap_changes(MethodObject::CalendarEventNotification, &bill_change_id)
        .await;
    let changes = response.changes().collect::<Vec<_>>();
    assert_eq!(changes.len(), 1);
    let notification_id = changes[0].as_created();
    let response = bill
        .jmap_get(
            MethodObject::CalendarEventNotification,
            [
                CalendarEventNotificationProperty::Id,
                CalendarEventNotificationProperty::ChangedBy,
                CalendarEventNotificationProperty::Comment,
                CalendarEventNotificationProperty::Type,
                CalendarEventNotificationProperty::CalendarEventId,
                CalendarEventNotificationProperty::IsDraft,
            ],
            [notification_id],
        )
        .await;
    response.list()[0].assert_is_equal(json!({
        "id": &notification_id,
        "changedBy": {
            "name": "John Doe",
            "email": "jdoe@example.com",
            "calendarAddress": "mailto:jdoe@example.com",
            "principalId": &john_id
        },
        "comment": null,
        "type": "updated",
        "calendarEventId": &bill_event_id,
        "isDraft": false
    }));
    let response = bill
        .jmap_get(
            MethodObject::CalendarEventNotification,
            [
                CalendarEventNotificationProperty::Event,
                CalendarEventNotificationProperty::EventPatch,
            ],
            [notification_id],
        )
        .await;
    let notification = &response.list()[0];
    assert_eq!(
        notification["event"]["title"],
        json!("Lunch"),
        "{response:?}"
    );
    assert!(
        notification["eventPatch"]
            .as_object()
            .is_some_and(|patch| !patch.is_empty()),
        "{response:?}"
    );

    // Verify Bill's event was updated
    let response = bill
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::Title,
                JSCalendarProperty::Status,
            ],
            [&bill_event_id],
        )
        .await;
    response.list()[0].assert_is_equal(json!({
        "id": &bill_event_id,
        "title": "Lunch",
        "status": "cancelled"
    }));

    // Scheduling messages are sent for a server-assigned organizer
    let jane_change_id = jane
        .jmap_get(
            MethodObject::CalendarEventNotification,
            [CalendarEventNotificationProperty::Id],
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();

    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [test_event_without_organizer().with_property(
                JSCalendarProperty::<Id>::CalendarIds,
                [john_calendar_id.as_str()].into_jmap_set(),
            )],
            [("sendSchedulingMessages", true)],
        )
        .await;
    let john_event_id = response.created(0).id().to_string();

    john.jmap_get(
        MethodObject::CalendarEvent,
        [
            JSCalendarProperty::<Id>::Id,
            JSCalendarProperty::OrganizerCalendarAddress,
        ],
        [&john_event_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
            "id": &john_event_id,
            "organizerCalendarAddress": "mailto:jdoe@example.com"
        }));

    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    test.wait_for_tasks().await;

    let response = jane
        .jmap_changes(MethodObject::CalendarEventNotification, &jane_change_id)
        .await;
    let changes = response.changes().collect::<Vec<_>>();
    assert_eq!(changes.len(), 1);
    let notification_id = changes[0].as_created();
    let jane_event_id = jane
        .jmap_get(
            MethodObject::CalendarEventNotification,
            [
                CalendarEventNotificationProperty::Id,
                CalendarEventNotificationProperty::CalendarEventId,
            ],
            [notification_id],
        )
        .await
        .list()[0]
        .text_field("calendarEventId")
        .to_string();

    jane.jmap_get(
        MethodObject::CalendarEvent,
        [
            JSCalendarProperty::<Id>::Id,
            JSCalendarProperty::Title,
            JSCalendarProperty::OrganizerCalendarAddress,
        ],
        [&jane_event_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
            "id": &jane_event_id,
            "title": "Brunch",
            "organizerCalendarAddress": "mailto:jdoe@example.com"
        }));

    // An attendee replying to the invitation does not take over as organizer
    jane.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &jane_event_id,
            json!({
         "participants/a0171748-fe8d-57d8-879e-56036a5251d1/participationStatus":
         "accepted"}),
        )],
        [("sendSchedulingMessages", true)],
    )
    .await
    .updated(&jane_event_id);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    jane.jmap_get(
        MethodObject::CalendarEvent,
        [
            JSCalendarProperty::<Id>::Id,
            JSCalendarProperty::OrganizerCalendarAddress,
        ],
        [&jane_event_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
            "id": &jane_event_id,
            "organizerCalendarAddress": "mailto:jdoe@example.com"
        }));

    // Direct changes carry no comment and report whether the event is a draft
    test.wait_for_tasks().await;
    let shared_calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Shared",
                "shareWith": { &jane_id: {"mayReadItems": true, "mayWriteAll": true} }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let draft_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &shared_calendar_id: true },
                "uid": "direct-draft",
                "title": "Draft",
                "start": "2026-06-01T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "isDraft": true
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let draft_path = event_dav_path(test, john, &draft_id).await;
    let calendar_path = draft_path
        .rsplit_once('/')
        .map(|(folder, _)| format!("{folder}/"))
        .unwrap();
    let commented_path = format!("{calendar_path}direct-commented.ics");
    john.webdav_client()
        .request(
            "PUT",
            &commented_path,
            concat!(
                "BEGIN:VCALENDAR\r\n",
                "VERSION:2.0\r\n",
                "PRODID:-//Stalwart//Test//EN\r\n",
                "BEGIN:VEVENT\r\n",
                "UID:direct-commented\r\n",
                "DTSTAMP:20260101T000000Z\r\n",
                "DTSTART:20260601T090000Z\r\n",
                "DURATION:PT1H\r\n",
                "SUMMARY:Commented\r\n",
                "COMMENT:Left by an attendee\r\n",
                "END:VEVENT\r\n",
                "END:VCALENDAR\r\n"
            ),
        )
        .await
        .with_status(StatusCode::CREATED);
    let john_notifications = john
        .jmap_get(
            MethodObject::CalendarEventNotification,
            [CalendarEventNotificationProperty::Id],
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();
    let jane_dav = jane.webdav_client();
    for (path, title) in [(&draft_path, "Draft"), (&commented_path, "Commented")] {
        let ical = dav_get(&jane_dav, path).await;
        jane_dav
            .request(
                "PUT",
                path,
                ical.replace(
                    &format!("SUMMARY:{title}"),
                    &format!("SUMMARY:{title} (changed)"),
                ),
            )
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    let response = john
        .jmap_changes(MethodObject::CalendarEventNotification, &john_notifications)
        .await;
    let notification_ids = response
        .changes()
        .map(|change| change.as_created().to_string())
        .collect::<Vec<_>>();
    let response = john
        .jmap_get(
            MethodObject::CalendarEventNotification,
            [
                CalendarEventNotificationProperty::Id,
                CalendarEventNotificationProperty::ChangedBy,
                CalendarEventNotificationProperty::Comment,
                CalendarEventNotificationProperty::Type,
                CalendarEventNotificationProperty::CalendarEventId,
                CalendarEventNotificationProperty::IsDraft,
            ],
            notification_ids.iter().map(String::as_str),
        )
        .await;
    let direct_notifications = response
        .list()
        .iter()
        .filter(|notification| notification["changedBy"]["principalId"] == json!(&jane_id))
        .collect::<Vec<_>>();
    assert_eq!(direct_notifications.len(), 2, "{response:?}");
    for notification in direct_notifications {
        assert_eq!(notification["type"], json!("updated"), "{notification}");
        assert_eq!(
            notification.get("comment"),
            Some(&Value::Null),
            "{notification}"
        );
        assert_eq!(
            notification["isDraft"],
            json!(notification["calendarEventId"] == json!(&draft_id)),
            "{notification}"
        );
    }

    // At the notification limit the oldest notification is replaced
    let admin = test.account("admin@example.com");
    let limited = admin
        .create_user_account(
            "limited@example.com",
            "limited + extra safety",
            "Limited User",
            &[],
            vec![Permission::UnlimitedRequests],
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            limited.id(),
            json!({
                Property::Quotas: {StorageQuota::MaxCalendarEventNotifications.as_str(): 2}
            }),
        )
        .await;
    let limited_calendar_id = limited
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Limited",
                "shareWith": { &jane_id: {"mayReadItems": true, "mayWriteAll": true} }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let limited_event_id = limited
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &limited_calendar_id: true },
                "uid": "limited",
                "title": "Limited",
                "start": "2026-06-01T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    for idx in 0..3 {
        jane.jmap_update_account(
            &limited,
            MethodObject::CalendarEvent,
            [(
                &limited_event_id,
                json!({"title": format!("Limited {idx}")}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&limited_event_id);
    }
    let mut titles = limited
        .jmap_get(
            MethodObject::CalendarEventNotification,
            [
                CalendarEventNotificationProperty::Id,
                CalendarEventNotificationProperty::EventPatch,
            ],
            Vec::<&str>::new(),
        )
        .await
        .list()
        .iter()
        .filter_map(|notification| notification["eventPatch"]["title"].as_str())
        .map(str::to_string)
        .collect::<Vec<_>>();
    titles.sort_unstable();
    assert_eq!(titles, ["Limited 1", "Limited 2"]);
    limited.destroy_all_calendars().await;
    limited.destroy_all_event_notifications().await;
    admin
        .registry_destroy(ObjectType::Account, [limited.id()])
        .await;

    // Shared calendars and group accounts
    shared_calendar_notifications(test).await;
    group_account_notifications(test).await;

    // Cleanup
    test.wait_for_tasks().await;
    for client in [john, jane, bill] {
        client.destroy_all_calendars().await;
        client.destroy_all_event_notifications().await;
        test.destroy_all_mailboxes(client).await;
    }
    test.assert_is_empty().await;
}

fn test_event_without_organizer() -> Value {
    json!({
      "uid": "9263504FD3AE",
      "title": "Brunch",
      "timeZone": "Europe/London",
      "start": DateTime::from_timestamp(now() as i64 + 60 * 60)
        .to_rfc3339().trim_end_matches("Z").to_string(),
      "duration": "PT1H",
      "freeBusyStatus": "busy",
      "updated": "2009-06-02T17:00:00Z",
      "sequence": 0,
      "@type": "Event",
      "participants": {
        "8584f8f9-5414-55e3-8a1c-ad6fc2f3ffb6": {
          "calendarAddress": "mailto:jdoe@example.com",
          "participationStatus": "accepted",
          "roles": {
            "chair": true,
            "owner": true
          },
          "@type": "Participant"
        },
        "a0171748-fe8d-57d8-879e-56036a5251d1": {
          "calendarAddress": "mailto:jane.smith@example.com",
          "@type": "Participant",
          "participationStatus": "needs-action",
          "kind": "individual"
        }
      }
    })
}

fn test_event() -> Value {
    json!({
      "uid": "9263504FD3AD",
      "title": "Lunch",
      "timeZone": "Europe/London",
      "start": DateTime::from_timestamp(now() as i64 + 60 * 60)
        .to_rfc3339().trim_end_matches("Z").to_string(),
      "duration": "PT1H",
      "freeBusyStatus": "busy",
      "updated": "2009-06-02T17:00:00Z",
      "sequence": 0,
      "@type": "Event",
      "participants": {
        "8584f8f9-5414-55e3-8a1c-ad6fc2f3ffb6": {
          "calendarAddress": "mailto:jdoe@example.com",
          "participationStatus": "accepted",
          "roles": {
            "chair": true,
            "owner": true
          },
          "@type": "Participant"
        },
        "a0171748-fe8d-57d8-879e-56036a5251d1": {
          "calendarAddress": "mailto:jane.smith@example.com",
          "@type": "Participant",
          "participationStatus": "needs-action",
          "kind": "individual"
        },
        "86720268-d67c-58c3-9217-03df7d7ee4d8": {
          "calendarAddress": "mailto:bill@example.com",
          "participationStatus": "needs-action",
          "@type": "Participant",
          "kind": "individual"
        }
      },
      "organizerCalendarAddress": "mailto:jdoe@example.com"
    })
}

async fn notification_list(actor: &Account, account: &Account) -> Vec<(String, String)> {
    actor
        .jmap_get_account(
            account,
            MethodObject::CalendarEventNotification,
            [
                CalendarEventNotificationProperty::Id,
                CalendarEventNotificationProperty::Type,
                CalendarEventNotificationProperty::CalendarEventId,
            ],
            Vec::<&str>::new(),
        )
        .await
        .list()
        .iter()
        .map(|notification| {
            (
                notification.text_field("id").to_string(),
                format!(
                    "{}:{}",
                    notification.text_field("type"),
                    notification.text_field("calendarEventId")
                ),
            )
        })
        .collect()
}

async fn assert_notifications(
    actor: &Account,
    account: &Account,
    expected: &[&str],
) -> Vec<String> {
    let notifications = notification_list(actor, account).await;
    let mut types = notifications
        .iter()
        .map(|(_, summary)| summary.as_str())
        .collect::<Vec<_>>();
    types.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(
        types,
        expected,
        "unexpected notifications for {} in account {}",
        actor.name(),
        account.name()
    );

    notifications
        .into_iter()
        .map(|(id, _)| id)
        .collect::<Vec<_>>()
}

async fn stored_notification_count(test: &TestServer, account: &'static str) -> usize {
    test.resources(account, Collection::CalendarEventNotification)
        .await
        .resources
        .count(false)
}

async fn subscribe(actor: &Account, account: &Account, calendar_id: &str) {
    actor
        .jmap_update_account(
            account,
            MethodObject::Calendar,
            [(calendar_id, json!({ "isSubscribed": true }))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(calendar_id);
}

async fn clear_notifications(actor: &Account, account: &Account) {
    let ids = notification_list(actor, account)
        .await
        .into_iter()
        .map(|(id, _)| id)
        .collect::<Vec<_>>();
    if !ids.is_empty() {
        actor
            .jmap_destroy_account(
                account,
                MethodObject::CalendarEventNotification,
                ids.iter().map(String::as_str),
                Vec::<(&str, &str)>::new(),
            )
            .await;
    }
}

async fn shared_calendar_notifications(test: &TestServer) {
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let bill = test.account("bill@example.com");
    let jane_id = jane.id_string().to_string();
    let bill_id = bill.id_string().to_string();

    // Start from a clean slate
    clear_notifications(john, john).await;

    // John shares a calendar with Jane and Bill
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Team",
                "shareWith": {
                    &jane_id: {"mayReadItems": true, "mayWriteAll": true},
                    &bill_id: {"mayReadItems": true}
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    // Jane subscribes to it, Bill does not
    subscribe(jane, john, &calendar_id).await;

    // A change made by the owner reaches the subscribed sharee only
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "uid": "shared-notify",
                "title": "Team meeting",
                "start": "2026-07-01T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    assert_notifications(jane, john, &[&format!("created:{event_id}")]).await;
    assert_notifications(bill, john, &[]).await;
    assert_notifications(john, john, &[]).await;

    // A private event is never disclosed to sharees
    let private_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "uid": "shared-notify-private",
                "title": "Private meeting",
                "privacy": "private",
                "start": "2026-07-02T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    assert_notifications(jane, john, &[&format!("created:{event_id}")]).await;

    // Subscribing reveals the notifications a sharee is now entitled to
    subscribe(bill, john, &calendar_id).await;
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(&event_id, json!({ "title": "Team meeting (moved)" }))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&event_id);
    let jane_ids = assert_notifications(
        jane,
        john,
        &[
            &format!("created:{event_id}"),
            &format!("updated:{event_id}"),
        ],
    )
    .await;
    assert_notifications(
        bill,
        john,
        &[
            &format!("created:{event_id}"),
            &format!("updated:{event_id}"),
        ],
    )
    .await;

    // A dismissal applies to the dismissing principal only
    let jane_state = jane
        .jmap_get_account(
            john,
            MethodObject::CalendarEventNotification,
            [CalendarEventNotificationProperty::Id],
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();
    jane.jmap_destroy_account(
        john,
        MethodObject::CalendarEventNotification,
        jane_ids.iter().map(String::as_str),
        Vec::<(&str, &str)>::new(),
    )
    .await
    .assert_destroyed(
        &jane_ids
            .iter()
            .map(|id| Id::from_str(id).unwrap())
            .collect::<Vec<_>>(),
    );
    assert_notifications(jane, john, &[]).await;
    let bill_ids = assert_notifications(
        bill,
        john,
        &[
            &format!("created:{event_id}"),
            &format!("updated:{event_id}"),
        ],
    )
    .await;
    assert_eq!(stored_notification_count(test, "jdoe@example.com").await, 2);

    // Dismissed notifications are reported as destroyed by /changes
    let response = jane
        .jmap_method_call(
            "CalendarEventNotification/changes",
            json!({
                "accountId": john.id_string(),
                "sinceState": &jane_state
            }),
        )
        .await;
    let destroyed = response.changes_by_type("destroyed").collect::<Vec<_>>();
    for id in &jane_ids {
        assert!(
            destroyed.contains(&id.as_str()),
            "{id} was not reported as destroyed: {response:?}"
        );
    }

    // The document is removed once every viewer has dismissed it
    bill.jmap_destroy_account(
        john,
        MethodObject::CalendarEventNotification,
        bill_ids.iter().map(String::as_str),
        Vec::<(&str, &str)>::new(),
    )
    .await;
    assert_notifications(bill, john, &[]).await;
    assert_eq!(stored_notification_count(test, "jdoe@example.com").await, 0);

    // Cleanup
    john.jmap_destroy(
        MethodObject::CalendarEvent,
        [&event_id, &private_id],
        Vec::<(&str, &str)>::new(),
    )
    .await;
    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
    assert_eq!(stored_notification_count(test, "jdoe@example.com").await, 0);
}

async fn group_account_notifications(test: &TestServer) {
    let admin = test.account("admin@example.com");
    let robert = test.account("robert@example.com");
    let bill = test.account("bill@example.com");
    let jane = test.account("jane.smith@example.com");
    let sales = test.account("sales@example.com");
    let sales_id = sales.id_string().to_string();
    let jane_id = jane.id_string().to_string();

    // Robert and Bill are members of the group, Jane is only a sharee
    for member in [robert, bill] {
        admin
            .registry_update_object(
                ObjectType::Account,
                member.id(),
                json!({ "memberGroupIds": { &sales_id: true } }),
            )
            .await;
        wait_for_account_access(member, &sales_id).await;
    }
    admin
        .registry_update_object(
            ObjectType::Account,
            jane.id(),
            json!({ "memberGroupIds": {} }),
        )
        .await;

    // A member creates a calendar in the group account and shares it with Jane
    let calendar_id = robert
        .jmap_create_account(
            sales,
            MethodObject::Calendar,
            [json!({
                "name": "Sales Team",
                "shareWith": { &jane_id: {"mayReadItems": true, "mayWriteAll": true} }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    wait_for_sharee_access(jane, sales, &calendar_id).await;
    subscribe(jane, sales, &calendar_id).await;

    // A co-member that never touched the calendar is subscribed by default
    let calendar = bill
        .jmap_get_account(
            sales,
            MethodObject::Calendar,
            ["name", "isSubscribed"],
            [&calendar_id],
        )
        .await
        .list()[0]
        .clone();
    assert_eq!(calendar["isSubscribed"], json!(true), "{calendar}");

    // A member's change reaches the other members and the subscribed sharee
    let event_id = robert
        .jmap_create_account(
            sales,
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "uid": "group-notify",
                "title": "Pipeline review",
                "start": "2026-07-03T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    assert_notifications(bill, sales, &[&format!("created:{event_id}")]).await;
    assert_notifications(jane, sales, &[&format!("created:{event_id}")]).await;
    assert_notifications(robert, sales, &[]).await;

    // Notifications for private events reach members only
    let private_id = robert
        .jmap_create_account(
            sales,
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "uid": "group-notify-private",
                "title": "Board briefing",
                "privacy": "private",
                "start": "2026-07-04T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    assert_notifications(
        bill,
        sales,
        &[
            &format!("created:{event_id}"),
            &format!("created:{private_id}"),
        ],
    )
    .await;
    assert_notifications(jane, sales, &[&format!("created:{event_id}")]).await;

    // A sharee's change reaches every member
    jane.jmap_update_account(
        sales,
        MethodObject::CalendarEvent,
        [(&event_id, json!({ "title": "Pipeline review (moved)" }))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&event_id);
    assert_notifications(robert, sales, &[&format!("updated:{event_id}")]).await;
    assert_notifications(
        bill,
        sales,
        &[
            &format!("created:{event_id}"),
            &format!("created:{private_id}"),
            &format!("updated:{event_id}"),
        ],
    )
    .await;
    assert_notifications(jane, sales, &[&format!("created:{event_id}")]).await;

    // An unsubscribed sharee receives nothing
    jane.jmap_update_account(
        sales,
        MethodObject::Calendar,
        [(&calendar_id, json!({ "isSubscribed": false }))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar_id);
    assert_notifications(jane, sales, &[]).await;

    // A dismissal hides the notification from the dismissing member, and the document
    // outlives it because the remaining members cannot be enumerated
    clear_notifications(robert, sales).await;
    clear_notifications(bill, sales).await;
    assert_notifications(robert, sales, &[]).await;
    assert_notifications(bill, sales, &[]).await;
    assert!(stored_notification_count(test, "sales@example.com").await > 0);

    // Destroying an event tells the other members
    robert
        .jmap_destroy_account(
            sales,
            MethodObject::CalendarEvent,
            [&event_id, &private_id],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_notifications(
        bill,
        sales,
        &[
            &format!("destroyed:{event_id}"),
            &format!("destroyed:{private_id}"),
        ],
    )
    .await;
    clear_notifications(bill, sales).await;
    assert_notifications(bill, sales, &[]).await;

    // Cleanup: destroying the calendars removes the notifications that referenced them
    robert
        .jmap_method_calls(json!([
            [
                "Calendar/get",
                { "accountId": &sales_id, "ids": (), "properties": ["id"] },
                "R1"
            ],
            [
                "Calendar/set",
                {
                    "accountId": &sales_id,
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
    assert_eq!(
        stored_notification_count(test, "sales@example.com").await,
        0
    );
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

async fn wait_for_sharee_access(account: &Account, owner: &Account, calendar_id: &str) {
    for _ in 0..50 {
        let response = account
            .jmap_get_account(
                owner,
                MethodObject::Calendar,
                ["isSubscribed"],
                [calendar_id],
            )
            .await;
        if response
            .list()
            .first()
            .is_some_and(|calendar| calendar["isSubscribed"] == json!(false))
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!(
        "Timed out waiting for {} to become a sharee only",
        account.name()
    );
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
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("Timed out waiting for access to account {account_id}");
}
