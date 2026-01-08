/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{IntoJmapSet, JMAPTest, JmapUtils, wait_for_index};
use calcard::jscalendar::JSCalendarProperty;
use jmap_proto::{
    object::calendar_event_notification::CalendarEventNotificationProperty,
    request::method::MethodObject,
};
use mail_parser::DateTime;
use serde_json::{Value, json};
use store::write::now;
use types::id::Id;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Calendar Event Notification tests...");
    let john = params.account("jdoe@example.com");
    let jane = params.account("jane.smith@example.com");
    let bill = params.account("bill@example.com");

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
    wait_for_index(&params.server).await;

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
            "principalId": &john_id
          },
          "type": "created",
          "calendarEventId": event_id,
          "isDraft": false,
          "event": john_event
            .clone()
            .with_property("sequence", 1)
            .with_property(
                "updated",
                notification
                    .text_field("event/updated")
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
                "principalId": &jane_id,
            })
        } else {
            json!({
                "name": "Bill Foobar",
                "email": "bill@example.com",
                "principalId": &bill_id,
            })
        };

        response.list()[0].assert_is_equal(json!({
            "id": &notification_id,
            "changedBy": changed_by,
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
                "chair": true
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
                "chair": true
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
            "principalId": &john_id
        },
        "type": "updated",
        "calendarEventId": &bill_event_id,
        "isDraft": false
    }));

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

    // Cleanup
    for client in [john, jane, bill] {
        client.destroy_all_calendars().await;
        client.destroy_all_event_notifications().await;
        params.destroy_all_mailboxes(client).await;
    }
    params.assert_is_empty().await;
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
            "chair": true
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
