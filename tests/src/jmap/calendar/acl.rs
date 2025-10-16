/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{JMAPTest, JmapUtils};
use calcard::jscalendar::JSCalendarProperty;
use jmap_proto::{
    object::{calendar::CalendarProperty, share_notification::ShareNotificationProperty},
    request::method::MethodObject,
};
use serde_json::json;
use types::id::Id;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Calendar ACL tests...");
    let john = params.account("jdoe@example.com");
    let jane = params.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();

    // Create test calendars
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Test #1",
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let john_calendar_id = response.created(0).id().to_string();
    let john_event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "@type": "Event",
                "uid": "a8df6573-0474-496d-8496-033ad45d7fea",
                "updated": "2020-01-02T18:23:04Z",
                "title": "John's Simple Event",
                "start": "2020-01-15T13:00:00",
                "timeZone": "America/New_York",
                "duration": "PT1H",
                "calendarIds": {
                    &john_calendar_id: true
                },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let response = jane
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Test #1",
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let jane_calendar_id = response.created(0).id().to_string();
    let jane_event_id = jane
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "uid": "a8df6575-0474-496d-8496-033ad45d7fea",
                "updated": "2020-01-02T18:23:04Z",
                "title": "Jane's Simple Event",
                "start": "2020-01-15T13:00:00",
                "timeZone": "America/New_York",
                "duration": "PT1H",
                "calendarIds": {
                    &jane_calendar_id: true
                },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    // Verify myRights
    john.jmap_get(
        MethodObject::Calendar,
        [
            CalendarProperty::Id,
            CalendarProperty::Name,
            CalendarProperty::MyRights,
            CalendarProperty::ShareWith,
        ],
        [john_calendar_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_calendar_id,
        "name": "Test #1",
        "myRights": {
            "mayReadItems": true,
            "mayWriteAll": true,
            "mayDelete": true,
            "mayShare": true,
            "mayWriteOwn": true,
            "mayReadFreeBusy": true,
            "mayUpdatePrivate": true,
            "mayRSVP": true
        },
        "shareWith": {}
        }));

    // Obtain share notifications
    let mut jane_share_change_id = jane
        .jmap_get(
            MethodObject::ShareNotification,
            Vec::<&str>::new(),
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();

    // Make sure Jane has no access
    assert_eq!(
        jane.jmap_get_account(
            john,
            MethodObject::Calendar,
            Vec::<&str>::new(),
            [john_calendar_id.as_str()],
        )
        .await
        .method_response()
        .typ(),
        "forbidden"
    );

    // Share calendar with Jane
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &john_calendar_id,
            json!({
                "shareWith": {
                   &jane_id : {
                     "mayReadItems": true,
                   }
                }
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_calendar_id);
    john.jmap_get(
        MethodObject::Calendar,
        [
            CalendarProperty::Id,
            CalendarProperty::Name,
            CalendarProperty::ShareWith,
        ],
        [john_calendar_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_calendar_id,
        "name": "Test #1",
        "shareWith": {
            &jane_id : {
                "mayReadItems": true,
                "mayWriteAll": false,
                "mayDelete": false,
                "mayShare": false,
                "mayWriteOwn": false,
                "mayReadFreeBusy": false,
                "mayUpdatePrivate": false,
                "mayRSVP": false
            }
        }
        }));

    // Verify Jane can access the event
    jane.jmap_get_account(
        john,
        MethodObject::Calendar,
        [
            CalendarProperty::Id,
            CalendarProperty::Name,
            CalendarProperty::MyRights,
        ],
        [john_calendar_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_calendar_id,
        "name": "Test #1",
        "myRights": {
            "mayReadItems": true,
            "mayWriteAll": false,
            "mayDelete": false,
            "mayShare": false,
            "mayWriteOwn": false,
            "mayReadFreeBusy": false,
            "mayUpdatePrivate": false,
            "mayRSVP": false
        }
        }));
    jane.jmap_get_account(
        john,
        MethodObject::CalendarEvent,
        [JSCalendarProperty::<Id>::Id, JSCalendarProperty::Title],
        [john_event_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_event_id,
        "title": "John's Simple Event",
        }));

    // Verify Jane received a share notification
    let response = jane
        .jmap_changes(MethodObject::ShareNotification, &jane_share_change_id)
        .await;
    jane_share_change_id = response.new_state().to_string();
    let changes = response.changes().collect::<Vec<_>>();
    assert_eq!(changes.len(), 1);
    let share_id = changes[0].as_created();
    jane.jmap_get(
        MethodObject::ShareNotification,
        [
            ShareNotificationProperty::Id,
            ShareNotificationProperty::ChangedBy,
            ShareNotificationProperty::ObjectType,
            ShareNotificationProperty::ObjectAccountId,
            ShareNotificationProperty::ObjectId,
            ShareNotificationProperty::OldRights,
            ShareNotificationProperty::NewRights,
            ShareNotificationProperty::Name,
        ],
        [share_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
          "id": &share_id,
          "changedBy": {
            "principalId": &john_id,
            "name": "John Doe",
            "email": "jdoe@example.com"
          },
          "objectType": "Calendar",
          "objectAccountId": &john_id,
          "objectId": &john_calendar_id,
          "oldRights": {
            "mayReadItems": false,
            "mayWriteAll": false,
            "mayDelete": false,
            "mayShare": false,
            "mayWriteOwn": false,
            "mayReadFreeBusy": false,
            "mayUpdatePrivate": false,
            "mayRSVP": false
          },
          "newRights": {
            "mayReadItems": true,
            "mayWriteAll": false,
            "mayDelete": false,
            "mayShare": false,
            "mayWriteOwn": false,
            "mayReadFreeBusy": false,
            "mayUpdatePrivate": false,
            "mayRSVP": false
          },
          "name": null
        }));

    // Updating and deleting should fail
    assert_eq!(
        jane.jmap_update_account(
            john,
            MethodObject::Calendar,
            [(&john_calendar_id, json!({}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&john_calendar_id)
        .description(),
        "You are not allowed to modify this calendar."
    );
    assert_eq!(
        jane.jmap_destroy_account(
            john,
            MethodObject::Calendar,
            [&john_calendar_id],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_destroyed(&john_calendar_id)
        .description(),
        "You are not allowed to delete this calendar."
    );
    assert!(
        jane.jmap_update_account(
            john,
            MethodObject::CalendarEvent,
            [(&john_event_id, json!({}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&john_event_id)
        .description()
        .contains("You are not allowed to modify calendar"),
    );
    assert!(
        jane.jmap_destroy_account(
            john,
            MethodObject::CalendarEvent,
            [&john_event_id],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_destroyed(&john_event_id)
        .description()
        .contains("You are not allowed to remove events from calendar"),
    );

    // Grant Jane write access
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &john_calendar_id,
            json!({
                format!("shareWith/{jane_id}/mayWriteAll"): true,
                format!("shareWith/{jane_id}/mayDelete"): true,
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_calendar_id);
    jane.jmap_get_account(
        john,
        MethodObject::Calendar,
        [
            CalendarProperty::Id,
            CalendarProperty::Name,
            CalendarProperty::MyRights,
        ],
        [john_calendar_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_calendar_id,
        "name": "Test #1",
        "myRights": {
            "mayReadItems": true,
            "mayWriteAll": true,
            "mayDelete": true,
            "mayShare": false,
            "mayWriteOwn": false,
            "mayReadFreeBusy": false,
            "mayUpdatePrivate": false,
            "mayRSVP": false
        }
        }));

    // Verify Jane received a share notification with the updated rights
    let response = jane
        .jmap_changes(MethodObject::ShareNotification, &jane_share_change_id)
        .await;
    jane_share_change_id = response.new_state().to_string();
    let changes = response.changes().collect::<Vec<_>>();
    assert_eq!(changes.len(), 1);
    let share_id = changes[0].as_created();
    jane.jmap_get(
        MethodObject::ShareNotification,
        [
            ShareNotificationProperty::Id,
            ShareNotificationProperty::ChangedBy,
            ShareNotificationProperty::ObjectType,
            ShareNotificationProperty::ObjectAccountId,
            ShareNotificationProperty::ObjectId,
            ShareNotificationProperty::OldRights,
            ShareNotificationProperty::NewRights,
            ShareNotificationProperty::Name,
        ],
        [share_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
          "id": &share_id,
          "changedBy": {
            "principalId": &john_id,
            "name": "John Doe",
            "email": "jdoe@example.com"
          },
          "objectType": "Calendar",
          "objectAccountId": &john_id,
          "objectId": &john_calendar_id,
          "oldRights": {
            "mayReadItems": true,
            "mayWriteAll": false,
            "mayDelete": false,
            "mayShare": false,
            "mayWriteOwn": false,
            "mayReadFreeBusy": false,
            "mayUpdatePrivate": false,
            "mayRSVP": false
          },
          "newRights": {
            "mayReadItems": true,
            "mayWriteAll": true,
            "mayDelete": true,
            "mayShare": false,
            "mayWriteOwn": false,
            "mayReadFreeBusy": false,
            "mayUpdatePrivate": false,
            "mayRSVP": false
          },
          "name": null
        }));

    // Creating a root folder should fail
    assert_eq!(
        jane.jmap_create_account(
            john,
            MethodObject::Calendar,
            [json!({
                "name": "A new shared calendar",
            })],
            Vec::<(&str, &str)>::new()
        )
        .await
        .not_created(0)
        .description(),
        "Cannot create calendars in a shared account."
    );

    // Copy Jane's event into John's calendar
    let john_copied_event_id = jane
        .jmap_copy(
            jane,
            john,
            MethodObject::CalendarEvent,
            [(
                &jane_event_id,
                json!({
                    "calendarIds": {
                        &john_calendar_id: true
                    }
                }),
            )],
            false,
        )
        .await
        .copied(&jane_event_id)
        .id()
        .to_string();
    jane.jmap_get_account(
        john,
        MethodObject::CalendarEvent,
        [
            JSCalendarProperty::<Id>::Id,
            JSCalendarProperty::CalendarIds,
            JSCalendarProperty::Title,
        ],
        [john_copied_event_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_copied_event_id,
        "title": "Jane's Simple Event",
        "calendarIds": {
            &john_calendar_id: true
        }
        }));

    // Destroy the copied event
    assert_eq!(
        jane.jmap_destroy_account(
            john,
            MethodObject::CalendarEvent,
            [john_copied_event_id.as_str()],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .collect::<Vec<_>>(),
        [&john_copied_event_id]
    );

    // Update John's event
    jane.jmap_update_account(
        john,
        MethodObject::CalendarEvent,
        [(
            &john_event_id,
            json!({
                "title": "John's Updated Event",
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_event_id);
    jane.jmap_get_account(
        john,
        MethodObject::CalendarEvent,
        [JSCalendarProperty::<Id>::Id, JSCalendarProperty::Title],
        [john_event_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_event_id,
        "title": "John's Updated Event",
        }));

    // Update John's calendar name
    jane.jmap_update_account(
        john,
        MethodObject::Calendar,
        [(
            &john_calendar_id,
            json!({
                "name": "Jane's version of John's Calendar",
                "description": "This is John's calendar, but Jane can edit it now"
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_calendar_id);
    jane.jmap_get_account(
        john,
        MethodObject::Calendar,
        [
            CalendarProperty::Id,
            CalendarProperty::Name,
            CalendarProperty::Description,
        ],
        [john_calendar_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_calendar_id,
        "name": "Jane's version of John's Calendar",
        "description": "This is John's calendar, but Jane can edit it now"
        }));

    // John should still see the old name
    john.jmap_get(
        MethodObject::Calendar,
        [
            CalendarProperty::Id,
            CalendarProperty::Name,
            CalendarProperty::Description,
        ],
        [john_calendar_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_calendar_id,
        "name": "Test #1",
        "description": null
        }));

    // Revoke Jane's access
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &john_calendar_id,
            json!({
                format!("shareWith/{jane_id}"): ()
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_calendar_id);
    john.jmap_get(
        MethodObject::Calendar,
        [
            CalendarProperty::Id,
            CalendarProperty::Name,
            CalendarProperty::ShareWith,
        ],
        [john_calendar_id.as_str()],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
        "id": john_calendar_id,
        "name": "Test #1",
        "shareWith": {}
        }));

    // Verify Jane can no longer access the calendar or its events
    assert_eq!(
        jane.jmap_get_account(
            john,
            MethodObject::Calendar,
            Vec::<&str>::new(),
            [john_calendar_id.as_str()],
        )
        .await
        .method_response()
        .typ(),
        "forbidden"
    );

    // Verify Jane received a share notification with the updated rights
    let response = jane
        .jmap_changes(MethodObject::ShareNotification, &jane_share_change_id)
        .await;
    let changes = response.changes().collect::<Vec<_>>();
    assert_eq!(changes.len(), 1);
    let share_id = changes[0].as_created();
    jane.jmap_get(
        MethodObject::ShareNotification,
        [
            ShareNotificationProperty::Id,
            ShareNotificationProperty::ChangedBy,
            ShareNotificationProperty::ObjectType,
            ShareNotificationProperty::ObjectAccountId,
            ShareNotificationProperty::ObjectId,
            ShareNotificationProperty::OldRights,
            ShareNotificationProperty::NewRights,
            ShareNotificationProperty::Name,
        ],
        [share_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
          "id": &share_id,
          "changedBy": {
            "principalId": &john_id,
            "name": "John Doe",
            "email": "jdoe@example.com"
          },
          "objectType": "Calendar",
          "objectAccountId": &john_id,
          "objectId": &john_calendar_id,
          "oldRights": {
            "mayReadItems": true,
            "mayWriteAll": true,
            "mayDelete": true,
            "mayShare": false,
            "mayWriteOwn": false,
            "mayReadFreeBusy": false,
            "mayUpdatePrivate": false,
            "mayRSVP": false
          },
          "newRights": {
            "mayReadItems": false,
            "mayWriteAll": false,
            "mayDelete": false,
            "mayShare": false,
            "mayWriteOwn": false,
            "mayReadFreeBusy": false,
            "mayUpdatePrivate": false,
            "mayRSVP": false
          },
          "name": null
        }));

    // Grant Jane delete access once again
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &john_calendar_id,
            json!({
                format!("shareWith/{jane_id}/mayReadItems"): true,
                format!("shareWith/{jane_id}/mayDelete"): true,
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&john_calendar_id);

    // Verify Jane can delete the calendar
    assert_eq!(
        jane.jmap_destroy_account(
            john,
            MethodObject::Calendar,
            [john_calendar_id.as_str()],
            [("onDestroyRemoveEvents", true)],
        )
        .await
        .destroyed()
        .collect::<Vec<_>>(),
        [john_calendar_id.as_str()]
    );

    // Destroy all mailboxes
    john.destroy_all_calendars().await;
    jane.destroy_all_calendars().await;
    params.assert_is_empty().await;
}
