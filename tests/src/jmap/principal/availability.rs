/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{IntoJmapSet, JMAPTest, JmapUtils, calendar::event::*};
use calcard::jscalendar::JSCalendarProperty;
use jmap_proto::request::method::MethodObject;
use serde_json::json;
use types::id::Id;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Principal Availability tests...");
    let john = params.account("jdoe@example.com");
    let jane = params.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();

    // Create test calendars
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Test Calendar",
                "includeInAvailability": "all"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let calendar1_id = response.created(0).id().to_string();

    // Create test events
    let event_1 = test_jscalendar_1().with_property(
        JSCalendarProperty::<Id>::CalendarIds,
        [calendar1_id.as_str()].into_jmap_set(),
    );
    let event_2 = test_jscalendar_2().with_property(
        JSCalendarProperty::<Id>::CalendarIds,
        [calendar1_id.as_str()].into_jmap_set(),
    );
    let event_3 = test_jscalendar_3()
        .with_property(
            JSCalendarProperty::<Id>::CalendarIds,
            [calendar1_id.as_str()].into_jmap_set(),
        )
        .with_property(
            JSCalendarProperty::<Id>::Participants,
            json!({
              "3f5bc8c0-c722-5345-b7d9-5a899db08a30": {
                "calendarAddress": "mailto:jdoe@example.com",
                "@type": "Participant",
                "roles": {
                  "attendee": true,
                  "chair": true
                },
                "participationStatus": "accepted"
              }
            }),
        );
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [event_1, event_2, event_3],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let _event_1_id = response.created(0).id().to_string();
    let _event_2_id = response.created(1).id().to_string();
    let event_3_id = response.created(2).id().to_string();

    // Jane should not have access to John's availability
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([]));

    // Grant Jane free/busy access
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &calendar1_id,
            json!({
                "shareWith": {
                   &jane_id : {
                     "mayReadFreeBusy": true,
                   }
                }
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar1_id);

    // Jane should see John's availability now
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([
      {
        "utcStart": "2006-01-02T15:00:00Z",
        "utcEnd": "2006-01-02T16:00:00Z",
        "busyStatus": "confirmed",
        "event": null
      },
      {
        "utcStart": "2006-01-02T17:00:00Z",
        "utcEnd": "2006-01-02T18:00:00Z",
        "busyStatus": "confirmed",
        "event": null
      },
      {
        "utcStart": "2006-01-03T17:00:00Z",
        "utcEnd": "2006-01-03T18:00:00Z",
        "busyStatus": "confirmed",
        "event": null
      },
      {
        "utcStart": "2006-01-04T15:00:00Z",
        "utcEnd": "2006-01-04T16:00:00Z",
        "busyStatus": "confirmed",
        "event": null
      },
      {
        "utcStart": "2006-01-04T19:00:00Z",
        "utcEnd": "2006-01-04T20:00:00Z",
        "busyStatus": "confirmed",
        "event": null
      },
      {
        "utcStart": "2006-01-05T17:00:00Z",
        "utcEnd": "2006-01-05T18:00:00Z",
        "busyStatus": "confirmed",
        "event": null
      },
      {
        "utcStart": "2006-01-06T19:00:00Z",
        "utcEnd": "2006-01-06T20:00:00Z",
        "busyStatus": "confirmed",
        "event": null
      }
    ]));

    // Update availability to none
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &calendar1_id,
            json!({
                "includeInAvailability": "none"
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar1_id);

    // Jane should not see any events now
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([]));

    // Update availability to attending
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &calendar1_id,
            json!({
                "includeInAvailability": "attending"
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar1_id);

    // Jane should only see events where John is attending
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([
      {
        "utcStart": "2006-01-04T15:00:00Z",
        "utcEnd": "2006-01-04T16:00:00Z",
        "busyStatus": "confirmed",
        "event": null
      }
    ]));

    // Update attending event to not attending
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &event_3_id,
            json!({
                "participants/3f5bc8c0-c722-5345-b7d9-5a899db08a30/participationStatus": "declined"
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&event_3_id);

    // Jane should not see any events now
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([]));

    // Cleanup
    john.destroy_all_calendars().await;
    params.assert_is_empty().await;
}
