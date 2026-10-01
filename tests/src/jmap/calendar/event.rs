/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    jmap::{ChangeType, IntoJmapSet, JmapUtils},
    server::TestServer,
    webdav::DummyWebDavClient,
};
use ahash::AHashSet;
use calcard::jscalendar::JSCalendarProperty;
use common::{NO_ID, PROD_ID};
use dav_proto::Depth;
use groupware::{DavResourceName, cache::GroupwareCache};
use hyper::StatusCode;
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};
use std::str::FromStr;
use types::{collection::SyncCollection, id::Id};

pub async fn test(test: &TestServer) {
    println!("Running Calendar Event tests...");
    let account = test.account("jdoe@example.com");

    // Create test calendars
    let response = account
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({
                    "name": "Holy Calendar, Batman!",
                    "timeZone": "Europe/Vatican",
                }),
                json!({
                    "name": "Calendar with Alerts",
                    "defaultAlertsWithTime": {
                        "abc": {
                            "action": "display",
                            "trigger": {
                                "relativeTo": "start",
                                "offset": "PT15M"
                            }
                        }
                    },
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let calendar1_id = response.created(0).id().to_string();
    let calendar2_id = response.created(1).id().to_string();

    // Obtain state
    let change_id = account
        .jmap_get(
            MethodObject::CalendarEvent,
            Vec::<&str>::new(),
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();

    // Create test events
    let event_1 = test_jscalendar_1().with_property(
        JSCalendarProperty::<Id>::CalendarIds,
        [calendar1_id.as_str()].into_jmap_set(),
    );
    let event_2 = test_jscalendar_2().with_property(
        JSCalendarProperty::<Id>::CalendarIds,
        [calendar2_id.as_str()].into_jmap_set(),
    );
    let event_3 = test_jscalendar_3().with_property(
        JSCalendarProperty::<Id>::CalendarIds,
        [calendar1_id.as_str(), calendar2_id.as_str()].into_jmap_set(),
    );
    let event_4 = test_jscalendar_4().with_property(
        JSCalendarProperty::<Id>::CalendarIds,
        [calendar1_id.as_str()].into_jmap_set(),
    );
    let response = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                event_1
                    .clone()
                    .with_property(JSCalendarProperty::<Id>::IsDraft, true)
                    .with_property(JSCalendarProperty::<Id>::MayInviteSelf, true)
                    .with_property(JSCalendarProperty::<Id>::MayInviteOthers, true)
                    .with_property(JSCalendarProperty::<Id>::HideAttendees, true),
                event_2
                    .clone()
                    .with_property(JSCalendarProperty::<Id>::UseDefaultAlerts, true),
                event_3
                    .clone()
                    .with_property(JSCalendarProperty::<Id>::UseDefaultAlerts, false),
                event_4,
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let event_1_id = response.created(0).id().to_string();
    let event_2_id = response.created(1).id().to_string();
    let event_3_id = response.created(2).id().to_string();
    let event_4_id = response.created(3).id().to_string();

    // Destroy tmp event
    test.wait_for_tasks().await;
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::CalendarEvent,
                [event_4_id.as_str()],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .destroyed()
            .next(),
        Some(event_4_id.as_str())
    );

    // Validate changes
    assert_eq!(
        account
            .jmap_changes(MethodObject::CalendarEvent, &change_id)
            .await
            .changes()
            .collect::<AHashSet<_>>(),
        [
            ChangeType::Created(&event_1_id),
            ChangeType::Created(&event_2_id),
            ChangeType::Created(&event_3_id)
        ]
        .into_iter()
        .collect::<AHashSet<_>>(),
    );

    // Verify event contents
    let response = account
        .jmap_get(
            MethodObject::CalendarEvent,
            Vec::<&str>::new(),
            [&event_1_id, &event_2_id, &event_3_id],
        )
        .await;

    assert_eq_ignoring_timestamps(
        &response.list()[0],
        event_1
            .with_property(JSCalendarProperty::<Id>::Id, event_1_id.as_str())
            .with_property(JSCalendarProperty::<Id>::IsDraft, true)
            .with_property(JSCalendarProperty::<Id>::IsOrigin, true)
            .with_property(JSCalendarProperty::<Id>::UseDefaultAlerts, false)
            .with_property(JSCalendarProperty::<Id>::MayInviteSelf, true)
            .with_property(JSCalendarProperty::<Id>::MayInviteOthers, true)
            .with_property(JSCalendarProperty::<Id>::HideAttendees, true),
    );
    assert_eq_ignoring_timestamps(
        &response.list()[1],
        event_2
            .with_property(JSCalendarProperty::<Id>::Id, event_2_id.as_str())
            .with_property(JSCalendarProperty::<Id>::IsDraft, false)
            .with_property(JSCalendarProperty::<Id>::IsOrigin, true)
            .with_property(JSCalendarProperty::<Id>::UseDefaultAlerts, true)
            .with_property(JSCalendarProperty::<Id>::MayInviteSelf, false)
            .with_property(JSCalendarProperty::<Id>::MayInviteOthers, false)
            .with_property(JSCalendarProperty::<Id>::HideAttendees, false)
            .with_property(
                JSCalendarProperty::<Id>::Alerts,
                json!({
                  "abc": {
                    "action": "display",
                    "trigger": {
                      "@type": "OffsetTrigger",
                      "offset": "PT15M"
                    },
                    "@type": "Alert"
                  }
                }),
            )
            .with_property(
                JSCalendarProperty::<Id>::RecurrenceOverrides,
                json!({
                  "2006-01-04T12:00:00": {
                    "title": "Event #2 bis",
                    "start": "2006-01-04T14:00:00"
                  },
                  "2006-01-06T12:00:00": {
                    "title": "Event #2 bis bis",
                    "start": "2006-01-06T14:00:00"
                  }
                }),
            ),
    );
    assert_eq_ignoring_timestamps(
        &response.list()[2],
        event_3
            .with_property(JSCalendarProperty::<Id>::Id, event_3_id.as_str())
            .with_property(JSCalendarProperty::<Id>::IsDraft, false)
            .with_property(JSCalendarProperty::<Id>::IsOrigin, false)
            .with_property(JSCalendarProperty::<Id>::UseDefaultAlerts, false)
            .with_property(JSCalendarProperty::<Id>::MayInviteSelf, false)
            .with_property(JSCalendarProperty::<Id>::MayInviteOthers, false)
            .with_property(JSCalendarProperty::<Id>::HideAttendees, false),
    );
    assert_eq!(
        response.list()[2]["updated"],
        json!("2006-02-06T00:12:20Z"),
        "events that are not origin keep the updated time"
    );
    assert_eq!(response.list()[2]["sequence"], json!(1));

    // Verify JMAP for Calendars properties
    let response = account
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::BaseEventId,
                JSCalendarProperty::MayInviteSelf,
                JSCalendarProperty::MayInviteOthers,
                JSCalendarProperty::HideAttendees,
                JSCalendarProperty::UseDefaultAlerts,
                JSCalendarProperty::UtcStart,
                JSCalendarProperty::UtcEnd,
            ],
            [&event_1_id, &event_2_id, &event_3_id],
        )
        .await;
    response.list()[0].assert_is_equal(json!({
      "id": &event_1_id,
      "baseEventId": null,
      "mayInviteSelf": true,
      "mayInviteOthers": true,
      "hideAttendees": true,
      "useDefaultAlerts": false,
      "utcStart": "2006-01-02T15:00:00Z",
      "utcEnd": "2006-01-02T16:00:00Z"
    }));
    response.list()[1].assert_is_equal(json!({
      "id": &event_2_id,
      "baseEventId": null,
      "mayInviteSelf": false,
      "mayInviteOthers": false,
      "hideAttendees": false,
      "useDefaultAlerts": true,
      "utcStart": "2006-01-02T17:00:00Z",
      "utcEnd": "2006-01-02T18:00:00Z"
    }));
    response.list()[2].assert_is_equal(json!({
        "id": &event_3_id,
        "baseEventId": null,
        "mayInviteSelf": false,
        "mayInviteOthers": false,
        "hideAttendees": false,
        "useDefaultAlerts": false,
        "utcStart": "2006-01-04T15:00:00Z",
        "utcEnd": "2006-01-04T16:00:00Z"
    }));

    // Test /get parameters
    let response = account
        .jmap_method_calls(json!([[
            "CalendarEvent/get",
            {
                "accountId": account.id_string(),
                "properties": ["id", "title", "recurrenceOverrides", "participants"],
                "ids": [&event_2_id, &event_3_id],
                "recurrenceOverridesBefore": "2006-01-07T00:00:00Z",
                "recurrenceOverridesAfter": "2006-01-06T00:00:00Z",
                "reduceParticipants": true,
            },
            "0"
        ]]))
        .await;
    assert_eq_ignoring_timestamps(
        response.list_array(),
        json!([
          {
            "title": "Event #2",
            "recurrenceOverrides": {
              "2006-01-06T12:00:00": {
                "start": "2006-01-06T14:00:00",
                "title": "Event #2 bis bis"
              }
            },
            "id": "c"
          },
          {
            "title": "Event #3",
            "participants": {
              "3f5bc8c0-c722-5345-b7d9-5a899db08a30": {
                "calendarAddress": "mailto:cyrus@example.com",
                "@type": "Participant",
                "roles": {
                  "chair": true,
                  "owner": true
                },
                "participationStatus": "accepted"
              }
            },
            "id": "d"
          }
        ]),
    );

    let response = account
        .jmap_method_calls(json!([[
            "CalendarEvent/get",
            {
                "accountId": account.id_string(),
                "properties": [],
                "ids": [&event_2_id, &event_3_id],
            },
            "0"
        ]]))
        .await;
    response.list()[0].assert_is_equal(json!({ "id": &event_2_id }));
    response.list()[1].assert_is_equal(json!({ "id": &event_3_id }));

    // Creating an event without calendar should fail
    assert_eq!(
        account
            .jmap_create(
                MethodObject::CalendarEvent,
                [json!({
                    "title": "Event #5",
                    "start": "2006-01-22T10:00:00",
                    "duration": "PT1H",
                    "timeZone": "US/Eastern",
                    "calendarIds": {},
                }),],
                Vec::<(&str, &str)>::new()
            )
            .await
            .not_created(0)
            .description(),
        "Event has to belong to at least one calendar."
    );

    // Creating an event with a duplicate UID should fail
    assert_eq!(
        account
            .jmap_create(
                MethodObject::CalendarEvent,
                [json!({
                    "title": "Event #5",
                    "start": "2006-01-22T10:00:00",
                    "duration": "PT1H",
                    "timeZone": "US/Eastern",
                    "uid": "00959BC664CA650E933C892C@example.com",
                    "calendarIds": {
                        &calendar1_id: true
                    },
                })],
                Vec::<(&str, &str)>::new()
            )
            .await
            .not_created(0)
            .description(),
        "An event with UID 00959BC664CA650E933C892C@example.com already exists."
    );

    // UIDs longer than the cached prefix are compared in full
    let long_uid = format!("{}@example.com", "a".repeat(300));
    let other_long_uid = format!("{}b@example.com", "a".repeat(300));
    let long_uid_event = |uid: &str, privacy: &str| {
        json!({
            "title": "Long UID",
            "start": "2006-01-23T10:00:00",
            "duration": "PT1H",
            "timeZone": "US/Eastern",
            "uid": uid,
            "privacy": privacy,
            "calendarIds": {
                &calendar1_id: true
            },
        })
    };
    let response = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                long_uid_event(&long_uid, "public"),
                long_uid_event(&other_long_uid, "private"),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let mut long_uid_ids = vec![
        response.created(0).id().to_string(),
        response.created(1).id().to_string(),
    ];
    assert_eq!(
        account
            .jmap_create(
                MethodObject::CalendarEvent,
                [long_uid_event(&long_uid, "public")],
                Vec::<(&str, &str)>::new()
            )
            .await
            .not_created(0)
            .description(),
        format!("An event with UID {long_uid} already exists.")
    );
    for (uid, privacy) in [
        (format!("{}c@example.com", "a".repeat(300)), "private"),
        (format!("{}d@example.com", "a".repeat(300)), "public"),
    ] {
        long_uid_ids.push(
            account
                .jmap_create(
                    MethodObject::CalendarEvent,
                    [long_uid_event(&uid, privacy)],
                    Vec::<(&str, &str)>::new(),
                )
                .await
                .created(0)
                .id()
                .to_string(),
        );
    }
    test.wait_for_tasks().await;
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::CalendarEvent,
                long_uid_ids.iter().map(String::as_str),
                Vec::<(&str, &str)>::new(),
            )
            .await
            .destroyed()
            .collect::<AHashSet<_>>(),
        long_uid_ids
            .iter()
            .map(String::as_str)
            .collect::<AHashSet<_>>()
    );

    // Patching tests
    let response = account
        .jmap_update(
            MethodObject::CalendarEvent,
            [
                (
                    &event_1_id,
                    json!({
                        "isDraft": false,
                        "mayInviteSelf": false,
                        "mayInviteOthers": false,
                        "hideAttendees": false,
                        "useDefaultAlerts": true,
                        "description": null,
                        "title": "Event one",
                        "keywords": {"work": true},
                        format!("calendarIds/{calendar2_id}"): true
                    }),
                ),
                (
                    &event_2_id,
                    json!({
                        "calendarIds": {
                            &calendar1_id: true,
                            &calendar2_id: true
                        },
                        "title": "Event two",
                        "useDefaultAlerts": false,
                        "description": "Updated description",
                        "recurrenceOverrides/2006-01-04T12:00:00/title":
                        "Event two overridden",
                        "recurrenceOverrides/2006-01-06T12:00:00/title":
                        "Event two overridden twice",

                    }),
                ),
                (
                    &event_3_id,
                    json!({
                        format!("calendarIds/{calendar2_id}"): false,
                        "title": "Event three",
                        "utcStart": "2006-01-04T14:00:00Z",
                        "utcEnd": "2006-01-04T16:00:00Z",
                        "participants/3f5bc8c0-c722-5345-b7d9-5a899db08a30/roles/chair": false,
                        "participants/3f5bc8c0-c722-5345-b7d9-5a899db08a30/roles/owner": true,
                        "participants/ec5e7db5-22a3-5ed5-89bf-c8894ab86805" : null,
                        "participants/7f2bd210-6c66-5b64-8562-0176b74462b1": {
                            "calendarAddress": "mailto:rupert@example.com",
                            "@type": "Participant",
                            "participationStatus": "needs-action"
                        }
                    }),
                ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;

    response.updated(&event_1_id);
    response.updated(&event_2_id);
    response.updated(&event_3_id);

    // Verify patches
    let response = account
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::CalendarIds,
                JSCalendarProperty::Title,
                JSCalendarProperty::Start,
                JSCalendarProperty::Description,
                JSCalendarProperty::Keywords,
                JSCalendarProperty::RecurrenceOverrides,
                JSCalendarProperty::Participants,
                JSCalendarProperty::MayInviteOthers,
                JSCalendarProperty::MayInviteSelf,
                JSCalendarProperty::HideAttendees,
                JSCalendarProperty::UseDefaultAlerts,
                JSCalendarProperty::IsDraft,
            ],
            [&event_1_id, &event_2_id, &event_3_id],
        )
        .await;

    response.list()[0].assert_is_equal(json!({
      "id": &event_1_id,
      "calendarIds":  {
        &calendar1_id: true,
        &calendar2_id: true
      },
      "isDraft": false,
      "mayInviteSelf": false,
      "mayInviteOthers": false,
      "hideAttendees": false,
      "useDefaultAlerts": true,
      "title": "Event one",
      "start": "2006-01-02T10:00:00",
      "keywords": {
        "work": true
      }
    }));

    assert_eq_ignoring_timestamps(
        &response.list()[1],
        json!({
            "id": &event_2_id,
            "calendarIds": {
              &calendar1_id: true,
              &calendar2_id: true
            },
            "title": "Event two",
            "start": "2006-01-02T12:00:00",
            "description": "Updated description",
            "recurrenceOverrides": {
                "2006-01-04T12:00:00": {
                    "title": "Event two overridden",
                    "start": "2006-01-04T14:00:00"
                },
                "2006-01-06T12:00:00": {
                    "title": "Event two overridden twice",
                    "start": "2006-01-06T14:00:00"
                }
            },
            "title": "Event two",
            "start": "2006-01-02T12:00:00",
            "mayInviteOthers": false,
            "mayInviteSelf": false,
            "hideAttendees": false,
            "useDefaultAlerts": false,
            "isDraft": false
        }),
    );

    response.list()[2].assert_is_equal(json!({
        "id": event_3_id,
        "calendarIds": {
            &calendar1_id: true,
        },
        "title": "Event three",
        "start": "2006-01-04T09:00:00",
        "participants": {
            "3f5bc8c0-c722-5345-b7d9-5a899db08a30": {
                "calendarAddress": "mailto:cyrus@example.com",
                "@type": "Participant",
                "roles": {
                    "owner": true
                },
                "participationStatus": "accepted"
            },
            "7f2bd210-6c66-5b64-8562-0176b74462b1": {
                "calendarAddress": "mailto:rupert@example.com",
                "@type": "Participant",
                "participationStatus": "needs-action"
            }
        },
        "mayInviteOthers": false,
        "mayInviteSelf": false,
        "hideAttendees": false,
        "useDefaultAlerts": false,
        "isDraft": false
    }));

    // Updates of events that are not origin keep updated and sequence
    account
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::Sequence,
                JSCalendarProperty::Updated,
            ],
            [&event_3_id],
        )
        .await
        .list()[0]
        .assert_is_equal(json!({
            "id": &event_3_id,
            "sequence": 1,
            "updated": "2006-02-06T00:12:20Z"
        }));

    // Query tests
    test.wait_for_tasks().await;
    assert_eq!(
        account
            .jmap_query(
                MethodObject::CalendarEvent,
                [
                    ("text", "Event one"),
                    ("inCalendar", calendar1_id.as_str()),
                    ("uid", "74855313FA803DA593CD579A@example.com"),
                    ("after", "2006-01-02T10:59:59"),
                    ("before", "2006-01-02T10:00:01"),
                ],
                ["start"],
                [("timeZone", "US/Eastern")],
            )
            .await
            .ids()
            .collect::<AHashSet<_>>(),
        [event_1_id.as_str()].into_iter().collect::<AHashSet<_>>()
    );

    // Recurrence expansion tests
    let response = account
        .jmap_query(
            MethodObject::CalendarEvent,
            [
                ("after", "2006-01-01T00:00:00"),
                ("before", "2006-01-08T00:00:00"),
            ],
            ["start"],
            [
                ("timeZone", Value::String("US/Eastern".into())),
                ("expandRecurrences", Value::Bool(true)),
            ],
        )
        .await;
    let ids = response.ids().collect::<Vec<_>>();
    assert_eq!(ids.len(), 7);
    account
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::BaseEventId,
                JSCalendarProperty::Start,
                JSCalendarProperty::Duration,
                JSCalendarProperty::TimeZone,
                JSCalendarProperty::Title,
                JSCalendarProperty::RecurrenceId,
            ],
            ids.clone(),
        )
        .await
        .list_array()
        .assert_is_equal(json!([
          {
            "duration": "PT1H",
            "title": "Event one",
            "start": "2006-01-02T10:00:00",
            "timeZone": "US/Eastern",
            "id": &event_1_id,
            "baseEventId": null
          },
          {
            "recurrenceId": "2006-01-02T12:00:00",
            "title": "Event two",
            "duration": "PT1H",
            "start": "2006-01-02T12:00:00",
            "timeZone": "US/Eastern",
            "id": &ids[1],
            "baseEventId": &event_2_id
          },
          {
            "duration": "PT1H",
            "start": "2006-01-03T12:00:00",
            "timeZone": "US/Eastern",
            "title": "Event two",
            "recurrenceId": "2006-01-03T12:00:00",
            "id": &ids[2],
            "baseEventId": &event_2_id
          },
          {
            "start": "2006-01-04T09:00:00",
            "timeZone": "US/Eastern",
            "duration": "PT2H",
            "title": "Event three",
            "id": &event_3_id,
            "baseEventId": null
          },
          {
            "recurrenceId": "2006-01-04T12:00:00",
            "title": "Event two overridden",
            "start": "2006-01-04T14:00:00",
            "timeZone": "US/Eastern",
            "duration": "PT1H",
            "id": &ids[4],
            "baseEventId": &event_2_id
          },
          {
            "recurrenceId": "2006-01-05T12:00:00",
            "duration": "PT1H",
            "timeZone": "US/Eastern",
            "start": "2006-01-05T12:00:00",
            "title": "Event two",
            "id": &ids[5],
            "baseEventId": &event_2_id
          },
          {
            "recurrenceId": "2006-01-06T12:00:00",
            "duration": "PT1H",
            "title": "Event two overridden twice",
            "timeZone": "US/Eastern",
            "start": "2006-01-06T14:00:00",
            "id": &ids[6],
            "baseEventId": &event_2_id
          }
        ]));

    // Parse tests
    account
        .jmap_method_calls(json!([
         [
          "Blob/upload",
          {
           "accountId": account.id_string(),
           "create": {
            "ical": {
             "data": [
              {
               "data:asText": r#"BEGIN:VCALENDAR
PRODID:-//xyz Corp//NONSGML PDA Calendar Version 1.0//EN
VERSION:2.0
BEGIN:VEVENT
DTSTAMP:19960704T120000Z
UID:uid1@example.com
ORGANIZER:mailto:jsmith@example.com
DTSTART:19960918T143000Z
DTEND:19960920T220000Z
STATUS:CONFIRMED
CATEGORIES:CONFERENCE
SUMMARY:Networld+Interop Conference
DESCRIPTION:Networld+Interop Conference
 and Exhibit\nAtlanta World Congress Center\n
Atlanta\, Georgia
END:VEVENT
END:VCALENDAR
"#
              }
            ]
           }
          }
         },
         "S4"
        ],
        [
          "CalendarEvent/parse",
          {
           "accountId": account.id_string(),
           "blobIds": [
             "#ical"
           ]
          },
          "G4"
         ]
        ]))
        .await
        .pointer("/methodResponses/1/1/parsed")
        .unwrap()
        .as_object()
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .1
        .assert_is_equal(json!([
  {
    "updated": "1996-07-04T12:00:00Z",
    "title": "Networld+Interop Conference",
    "description": "Networld+Interop Conferenceand Exhibit\nAtlanta World Congress Center\n",
    "timeZone": "Etc/UTC",
    "start": "1996-09-18T14:30:00",
    "status": "confirmed",
    "iCalendar": {
      "convertedProperties": {
        "duration": {
          "name": "dtend"
        }
      },
      "name": "vevent"
    },
    "@type": "Event",
    "uid": "uid1@example.com",
    "id": null,
    "baseEventId": null,
    "calendarIds": null,
    "isDraft": null,
    "isOrigin": null,
    "participants": {
      "25d7647e-52fc-559b-88df-d66f08da079c": {
        "calendarAddress": "mailto:jsmith@example.com",
        "@type": "Participant",
        "roles": {
          "owner": true
        }
      }
    },
    "keywords": {
      "CONFERENCE": true
    },
    "organizerCalendarAddress": "mailto:jsmith@example.com",
    "duration": "P2DT7H30M"
  }
]));

    // Deletion tests
    test.wait_for_tasks().await;
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::CalendarEvent,
                [event_2_id.as_str(), event_3_id.as_str()],
                Vec::<(&str, &str)>::new()
            )
            .await
            .destroyed()
            .collect::<AHashSet<_>>(),
        [event_2_id.as_str(), event_3_id.as_str()]
            .into_iter()
            .collect::<AHashSet<_>>()
    );

    // CardDAV compatibility tests
    let account_id = account.id().document_id();
    let dav_client = account.webdav_client();
    let resources = test
        .server
        .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .unwrap();
    let path = format!(
        "{}{}",
        resources.base_path,
        resources
            .paths
            .iter()
            .find(|(_, path)| path.parent_id != NO_ID)
            .map(|(chunk, path)| {
                std::str::from_utf8(&chunk.bytes[path.path.range()])
                    .unwrap()
                    .to_string()
            })
            .unwrap()
    );

    let ical = dav_client
        .request("GET", &path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert!(
        ical.lines().any(|line| line.starts_with("CREATED:")),
        "{ical}"
    );
    let (lines, timezones) = split_timezones(&ical);
    assert_eq!(timezone_ids(&timezones), ["US/Eastern"], "{ical}");
    let ical = lines
        .into_iter()
        .filter(|line| !line.starts_with("DTSTAMP") && !line.starts_with("CREATED"))
        .collect::<AHashSet<_>>();
    let expected_ical = TEST_ICAL_1
        .lines()
        .filter(|line| !line.starts_with("DTSTAMP"))
        .map(String::from)
        .chain(["SEQUENCE:1".to_string(), format!("PRODID:{PROD_ID}")])
        .collect::<AHashSet<_>>();
    assert_eq!(ical, expected_ical);

    // Events written over JMAP carry PRODID and the VTIMEZONEs they reference
    let response = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({
                    "@type": "Event",
                    "uid": "tz-server-prodid@example.com",
                    "title": "Server PRODID",
                    "start": "2030-03-01T09:00:00",
                    "duration": "PT1H",
                    "timeZone": "America/New_York",
                    "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "weekly"},
                    "alerts": {
                        "a1": {
                            "@type": "Alert",
                            "trigger": {"@type": "OffsetTrigger", "offset": "-PT15M"}
                        }
                    },
                    "calendarIds": {&calendar1_id: true}
                }),
                json!({
                    "@type": "Event",
                    "uid": "tz-client-prodid@example.com",
                    "title": "Client PRODID",
                    "prodId": "-//Example Corp//Client 1.0//EN",
                    "start": "2030-03-01T09:00:00",
                    "duration": "PT1H",
                    "timeZone": "Asia/Tokyo",
                    "calendarIds": {&calendar1_id: true}
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let server_prodid_id = response.created(0).id().to_string();
    let client_prodid_id = response.created(1).id().to_string();

    let ical = caldav_event(test, &dav_client, account_id, &server_prodid_id).await;
    let (lines, timezones) = split_timezones(&ical);
    assert!(lines.contains(&format!("PRODID:{PROD_ID}")), "{ical}");
    assert!(
        lines.contains(&"DTSTART;TZID=America/New_York:20300301T090000".to_string()),
        "{ical}"
    );
    assert!(lines.contains(&"ACTION:DISPLAY".to_string()), "{ical}");
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("DESCRIPTION:") || line.starts_with("DESCRIPTION;")),
        "{ical}"
    );
    assert_eq!(timezone_ids(&timezones), ["America/New_York"], "{ical}");
    assert!(
        timezones[0].iter().any(|line| line == "BEGIN:STANDARD")
            && timezones[0].iter().any(|line| line == "BEGIN:DAYLIGHT"),
        "{ical}"
    );

    let ical = caldav_event(test, &dav_client, account_id, &client_prodid_id).await;
    let (lines, timezones) = split_timezones(&ical);
    assert!(
        lines.contains(&"PRODID:-//Example Corp//Client 1.0//EN".to_string()),
        "{ical}"
    );
    assert!(!lines.contains(&format!("PRODID:{PROD_ID}")), "{ical}");
    assert_eq!(timezone_ids(&timezones), ["Asia/Tokyo"], "{ical}");
    account
        .jmap_update(
            MethodObject::CalendarEvent,
            [(
                &client_prodid_id,
                json!({"prodId": "-//Example Corp//Client 2.0//EN"}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&client_prodid_id);
    let ical = caldav_event(test, &dav_client, account_id, &client_prodid_id).await;
    let (lines, _) = split_timezones(&ical);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("PRODID:"))
            .collect::<Vec<_>>(),
        ["PRODID:-//Example Corp//Client 2.0//EN"],
        "{ical}"
    );

    // Changing the time zone over JMAP replaces the VTIMEZONE instead of keeping the old one
    account
        .jmap_update(
            MethodObject::CalendarEvent,
            [(&server_prodid_id, json!({"timeZone": "Europe/Berlin"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&server_prodid_id);
    let ical = caldav_event(test, &dav_client, account_id, &server_prodid_id).await;
    let (lines, timezones) = split_timezones(&ical);
    assert_eq!(timezone_ids(&timezones), ["Europe/Berlin"], "{ical}");
    assert!(lines.contains(&format!("PRODID:{PROD_ID}")), "{ical}");
    assert!(
        lines.contains(&"DTSTART;TZID=Europe/Berlin:20300301T090000".to_string()),
        "{ical}"
    );

    // A JMAP update regenerates IANA VTIMEZONEs supplied over CalDAV and keeps custom ones
    let calendar_path = path.rsplit_once('/').expect("event path").0;
    let mut caldav_ids = Vec::new();
    for (name, ical, tz_id, is_regenerated) in [
        ("custom-tz.ics", CUSTOM_TZ_ICAL, "Custom Zone", false),
        ("stale-tz.ics", STALE_TZ_ICAL, "Europe/Berlin", true),
    ] {
        let event_path = format!("{calendar_path}/{name}");
        dav_client
            .request("PUT", &event_path, ical)
            .await
            .with_status(StatusCode::CREATED);
        let resources = test
            .server
            .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
            .await
            .expect("calendar resources");
        let event_id = Id::from(
            resources
                .by_path(
                    event_path
                        .strip_prefix(resources.base_path.as_str())
                        .expect("path under base"),
                )
                .expect("event put over CalDAV")
                .document_id(),
        )
        .to_string();
        account
            .jmap_update(
                MethodObject::CalendarEvent,
                [(&event_id, json!({"title": "Updated over JMAP"}))],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .updated(&event_id);
        let ical = dav_client
            .request("GET", &event_path, "")
            .await
            .with_status(StatusCode::OK)
            .expect_body()
            .to_string();
        let (_, timezones) = split_timezones(&ical);
        assert_eq!(timezone_ids(&timezones), [tz_id], "{ical}");
        assert_eq!(
            timezones[0]
                .iter()
                .any(|line| line == "X-CUSTOM-MARKER:original"),
            !is_regenerated,
            "{ical}"
        );
        caldav_ids.push(event_id);
    }

    // The number of distinct time zones an event may reference is capped
    let zone_properties = |count: usize| {
        (0..count)
            .map(|num| {
                json!([
                    format!("x-zone-{num}"),
                    {"tzid": format!("Zone {num}")},
                    "unknown",
                    "1"
                ])
            })
            .collect::<Vec<_>>()
    };
    let response = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [64, 65].map(|count| {
                json!({
                    "@type": "Event",
                    "uid": format!("tz-cap-{count}@example.com"),
                    "title": "Time zone cap",
                    "start": "2030-03-01T09:00:00",
                    "duration": "PT1H",
                    "calendarIds": {&calendar1_id: true},
                    "iCalendar": {"name": "vevent", "properties": zone_properties(count)}
                })
            }),
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let at_cap_id = response.created(0).id().to_string();
    assert_eq!(
        response.not_created(1)["type"],
        json!("invalidProperties"),
        "{response:?}"
    );
    assert!(
        response.not_created(1)["description"]
            .as_str()
            .is_some_and(|description| description.contains("64 time zones")),
        "{response:?}"
    );

    account
        .jmap_destroy(
            MethodObject::CalendarEvent,
            [
                at_cap_id.as_str(),
                server_prodid_id.as_str(),
                client_prodid_id.as_str(),
                caldav_ids[0].as_str(),
                caldav_ids[1].as_str(),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;

    // Organizer assignment tests
    let response = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                test_jscalendar_participants("organizer-auto@example.com", None).with_property(
                    JSCalendarProperty::<Id>::CalendarIds,
                    [calendar1_id.as_str()].into_jmap_set(),
                ),
                test_jscalendar_participants(
                    "organizer-explicit@example.com",
                    Some("mailto:cyrus@example.com"),
                )
                .with_property(
                    JSCalendarProperty::<Id>::CalendarIds,
                    [calendar1_id.as_str()].into_jmap_set(),
                ),
                test_jscalendar_4()
                    .with_property(JSCalendarProperty::<Id>::Uid, "organizer-none@example.com")
                    .with_property(
                        JSCalendarProperty::<Id>::CalendarIds,
                        [calendar1_id.as_str()].into_jmap_set(),
                    ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let auto_event_id = response.created(0).id().to_string();
    let explicit_event_id = response.created(1).id().to_string();
    let no_participants_event_id = response.created(2).id().to_string();

    let response = account
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::OrganizerCalendarAddress,
            ],
            [
                &auto_event_id,
                &explicit_event_id,
                &no_participants_event_id,
            ],
        )
        .await;

    // The server assigns an organizer when participants are present but none was supplied
    response.list()[0].assert_is_equal(json!({
        "id": &auto_event_id,
        "organizerCalendarAddress": "mailto:jdoe@example.com"
    }));

    // An organizer supplied by the client is never overwritten
    response.list()[1].assert_is_equal(json!({
        "id": &explicit_event_id,
        "organizerCalendarAddress": "mailto:cyrus@example.com"
    }));

    // An event without participants is left without an organizer
    response.list()[2].assert_is_equal(json!({
        "id": &no_participants_event_id
    }));

    // Adding participants to an event that had none assigns the organizer
    account
        .jmap_update(
            MethodObject::CalendarEvent,
            [(
                &no_participants_event_id,
                json!({
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
                            "calendarAddress": "mailto:rupert@example.com",
                            "participationStatus": "needs-action",
                            "kind": "individual",
                            "@type": "Participant"
                        }
                    }
                }),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&no_participants_event_id);

    account
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::OrganizerCalendarAddress,
            ],
            [&no_participants_event_id],
        )
        .await
        .list()[0]
        .assert_is_equal(json!({
            "id": &no_participants_event_id,
            "organizerCalendarAddress": "mailto:jdoe@example.com"
        }));

    // Moving an event between calendars tombstones the previous CalDAV href
    test.wait_for_tasks().await;
    let cal_base_path = format!("{}/jdoe%40example.com/", DavResourceName::Cal.base_path());
    let sync_token = dav_client
        .sync_collection(&cal_base_path, "", Depth::Infinity, None, ["D:getetag"])
        .await
        .sync_token()
        .to_string();
    let moved_event_id = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "@type": "Event",
                "uid": "d3a15a44-fe25-4b6a-9e2f-58d40f0f1d4c",
                "title": "Moving Event",
                "start": "2026-01-15T13:00:00",
                "timeZone": "America/New_York",
                "duration": "PT1H",
                "calendarIds": {
                    &calendar1_id: true
                },
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let response = dav_client
        .sync_collection(
            &cal_base_path,
            &sync_token,
            Depth::Infinity,
            None,
            ["D:getetag"],
        )
        .await
        .with_href_count(1);
    let sync_token = response.sync_token().to_string();
    let href_in_calendar1 = response.hrefs()[0].to_string();

    account
        .jmap_update(
            MethodObject::CalendarEvent,
            [(
                &moved_event_id,
                json!({
                    "calendarIds": {
                        &calendar2_id: true
                    }
                }),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&moved_event_id);

    let response = dav_client
        .sync_collection(
            &cal_base_path,
            &sync_token,
            Depth::Infinity,
            None,
            ["D:getetag"],
        )
        .await
        .with_href_count(2);
    let sync_token = response.sync_token().to_string();
    let href_in_calendar2 = response
        .hrefs()
        .into_iter()
        .find(|href| *href != href_in_calendar1)
        .unwrap()
        .to_string();
    let response = response.into_propfind_response(None);
    response
        .properties(&href_in_calendar1)
        .with_status(StatusCode::NOT_FOUND);
    response
        .properties(&href_in_calendar2)
        .with_status(StatusCode::OK);

    account
        .jmap_destroy(
            MethodObject::CalendarEvent,
            [moved_event_id.as_str()],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .assert_destroyed(&[Id::from_str(&moved_event_id).unwrap()]);

    dav_client
        .sync_collection(
            &cal_base_path,
            &sync_token,
            Depth::Infinity,
            None,
            ["D:getetag"],
        )
        .await
        .with_href_count(1)
        .into_propfind_response(None)
        .properties(&href_in_calendar2)
        .with_status(StatusCode::NOT_FOUND);

    // Unbounded yearly recurrences remain queryable far beyond their first instance
    let yearly_event_id = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "@type": "Event",
                "uid": "yearly-unbounded@example.com",
                "title": "Unbounded yearly event",
                "start": "2018-06-01T09:00:00",
                "duration": "PT1H",
                "timeZone": "Etc/UTC",
                "calendarIds": {
                    &calendar1_id: true
                },
                "recurrenceRule": {
                    "@type": "RecurrenceRule",
                    "frequency": "yearly"
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    test.wait_for_tasks().await;

    assert!(
        account
            .jmap_query(
                MethodObject::CalendarEvent,
                [
                    ("after", "2027-06-01T00:00:00"),
                    ("before", "2027-07-01T00:00:00"),
                ],
                ["start"],
                [("timeZone", "Etc/UTC")],
            )
            .await
            .ids()
            .any(|id| id == yearly_event_id),
        "unbounded yearly event was pruned from a June 2027 query"
    );

    account
        .jmap_destroy(
            MethodObject::CalendarEvent,
            [yearly_event_id.as_str()],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .assert_destroyed(&[Id::from_str(&yearly_event_id).unwrap()]);

    // Clean up
    test.wait_for_tasks().await;
    account.destroy_all_calendars().await;
    test.assert_is_empty().await;
}

fn test_jscalendar_participants(uid: &str, organizer: Option<&str>) -> Value {
    let mut event = json!({
      "@type": "Event",
      "uid": uid,
      "title": "Organizer assignment",
      "start": "2006-01-04T10:00:00",
      "duration": "PT1H",
      "timeZone": "US/Eastern",
      "updated": "2006-02-06T00:11:02Z",
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
          "calendarAddress": "mailto:rupert@example.com",
          "participationStatus": "needs-action",
          "kind": "individual",
          "@type": "Participant"
        }
      }
    });

    if let Some(organizer) = organizer {
        event.as_object_mut().unwrap().insert(
            "organizerCalendarAddress".to_string(),
            Value::String(organizer.to_string()),
        );
    }

    event
}

pub fn assert_eq_ignoring_timestamps(got: &Value, expected: Value) {
    strip_timestamps(got.clone()).assert_is_equal(strip_timestamps(expected));
}

fn strip_timestamps(mut value: Value) -> Value {
    match &mut value {
        Value::Object(map) => {
            map.remove("updated");
            map.remove("created");
        }
        Value::Array(array) => {
            for entry in array.iter_mut() {
                *entry = strip_timestamps(std::mem::take(entry));
            }
        }
        _ => {}
    }
    value
}

pub fn test_jscalendar_1() -> Value {
    json!({
      "duration": "PT1H",
      "@type": "Event",
      "description": "Go Steelers!",
      "updated": "2006-02-06T00:11:02Z",
      "timeZone": "US/Eastern",
      "start": "2006-01-02T10:00:00",
      "title": "Event #1",
      "uid": "74855313FA803DA593CD579A@example.com"
    })
}

pub fn test_jscalendar_2() -> Value {
    json!({
      "title": "Event #2",
      "duration": "PT1H",
      "updated": "2006-02-06T00:11:21Z",
      "recurrenceRule": {
        "frequency": "daily",
        "count": 5
      },
      "start": "2006-01-02T12:00:00",
      "uid": "00959BC664CA650E933C892C@example.com",
      "@type": "Event",
      "timeZone": "US/Eastern",
      "recurrenceOverrides": {
        "2006-01-04T12:00:00": {
          "title": "Event #2 bis",
          "start": "2006-01-04T14:00:00",
          "updated": "2006-02-06T00:11:21Z"
        },
        "2006-01-06T12:00:00": {
          "title": "Event #2 bis bis",
          "start": "2006-01-06T14:00:00",
          "updated": "2006-02-06T00:11:21Z"
        }
      }
    })
}

pub fn test_jscalendar_3() -> Value {
    json!({
      "duration": "PT1H",
      "organizerCalendarAddress": "mailto:cyrus@example.com",
      "@type": "Event",
      "start": "2006-01-04T10:00:00",
      "status": "tentative",
      "uid": "DC6C50A017428C5216A2F1CD@example.com",
      "sequence": 1,
      "participants": {
        "3f5bc8c0-c722-5345-b7d9-5a899db08a30": {
          "calendarAddress": "mailto:cyrus@example.com",
          "@type": "Participant",
          "roles": {
            "chair": true,
            "owner": true
          },
          "participationStatus": "accepted"
        },
        "ec5e7db5-22a3-5ed5-89bf-c8894ab86805": {
          "calendarAddress": "mailto:lisa@example.com",
          "@type": "Participant",
          "participationStatus": "needs-action"
        }
      },
      "title": "Event #3",
      "updated": "2006-02-06T00:12:20Z",
      "timeZone": "US/Eastern"
    })
}

pub fn test_jscalendar_4() -> Value {
    json!({
      "duration": "PT1H",
      "@type": "Event",
      "description": "Tmp Event",
      "updated": "2006-02-06T00:11:02Z",
      "timeZone": "US/Eastern",
      "start": "2006-01-02T10:00:00",
      "title": "Tmp Event",
      "uid": "tmp-event@example.com"
    })
}

pub(super) fn split_timezones(ical: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let mut lines = Vec::new();
    let mut timezones = Vec::new();
    let mut timezone: Option<Vec<String>> = None;
    for line in ical.lines() {
        if let Some(current) = timezone.as_mut() {
            current.push(line.to_string());
            if line == "END:VTIMEZONE" {
                timezones.extend(timezone.take());
            }
        } else if line == "BEGIN:VTIMEZONE" {
            timezone = Some(vec![line.to_string()]);
        } else {
            lines.push(line.to_string());
        }
    }
    (lines, timezones)
}

pub(super) fn timezone_ids(timezones: &[Vec<String>]) -> Vec<&str> {
    timezones
        .iter()
        .filter_map(|timezone| timezone.iter().find_map(|line| line.strip_prefix("TZID:")))
        .collect()
}

pub(super) async fn caldav_event(
    test: &TestServer,
    client: &DummyWebDavClient,
    account_id: u32,
    id: &str,
) -> String {
    let resources = test
        .server
        .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .expect("calendar resources");
    let document_id = Id::from_str(id).expect("valid id").document_id();
    let path = resources.format_resource(
        resources
            .any_resource_path_by_id(document_id)
            .expect("event path"),
    );
    client
        .request("GET", &path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string()
}

const CUSTOM_TZ_ICAL: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp//Client 1.0//EN
BEGIN:VTIMEZONE
TZID:Custom Zone
X-CUSTOM-MARKER:original
BEGIN:STANDARD
DTSTART:19700101T000000
TZOFFSETFROM:+0330
TZOFFSETTO:+0330
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
UID:custom-tz@example.com
DTSTAMP:20300101T000000Z
DTSTART;TZID=Custom Zone:20300301T090000
DURATION:PT1H
SUMMARY:Custom zone
END:VEVENT
END:VCALENDAR
"#;

const STALE_TZ_ICAL: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp//Client 1.0//EN
BEGIN:VTIMEZONE
TZID:Europe/Berlin
X-CUSTOM-MARKER:original
BEGIN:STANDARD
DTSTART:19700101T000000
TZOFFSETFROM:+0100
TZOFFSETTO:+0100
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
UID:stale-tz@example.com
DTSTAMP:20300101T000000Z
DTSTART;TZID=Europe/Berlin:20300301T090000
DURATION:PT1H
SUMMARY:Stale zone
END:VEVENT
END:VCALENDAR
"#;

const TEST_ICAL_1: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
DTSTART;TZID=US/Eastern:20060102T100000
UID:74855313FA803DA593CD579A@example.com
DURATION:PT1H
SUMMARY:Event one
DTSTAMP:20060206T001102Z
CATEGORIES:work
BEGIN:VALARM
JSID:abc
ACTION:DISPLAY
TRIGGER:PT15M
DESCRIPTION:Event one
END:VALARM
END:VEVENT
END:VCALENDAR
"#;
