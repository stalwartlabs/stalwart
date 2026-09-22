/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    jmap::{ChangeType, JmapUtils},
    server::TestServer,
};
use jmap_proto::{object::calendar::CalendarProperty, request::method::MethodObject};
use serde_json::json;

pub async fn test(test: &TestServer) {
    println!("Running Calendar tests...");
    let account = test.account("jdoe@example.com");

    // Make sure the default calendar exists
    let response = account
        .jmap_get(
            MethodObject::Calendar,
            [
                CalendarProperty::Id,
                CalendarProperty::Name,
                CalendarProperty::Description,
                CalendarProperty::SortOrder,
                CalendarProperty::Color,
                CalendarProperty::TimeZone,
                CalendarProperty::IsSubscribed,
                CalendarProperty::IsDefault,
                CalendarProperty::IsVisible,
                CalendarProperty::IncludeInAvailability,
                CalendarProperty::DefaultAlertsWithTime,
                CalendarProperty::DefaultAlertsWithoutTime,
            ],
            Vec::<&str>::new(),
        )
        .await;
    let list = response.list();
    assert_eq!(list.len(), 1);
    let default_calendar_id = list[0].id().to_string();
    assert_eq!(
        list[0],
        json!({
            "id": default_calendar_id,
            "name": "Stalwart Calendar (jdoe@example.com)",
            "description": null,
            "sortOrder": 0,
            "isSubscribed": true,
            "isDefault": true,
            "color": null,
            "timeZone": null,
            "isVisible": true,
            "includeInAvailability": "all",
            "defaultAlertsWithTime": {},
            "defaultAlertsWithoutTime": {}
        })
    );
    let change_id = response.state();

    // Create Calendar
    let calendar_id = account
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Test calendar",
                "description": "My personal calendar",
                "sortOrder": 1,
                "isSubscribed": true,
                "color": "#ff0000",
                "timeZone": "Indian/Christmas",
                "isVisible": false,
                "includeInAvailability": "attending",
                "defaultAlertsWithTime": {
                    "with-time-0": {
                        "action": "display",
                        "trigger": {
                            "relativeTo": "start",
                            "offset": "PT15M"
                        }
                    },
                    "with-time-1": {
                        "action": "email",
                        "trigger": {
                            "relativeTo": "end",
                            "offset": "PT30M"
                        }
                    }
                },
                "defaultAlertsWithoutTime": {
                    "without-time-0": {
                        "action": "display",
                        "trigger": {
                            "relativeTo": "start",
                            "offset": "P1D"
                        }
                    },
                    "without-time-1": {
                        "action": "email",
                        "trigger": {
                            "relativeTo": "end",
                            "offset": "P2D"
                        }
                    }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    // Validate changes
    assert_eq!(
        account
            .jmap_changes(MethodObject::Calendar, change_id)
            .await
            .changes()
            .collect::<Vec<_>>(),
        [ChangeType::Created(&calendar_id)]
    );

    // Get Calendar
    let response = account
        .jmap_get(
            MethodObject::Calendar,
            [
                CalendarProperty::Id,
                CalendarProperty::Name,
                CalendarProperty::Description,
                CalendarProperty::SortOrder,
                CalendarProperty::Color,
                CalendarProperty::TimeZone,
                CalendarProperty::IsSubscribed,
                CalendarProperty::IsDefault,
                CalendarProperty::IsVisible,
                CalendarProperty::IncludeInAvailability,
                CalendarProperty::DefaultAlertsWithTime,
                CalendarProperty::DefaultAlertsWithoutTime,
            ],
            [&calendar_id],
        )
        .await;

    response.list()[0].assert_is_equal(json!({
        "name": "Test calendar",
        "description": "My personal calendar",
        "sortOrder": 1,
        "isSubscribed": true,
        "isVisible": false,
        "isDefault": false,
        "color": "#ff0000",
        "timeZone": "Indian/Christmas",
        "includeInAvailability": "attending",
        "defaultAlertsWithTime": {
            "with-time-0": {
                "@type": "Alert",
                "action": "display",
                "trigger": {
                    "@type": "OffsetTrigger",
                    "relativeTo": "start",
                    "offset": "PT15M"
                }
            },
            "with-time-1": {
                "@type": "Alert",
                "action": "email",
                "trigger": {
                    "@type": "OffsetTrigger",
                    "relativeTo": "end",
                    "offset": "PT30M"
                }
            }
        },
        "defaultAlertsWithoutTime": {
            "without-time-0": {
                "@type": "Alert",
                "action": "display",
                "trigger": {
                    "@type": "OffsetTrigger",
                    "relativeTo": "start",
                    "offset": "P1D"
                }
            },
            "without-time-1": {
                "@type": "Alert",
                "action": "email",
                "trigger": {
                    "@type": "OffsetTrigger",
                    "relativeTo": "end",
                    "offset": "P2D"
                }
            }
        },
        "id": calendar_id,
    }));

    // Update Calendar and set it as default
    account
        .jmap_update(
            MethodObject::Calendar,
            [(
                calendar_id.as_str(),
                json!({
                    "name": "Updated calendar",
                    "description": "My updated personal calendar",
                    "sortOrder": 2,
                    "isSubscribed": false,
                    "isVisible": true,
                    "timeZone": null,
                    "color": null,
                    "includeInAvailability": "none",
                    "defaultAlertsWithTime": {
                        "with-time-0": {
                            "action": "email",
                            "trigger": {
                                "relativeTo": "start",
                                "offset": "PT10M"
                            }
                        }
                    },
                    "defaultAlertsWithoutTime/without-time-0": {
                        "action": "email",
                        "trigger": {
                            "relativeTo": "start",
                            "offset": "P3D"
                        }
                    },
                    "defaultAlertsWithoutTime/without-time-1": null,
                    "defaultAlertsWithoutTime/without-time-2": {
                        "action": "display",
                        "trigger": {
                            "relativeTo": "end",
                            "offset": "P1W"
                        }
                    }
                }),
            )],
            [("onSuccessSetIsDefault", calendar_id.as_str())],
        )
        .await
        .updated(&calendar_id);

    // Validate changes
    let response = account
        .jmap_get(
            MethodObject::Calendar,
            [
                CalendarProperty::Id,
                CalendarProperty::Name,
                CalendarProperty::Description,
                CalendarProperty::SortOrder,
                CalendarProperty::Color,
                CalendarProperty::TimeZone,
                CalendarProperty::IsSubscribed,
                CalendarProperty::IsDefault,
                CalendarProperty::IsVisible,
                CalendarProperty::IncludeInAvailability,
                CalendarProperty::DefaultAlertsWithTime,
                CalendarProperty::DefaultAlertsWithoutTime,
            ],
            [&calendar_id, &default_calendar_id],
        )
        .await;
    response.list()[0].assert_is_equal(json!({
        "id": calendar_id,
        "name": "Updated calendar",
        "description": "My updated personal calendar",
        "sortOrder": 2,
        "isSubscribed": false,
        "isDefault": true,
        "color": null,
        "timeZone": null,
        "isVisible": true,
        "includeInAvailability": "none",
        "defaultAlertsWithTime": {
            "with-time-0": {
                "@type": "Alert",
                "action": "email",
                "trigger": {
                    "@type": "OffsetTrigger",
                    "relativeTo": "start",
                    "offset": "PT10M"
                }
            }
        },
        "defaultAlertsWithoutTime": {
            "without-time-0": {
                "@type": "Alert",
                "action": "email",
                "trigger": {
                    "@type": "OffsetTrigger",
                    "relativeTo": "start",
                    "offset": "P3D"
                }
            },
            "without-time-2": {
                "@type": "Alert",
                "action": "display",
                "trigger": {
                    "@type": "OffsetTrigger",
                    "relativeTo": "end",
                    "offset": "P1W"
                }
            }
        }
    }));
    response.list()[1].assert_is_equal(json!({
        "id": default_calendar_id,
        "name": "Stalwart Calendar (jdoe@example.com)",
        "description": (),
        "sortOrder": 0,
        "isSubscribed": true,
        "isDefault": false,
        "color": null,
        "timeZone": null,
        "isVisible": true,
        "includeInAvailability": "all",
        "defaultAlertsWithTime": {},
        "defaultAlertsWithoutTime": {}
    }));

    account
        .jmap_update(
            MethodObject::Calendar,
            [(
                calendar_id.as_str(),
                json!({ "defaultAlertsWithTime": null }),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&calendar_id);
    let response = account
        .jmap_get(
            MethodObject::Calendar,
            [
                CalendarProperty::DefaultAlertsWithTime,
                CalendarProperty::DefaultAlertsWithoutTime,
            ],
            [&calendar_id],
        )
        .await;
    assert_eq!(response.list()[0]["defaultAlertsWithTime"], json!({}));
    assert_eq!(
        response.list()[0]["defaultAlertsWithoutTime"]
            .as_object()
            .map(|alerts| alerts.len()),
        Some(2)
    );

    // Create an event
    let _ = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": {
                    &calendar_id: true
                },
                "@type": "Event",
                "uid": "a8df6573-0474-496d-8496-033ad45d7fea",
                "updated": "2020-01-02T18:23:04Z",
                "title": "Some event",
                "start": "2020-01-15T13:00:00",
                "timeZone": "America/New_York",
                "duration": "PT1H"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id();

    // Try destroying the calendar (should fail)
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::Calendar,
                [&calendar_id],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .not_destroyed(&calendar_id)
            .typ(),
        "calendarHasEvent"
    );

    // Destroy using force
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::Calendar,
                [&calendar_id],
                [("onDestroyRemoveEvents", true)],
            )
            .await
            .destroyed()
            .collect::<Vec<_>>(),
        vec![&calendar_id]
    );

    sharee_destroy_respects_privacy(test).await;

    // Destroy all mailboxes
    account.destroy_all_calendars().await;
    test.assert_is_empty().await;
}

async fn sharee_destroy_respects_privacy(test: &TestServer) {
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Team",
                "shareWith": {
                    &jane_id: { "mayReadItems": true, "mayWriteAll": true, "mayDelete": true }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let event = |uid: &str, privacy: &str| {
        json!({
            "calendarIds": { &calendar_id: true },
            "uid": uid,
            "title": uid,
            "privacy": privacy,
            "start": "2030-04-01T10:00:00",
            "timeZone": "Etc/UTC",
            "duration": "PT1H"
        })
    };
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                event("team-public", "public"),
                event("team-private", "private"),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let visible_ids = [
        response.created(0).id().to_string(),
        response.created(1).id().to_string(),
    ];
    let jane_destroy = async |remove_events: bool| {
        jane.jmap_method_call(
            "Calendar/set",
            json!({
                "accountId": &john_id,
                "destroy": [&calendar_id],
                "onDestroyRemoveEvents": remove_events
            }),
        )
        .await
    };

    assert_eq!(
        jane_destroy(false).await.not_destroyed(&calendar_id).typ(),
        "calendarHasEvent"
    );
    assert_eq!(
        jane_destroy(true).await.not_destroyed(&calendar_id).typ(),
        "forbidden"
    );

    john.jmap_destroy(
        MethodObject::CalendarEvent,
        visible_ids.iter(),
        Vec::<(&str, &str)>::new(),
    )
    .await;
    let secret_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [event("team-secret", "secret")],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    assert_eq!(
        jane_destroy(false).await.not_destroyed(&calendar_id).typ(),
        "forbidden"
    );

    john.jmap_destroy(
        MethodObject::CalendarEvent,
        [&secret_id],
        Vec::<(&str, &str)>::new(),
    )
    .await;
    assert_eq!(
        jane_destroy(false).await.destroyed().collect::<Vec<_>>(),
        [calendar_id.as_str()]
    );
    jane.destroy_all_event_notifications().await;
    john.destroy_all_event_notifications().await;
}
