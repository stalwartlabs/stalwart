/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    account::Account,
    jmap::{JmapResponse, JmapUtils},
    server::TestServer,
    webdav::DummyWebDavClient,
};
use calcard::jscalendar::JSCalendarProperty;
use common::NO_ID;
use groupware::cache::GroupwareCache;
use hyper::StatusCode;
use jmap_proto::{
    object::{calendar::CalendarProperty, participant_identity::ParticipantIdentityProperty},
    request::method::MethodObject,
};
use serde_json::{Value, json};
use std::{str::FromStr, time::Duration};
use store::write::BatchBuilder;
use types::{
    collection::{Collection, SyncCollection},
    field::PrincipalField,
    id::Id,
};

pub async fn test(test: &TestServer) {
    println!("Running Calendar conformance tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let bill = test.account("bill@example.com");

    calendar_query_acl(john, jane).await;
    calendar_per_user_properties(john, jane).await;
    calendar_share_with(john, jane, bill).await;
    calendar_default(john).await;
    calendar_validation(john).await;
    event_set(test, john).await;
    event_override_patches(john).await;
    event_sequence(john).await;
    server_set_values(test, john).await;
    event_rights(test, john, jane).await;
    event_get(test, john, jane).await;
    event_query(test, john).await;
    event_parse(john).await;
    event_copy(test, john, jane).await;
    event_instance_rights(john, jane).await;
    sharee_metadata_changes(john, jane).await;
    event_method_errors(john).await;
    identity_set(test, john).await;
    related_alerts_keep_the_event_uid(test, john).await;

    john.destroy_all_calendars().await;
    jane.destroy_all_calendars().await;
    john.destroy_all_event_notifications().await;
    jane.destroy_all_event_notifications().await;
    test.assert_is_empty().await;
}

async fn calendar_query_acl(john: &Account, jane: &Account) {
    let jane_id = jane.id_string().to_string();
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({"name": "Shared"}),
                json!({"name": "Free busy only"}),
                json!({"name": "Private"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let shared_id = response.created(0).id().to_string();
    let free_busy_id = response.created(1).id().to_string();
    let private_id = response.created(2).id().to_string();
    for (calendar_id, rights) in [
        (&shared_id, json!({"mayReadItems": true})),
        (&free_busy_id, json!({"mayReadFreeBusy": true})),
    ] {
        john.jmap_update(
            MethodObject::Calendar,
            [(calendar_id, json!({"shareWith": {&jane_id: rights}}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(calendar_id);
    }

    // Only calendars readable by Jane are returned
    let response = jane
        .jmap_method_call("Calendar/query", json!({"accountId": john.id_string()}))
        .await;
    assert_eq!(response.ids().collect::<Vec<_>>(), [shared_id.as_str()]);
    assert_ne!(response.method_response()["queryState"], json!(""));

    // The owner sees all of them
    let response = john
        .jmap_method_call("Calendar/query", json!({"accountId": john.id_string()}))
        .await;
    let ids = response.ids().collect::<Vec<_>>();
    for calendar_id in [&shared_id, &free_busy_id, &private_id] {
        assert!(
            ids.contains(&calendar_id.as_str()),
            "{calendar_id} not in {ids:?}"
        );
    }

    john.jmap_destroy(
        MethodObject::Calendar,
        [&shared_id, &free_busy_id, &private_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn calendar_per_user_properties(john: &Account, jane: &Account) {
    let jane_id = jane.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Team",
                "color": "#00ff00",
                "sortOrder": 5,
                "isVisible": false,
                "includeInAvailability": "attending",
                "timeZone": "Europe/Madrid",
                "defaultAlertsWithTime": {
                    "team-alert": {
                        "action": "display",
                        "trigger": {"relativeTo": "start", "offset": "PT15M"}
                    }
                },
                "shareWith": {&jane_id: {"mayReadItems": true}}
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let properties = [
        CalendarProperty::Name,
        CalendarProperty::Color,
        CalendarProperty::SortOrder,
        CalendarProperty::IsSubscribed,
        CalendarProperty::IsVisible,
        CalendarProperty::IncludeInAvailability,
        CalendarProperty::TimeZone,
        CalendarProperty::DefaultAlertsWithTime,
    ];

    // Name, color and time zone are inherited, everything else uses the defaults
    jane.jmap_get_account(
        john,
        MethodObject::Calendar,
        properties.iter(),
        [&calendar_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
            "id": &calendar_id,
            "name": "Team",
            "color": "#00ff00",
            "sortOrder": 0,
            "isSubscribed": false,
            "isVisible": true,
            "includeInAvailability": "none",
            "timeZone": "Europe/Madrid",
            "defaultAlertsWithTime": {}
        }));

    // A sharee with read access may change per-user properties
    jane.jmap_update_account(
        john,
        MethodObject::Calendar,
        [(
            &calendar_id,
            json!({
                "name": "Jane's view",
                "sortOrder": 2,
                "isSubscribed": true,
                "isVisible": false,
                "includeInAvailability": "all"
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar_id);
    jane.jmap_get_account(
        john,
        MethodObject::Calendar,
        properties.iter(),
        [&calendar_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
            "id": &calendar_id,
            "name": "Jane's view",
            "color": "#00ff00",
            "sortOrder": 2,
            "isSubscribed": true,
            "isVisible": false,
            "includeInAvailability": "all",
            "timeZone": "Europe/Madrid",
            "defaultAlertsWithTime": {}
        }));
    john.jmap_get(MethodObject::Calendar, properties.iter(), [&calendar_id])
        .await
        .list()[0]
        .assert_is_equal(json!({
            "id": &calendar_id,
            "name": "Team",
            "color": "#00ff00",
            "sortOrder": 5,
            "isSubscribed": true,
            "isVisible": false,
            "includeInAvailability": "attending",
            "timeZone": "Europe/Madrid",
            "defaultAlertsWithTime": {
                "team-alert": {
                    "@type": "Alert",
                    "action": "display",
                    "trigger": {
                        "@type": "OffsetTrigger",
                        "relativeTo": "start",
                        "offset": "PT15M"
                    }
                }
            }
        }));

    // Other properties still require write access
    assert_eq!(
        jane.jmap_update_account(
            john,
            MethodObject::Calendar,
            [(&calendar_id, json!({"description": "Not allowed"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&calendar_id)
        .typ(),
        "forbidden"
    );

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn calendar_share_with(john: &Account, jane: &Account, bill: &Account) {
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let bill_id = bill.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Delegated",
                "shareWith": {&jane_id: {"mayReadItems": true, "mayShare": true}}
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    // Jane cannot grant a right she does not hold
    assert_eq!(
        jane.jmap_update_account(
            john,
            MethodObject::Calendar,
            [(
                &calendar_id,
                json!({format!("shareWith/{bill_id}"): {"mayWriteAll": true}}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&calendar_id)
        .typ(),
        "forbidden"
    );

    // But she can grant rights she holds
    jane.jmap_update_account(
        john,
        MethodObject::Calendar,
        [(
            &calendar_id,
            json!({format!("shareWith/{bill_id}"): {"mayReadItems": true}}),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar_id);

    // Rights implied by mayWriteAll are held and cannot be removed on their own
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &calendar_id,
            json!({format!("shareWith/{jane_id}"): {
                "mayReadItems": true,
                "mayWriteAll": true,
                "mayShare": true
            }}),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar_id);
    jane.jmap_update_account(
        john,
        MethodObject::Calendar,
        [(
            &calendar_id,
            json!({format!("shareWith/{bill_id}/mayRSVP"): true}),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar_id);
    for patch in [
        json!({format!("shareWith/{jane_id}/mayRSVP"): false}),
        json!({format!("shareWith/{bill_id}"): {
            "mayReadItems": true,
            "mayWriteAll": true,
            "mayUpdatePrivate": false
        }}),
    ] {
        assert_eq!(
            john.jmap_update(
                MethodObject::Calendar,
                [(&calendar_id, patch.clone())],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .not_updated(&calendar_id)
            .typ(),
            "invalidProperties",
            "{patch}"
        );
    }

    // The owner cannot be part of shareWith
    assert_eq!(
        john.jmap_update(
            MethodObject::Calendar,
            [(
                &calendar_id,
                json!({format!("shareWith/{john_id}"): {"mayReadItems": true}}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&calendar_id)
        .typ(),
        "invalidProperties"
    );

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn calendar_default(john: &Account) {
    let default_id = john
        .jmap_get(
            MethodObject::Calendar,
            [CalendarProperty::Id, CalendarProperty::IsDefault],
            Vec::<&str>::new(),
        )
        .await
        .list()
        .iter()
        .find(|calendar| calendar["isDefault"] == json!(true))
        .expect("default calendar")
        .id()
        .to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "New default"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();

    // Both changed calendars are reported
    let response = john
        .jmap_method_call(
            "Calendar/set",
            json!({
                "accountId": john.id_string(),
                "onSuccessSetIsDefault": &calendar_id
            }),
        )
        .await;
    response
        .updated(&calendar_id)
        .assert_is_equal(json!({"isDefault": true}));
    response
        .updated(&default_id)
        .assert_is_equal(json!({"isDefault": false}));

    // Unknown ids are ignored
    let response = john
        .jmap_method_call(
            "Calendar/set",
            json!({
                "accountId": john.id_string(),
                "onSuccessSetIsDefault": "zzzzzz"
            }),
        )
        .await;
    assert_eq!(response.method_response().get("updated"), None);
    assert_eq!(
        john.jmap_get(
            MethodObject::Calendar,
            [CalendarProperty::IsDefault],
            [&calendar_id],
        )
        .await
        .list()[0]["isDefault"],
        json!(true)
    );

    // Restore the previous default
    john.jmap_method_call(
        "Calendar/set",
        json!({
            "accountId": john.id_string(),
            "onSuccessSetIsDefault": &default_id,
            "destroy": [&calendar_id]
        }),
    )
    .await;
}

async fn calendar_validation(john: &Account) {
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({"name": "Named color", "color": "DarkBlue"}),
                json!({"name": "Short hex", "color": "#abc"}),
                json!({"name": "Bad color", "color": "rebeccapurple"}),
                json!({"name": "Bad hex", "color": "#abcd"}),
                json!({"name": "Bad order", "sortOrder": 2147483648u64}),
                json!({
                    "name": "Absolute trigger",
                    "defaultAlertsWithTime": {
                        "absolute": {
                            "action": "display",
                            "trigger": {"@type": "AbsoluteTrigger", "when": "2026-01-01T00:00:00Z"}
                        }
                    }
                }),
                json!({
                    "name": "Duplicate alert ids",
                    "defaultAlertsWithTime": {
                        "dup": {"action": "display", "trigger": {"offset": "PT5M"}}
                    },
                    "defaultAlertsWithoutTime": {
                        "dup": {"action": "display", "trigger": {"offset": "P1D"}}
                    }
                }),
                json!({
                    "name": "Unique alert id",
                    "defaultAlertsWithTime": {
                        "unique": {"action": "display", "trigger": {"offset": "PT5M"}}
                    }
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let created = [
        response.created(0).id().to_string(),
        response.created(1).id().to_string(),
        response.created(7).id().to_string(),
    ];
    for idx in 2..=6 {
        assert_eq!(
            response.not_created(idx).typ(),
            "invalidProperties",
            "{idx}"
        );
    }

    // Alert ids must be unique across calendars
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Reused alert id",
                "defaultAlertsWithoutTime": {
                    "unique": {"action": "display", "trigger": {"offset": "P1D"}}
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "invalidProperties");

    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({
                    "name": "Same request A",
                    "defaultAlertsWithTime": {
                        "same-request": {"action": "display", "trigger": {"offset": "-PT5M"}}
                    }
                }),
                json!({
                    "name": "Same request B",
                    "defaultAlertsWithoutTime": {
                        "same-request": {"action": "display", "trigger": {"offset": "-P1D"}}
                    }
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let same_request_id = response.created(0).id().to_string();
    assert_eq!(response.not_created(1).typ(), "invalidProperties");

    let too_many_alerts = |count: usize| {
        Value::Object(
            (0..count)
                .map(|idx| {
                    (
                        format!("limit-{idx}"),
                        json!({"action": "display", "trigger": {"offset": format!("-PT{idx}M")}}),
                    )
                })
                .collect(),
        )
    };
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({"name": "Too many alerts", "defaultAlertsWithTime": too_many_alerts(33)}),
                json!({"name": "Enough alerts", "defaultAlertsWithoutTime": too_many_alerts(32)}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "invalidProperties");
    let limit_id = response.created(1).id().to_string();
    let response = john
        .jmap_update(
            MethodObject::Calendar,
            [(
                &limit_id,
                json!({"defaultAlertsWithoutTime/limit-extra": {
                    "action": "display",
                    "trigger": {"offset": "-P2D"}
                }}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_updated(&limit_id).typ(), "invalidProperties");

    // Unsupported pointers are reported as invalidPatch
    let response = john
        .jmap_update(
            MethodObject::Calendar,
            [(&created[0], json!({"name/foo": "bar"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_updated(&created[0]).typ(), "invalidPatch");

    john.jmap_destroy(
        MethodObject::Calendar,
        created.iter().chain([&same_request_id, &limit_id]),
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn event_rights(test: &TestServer, john: &Account, jane: &Account) {
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Rights"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let share = async |rights: Value| {
        john.jmap_update(
            MethodObject::Calendar,
            [(&calendar_id, json!({ "shareWith": { &jane_id: rights } }))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&calendar_id);
    };
    let event = |uid: &str, organizer: &str, participants: Value| {
        json!({
            "calendarIds": {&calendar_id: true},
            "uid": uid,
            "title": "Rights",
            "start": "2026-06-01T09:00:00",
            "timeZone": "Etc/UTC",
            "duration": "PT1H",
            "recurrenceRule": {"frequency": "daily", "count": 3},
            "organizerCalendarAddress": organizer,
            "participants": participants
        })
    };
    let attendee = |address: &str| {
        json!({
            "@type": "Participant",
            "calendarAddress": address,
            "roles": {"attendee": true},
            "participationStatus": "needs-action"
        })
    };
    let owner = |address: &str| {
        json!({
            "@type": "Participant",
            "calendarAddress": address,
            "roles": {"owner": true, "attendee": true},
            "participationStatus": "accepted"
        })
    };
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                event(
                    "rights-invited",
                    "mailto:jdoe@example.com",
                    json!({
                        "john": owner("mailto:jdoe@example.com"),
                        "jane": attendee("mailto:Jane.Smith@example.com"),
                        "bill": attendee("mailto:bill@example.com")
                    }),
                ),
                event(
                    "rights-open",
                    "mailto:jdoe@example.com",
                    json!({ "john": owner("mailto:jdoe@example.com") }),
                )
                .with_property("mayInviteSelf", true),
                event(
                    "rights-jane-owner",
                    "mailto:jane.smith@example.com",
                    json!({ "jane": owner("mailto:jane.smith@example.com") }),
                ),
                event(
                    "rights-others",
                    "mailto:jdoe@example.com",
                    json!({ "john": owner("mailto:jdoe@example.com") }),
                )
                .with_property("mayInviteOthers", true),
                event(
                    "rights-occurrence-owner",
                    "mailto:jdoe@example.com",
                    json!({ "john": owner("mailto:jdoe@example.com") }),
                )
                .with_property(
                    "recurrenceOverrides",
                    json!({
                        "2026-06-02T09:00:00": {
                            "participants/jane": owner("mailto:jane.smith@example.com")
                        }
                    }),
                ),
                event(
                    "rights-transfer",
                    "mailto:jane.smith@example.com",
                    json!({ "jane": owner("mailto:jane.smith@example.com") }),
                ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let invited_id = response.created(0).id().to_string();
    let open_id = response.created(1).id().to_string();
    let jane_owner_id = response.created(2).id().to_string();
    let others_id = response.created(3).id().to_string();
    let occurrence_owner_id = response.created(4).id().to_string();
    let transfer_id = response.created(5).id().to_string();
    let update = async |id: &str, patch: Value| {
        jane.jmap_method_call(
            "CalendarEvent/set",
            json!({ "accountId": &john_id, "update": { id: patch } }),
        )
        .await
    };
    let assert_updated = async |id: &str, patch: Value| {
        let response = update(id, patch.clone()).await;
        response.updated(id);
    };
    let assert_forbidden = async |id: &str, patch: Value| {
        let response = update(id, patch.clone()).await;
        assert_eq!(
            response.not_updated(id).typ(),
            "forbidden",
            "{patch}: {response:?}"
        );
    };

    // mayRSVP allows replying as one of the user's identities, and nothing else
    share(json!({"mayReadItems": true, "mayRSVP": true})).await;
    assert_updated(
        &invited_id,
        json!({"participants/jane/participationStatus": "accepted"}),
    )
    .await;
    assert_updated(
        &invited_id,
        json!({
            "recurrenceOverrides": {
                "2026-06-02T09:00:00": { "participants/jane/participationStatus": "declined" }
            }
        }),
    )
    .await;
    assert_forbidden(
        &invited_id,
        json!({"participants/bill/participationStatus": "accepted"}),
    )
    .await;
    assert_forbidden(&invited_id, json!({"title": "Changed"})).await;
    assert_forbidden(&invited_id, json!({"keywords": {"mine": true}})).await;

    // Adding or removing occurrences is not a reply
    for patch in [
        json!({"recurrenceOverrides/2026-07-15T09:00:00": {}}),
        json!({
            "recurrenceOverrides/2026-07-16T09:00:00": {
                "participants/jane/participationStatus": "accepted"
            }
        }),
    ] {
        assert_forbidden(&invited_id, patch).await;
    }
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &invited_id,
            json!({"recurrenceOverrides/2026-07-20T09:00:00": {}}),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&invited_id);
    assert_forbidden(
        &invited_id,
        json!({"recurrenceOverrides/2026-07-20T09:00:00": null}),
    )
    .await;

    // The same rules apply to CalDAV, client bookkeeping properties are ignored
    let dav = jane.webdav_client();
    let invited_path = event_dav_path(test, john, &invited_id).await;
    let calendar_path = invited_path
        .rsplit_once('/')
        .map(|(folder, _)| format!("{folder}/"))
        .unwrap();
    let invited_ical = dav_get(&dav, &invited_path).await;
    let mut replaced = 0;
    let jane_replies = invited_ical
        .lines()
        .map(|line| {
            if line.to_ascii_lowercase().contains("jane.smith@example.com")
                && line.contains("PARTSTAT=ACCEPTED")
            {
                replaced += 1;
                line.replace("PARTSTAT=ACCEPTED", "PARTSTAT=TENTATIVE")
            } else if line.starts_with("DTSTAMP:") {
                "DTSTAMP:20260105T000000Z\r\nLAST-MODIFIED:20260105T000000Z".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    assert!(replaced > 0, "{invited_ical}");
    dav.request(
        "PUT",
        &invited_path,
        invited_ical.replace("SUMMARY:Rights", "SUMMARY:Changed"),
    )
    .await
    .with_status(StatusCode::FORBIDDEN);
    assert!(
        invited_ical.contains("RRULE:FREQ=DAILY;COUNT=3\r\n"),
        "{invited_ical}"
    );
    dav.request(
        "PUT",
        &invited_path,
        invited_ical.replace(
            "RRULE:FREQ=DAILY;COUNT=3\r\n",
            "RRULE:FREQ=DAILY;COUNT=3\r\nRDATE:20260801T090000Z\r\n",
        ),
    )
    .await
    .with_status(StatusCode::FORBIDDEN);
    dav.request("PUT", &invited_path, jane_replies.as_str())
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_eq!(
        jane.jmap_get_account(
            john,
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::Participants],
            [&invited_id],
        )
        .await
        .list()[0]["participants"]["jane"]["participationStatus"],
        json!("tentative")
    );

    // Every instance of a resource is compared
    let instances_path = format!("{calendar_path}rights-instances.ics");
    let instances = |second_start: &str, second_partstat: &str| {
        let instance = |recurrence_id: &str, start: &str, partstat: &str| {
            format!(
                concat!(
                    "BEGIN:VEVENT\r\n",
                    "UID:rights-instances\r\n",
                    "DTSTAMP:20260101T000000Z\r\n",
                    "RECURRENCE-ID:{}\r\n",
                    "DTSTART:{}\r\n",
                    "DURATION:PT1H\r\n",
                    "SUMMARY:Instance\r\n",
                    "ORGANIZER:mailto:jdoe@example.com\r\n",
                    "ATTENDEE;PARTSTAT=ACCEPTED:mailto:jdoe@example.com\r\n",
                    "ATTENDEE;PARTSTAT={}:mailto:jane.smith@example.com\r\n",
                    "END:VEVENT\r\n"
                ),
                recurrence_id, start, partstat
            )
        };
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Stalwart//Test//EN\r\n{}{}END:VCALENDAR\r\n",
            instance("20260602T090000Z", "20260602T090000Z", "NEEDS-ACTION"),
            instance("20260603T090000Z", second_start, second_partstat)
        )
    };
    john.webdav_client()
        .request(
            "PUT",
            &instances_path,
            instances("20260603T090000Z", "NEEDS-ACTION"),
        )
        .await
        .with_status(StatusCode::CREATED);
    dav.request(
        "PUT",
        &instances_path,
        instances("20260604T090000Z", "NEEDS-ACTION"),
    )
    .await
    .with_status(StatusCode::FORBIDDEN);
    dav.request(
        "PUT",
        &instances_path,
        instances("20260603T090000Z", "ACCEPTED"),
    )
    .await
    .with_status(StatusCode::NO_CONTENT);

    // Adding yourself requires mayInviteSelf on the event, others require mayInviteOthers
    assert_forbidden(
        &open_id,
        json!({"participants/jane": owner("mailto:jane.smith@example.com")}),
    )
    .await;
    assert_forbidden(
        &others_id,
        json!({"participants/carl": attendee("mailto:carl@example.com")}),
    )
    .await;
    for (event_id, attendee_line) in [
        (
            &open_id,
            "ATTENDEE;ROLE=CHAIR;PARTSTAT=ACCEPTED:mailto:jane.smith@example.com",
        ),
        (
            &others_id,
            "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carl@example.com",
        ),
    ] {
        let path = event_dav_path(test, john, event_id).await;
        let ical = dav_get(&dav, &path).await;
        dav.request(
            "PUT",
            &path,
            ical.replacen("END:VEVENT", &format!("{attendee_line}\r\nEND:VEVENT"), 1),
        )
        .await
        .with_status(StatusCode::FORBIDDEN);
    }
    assert_updated(
        &open_id,
        json!({"participants/jane": attendee("mailto:jane.smith@example.com")}),
    )
    .await;
    assert_forbidden(
        &open_id,
        json!({"participants/carl": attendee("mailto:carl@example.com")}),
    )
    .await;
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(&open_id, json!({"mayInviteOthers": true}))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&open_id);
    assert_updated(
        &open_id,
        json!({"participants/carl": attendee("mailto:carl@example.com")}),
    )
    .await;
    assert_forbidden(
        &open_id,
        json!({"participants/dave": owner("mailto:dave@example.com")}),
    )
    .await;
    assert_forbidden(
        &invited_id,
        json!({"participants/erin": attendee("mailto:erin@example.com")}),
    )
    .await;

    // mayUpdatePrivate allows personal properties only
    share(json!({"mayReadItems": true, "mayUpdatePrivate": true})).await;
    assert_updated(&invited_id, json!({"keywords": {"mine": true}})).await;
    assert_forbidden(
        &invited_id,
        json!({"participants/jane/participationStatus": "declined"}),
    )
    .await;

    let invited_ical = dav_get(&dav, &invited_path).await;
    dav.request(
        "PUT",
        &invited_path,
        invited_ical.replacen(
            "END:VEVENT",
            "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT",
            1,
        ),
    )
    .await
    .with_status(StatusCode::NO_CONTENT);
    dav.request(
        "PUT",
        &invited_path,
        invited_ical.replace("SUMMARY:Rights", "SUMMARY:Changed"),
    )
    .await
    .with_status(StatusCode::FORBIDDEN);

    // mayWriteOwn allows changes to events owned by the user or without owner
    share(json!({"mayReadItems": true, "mayWriteOwn": true})).await;
    dav.request("DELETE", &invited_path, "")
        .await
        .with_status(StatusCode::FORBIDDEN);
    let own_path = format!("{calendar_path}dav-no-owner.ics");
    dav.request(
        "PUT",
        &own_path,
        concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:-//Stalwart//Test//EN\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:dav-no-owner\r\n",
            "DTSTAMP:20260101T000000Z\r\n",
            "DTSTART:20260601T090000Z\r\n",
            "DURATION:PT1H\r\n",
            "SUMMARY:No owner\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ),
    )
    .await
    .with_status(StatusCode::CREATED);

    // COPY and MOVE of events follow the same ownership rules
    let target_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Rights target", "shareWith": { &jane_id: {"mayReadItems": true} }})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let target_path = resource_dav_path(test, john, &target_id, true).await;
    let own_copy_path = format!("{target_path}dav-no-owner-copy.ics");
    let own_move_path = format!("{target_path}dav-no-owner-move.ics");
    let copy_move = async |method: &str, from: &str, to: &str, status: StatusCode| {
        dav.request_with_headers(method, from, [("destination", to)], "")
            .await
            .with_status(status);
    };
    copy_move("COPY", &own_path, &own_copy_path, StatusCode::FORBIDDEN).await;
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &target_id,
            json!({ "shareWith": { &jane_id: {"mayReadItems": true, "mayWriteOwn": true} } }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&target_id);
    let invited_target_path = format!("{target_path}invited.ics");
    for method in ["COPY", "MOVE"] {
        copy_move(
            method,
            &invited_path,
            &invited_target_path,
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    copy_move("COPY", &own_path, &own_copy_path, StatusCode::CREATED).await;
    dav.request("DELETE", &own_copy_path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    dav.request(
        "PUT",
        &own_move_path,
        concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:-//Stalwart//Test//EN\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:dav-no-owner-target\r\n",
            "DTSTAMP:20260101T000000Z\r\n",
            "DTSTART:20260602T090000Z\r\n",
            "DURATION:PT1H\r\n",
            "SUMMARY:No owner target\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ),
    )
    .await
    .with_status(StatusCode::CREATED);
    copy_move("MOVE", &own_path, &own_move_path, StatusCode::NO_CONTENT).await;
    copy_move("MOVE", &own_move_path, &own_path, StatusCode::CREATED).await;
    dav.request("DELETE", &own_path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_forbidden(&invited_id, json!({"title": "Changed"})).await;
    assert_updated(&jane_owner_id, json!({"title": "Changed"})).await;

    // Ownership comes from the participants of the series and cannot be self-granted
    assert_forbidden(&occurrence_owner_id, json!({"title": "Changed"})).await;
    assert_forbidden(&invited_id, json!({"participants/jane/roles/owner": true})).await;
    let invited_ical = dav_get(&dav, &invited_path).await;
    let jane_owns = invited_ical
        .lines()
        .map(|line| {
            if line.starts_with("ATTENDEE")
                && line.to_ascii_lowercase().contains("jane.smith@example.com")
            {
                line.replacen("ATTENDEE", "ATTENDEE;ROLE=CHAIR", 1)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    assert!(jane_owns.contains("ROLE=CHAIR"), "{invited_ical}");
    dav.request("PUT", &invited_path, jane_owns.as_str())
        .await
        .with_status(StatusCode::FORBIDDEN);

    // Owners may transfer the ownership of their events
    assert_updated(
        &transfer_id,
        json!({
            "organizerCalendarAddress": "mailto:bill@example.com",
            "participants/jane/roles": {"attendee": true},
            "participants/bill": owner("mailto:bill@example.com")
        }),
    )
    .await;
    assert_forbidden(&transfer_id, json!({"title": "Mine again"})).await;

    let response = jane
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "create": {
                    "i0": {
                        "calendarIds": {&calendar_id: true},
                        "uid": "rights-no-owner",
                        "title": "No owner",
                        "start": "2026-06-01T09:00:00",
                        "duration": "PT1H"
                    },
                    "i1": event(
                        "rights-other-owner",
                        "mailto:bill@example.com",
                        json!({ "bill": owner("mailto:bill@example.com") }),
                    ),
                    "i2": {
                        "calendarIds": {&calendar_id: true},
                        "uid": "rights-assigned-organizer",
                        "title": "Assigned organizer",
                        "start": "2026-06-01T09:00:00",
                        "duration": "PT1H",
                        "participants": { "bill": attendee("mailto:bill@example.com") }
                    }
                },
                "destroy": [&invited_id, &jane_owner_id]
            }),
        )
        .await;
    let no_owner_id = response.created(0).id().to_string();
    assert_eq!(response.not_created(1).typ(), "forbidden", "{response:?}");
    assert_eq!(response.not_created(2).typ(), "forbidden", "{response:?}");
    assert_eq!(
        response.method_response()["notDestroyed"][&invited_id]["type"],
        json!("forbidden"),
        "{response:?}"
    );
    assert_eq!(
        response.destroyed().collect::<Vec<_>>(),
        [jane_owner_id.as_str()],
        "{response:?}"
    );
    assert_updated(&no_owner_id, json!({"title": "Still no owner"})).await;

    // mayWriteAll implies the other write rights
    share(json!({"mayReadItems": true, "mayWriteAll": true})).await;
    let rights = jane
        .jmap_get_account(
            john,
            MethodObject::Calendar,
            [CalendarProperty::MyRights],
            [&calendar_id],
        )
        .await
        .list()[0]["myRights"]
        .clone();
    for right in ["mayWriteOwn", "mayUpdatePrivate", "mayRSVP"] {
        assert_eq!(rights[right], json!(true), "{rights}");
    }
    assert_updated(&invited_id, json!({"title": "Changed"})).await;

    // The owner is notified with the event before the change and a patch
    let notifications = john
        .jmap_method_call(
            "CalendarEventNotification/get",
            json!({
                "accountId": &john_id,
                "ids": null,
                "properties": ["type", "calendarEventId", "changedBy", "event", "eventPatch"]
            }),
        )
        .await;
    let notification = notifications
        .list()
        .iter()
        .rev()
        .find(|notification| {
            notification["type"] == json!("updated")
                && notification["calendarEventId"] == json!(&invited_id)
                && notification["eventPatch"]["title"] == json!("Changed")
        })
        .unwrap_or_else(|| panic!("{notifications:?}"));
    assert_eq!(notification["event"]["title"], json!("Rights"));
    assert_eq!(
        notification["changedBy"]["principalId"],
        json!(&jane_id),
        "{notification:?}"
    );
    assert!(
        notifications
            .list()
            .iter()
            .any(|notification| notification["type"] == json!("destroyed")),
        "{notifications:?}"
    );
}

async fn related_alerts_keep_the_event_uid(test: &TestServer, john: &Account) {
    let uid = "related-alerts@example.com";
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Related alerts"})],
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
                "calendarIds": { &calendar_id: true },
                "uid": uid,
                "title": "Snoozed",
                "start": "2030-05-01T10:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "alerts": {
                    "original": {
                        "@type": "Alert",
                        "trigger": { "@type": "OffsetTrigger", "offset": "-PT15M" },
                        "acknowledged": "2030-05-01T09:46:00Z"
                    },
                    "snooze": {
                        "@type": "Alert",
                        "trigger": { "@type": "AbsoluteTrigger", "when": "2030-05-01T09:55:00Z" },
                        "relatedTo": {
                            "original": { "@type": "Relation", "relation": { "snooze": true } }
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
    let events_with_uid = async || {
        john.jmap_method_call(
            "CalendarEvent/query",
            json!({ "accountId": john.id_string(), "filter": { "uid": uid } }),
        )
        .await
        .method_response()["ids"]
            .clone()
    };

    let dav = john.webdav_client();
    let path = event_dav_path(test, john, &event_id).await;
    let ical = dav_get(&dav, &path).await;
    assert_eq!(ical.matches("\r\nUID:").count(), 2, "{ical}");
    assert!(ical.contains("RELATED-TO;RELTYPE=SNOOZE:"), "{ical}");
    assert_eq!(events_with_uid().await, json!([&event_id]));

    john.jmap_update(
        MethodObject::CalendarEvent,
        [(&event_id, json!({ "title": "Snoozed and renamed" }))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&event_id);
    assert_eq!(events_with_uid().await, json!([&event_id]));
    let event = john
        .jmap_get(MethodObject::CalendarEvent, ["uid", "alerts"], [&event_id])
        .await
        .list()[0]
        .clone();
    assert_eq!(event["uid"], json!(uid), "{event}");
    assert_eq!(
        event["alerts"]["snooze"]["relatedTo"]["original"]["relation"],
        json!({ "snooze": true }),
        "{event}"
    );

    let ical = dav_get(&dav, &path).await;
    dav.request("PUT", &path, ical.as_str())
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_eq!(events_with_uid().await, json!([&event_id]));

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

pub(crate) async fn event_dav_path(test: &TestServer, account: &Account, event_id: &str) -> String {
    resource_dav_path(test, account, event_id, false).await
}

async fn resource_dav_path(
    test: &TestServer,
    account: &Account,
    id: &str,
    is_container: bool,
) -> String {
    let account_id = account.id().document_id();
    let document_id = Id::from_str(id).unwrap().document_id();
    let resources = test
        .server
        .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .unwrap();
    let path = resources
        .paths
        .iter()
        .find(|(_, path)| {
            (path.parent_id == NO_ID) == is_container && path.document_id == document_id
        })
        .map(|(chunk, path)| std::str::from_utf8(&chunk.bytes[path.path.range()]).unwrap())
        .unwrap();
    if is_container {
        format!("{}{path}/", resources.base_path)
    } else {
        format!("{}{path}", resources.base_path)
    }
}

async fn event_id_by_uid(test: &TestServer, account: &Account, uid: &str) -> String {
    let account_id = account.id().document_id();
    let resources = test
        .server
        .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .unwrap();
    let document_id = resources
        .resources
        .iter()
        .find(|resource| resource.uid() == Some(uid))
        .map(|resource| resource.document_id())
        .unwrap_or_else(|| panic!("no event with uid {uid}"));
    Id::from(document_id).to_string()
}

pub(crate) async fn dav_get(client: &DummyWebDavClient, path: &str) -> String {
    client
        .request("GET", path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .replace("\r\n ", "")
}

async fn server_set_values(test: &TestServer, john: &Account) {
    let john_id = john.id_string().to_string();
    let response = john
        .jmap_method_call(
            "Calendar/set",
            json!({ "accountId": &john_id, "create": { "i0": { "name": "Server set" } } }),
        )
        .await;
    let created = response.created(0);
    let calendar_id = created["id"].as_str().unwrap().to_string();
    for (property, value) in [
        ("sortOrder", json!(0)),
        ("isSubscribed", json!(true)),
        ("isVisible", json!(true)),
        ("isDefault", json!(false)),
        ("includeInAvailability", json!("all")),
        ("defaultAlertsWithTime", json!({})),
    ] {
        assert_eq!(created[property], value, "{property}: {response:?}");
    }
    assert_eq!(
        created["myRights"]["mayWriteAll"],
        json!(true),
        "{response:?}"
    );
    assert!(created.get("name").is_none(), "{response:?}");

    // Events report the values set by the server on create and update
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "create": {
                    "i0": {
                        "calendarIds": { &calendar_id: true },
                        "title": "Server set",
                        "utcStart": "2026-08-01T09:00:00Z",
                        "duration": "PT1H"
                    }
                }
            }),
        )
        .await;
    let created = response.created(0);
    let event_id = created["id"].as_str().unwrap().to_string();
    for property in [
        "uid", "@type", "created", "updated", "isOrigin", "start", "timeZone",
    ] {
        assert!(
            created.get(property).is_some_and(|value| !value.is_null()),
            "{property}: {response:?}"
        );
    }
    assert_eq!(created["@type"], json!("Event"), "{response:?}");
    assert!(created.get("title").is_none(), "{response:?}");
    assert!(created.get("duration").is_none(), "{response:?}");

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": { &event_id: { "title": "Server set (changed)" } }
            }),
        )
        .await;
    let updated = response.updated(&event_id);
    assert_eq!(updated["sequence"], json!(1), "{response:?}");
    assert!(updated["updated"].is_string(), "{response:?}");
    assert!(updated.get("uid").is_none(), "{response:?}");
    assert!(updated.get("title").is_none(), "{response:?}");

    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": { &event_id: { "title": "Explicit", "sequence": 7 } }
            }),
        )
        .await;
    assert!(
        response.updated(&event_id).get("sequence").is_none(),
        "{response:?}"
    );

    // Per-user properties of the owner do not change the updated time
    let updated_time = async || {
        john.jmap_get(
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::Id, JSCalendarProperty::Updated],
            [&event_id],
        )
        .await
        .list()[0]["updated"]
            .clone()
    };
    let before = updated_time().await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": { &event_id: { "keywords": {"personal": true}, "color": "red" } }
            }),
        )
        .await;
    let updated = response.updated(&event_id);
    assert!(updated.get("updated").is_none(), "{response:?}");
    assert!(updated.get("sequence").is_none(), "{response:?}");
    assert_eq!(updated_time().await, before);

    // An object returned by /get is a valid patch
    let mut event = john
        .jmap_method_call(
            "CalendarEvent/get",
            json!({ "accountId": &john_id, "ids": [&event_id] }),
        )
        .await
        .list()[0]
        .clone();
    event["title"] = json!("Echoed");
    event["baseEventId"] = Value::Null;
    event["method"] = Value::Null;
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({ "accountId": &john_id, "update": { &event_id: &event } }),
        )
        .await;
    let updated = response.updated(&event_id);
    assert_eq!(updated["sequence"], json!(8), "{response:?}");
    assert!(updated.get("title").is_none(), "{response:?}");
    assert!(updated.get("isOrigin").is_none(), "{response:?}");
    for (property, value) in [
        ("isOrigin", json!(false)),
        ("baseEventId", json!(&event_id)),
        ("method", json!("request")),
    ] {
        let response = john
            .jmap_method_call(
                "CalendarEvent/set",
                json!({ "accountId": &john_id, "update": { &event_id: { property: value } } }),
            )
            .await;
        assert_eq!(
            response.not_updated(&event_id).typ(),
            "invalidProperties",
            "{property}: {response:?}"
        );
    }

    // Organizers and participants assigned by the server are reported
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "create": {
                    "i0": {
                        "calendarIds": { &calendar_id: true },
                        "title": "Organizer",
                        "start": "2026-08-02T09:00:00",
                        "timeZone": "Etc/UTC",
                        "duration": "PT1H",
                        "participants": {
                            "jane": {
                                "@type": "Participant",
                                "calendarAddress": "mailto:jane.smith@example.com",
                                "roles": { "attendee": true }
                            }
                        }
                    }
                }
            }),
        )
        .await;
    let created = response.created(0);
    assert_eq!(
        created["organizerCalendarAddress"],
        json!("mailto:jdoe@example.com"),
        "{response:?}"
    );
    let participants = created["participants"]
        .as_object()
        .unwrap_or_else(|| panic!("participants not reported: {response:?}"));
    assert_eq!(participants.len(), 2, "{response:?}");
    assert!(
        participants
            .values()
            .any(|participant| participant["calendarAddress"] == json!("mailto:jdoe@example.com")),
        "{response:?}"
    );
    assert!(created.get("start").is_none(), "{response:?}");

    // Updates through an instance id report the values set by the server
    let recurring_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "title": "Recurring",
                "start": "2026-08-03T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "recurrenceRule": { "@type": "RecurrenceRule", "frequency": "daily", "count": 3 }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let instance_id = john
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": &john_id,
                "expandRecurrences": true,
                "filter": {
                    "inCalendar": &calendar_id,
                    "after": "2026-08-04T00:00:00",
                    "before": "2026-08-05T00:00:00"
                }
            }),
        )
        .await
        .ids()
        .next()
        .expect("expanded instance")
        .to_string();
    assert_ne!(instance_id, recurring_id);
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({ "accountId": &john_id, "update": { &instance_id: { "title": "Moved" } } }),
        )
        .await;
    assert_eq!(
        response.updated(&instance_id)["sequence"],
        json!(1),
        "{response:?}"
    );

    // Blob ids replaced by the server are returned
    let upload = async |data: &str| {
        let response = john
            .jmap_method_call(
                "Blob/upload",
                json!({
                    "accountId": &john_id,
                    "create": { "b": { "data": [{ "data:asBase64": data }], "type": "image/png" } }
                }),
            )
            .await;
        response.method_response()["created"]["b"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("upload failed: {response:?}"))
            .to_string()
    };
    let png_blob = upload("iVBORw0KGgo=").await;
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "create": {
                    "i0": {
                        "calendarIds": { &calendar_id: true },
                        "title": "Blobs",
                        "start": "2026-08-06T09:00:00",
                        "timeZone": "Etc/UTC",
                        "links": {
                            "png": { "@type": "Link", "blobId": &png_blob, "contentType": "image/png" }
                        }
                    }
                }
            }),
        )
        .await;
    let created = response.created(0);
    let blob_event_id = created["id"].as_str().unwrap().to_string();
    let links = |event: &Value| event["links"].clone();
    let blob_event = async || {
        john.jmap_method_call(
            "CalendarEvent/get",
            json!({ "accountId": &john_id, "ids": [&blob_event_id] }),
        )
        .await
        .list()[0]
            .clone()
    };
    let created_png = created["links"]["png"]["blobId"]
        .as_str()
        .unwrap_or_else(|| panic!("links not reported: {response:?}"))
        .to_string();
    assert_ne!(created_png, png_blob);
    assert_eq!(links(created), links(&blob_event().await));
    let other_blob = upload("iVBORw0KGgoAAAA=").await;
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": {
                    &blob_event_id: {
                        "links/other": { "@type": "Link", "blobId": &other_blob, "contentType": "image/png" }
                    }
                }
            }),
        )
        .await;
    let updated = response.updated(&blob_event_id);
    assert_ne!(
        updated["links"]["other"]["blobId"],
        json!(&other_blob),
        "{response:?}"
    );
    assert_eq!(links(updated), links(&blob_event().await), "{response:?}");
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": {
                    &blob_event_id: {
                        "links/copy": { "@type": "Link", "blobId": &created_png, "contentType": "image/png" }
                    }
                }
            }),
        )
        .await;
    assert!(
        response.updated(&blob_event_id).get("links").is_none(),
        "{response:?}"
    );

    // Blob ids replaced by the server are returned for updates through instance ids
    let instance_blob = upload("iVBORw0KGgoAAAAB").await;
    let blob_series_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "title": "Blob series",
                "start": "2026-08-10T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "recurrenceRule": { "@type": "RecurrenceRule", "frequency": "daily", "count": 3 }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let blob_instance_id = john
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": &john_id,
                "expandRecurrences": true,
                "filter": {
                    "inCalendar": &calendar_id,
                    "after": "2026-08-11T00:00:00",
                    "before": "2026-08-12T00:00:00"
                }
            }),
        )
        .await
        .ids()
        .next()
        .expect("expanded instance")
        .to_string();
    assert_ne!(blob_instance_id, blob_series_id);
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": {
                    &blob_instance_id: {
                        "links": {
                            "png": {
                                "@type": "Link",
                                "blobId": &instance_blob,
                                "contentType": "image/png"
                            }
                        }
                    }
                }
            }),
        )
        .await;
    let updated = response.updated(&blob_instance_id);
    assert!(
        updated["links"]["png"]["blobId"].is_string(),
        "{response:?}"
    );
    assert_ne!(
        updated["links"]["png"]["blobId"],
        json!(&instance_blob),
        "{response:?}"
    );
    let stored_instance = john
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": &john_id,
                "ids": [&blob_instance_id],
                "properties": ["links"]
            }),
        )
        .await
        .list()[0]
        .clone();
    assert_eq!(links(updated), links(&stored_instance), "{response:?}");

    // Participant identities report defaults and normalized addresses
    let identity_ids = john
        .jmap_method_call(
            "ParticipantIdentity/get",
            json!({ "accountId": &john_id, "ids": null, "properties": ["id"] }),
        )
        .await
        .list()
        .iter()
        .map(|identity| identity["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    john.jmap_method_call(
        "ParticipantIdentity/set",
        json!({ "accountId": &john_id, "destroy": identity_ids }),
    )
    .await;
    let response = john
        .jmap_method_call(
            "ParticipantIdentity/set",
            json!({
                "accountId": &john_id,
                "create": { "i0": { "calendarAddress": "jdoe@example.com" } }
            }),
        )
        .await;
    let created = response.created(0);
    assert_eq!(
        created["calendarAddress"],
        json!("mailto:jdoe@example.com"),
        "{response:?}"
    );
    assert!(created["name"].is_string(), "{response:?}");
    assert!(created["isDefault"].is_boolean(), "{response:?}");

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(john.id().document_id())
        .with_collection(Collection::Principal)
        .with_document(0)
        .clear(PrincipalField::ParticipantIdentities);
    test.server.commit_batch(batch).await.unwrap();
}

async fn event_sequence(john: &Account) {
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Sequence"})],
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
                "calendarIds": {&calendar_id: true},
                "uid": "sequence",
                "title": "Sequence",
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
    let sequence = async || {
        john.jmap_get(
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::Sequence],
            [&event_id],
        )
        .await
        .list()[0]["sequence"]
            .as_u64()
            .unwrap_or_default()
    };
    let update = async |patch: Value| {
        john.jmap_update(
            MethodObject::CalendarEvent,
            [(&event_id, patch)],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&event_id);
    };
    let initial = sequence().await;

    // Changing a shared property increments the sequence
    update(json!({"title": "Sequence (changed)"})).await;
    assert_eq!(sequence().await, initial + 1);

    // Per-user properties do not
    update(json!({"keywords": {"personal": true}, "color": "red"})).await;
    assert_eq!(sequence().await, initial + 1);

    // A higher sequence from the client is kept, a lower one is incremented
    update(json!({"title": "Raised", "sequence": initial + 5})).await;
    assert_eq!(sequence().await, initial + 5);
    update(json!({"title": "Lowered", "sequence": initial + 2})).await;
    assert_eq!(sequence().await, initial + 6);
    update(json!({"sequence": 0})).await;
    assert_eq!(sequence().await, initial + 7);

    // Scheduling flags are not per-user, alerts and free/busy status are
    let mut expected = initial + 7;
    for patch in [
        json!({"hideAttendees": true}),
        json!({"mayInviteSelf": true}),
        json!({"mayInviteOthers": true}),
    ] {
        update(patch.clone()).await;
        expected += 1;
        assert_eq!(sequence().await, expected, "{patch}");
    }
    for patch in [
        json!({"freeBusyStatus": "free"}),
        json!({
            "alerts": {
                "a1": {
                    "@type": "Alert",
                    "trigger": {"@type": "OffsetTrigger", "offset": "-PT5M"}
                }
            }
        }),
        json!({"useDefaultAlerts": true}),
    ] {
        update(patch.clone()).await;
        assert_eq!(sequence().await, expected, "{patch}");
    }
}

async fn event_override_patches(john: &Account) {
    const RID: &str = "2025-03-05T09:00:00";
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Override patches"})],
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
                "calendarIds": {&calendar_id: true},
                "uid": "override-patches",
                "title": "FooBar team meeting",
                "start": "2025-01-08T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "recurrenceRule": {
                    "@type": "RecurrenceRule",
                    "frequency": "weekly",
                    "count": 20
                },
                "organizerCalendarAddress": "mailto:zoe@foobar.example.com",
                "participants": {
                    "tom": {
                        "@type": "Participant",
                        "name": "Tom",
                        "calendarAddress": "mailto:tom@foobar.example.com",
                        "participationStatus": "accepted",
                        "roles": { "attendee": true }
                    },
                    "zoe": {
                        "@type": "Participant",
                        "name": "Zoe",
                        "calendarAddress": "mailto:zoe@foobar.example.com",
                        "participationStatus": "accepted",
                        "roles": { "owner": true, "attendee": true, "chair": true }
                    }
                },
                "recurrenceOverrides": {
                    RID: {
                        "start": "2025-03-05T10:00:00",
                        "participants/tom/participationStatus": "declined"
                    }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let overrides = async || {
        john.jmap_get(
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::RecurrenceOverrides],
            [&event_id],
        )
        .await
        .list()[0]["recurrenceOverrides"]
            .clone()
    };
    let update = async |patch: Value| {
        john.jmap_update(
            MethodObject::CalendarEvent,
            [(&event_id, patch)],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&event_id);
    };
    assert_eq!(
        overrides().await,
        json!({ RID: {
            "start": "2025-03-05T10:00:00",
            "participants/tom/participationStatus": "declined"
        }})
    );

    // Figures 2 and 3: an escaped pointer adds a key to the override patch
    update(json!({
        format!("recurrenceOverrides/{RID}/participants~1zoe~1participationStatus"): "declined"
    }))
    .await;
    assert_eq!(
        overrides().await,
        json!({ RID: {
            "start": "2025-03-05T10:00:00",
            "participants/tom/participationStatus": "declined",
            "participants/zoe/participationStatus": "declined"
        }})
    );

    // Figure 4: null removes a key from the override patch
    update(json!({
        format!("recurrenceOverrides/{RID}/participants~1tom~1participationStatus"): null
    }))
    .await;
    assert_eq!(
        overrides().await,
        json!({ RID: {
            "start": "2025-03-05T10:00:00",
            "participants/zoe/participationStatus": "declined"
        }})
    );

    // Figure 6: replacing the override patch keeps null values
    update(json!({
        format!("recurrenceOverrides/{RID}"): {
            "start": "2025-03-05T10:00:00",
            "participants/zoe/participationStatus": "declined",
            "participants/tom": null
        }
    }))
    .await;
    assert_eq!(
        overrides().await,
        json!({ RID: {
            "start": "2025-03-05T10:00:00",
            "participants/zoe/participationStatus": "declined",
            "participants/tom": null
        }})
    );
}

async fn event_set(test: &TestServer, john: &Account) {
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Events", "timeZone": "Europe/Madrid"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let event = |uid: &str| {
        json!({
            "calendarIds": {&calendar_id: true},
            "uid": uid,
            "title": "Conformance",
            "start": "2026-03-02T10:00:00",
            "timeZone": "Europe/Madrid",
            "duration": "PT1H"
        })
    };

    // Nulls on create are ignored, created is set and updated is stamped
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                event("null-values").with_property("description", Value::Null),
                event("draft").with_property("isDraft", true),
                event("future-created").with_property("created", "2999-01-01T00:00:00Z"),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let null_id = response.created(0).id().to_string();
    let draft_id = response.created(1).id().to_string();
    let future_id = response.created(2).id().to_string();
    let response = john
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::Description,
                JSCalendarProperty::Created,
                JSCalendarProperty::Updated,
            ],
            [&null_id, &future_id],
        )
        .await;
    let list = response.list();
    assert_eq!(list[0].get("description"), None);
    assert!(list[0]["created"].is_string(), "{:?}", list[0]);
    assert!(list[0]["updated"].is_string(), "{:?}", list[0]);
    assert!(
        list[1]["created"].as_str().unwrap() <= list[1]["updated"].as_str().unwrap(),
        "{:?}",
        list[1]
    );
    assert_ne!(
        list[1]["created"],
        json!("2999-01-01T00:00:00Z"),
        "{:?}",
        list[1]
    );

    // isDraft can be cleared but never set again
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(&draft_id, json!({"isDraft": false}))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&draft_id);
    assert_eq!(
        john.jmap_update(
            MethodObject::CalendarEvent,
            [(&draft_id, json!({"isDraft": true}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&draft_id)
        .typ(),
        "invalidProperties"
    );

    // A null JMAP boolean property on update means its default value
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &draft_id,
            json!({
                "isDraft": null,
                "mayInviteSelf": null,
                "mayInviteOthers": null,
                "hideAttendees": null,
                "useDefaultAlerts": null
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&draft_id);
    john.jmap_get(
        MethodObject::CalendarEvent,
        [
            JSCalendarProperty::<Id>::Id,
            JSCalendarProperty::IsDraft,
            JSCalendarProperty::MayInviteSelf,
            JSCalendarProperty::MayInviteOthers,
            JSCalendarProperty::HideAttendees,
            JSCalendarProperty::UseDefaultAlerts,
        ],
        [&draft_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
            "id": &draft_id,
            "isDraft": false,
            "mayInviteSelf": false,
            "mayInviteOthers": false,
            "hideAttendees": false,
            "useDefaultAlerts": false
        }));

    // Unknown and vendor-specific properties are preserved
    let vendor_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [event("vendor-property")
                .with_property("example.com:color", "teal")
                .with_property("futureProperty", json!({"a": 1}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let vendor_event = async || {
        john.jmap_method_call(
            "CalendarEvent/get",
            json!({"accountId": john.id_string(), "ids": [&vendor_id]}),
        )
        .await
        .list()[0]
            .clone()
    };
    let event_value = vendor_event().await;
    assert_eq!(
        event_value["example.com:color"],
        json!("teal"),
        "{event_value}"
    );
    assert_eq!(
        event_value["futureProperty"],
        json!({"a": 1}),
        "{event_value}"
    );
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &vendor_id,
            json!({"example.com:color": {"light": "teal"}, "futureProperty": null}),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&vendor_id);
    let event_value = vendor_event().await;
    assert_eq!(
        event_value["example.com:color"],
        json!({"light": "teal"}),
        "{event_value}"
    );
    assert!(event_value.get("futureProperty").is_none(), "{event_value}");
    assert_eq!(
        john.jmap_create(
            MethodObject::CalendarEvent,
            [event("invalid-property-name").with_property("invalid name", true)],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_created(0)
        .typ(),
        "invalidProperties"
    );

    // Pointers that cannot be applied on create are invalid properties
    assert_eq!(
        john.jmap_create(
            MethodObject::CalendarEvent,
            [event("create-pointer").with_property("locations/missing/name", "Nowhere")],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_created(0)
        .typ(),
        "invalidProperties"
    );

    // Events over the size limit are too large
    const MAX_ICALENDAR_SIZE: usize = 524_288;
    let large_description = "a".repeat(MAX_ICALENDAR_SIZE);
    assert_eq!(
        john.jmap_create(
            MethodObject::CalendarEvent,
            [event("too-large").with_property("description", large_description.as_str())],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_created(0)
        .typ(),
        "tooLarge"
    );
    assert_eq!(
        john.jmap_update(
            MethodObject::CalendarEvent,
            [(&vendor_id, json!({"description": large_description}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&vendor_id)
        .typ(),
        "tooLarge"
    );

    // The uid of an event cannot be removed
    assert_eq!(
        john.jmap_update(
            MethodObject::CalendarEvent,
            [(&vendor_id, json!({"uid": null}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&vendor_id)
        .typ(),
        "invalidProperties"
    );

    // utcStart alone takes the calendar time zone, utcEnd alone sets the duration
    let utc_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": {&calendar_id: true},
                "title": "UTC",
                "utcStart": "2026-03-02T09:00:00Z"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(&utc_id, json!({"utcEnd": "2026-03-02T11:30:00Z"}))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&utc_id);
    john.jmap_get(
        MethodObject::CalendarEvent,
        [
            JSCalendarProperty::<Id>::Start,
            JSCalendarProperty::TimeZone,
            JSCalendarProperty::Duration,
            JSCalendarProperty::UtcStart,
            JSCalendarProperty::UtcEnd,
        ],
        [&utc_id],
    )
    .await
    .list()[0]
        .assert_is_equal(json!({
            "id": &utc_id,
            "start": "2026-03-02T10:00:00",
            "timeZone": "Europe/Madrid",
            "duration": "PT2H30M",
            "utcStart": "2026-03-02T09:00:00Z",
            "utcEnd": "2026-03-02T11:30:00Z"
        }));

    // Invalid combinations
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                event("utc-start-and-start").with_property("utcStart", "2026-03-02T09:00:00Z"),
                event("utc-end-and-duration").with_property("utcEnd", "2026-03-02T11:00:00Z"),
                event("utc-in-override").with_property(
                    "recurrenceOverrides",
                    json!({"2026-03-03T10:00:00": {"utcStart": "2026-03-03T09:00:00Z"}}),
                ),
                event("too-many-participants").with_property(
                    "participants",
                    Value::Object(
                        (0..21)
                            .map(|i| {
                                (
                                    format!("p{i}"),
                                    json!({
                                        "@type": "Participant",
                                        "calendarAddress": format!("mailto:p{i}@example.org"),
                                        "roles": {"attendee": true}
                                    }),
                                )
                            })
                            .collect(),
                    ),
                ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for idx in 0..4 {
        assert_eq!(
            response.not_created(idx).typ(),
            "invalidProperties",
            "{idx}"
        );
    }
    assert_eq!(
        john.jmap_update(
            MethodObject::CalendarEvent,
            [(
                &utc_id,
                json!({"recurrenceOverrides/2026-03-03T10:00:00/utcStart": "2026-03-03T09:00:00Z"}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&utc_id)
        .typ(),
        "invalidProperties"
    );

    // Patching a path that does not exist is an invalidPatch
    assert_eq!(
        john.jmap_update(
            MethodObject::CalendarEvent,
            [(&utc_id, json!({"locations/missing/name": "Nowhere"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&utc_id)
        .typ(),
        "invalidPatch"
    );

    // utcStart falls back to Etc/UTC when the calendars do not share a time zone
    let utc_calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "UTC fallback", "timeZone": "Asia/Tokyo"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": {&calendar_id: true, &utc_calendar_id: true},
                "title": "UTC fallback",
                "utcStart": "2026-03-02T09:00:00Z"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(
        response.created(0)["timeZone"],
        json!("Etc/UTC"),
        "{response:?}"
    );
    assert_eq!(
        response.created(0)["start"],
        json!("2026-03-02T09:00:00"),
        "{response:?}"
    );

    // Recurrence overrides cannot change series properties or JMAP metadata
    const RID: &str = "2026-03-03T10:00:00";
    let series = || {
        event("override-validation").with_property(
            "recurrenceRule",
            json!({"@type": "RecurrenceRule", "frequency": "daily", "count": 3}),
        )
    };
    let forbidden = [
        ("@type", json!("Task")),
        ("method", json!("request")),
        ("organizerCalendarAddress", json!("mailto:zoe@example.com")),
        (
            "participants/p1/calendarAddress",
            json!("mailto:p1@example.com"),
        ),
        ("privacy", json!("secret")),
        ("prodId", json!("-//Other//EN")),
        ("recurrenceId", json!(RID)),
        ("recurrenceIdTimeZone", json!("Europe/Paris")),
        ("sentBy", json!("mailto:zoe@example.com")),
        ("uid", json!("other-uid")),
        ("recurrenceRule", json!({"frequency": "weekly"})),
        ("recurrenceOverrides", json!({})),
        ("isDraft", json!(true)),
        ("mayInviteSelf", json!(true)),
        ("mayInviteOthers", json!(true)),
        ("hideAttendees", json!(true)),
        ("calendarIds", json!({&calendar_id: true})),
        ("useDefaultAlerts", json!(true)),
    ];
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            forbidden.iter().map(|(key, value)| {
                series().with_property(
                    "recurrenceOverrides",
                    json!({RID: {"title": "Moved", *key: value}}),
                )
            }),
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for (idx, (key, _)) in forbidden.iter().enumerate() {
        assert_eq!(
            response.not_created(idx as u32).typ(),
            "invalidProperties",
            "{key}: {response:?}"
        );
    }
    let series_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [series().with_property("recurrenceOverrides", json!({RID: {"title": "Moved"}}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    for (key, value) in &forbidden {
        for patch in [
            json!({ format!("recurrenceOverrides/{RID}/{}", key.replace('/', "~1")): value }),
            json!({ format!("recurrenceOverrides/{RID}"): {"title": "Moved", *key: value} }),
            json!({ "recurrenceOverrides": {RID: {"title": "Moved", *key: value}} }),
        ] {
            assert_eq!(
                john.jmap_update(
                    MethodObject::CalendarEvent,
                    [(&series_id, patch.clone())],
                    Vec::<(&str, &str)>::new(),
                )
                .await
                .not_updated(&series_id)
                .typ(),
                "invalidProperties",
                "{patch}"
            );
        }
    }
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &series_id,
            json!({
                format!("recurrenceOverrides/{RID}/relatedTo"): {
                    "parent-uid": {"@type": "Relation", "relation": {"parent": true}}
                }
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&series_id);
    let response = john
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::Privacy,
                JSCalendarProperty::RecurrenceOverrides,
            ],
            [&series_id],
        )
        .await;
    let series_event = &response.list()[0];
    assert_eq!(series_event.get("privacy"), None, "{series_event}");
    assert_eq!(
        series_event["recurrenceOverrides"][RID]["title"],
        json!("Moved"),
        "{series_event}"
    );
    assert_eq!(
        series_event["recurrenceOverrides"][RID]["relatedTo"]["parent-uid"]["relation"],
        json!({"parent": true}),
        "{series_event}"
    );

    // An event with a recurrenceId cannot have a recurrence rule or overrides
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                event("instance-with-rule")
                    .with_property("recurrenceId", "2026-03-02T10:00:00")
                    .with_property("recurrenceRule", json!({"frequency": "daily"})),
                event("instance-with-overrides")
                    .with_property("recurrenceId", "2026-03-02T10:00:00")
                    .with_property(
                        "recurrenceOverrides",
                        json!({"2026-03-03T10:00:00": {"title": "Moved"}}),
                    ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for idx in 0..2 {
        assert_eq!(
            response.not_created(idx).typ(),
            "invalidProperties",
            "{idx}"
        );
    }

    // An instance cannot share the uid of a base event with overrides
    assert_eq!(
        john.jmap_create(
            MethodObject::CalendarEvent,
            [event("override-validation")
                .with_property("recurrenceId", "2026-03-04T10:00:00")
                .with_property("start", "2026-03-04T10:00:00")],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_created(0)
        .typ(),
        "invalidProperties"
    );

    // Calendar objects without events cannot be updated
    let collection = resource_dav_path(test, john, &calendar_id, true).await;
    john.webdav_client()
        .request(
            "PUT",
            &format!("{collection}journal.ics"),
            concat!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n",
                "BEGIN:VJOURNAL\r\nUID:journal-entry\r\nDTSTAMP:20260101T000000Z\r\n",
                "SUMMARY:Journal\r\nEND:VJOURNAL\r\nEND:VCALENDAR\r\n"
            ),
        )
        .await
        .with_status(StatusCode::CREATED);
    let journal_id = event_id_by_uid(test, john, "journal-entry").await;
    assert_eq!(
        john.jmap_update(
            MethodObject::CalendarEvent,
            [(&journal_id, json!({"title": "Journal (changed)"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&journal_id)
        .typ(),
        "invalidProperties"
    );

    john.jmap_destroy(
        MethodObject::Calendar,
        [&utc_calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;

    // Events sharing a uid need distinct recurrence ids
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({"name": "Instances", "timeZone": "Europe/Madrid"}),
                json!({"name": "More instances", "timeZone": "Europe/Madrid"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let instances_calendar_id = response.created(0).id().to_string();
    let spare_calendar_id = response.created(1).id().to_string();
    let instance = |recurrence_id: &str| {
        event("split-series")
            .with_property("recurrenceId", recurrence_id)
            .with_property("start", recurrence_id)
    };
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [instance("2026-04-01T10:00:00")],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let instance_1 = response.created(0).id().to_string();
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                instance("2026-04-08T10:00:00")
                    .with_property("calendarIds", json!({&instances_calendar_id: true})),
                instance("2026-04-15T10:00:00"),
                instance("2026-04-01T10:00:00"),
                event("split-series"),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let instance_2 = response.created(0).id().to_string();
    let shared_calendar = response.not_created(1);
    assert_eq!(shared_calendar.typ(), "invalidProperties", "{response:?}");
    assert_eq!(
        shared_calendar["properties"],
        json!(["calendarIds"]),
        "{response:?}"
    );
    assert_eq!(response.not_created(2).typ(), "invalidProperties");
    assert_eq!(response.not_created(3).typ(), "invalidProperties");

    let response = john
        .jmap_update(
            MethodObject::CalendarEvent,
            [(
                &instance_2,
                json!({ format!("calendarIds/{calendar_id}"): true }),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(
        response.not_updated(&instance_2)["properties"],
        json!(["calendarIds"]),
        "{response:?}"
    );
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &instance_2,
            json!({ "calendarIds": {&spare_calendar_id: true} }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&instance_2);

    // Replacing the instances with the base event in a single request is allowed
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": john.id_string(),
                "create": {"base": event("split-series").with_property(
                    "recurrenceRule", json!({"frequency": "weekly", "count": 4})
                )},
                "destroy": [&instance_1, &instance_2]
            }),
        )
        .await;
    response.method_response()["created"]["base"].id();
    assert_eq!(response.destroyed().count(), 2);

    let instance = |recurrence_id: &str| {
        event("split-creates")
            .with_property("recurrenceId", recurrence_id)
            .with_property("start", recurrence_id)
    };
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                instance("2026-06-03T10:00:00"),
                instance("2026-06-03T10:00:00"),
                instance("2026-06-10T10:00:00"),
                instance("2026-06-17T10:00:00")
                    .with_property("calendarIds", json!({&instances_calendar_id: true})),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.created(0);
    assert_eq!(
        response.not_created(1)["properties"],
        json!(["uid"]),
        "{response:?}"
    );
    assert_eq!(
        response.not_created(2)["properties"],
        json!(["calendarIds"]),
        "{response:?}"
    );
    response.created(3);

    for calendar_id in [&calendar_id, &instances_calendar_id, &spare_calendar_id] {
        john.jmap_destroy(
            MethodObject::Calendar,
            [calendar_id],
            [("onDestroyRemoveEvents", true)],
        )
        .await;
    }
}

async fn event_get(test: &TestServer, john: &Account, jane: &Account) {
    let jane_id = jane.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Hidden attendees",
                "shareWith": {&jane_id: {"mayReadItems": true}}
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
                "calendarIds": {&calendar_id: true},
                "uid": "hidden-attendees",
                "title": "Board meeting",
                "start": "2026-05-04T09:00:00",
                "timeZone": "Europe/Madrid",
                "duration": "PT1H",
                "hideAttendees": true,
                "organizerCalendarAddress": "mailto:jdoe@example.com",
                "recurrenceRule": {"frequency": "daily", "count": 3},
                "recurrenceOverrides": {
                    "2026-05-05T09:00:00": {
                        "title": "Board meeting (moved)",
                        "participants/jane/participationStatus": "accepted",
                        "participants/bill/participationStatus": "declined"
                    }
                },
                "participants": {
                    "owner": {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jdoe@example.com",
                        "roles": {"owner": true, "attendee": true},
                        "participationStatus": "accepted"
                    },
                    "jane": {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jane.smith@example.com",
                        "roles": {"attendee": true}
                    },
                    "bill": {
                        "@type": "Participant",
                        "name": "Bill Secret",
                        "description": "Bill is interviewing for a job elsewhere",
                        "links": {
                            "cv": {"@type": "Link", "href": "https://example.com/bill-cv"}
                        },
                        "calendarAddress": "mailto:bill@example.com",
                        "roles": {"attendee": true}
                    }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    test.wait_for_tasks().await;

    // The owner sees all participants, the sharee only the owner and herself
    let participants = |response: &JmapResponse| {
        let mut ids = response.list()[0]["participants"]
            .as_object()
            .unwrap()
            .values()
            .map(|p| p["calendarAddress"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        ids.sort();
        ids
    };
    let response = john
        .jmap_get(
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::Participants],
            [&event_id],
        )
        .await;
    assert_eq!(participants(&response).len(), 3);
    let response = jane
        .jmap_get_account(
            john,
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::Participants],
            [&event_id],
        )
        .await;
    assert_eq!(
        participants(&response),
        ["mailto:jane.smith@example.com", "mailto:jdoe@example.com"]
    );

    // Hidden participants stay hidden in overrides, synthetic instances and queries
    let assert_hidden = |value: &Value| {
        for hidden in [
            "bill@example.com",
            "Bill Secret",
            "interviewing",
            "bill-cv",
            "declined",
        ] {
            assert!(!value.to_string().contains(hidden), "{hidden}: {value}");
        }
    };
    let response = jane
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": john.id_string(),
                "ids": [&event_id],
                "properties": ["participants", "recurrenceOverrides"]
            }),
        )
        .await;
    assert_hidden(response.list_array());
    assert_eq!(
        response.list()[0]["recurrenceOverrides"]["2026-05-05T09:00:00"]["participants/jane/participationStatus"],
        json!("accepted")
    );
    let instance_ids = jane
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": john.id_string(),
                "expandRecurrences": true,
                "filter": {
                    "inCalendar": &calendar_id,
                    "after": "2026-05-04T00:00:00",
                    "before": "2026-05-07T00:00:00"
                }
            }),
        )
        .await
        .ids()
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(instance_ids.len(), 3);
    let response = jane
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": john.id_string(),
                "ids": &instance_ids,
                "properties": ["participants"]
            }),
        )
        .await;
    assert_hidden(response.list_array());
    for instance in response.list() {
        let mut ids = instance["participants"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        ids.sort_unstable();
        assert_eq!(ids, ["jane", "owner"], "{instance}");
    }
    let response = john
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": john.id_string(),
                "ids": [&event_id],
                "properties": ["participants", "recurrenceOverrides"],
                "reduceParticipants": true
            }),
        )
        .await;
    assert_hidden(response.list_array());
    assert_eq!(
        response.list()[0]["participants"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["owner"]
    );
    for (filter, expand_recurrences) in [
        (json!({"attendee": "bill"}), false),
        (json!({"text": "bill@example.com"}), false),
        (json!({"text": "secret"}), false),
        (json!({"attendee": "bill"}), true),
        (json!({"text": "bill"}), true),
    ] {
        let mut filter = filter;
        filter["inCalendar"] = json!(&calendar_id);
        if expand_recurrences {
            filter["after"] = json!("2026-05-04T00:00:00");
            filter["before"] = json!("2026-05-07T00:00:00");
        }
        let query = json!({
            "accountId": john.id_string(),
            "expandRecurrences": expand_recurrences,
            "filter": filter
        });
        assert_eq!(
            jane.jmap_method_call("CalendarEvent/query", query.clone())
                .await
                .ids()
                .count(),
            0,
            "{query}"
        );
        assert_ne!(
            john.jmap_method_call("CalendarEvent/query", query.clone())
                .await
                .ids()
                .count(),
            0,
            "{query}"
        );
    }

    // Duplicate ids are returned once
    let response = john
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": john.id_string(),
                "ids": [&event_id, &instance_ids[1], &event_id, &instance_ids[1]],
                "properties": ["id"]
            }),
        )
        .await;
    assert_eq!(
        response
            .list()
            .iter()
            .map(|event| event.id())
            .collect::<Vec<_>>(),
        [event_id.as_str(), instance_ids[1].as_str()]
    );

    // An invalid time zone is rejected
    for (method, arguments) in [
        (
            "CalendarEvent/get",
            json!({"accountId": john.id_string(), "ids": [&event_id], "timeZone": "Mars/Olympus_Mons"}),
        ),
        (
            "CalendarEvent/query",
            json!({"accountId": john.id_string(), "timeZone": "Mars/Olympus_Mons"}),
        ),
    ] {
        assert_eq!(
            john.jmap_method_call(method, arguments)
                .await
                .method_response()["type"],
            json!("invalidArguments"),
            "{method}"
        );
    }

    // maxChanges must be positive
    let state = response.method_response()["state"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        john.jmap_method_call(
            "CalendarEvent/changes",
            json!({"accountId": john.id_string(), "sinceState": state, "maxChanges": 0}),
        )
        .await
        .method_response()["type"],
        json!("invalidArguments")
    );

    // Participants are matched against the participant identities of the user
    let identity_ids = jane
        .jmap_method_call(
            "ParticipantIdentity/get",
            json!({ "accountId": &jane_id, "ids": null, "properties": ["id"] }),
        )
        .await
        .list()
        .iter()
        .map(|identity| identity["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(!identity_ids.is_empty());
    jane.jmap_method_call(
        "ParticipantIdentity/set",
        json!({ "accountId": &jane_id, "destroy": identity_ids }),
    )
    .await;
    let response = jane
        .jmap_get_account(
            john,
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::Participants],
            [&event_id],
        )
        .await;
    assert_eq!(participants(&response), ["mailto:jdoe@example.com"]);
    jane.jmap_method_call(
        "ParticipantIdentity/set",
        json!({
            "accountId": &jane_id,
            "create": { "i0": { "calendarAddress": "MAILTO:Jane.Smith@Example.COM" } }
        }),
    )
    .await
    .created(0);
    let response = jane
        .jmap_get_account(
            john,
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::Participants],
            [&event_id],
        )
        .await;
    assert_eq!(
        participants(&response),
        ["mailto:jane.smith@example.com", "mailto:jdoe@example.com"]
    );
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(jane.id().document_id())
        .with_collection(Collection::Principal)
        .with_document(0)
        .clear(PrincipalField::ParticipantIdentities);
    test.server.commit_batch(batch).await.unwrap();

    // Properties returned by default
    let response = john
        .jmap_get(MethodObject::CalendarEvent, Vec::<&str>::new(), [&event_id])
        .await;
    let event = &response.list()[0];
    for property in [
        "id",
        "calendarIds",
        "isDraft",
        "isOrigin",
        "useDefaultAlerts",
        "mayInviteSelf",
        "mayInviteOthers",
        "hideAttendees",
    ] {
        assert!(
            event.get(property).is_some(),
            "missing {property}: {event:?}"
        );
    }

    // utcStart cannot be combined with recurrenceOverrides
    let response = john
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::UtcStart,
                JSCalendarProperty::RecurrenceOverrides,
            ],
            [&event_id],
        )
        .await;
    assert_eq!(
        response.method_response()["type"],
        json!("invalidArguments")
    );

    // An inverted override window returns no overrides
    let response = john
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": john.id_string(),
                "ids": [&event_id],
                "properties": ["recurrenceOverrides"],
                "recurrenceOverridesAfter": "2026-06-01T00:00:00Z",
                "recurrenceOverridesBefore": "2026-01-01T00:00:00Z"
            }),
        )
        .await;
    assert_eq!(response.list()[0].get("recurrenceOverrides"), None);

    // The override window also applies to excluded and added occurrences
    let window_event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": {&calendar_id: true},
                "uid": "override-window",
                "title": "Window",
                "start": "2026-06-01T09:00:00",
                "timeZone": "Europe/Madrid",
                "duration": "PT1H",
                "recurrenceRule": {"frequency": "daily", "count": 5},
                "recurrenceOverrides": {
                    "2026-06-02T09:00:00": {"excluded": true},
                    "2026-06-04T09:00:00": {"title": "Window (changed)"},
                    "2026-06-10T09:00:00": {}
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    for (window, expected) in [
        (
            json!({"recurrenceOverridesAfter": "2026-06-03T00:00:00Z"}),
            vec!["2026-06-04T09:00:00", "2026-06-10T09:00:00"],
        ),
        (
            json!({"recurrenceOverridesBefore": "2026-06-04T07:00:00Z"}),
            vec!["2026-06-02T09:00:00"],
        ),
        (
            json!({
                "recurrenceOverridesAfter": "2026-06-04T07:00:00Z",
                "recurrenceOverridesBefore": "2026-06-10T07:00:00Z"
            }),
            vec!["2026-06-04T09:00:00"],
        ),
    ] {
        let mut arguments = json!({
            "accountId": john.id_string(),
            "ids": [&window_event_id],
            "properties": ["recurrenceOverrides"]
        });
        for (key, value) in window.as_object().unwrap() {
            arguments[key] = value.clone();
        }
        let response = john.jmap_method_call("CalendarEvent/get", arguments).await;
        let mut keys = response.list()[0]["recurrenceOverrides"]
            .as_object()
            .map(|overrides| overrides.keys().map(String::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        keys.sort_unstable();
        assert_eq!(keys, expected, "{window}");
    }

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn event_query(test: &TestServer, john: &Account) {
    // Text conditions match each expanded occurrence on its own
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Occurrences"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    john.jmap_create(
        MethodObject::CalendarEvent,
        [json!({
            "calendarIds": {&calendar_id: true},
            "uid": "per-instance-text",
            "title": "Standup",
            "description": "Daily sync with the whole team",
            "start": "2030-03-01T09:00:00",
            "timeZone": "Etc/UTC",
            "duration": "PT30M",
            "locations": {"room": {"@type": "Location", "name": "Room 5"}},
            "recurrenceRule": {"frequency": "daily", "count": 6},
            "recurrenceOverrides": {
                "2030-03-02T09:00:00": {"title": "Planning review"},
                "2030-03-03T09:00:00": {
                    "locations": {"berlin": {"@type": "Location", "name": "Berlin office"}}
                },
                "2030-03-04T09:00:00": {"title": "Quarterly reviews"},
                "2030-03-05T09:00:00": {"locations": null, "description": null},
                "2030-03-06T09:00:00": {"title": "Sales calls"}
            }
        })],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .created(0);
    john.jmap_create(
        MethodObject::CalendarEvent,
        [json!({
            "calendarIds": {&calendar_id: true},
            "uid": "per-instance-cjk",
            "title": "東京本社で四半期の会議を開きます",
            "description": "四半期の業績について話し合います",
            "start": "2030-05-01T09:00:00",
            "timeZone": "Asia/Tokyo",
            "duration": "PT1H",
            "recurrenceRule": {"frequency": "daily", "count": 2},
            "recurrenceOverrides": {
                "2030-05-02T09:00:00": {"title": "東京本社で打ち合わせをします"}
            }
        })],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .created(0);
    test.wait_for_tasks().await;
    for (condition, window, expected) in [
        (
            json!({"title": "planning"}),
            None,
            vec!["2030-03-02T09:00:00"],
        ),
        (json!({"title": "plan*"}), None, vec!["2030-03-02T09:00:00"]),
        (
            json!({"title": "\"planning review\""}),
            None,
            vec!["2030-03-02T09:00:00"],
        ),
        (
            json!({"title": "standup"}),
            None,
            vec![
                "2030-03-01T09:00:00",
                "2030-03-03T09:00:00",
                "2030-03-05T09:00:00",
            ],
        ),
        (
            json!({"location": "berlin"}),
            None,
            vec!["2030-03-03T09:00:00"],
        ),
        (json!({"text": "berlin"}), None, vec!["2030-03-03T09:00:00"]),
        (
            json!({"title": "review"}),
            None,
            vec!["2030-03-02T09:00:00", "2030-03-04T09:00:00"],
        ),
        (json!({"title": "call"}), None, vec!["2030-03-06T09:00:00"]),
        (
            json!({"location": "rooms"}),
            None,
            vec![
                "2030-03-01T09:00:00",
                "2030-03-02T09:00:00",
                "2030-03-04T09:00:00",
                "2030-03-06T09:00:00",
            ],
        ),
        (
            json!({"description": "sync"}),
            None,
            vec![
                "2030-03-01T09:00:00",
                "2030-03-02T09:00:00",
                "2030-03-03T09:00:00",
                "2030-03-04T09:00:00",
                "2030-03-06T09:00:00",
            ],
        ),
        (
            json!({"title": "standup", "location": "berlin"}),
            None,
            vec!["2030-03-03T09:00:00"],
        ),
        (
            json!({"title": "planning", "location": "berlin"}),
            None,
            vec![],
        ),
        (
            json!({"title": "会議*"}),
            Some(("2030-04-30T00:00:00", "2030-05-03T00:00:00")),
            vec!["2030-05-01T09:00:00"],
        ),
    ] {
        let (after, before) = window.unwrap_or(("2030-03-01T00:00:00", "2030-03-07T00:00:00"));
        let mut filter = condition.clone();
        filter["after"] = json!(after);
        filter["before"] = json!(before);
        let response = john
            .jmap_method_call(
                "CalendarEvent/query",
                json!({
                    "accountId": john.id_string(),
                    "expandRecurrences": true,
                    "filter": filter,
                    "sort": [{"property": "start"}]
                }),
            )
            .await;
        let ids = response.method_response()["ids"]
            .as_array()
            .unwrap_or_else(|| panic!("{condition}: {response:?}"))
            .iter()
            .map(|id| id.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let recurrence_ids = if ids.is_empty() {
            vec![]
        } else {
            john.jmap_get(MethodObject::CalendarEvent, ["recurrenceId"], &ids)
                .await
                .list()
                .iter()
                .map(|event| {
                    event["recurrenceId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(recurrence_ids, expected, "{condition}: {response:?}");
    }

    // Floating and all-day events are matched in the time zone of the query
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({
                    "calendarIds": {&calendar_id: true},
                    "uid": "tokyo-all-day",
                    "title": "Holiday",
                    "start": "2030-06-10T00:00:00",
                    "duration": "P1D",
                    "showWithoutTime": true
                }),
                json!({
                    "calendarIds": {&calendar_id: true},
                    "uid": "tokyo-floating",
                    "title": "Floating",
                    "start": "2030-06-11T10:00:00",
                    "duration": "PT1H"
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let all_day_id = response.created(0).id().to_string();
    let floating_id = response.created(1).id().to_string();
    test.wait_for_tasks().await;
    for (after, before, expected) in [
        (
            "2030-06-10T00:00:00",
            "2030-06-10T02:00:00",
            vec![all_day_id.as_str()],
        ),
        (
            "2030-06-10T22:00:00",
            "2030-06-11T00:00:00",
            vec![all_day_id.as_str()],
        ),
        ("2030-06-11T00:00:00", "2030-06-11T02:00:00", vec![]),
        ("2030-06-09T22:00:00", "2030-06-10T00:00:00", vec![]),
        (
            "2030-06-11T10:00:00",
            "2030-06-11T11:00:00",
            vec![floating_id.as_str()],
        ),
        ("2030-06-11T11:00:00", "2030-06-11T12:00:00", vec![]),
    ] {
        for expand_recurrences in [false, true] {
            let response = john
                .jmap_method_call(
                    "CalendarEvent/query",
                    json!({
                        "accountId": john.id_string(),
                        "timeZone": "Asia/Tokyo",
                        "expandRecurrences": expand_recurrences,
                        "filter": {"inCalendar": &calendar_id, "after": after, "before": before}
                    }),
                )
                .await;
            assert_eq!(
                response.ids().collect::<Vec<_>>(),
                expected,
                "{after} - {before} (expand: {expand_recurrences}): {response:?}"
            );
        }
    }

    // Expanded instances are sorted by their recurrence id, including before 1970
    john.jmap_create(
        MethodObject::CalendarEvent,
        [
            json!({
                "calendarIds": {&calendar_id: true},
                "uid": "sorted-instances",
                "title": "Sorted",
                "start": "2030-07-01T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT30M",
                "recurrenceRule": {"frequency": "daily", "count": 3},
                "recurrenceOverrides": {
                    "2030-07-01T09:00:00": {"start": "2030-07-05T09:00:00"}
                }
            }),
            json!({
                "calendarIds": {&calendar_id: true},
                "uid": "before-epoch",
                "title": "Epoch",
                "start": "1969-12-31T23:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT30M",
                "recurrenceRule": {"frequency": "daily", "count": 2}
            }),
        ],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .created(1);
    test.wait_for_tasks().await;
    for (uid, window, sort, expected) in [
        (
            "sorted-instances",
            ("2030-06-30T00:00:00", "2030-07-06T00:00:00"),
            json!([{"property": "start"}]),
            vec![
                "2030-07-02T09:00:00",
                "2030-07-03T09:00:00",
                "2030-07-01T09:00:00",
            ],
        ),
        (
            "sorted-instances",
            ("2030-06-30T00:00:00", "2030-07-06T00:00:00"),
            json!([{"property": "recurrenceId"}]),
            vec![
                "2030-07-01T09:00:00",
                "2030-07-02T09:00:00",
                "2030-07-03T09:00:00",
            ],
        ),
        (
            "sorted-instances",
            ("2030-06-30T00:00:00", "2030-07-06T00:00:00"),
            json!([{"property": "recurrenceId", "isAscending": false}]),
            vec![
                "2030-07-03T09:00:00",
                "2030-07-02T09:00:00",
                "2030-07-01T09:00:00",
            ],
        ),
        (
            "before-epoch",
            ("1969-12-31T00:00:00", "1970-01-02T00:00:00"),
            json!([{"property": "start"}]),
            vec!["1969-12-31T23:00:00", "1970-01-01T23:00:00"],
        ),
    ] {
        let response = john
            .jmap_method_call(
                "CalendarEvent/query",
                json!({
                    "accountId": john.id_string(),
                    "expandRecurrences": true,
                    "filter": {"uid": uid, "after": window.0, "before": window.1},
                    "sort": sort
                }),
            )
            .await;
        let ids = response.ids().map(str::to_string).collect::<Vec<_>>();
        let recurrence_ids = john
            .jmap_get(MethodObject::CalendarEvent, ["recurrenceId"], &ids)
            .await
            .list()
            .iter()
            .map(|event| event.text_field("recurrenceId").to_string())
            .collect::<Vec<_>>();
        assert_eq!(recurrence_ids, expected, "{uid} {sort}: {response:?}");
    }
    let response = john
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": john.id_string(),
                "expandRecurrences": true,
                "filter": {"after": "2030-06-30T00:00:00", "before": "2030-07-06T00:00:00"},
                "sort": [{"property": "title"}]
            }),
        )
        .await;
    assert_eq!(response.method_response()["type"], json!("unsupportedSort"));

    // A FilterOperator is rejected even if nothing would match
    let response = john
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": john.id_string(),
                "expandRecurrences": true,
                "filter": {
                    "operator": "OR",
                    "conditions": [
                        {"after": "2030-01-01T00:00:00", "before": "2030-01-02T00:00:00"},
                        {"title": "nothing"}
                    ]
                }
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["type"],
        json!("invalidArguments")
    );

    let response = john
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": john.id_string(),
                "expandRecurrences": true,
                "filter": {"after": "2030-01-01T00:00:00"}
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["type"],
        json!("invalidArguments")
    );

    // The expansion window cannot exceed maxExpandedQueryDuration
    let response = john
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": john.id_string(),
                "expandRecurrences": true,
                "filter": {"after": "2030-01-01T00:00:00", "before": "2032-01-01T00:00:00"}
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["type"],
        json!("expandDurationTooLarge")
    );

    // Expanded queries cannot calculate changes
    let response = john
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": john.id_string(),
                "expandRecurrences": true,
                "filter": {"after": "2030-01-01T00:00:00", "before": "2030-01-02T00:00:00"}
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["canCalculateChanges"],
        json!(false)
    );
    let query_state = response.method_response()["queryState"]
        .as_str()
        .unwrap()
        .to_string();
    let response = john
        .jmap_method_call(
            "CalendarEvent/queryChanges",
            json!({
                "accountId": john.id_string(),
                "expandRecurrences": true,
                "sinceQueryState": query_state,
                "filter": {"after": "2030-01-01T00:00:00", "before": "2030-01-02T00:00:00"}
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["type"],
        json!("cannotCalculateChanges")
    );
}

async fn event_parse(john: &Account) {
    let upload = async |ics: &str| {
        john.jmap_method_call(
            "Blob/upload",
            json!({
                "accountId": john.id_string(),
                "create": {
                    "ics": {
                        "data": [{"data:asText": ics}],
                        "type": "text/calendar"
                    }
                }
            }),
        )
        .await
        .method_response()["created"]["ics"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let blob_id = upload(concat!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n",
        "BEGIN:VEVENT\r\nUID:parse-test\r\nDTSTAMP:20260101T000000Z\r\n",
        "DTSTART:20260101T100000Z\r\nSUMMARY:Parsed\r\n",
        "END:VEVENT\r\nEND:VCALENDAR\r\n"
    ))
    .await;

    // Metadata properties are null when all properties are returned
    let response = john
        .jmap_method_call(
            "CalendarEvent/parse",
            json!({ "accountId": john.id_string(), "blobIds": [&blob_id] }),
        )
        .await;
    let parsed = &response.method_response()["parsed"][&blob_id][0];
    for property in ["id", "baseEventId", "calendarIds", "isDraft", "isOrigin"] {
        assert_eq!(
            parsed.get(property),
            Some(&Value::Null),
            "{property}: {parsed}"
        );
    }
    assert_eq!(parsed["title"], json!("Parsed"), "{parsed}");

    // Calendar data without events or tasks cannot be parsed
    let not_parsable = [
        upload("BEGIN:VEVENT\r\nUID:bare\r\nDTSTART:20300101T090000Z\r\nEND:VEVENT\r\n").await,
        upload(concat!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n",
            "BEGIN:VJOURNAL\r\nUID:journal\r\nDTSTAMP:20260101T000000Z\r\n",
            "END:VJOURNAL\r\nEND:VCALENDAR\r\n"
        ))
        .await,
    ];
    let response = john
        .jmap_method_call(
            "CalendarEvent/parse",
            json!({ "accountId": john.id_string(), "blobIds": &not_parsable }),
        )
        .await;
    assert_eq!(
        response.method_response()["notParsable"],
        json!(&not_parsable),
        "{response:?}"
    );

    let response = john
        .jmap_method_call(
            "CalendarEvent/parse",
            json!({
                "accountId": john.id_string(),
                "blobIds": [&blob_id],
                "properties": ["id", "baseEventId", "calendarIds", "isDraft", "isOrigin", "title"]
            }),
        )
        .await;
    response.method_response()["parsed"][&blob_id][0].assert_is_equal(json!({
        "title": "Parsed",
        "id": null,
        "baseEventId": null,
        "calendarIds": null,
        "isDraft": null,
        "isOrigin": null
    }));
}

async fn event_copy(test: &TestServer, john: &Account, jane: &Account) {
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let source_calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Copy source",
                "shareWith": {&jane_id: {"mayReadItems": true, "mayUpdatePrivate": true}}
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let target_calendar_id = jane
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Copy target",
                "shareWith": {&john_id: {"mayReadItems": true, "mayWriteAll": true}}
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let from_state = john
        .jmap_get(
            MethodObject::CalendarEvent,
            Vec::<&str>::new(),
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({
                    "calendarIds": {&source_calendar_id: true},
                    "uid": "copy-source",
                    "title": "Copied",
                    "start": "2026-09-01T09:00:00",
                    "timeZone": "Etc/UTC",
                    "duration": "PT1H",
                    "keywords": {"owner": true},
                    "color": "red",
                    "alerts": {
                        "owner": {
                            "@type": "Alert",
                            "trigger": {"@type": "OffsetTrigger", "offset": "-PT1H"}
                        }
                    },
                    "isDraft": true,
                    "mayInviteSelf": true,
                    "mayInviteOthers": true,
                    "hideAttendees": true
                }),
                json!({
                    "calendarIds": {&source_calendar_id: true},
                    "uid": "copy-organized",
                    "title": "Organized",
                    "start": "2026-09-02T09:00:00",
                    "timeZone": "Etc/UTC",
                    "duration": "PT1H",
                    "participants": {
                        "bill": {
                            "@type": "Participant",
                            "calendarAddress": "mailto:bill@example.com",
                            "roles": {"attendee": true}
                        }
                    }
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let source_id = response.created(0).id().to_string();
    let organized_id = response.created(1).id().to_string();
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({
            "accountId": &john_id,
            "update": {
                &source_id: {
                    "keywords": {"jane": true},
                    "useDefaultAlerts": true,
                    "alerts": {
                        "mine": {
                            "@type": "Alert",
                            "trigger": {"@type": "OffsetTrigger", "offset": "-PT10M"}
                        }
                    }
                }
            }
        }),
    )
    .await
    .updated(&source_id);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // The source account state is checked
    let response = jane
        .jmap_method_call(
            "CalendarEvent/copy",
            json!({
                "fromAccountId": &john_id,
                "ifFromInState": &from_state,
                "accountId": &jane_id,
                "create": {&source_id: {"id": &source_id, "calendarIds": {&target_calendar_id: true}}}
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["type"],
        json!("stateMismatch"),
        "{response:?}"
    );

    // Sharees copy their own view, and the JMAP metadata of the source is kept
    let response = jane
        .jmap_method_call(
            "CalendarEvent/copy",
            json!({
                "fromAccountId": &john_id,
                "accountId": &jane_id,
                "create": {&source_id: {"id": &source_id, "calendarIds": {&target_calendar_id: true}}}
            }),
        )
        .await;
    let created = response.copied(&source_id);
    let copy_id = created.id().to_string();
    for property in [
        "title",
        "start",
        "duration",
        "timeZone",
        "uid",
        "sequence",
        "created",
        "organizerCalendarAddress",
    ] {
        assert!(created.get(property).is_none(), "{property}: {response:?}");
    }
    assert_eq!(created["isOrigin"], json!(true), "{response:?}");
    let copy = async || {
        jane.jmap_method_call(
            "CalendarEvent/get",
            json!({"accountId": &jane_id, "ids": [&copy_id]}),
        )
        .await
        .list()[0]
            .clone()
    };
    let copied = copy().await;
    assert_eq!(copied["keywords"], json!({"jane": true}), "{copied}");
    assert!(copied.get("color").is_none(), "{copied}");
    assert!(
        copied
            .get("alerts")
            .is_none_or(|alerts| alerts.as_object().is_none_or(|alerts| alerts.is_empty())),
        "{copied}"
    );
    for property in [
        "isDraft",
        "mayInviteSelf",
        "mayInviteOthers",
        "hideAttendees",
        "useDefaultAlerts",
    ] {
        assert_eq!(copied[property], json!(true), "{property}: {copied}");
    }
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({"accountId": &jane_id, "update": {&copy_id: {"useDefaultAlerts": false}}}),
    )
    .await
    .updated(&copy_id);
    let copied = copy().await;
    assert_eq!(
        copied["alerts"]
            .as_object()
            .map(|alerts| alerts.keys().map(String::as_str).collect::<Vec<_>>()),
        Some(vec!["mine"]),
        "{copied}"
    );

    // Blob ids of copied attachments are returned
    let response = john
        .jmap_method_call(
            "Blob/upload",
            json!({
                "accountId": &john_id,
                "create": { "b": { "data": [{ "data:asBase64": "iVBORw0KGgo=" }], "type": "image/png" } }
            }),
        )
        .await;
    let png_blob = response.method_response()["created"]["b"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("upload failed: {response:?}"))
        .to_string();
    let attachment_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": {&source_calendar_id: true},
                "title": "Attachment",
                "start": "2026-09-03T09:00:00",
                "timeZone": "Etc/UTC",
                "links": {
                    "png": {"@type": "Link", "blobId": &png_blob, "contentType": "image/png"}
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let response = jane
        .jmap_method_call(
            "CalendarEvent/copy",
            json!({
                "fromAccountId": &john_id,
                "accountId": &jane_id,
                "create": {"k-att": {"id": &attachment_id, "calendarIds": {&target_calendar_id: true}}}
            }),
        )
        .await;
    let created = response.copied("k-att");
    let copied = jane
        .jmap_method_call(
            "CalendarEvent/get",
            json!({"accountId": &jane_id, "ids": [created.id()]}),
        )
        .await
        .list()[0]
        .clone();
    assert!(
        created["links"]["png"]["blobId"].is_string(),
        "{response:?}"
    );
    assert_eq!(created["links"], copied["links"], "{response:?}");

    // Copies are created with the account information of the target account
    let source = john
        .jmap_get(
            MethodObject::CalendarEvent,
            [
                JSCalendarProperty::<Id>::Id,
                JSCalendarProperty::Updated,
                JSCalendarProperty::IsOrigin,
            ],
            [&organized_id],
        )
        .await
        .list()[0]
        .clone();
    assert_eq!(source["isOrigin"], json!(true), "{source}");
    let response = john
        .jmap_method_call(
            "CalendarEvent/copy",
            json!({
                "fromAccountId": &john_id,
                "accountId": &jane_id,
                "create": {&organized_id: {"id": &organized_id, "calendarIds": {&target_calendar_id: true}}}
            }),
        )
        .await;
    let created = response.copied(&organized_id);
    assert_eq!(created["isOrigin"], json!(false), "{response:?}");
    assert!(created.get("updated").is_none(), "{response:?}");
    let copied = jane
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": &jane_id,
                "ids": [created.id()],
                "properties": ["isOrigin", "updated"]
            }),
        )
        .await
        .list()[0]
        .clone();
    assert_eq!(copied["isOrigin"], json!(false), "{copied}");
    assert_eq!(copied["updated"], source["updated"], "{copied}");

    // Calendar objects without events or tasks cannot be copied
    let collection = resource_dav_path(test, john, &source_calendar_id, true).await;
    john.webdav_client()
        .request(
            "PUT",
            &format!("{collection}journal.ics"),
            concat!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n",
                "BEGIN:VJOURNAL\r\nUID:copy-journal\r\nDTSTAMP:20260101T000000Z\r\n",
                "SUMMARY:Journal\r\nEND:VJOURNAL\r\nEND:VCALENDAR\r\n"
            ),
        )
        .await
        .with_status(StatusCode::CREATED);
    let journal_id = event_id_by_uid(test, john, "copy-journal").await;
    let response = jane
        .jmap_method_call(
            "CalendarEvent/copy",
            json!({
                "fromAccountId": &john_id,
                "accountId": &jane_id,
                "create": {&journal_id: {"id": &journal_id, "calendarIds": {&target_calendar_id: true}}}
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["notCreated"][&journal_id]["type"],
        json!("invalidProperties"),
        "{response:?}"
    );

    // The create map is keyed by creation ids and the results reach createdIds
    let reference_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": {&source_calendar_id: true},
                "title": "Creation id copy",
                "start": "2026-09-10T09:00:00",
                "timeZone": "Etc/UTC"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let raw = jane
        .jmap_raw_post(
            json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
                "createdIds": {},
                "methodCalls": [
                    [
                        "CalendarEvent/copy",
                        {
                            "fromAccountId": &john_id,
                            "accountId": &jane_id,
                            "create": {
                                "k1": {
                                    "id": &reference_id,
                                    "calendarIds": { &target_calendar_id: true }
                                }
                            }
                        },
                        "c0"
                    ],
                    [
                        "CalendarEvent/get",
                        {
                            "accountId": &jane_id,
                            "ids": ["#k1"],
                            "properties": ["id", "title"]
                        },
                        "c1"
                    ]
                ]
            })
            .to_string(),
            "application/json",
        )
        .await;
    let response = JmapResponse(
        raw.json()
            .unwrap_or_else(|| panic!("Response was not valid JSON: {}", raw.text())),
    );
    let reference_copy_id = response.copied("k1").id().to_string();
    assert_ne!(reference_copy_id, reference_id, "{response:?}");
    assert_eq!(
        response.0["createdIds"]["k1"],
        json!(&reference_copy_id),
        "{response:?}"
    );
    assert_eq!(
        response.0.pointer("/methodResponses/1/1/list/0/title"),
        Some(&json!("Creation id copy")),
        "{response:?}"
    );

    // Nested creation ids inside the copied object are resolved
    let nested_source_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": {&source_calendar_id: true},
                "title": "Nested creation id copy",
                "start": "2026-09-11T09:00:00",
                "timeZone": "Etc/UTC"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let raw = jane
        .jmap_raw_post(
            json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
                "methodCalls": [
                    [
                        "Calendar/set",
                        {
                            "accountId": &jane_id,
                            "create": { "c1": { "name": "Copy target" } }
                        },
                        "c0"
                    ],
                    [
                        "CalendarEvent/copy",
                        {
                            "fromAccountId": &john_id,
                            "accountId": &jane_id,
                            "create": {
                                "k2": {
                                    "id": &nested_source_id,
                                    "calendarIds": { "#c1": true }
                                }
                            }
                        },
                        "c1"
                    ]
                ]
            })
            .to_string(),
            "application/json",
        )
        .await;
    let response = JmapResponse(
        raw.json()
            .unwrap_or_else(|| panic!("Response was not valid JSON: {}", raw.text())),
    );
    let nested_calendar_id = response.0["methodResponses"][0][1]["created"]["c1"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("calendar not created: {response:?}"))
        .to_string();
    let nested_copy_id = response.0["methodResponses"][1][1]["created"]["k2"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("copy failed: {response:?}"))
        .to_string();
    let nested_copy = jane
        .jmap_method_call(
            "CalendarEvent/get",
            json!({
                "accountId": &jane_id,
                "ids": [&nested_copy_id],
                "properties": ["calendarIds"]
            }),
        )
        .await
        .list()[0]
        .clone();
    assert_eq!(
        nested_copy["calendarIds"],
        json!({ &nested_calendar_id: true }),
        "{nested_copy}"
    );
    jane.jmap_destroy(
        MethodObject::Calendar,
        [&nested_calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;

    // A create object without an "id" property is rejected
    let response = jane
        .jmap_method_call(
            "CalendarEvent/copy",
            json!({
                "fromAccountId": &john_id,
                "accountId": &jane_id,
                "create": {
                    &reference_id: { "calendarIds": { &target_calendar_id: true } }
                }
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["notCreated"][&reference_id]["type"],
        json!("invalidProperties"),
        "{response:?}"
    );

    jane.jmap_destroy(
        MethodObject::Calendar,
        [&target_calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
    john.jmap_destroy(
        MethodObject::Calendar,
        [&source_calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn event_instance_rights(john: &Account, jane: &Account) {
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({
                    "name": "Instance RSVP",
                    "shareWith": {&jane_id: {"mayReadItems": true, "mayRSVP": true}}
                }),
                json!({
                    "name": "Instance personal",
                    "shareWith": {&jane_id: {"mayReadItems": true, "mayUpdatePrivate": true}}
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let rsvp_calendar_id = response.created(0).id().to_string();
    let personal_calendar_id = response.created(1).id().to_string();
    let event = |calendar_id: &str, uid: &str| {
        json!({
            "calendarIds": {calendar_id: true},
            "uid": uid,
            "title": "Instances",
            "start": "2030-03-01T09:00:00",
            "timeZone": "Etc/UTC",
            "duration": "PT1H",
            "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "daily", "count": 3},
            "participants": {
                "john": {
                    "@type": "Participant",
                    "calendarAddress": "mailto:jdoe@example.com",
                    "roles": {"owner": true, "attendee": true}
                },
                "jane": {
                    "@type": "Participant",
                    "calendarAddress": "mailto:jane.smith@example.com",
                    "roles": {"attendee": true},
                    "participationStatus": "needs-action"
                }
            }
        })
    };
    john.jmap_create(
        MethodObject::CalendarEvent,
        [
            event(&rsvp_calendar_id, "instance-rsvp"),
            event(&personal_calendar_id, "instance-personal"),
        ],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .created(1);
    let instance_id = async |calendar_id: &str| {
        jane.jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": &john_id,
                "expandRecurrences": true,
                "filter": {
                    "inCalendar": calendar_id,
                    "after": "2030-03-02T00:00:00",
                    "before": "2030-03-03T00:00:00"
                }
            }),
        )
        .await
        .ids()
        .next()
        .expect("expanded instance")
        .to_string()
    };
    let update = async |id: &str, patch: Value| {
        jane.jmap_method_call(
            "CalendarEvent/set",
            json!({"accountId": &john_id, "update": {id: patch}}),
        )
        .await
    };

    // Sharees may reply to or personalize a single occurrence
    let rsvp_instance = instance_id(&rsvp_calendar_id).await;
    update(
        &rsvp_instance,
        json!({"participants/jane/participationStatus": "declined"}),
    )
    .await
    .updated(&rsvp_instance);
    assert_eq!(
        update(&rsvp_instance, json!({"title": "Renamed"}))
            .await
            .not_updated(&rsvp_instance)
            .typ(),
        "forbidden"
    );
    let personal_instance = instance_id(&personal_calendar_id).await;
    update(&personal_instance, json!({"keywords": {"personal": true}}))
        .await
        .updated(&personal_instance);

    john.jmap_destroy(
        MethodObject::Calendar,
        [&rsvp_calendar_id, &personal_calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn sharee_metadata_changes(john: &Account, jane: &Account) {
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Sharee metadata",
                "shareWith": {&jane_id: {"mayReadItems": true, "mayWriteAll": true}}
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
                "calendarIds": {&calendar_id: true},
                "title": "Draft",
                "start": "2030-04-01T09:00:00",
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
    let notifications = async || {
        john.jmap_method_call(
            "CalendarEventNotification/get",
            json!({"accountId": &john_id, "ids": null, "properties": ["id"]}),
        )
        .await
        .list()
        .len()
    };

    // Changes to the event metadata by sharees are not per-user changes
    let before = notifications().await;
    jane.jmap_method_call(
        "CalendarEvent/set",
        json!({"accountId": &john_id, "update": {&event_id: {"isDraft": false}}}),
    )
    .await
    .updated(&event_id);
    assert_eq!(notifications().await, before + 1);
    assert_eq!(
        john.jmap_get(
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::Id, JSCalendarProperty::IsDraft],
            [&event_id],
        )
        .await
        .list()[0]["isDraft"],
        json!(false)
    );

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn event_method_errors(john: &Account) {
    let john_id = john.id_string().to_string();

    // Event notifications are created by the server only
    let response = john
        .jmap_method_call(
            "CalendarEventNotification/set",
            json!({
                "accountId": &john_id,
                "create": {"n0": {}},
                "update": {"a": {}}
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["notCreated"]["n0"]["type"],
        json!("forbidden"),
        "{response:?}"
    );
    assert_eq!(
        response.method_response()["notUpdated"]["a"]["type"],
        json!("forbidden"),
        "{response:?}"
    );

    // Expanding more occurrences than the server allows cannot be calculated
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Occurrences"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    john.jmap_create(
        MethodObject::CalendarEvent,
        ["2030-02-01T00:00:00", "2030-02-01T00:30:00"].map(|start| {
            json!({
                "calendarIds": {&calendar_id: true},
                "title": "Hourly",
                "start": start,
                "timeZone": "Etc/UTC",
                "duration": "PT15M",
                "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "hourly", "count": 2000}
            })
        }),
        Vec::<(&str, &str)>::new(),
    )
    .await
    .created(1);
    let response = john
        .jmap_method_call(
            "CalendarEvent/query",
            json!({
                "accountId": &john_id,
                "expandRecurrences": true,
                "filter": {
                    "inCalendar": &calendar_id,
                    "after": "2030-02-01T00:00:00",
                    "before": "2030-06-01T00:00:00"
                }
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["type"],
        json!("cannotCalculateOccurrences"),
        "{response:?}"
    );

    john.jmap_destroy(
        MethodObject::Calendar,
        [&calendar_id],
        [("onDestroyRemoveEvents", true)],
    )
    .await;
}

async fn identity_set(test: &TestServer, john: &Account) {
    let properties = [
        ParticipantIdentityProperty::Id,
        ParticipantIdentityProperty::CalendarAddress,
        ParticipantIdentityProperty::IsDefault,
    ];
    let identities = john
        .jmap_get(
            MethodObject::ParticipantIdentity,
            properties.iter(),
            Vec::<&str>::new(),
        )
        .await
        .list()
        .to_vec();
    let default_id = identities
        .iter()
        .find(|identity| identity["isDefault"] == json!(true))
        .unwrap()
        .id()
        .to_string();
    let other = identities
        .iter()
        .find(|identity| identity["isDefault"] == json!(false))
        .unwrap();
    let other_id = other.id().to_string();
    let other_address = other["calendarAddress"].as_str().unwrap().to_string();

    // Two identities cannot share an address
    assert_eq!(
        john.jmap_update(
            MethodObject::ParticipantIdentity,
            [(&default_id, json!({"calendarAddress": &other_address}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .not_updated(&default_id)
        .typ(),
        "forbidden"
    );

    // Addresses are reported when the server normalizes them
    let default_address = identities
        .iter()
        .find(|identity| identity["isDefault"] == json!(true))
        .and_then(|identity| identity["calendarAddress"].as_str())
        .unwrap()
        .to_string();
    john.jmap_update(
        MethodObject::ParticipantIdentity,
        [(
            &default_id,
            json!({"calendarAddress": default_address.to_uppercase()}),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&default_id)
    .assert_is_equal(json!({"calendarAddress": &default_address}));

    // The default is not changed when another operation fails
    let response = john
        .jmap_method_call(
            "ParticipantIdentity/set",
            json!({
                "accountId": john.id_string(),
                "onSuccessSetIsDefault": &other_id,
                "create": {"bad": {"calendarAddress": "mailto:nobody@example.org"}}
            }),
        )
        .await;
    assert_eq!(response.method_response().get("updated"), None);
    assert_eq!(
        response.method_response()["notCreated"]["bad"]["type"],
        json!("forbidden"),
        "{response:?}"
    );

    // Changing the default reports both identities
    let response = john
        .jmap_method_call(
            "ParticipantIdentity/set",
            json!({
                "accountId": john.id_string(),
                "onSuccessSetIsDefault": &other_id
            }),
        )
        .await;
    response
        .updated(&other_id)
        .assert_is_equal(json!({"isDefault": true}));
    response
        .updated(&default_id)
        .assert_is_equal(json!({"isDefault": false}));

    // Destroying the default identity promotes another one
    let response = john
        .jmap_destroy(
            MethodObject::ParticipantIdentity,
            [&other_id],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response
        .updated(&default_id)
        .assert_is_equal(json!({"isDefault": true}));
    assert_eq!(
        john.jmap_get(
            MethodObject::ParticipantIdentity,
            properties.iter(),
            [&default_id]
        )
        .await
        .list()[0]["isDefault"],
        json!(true)
    );

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(john.id().document_id())
        .with_collection(Collection::Principal)
        .with_document(0)
        .clear(PrincipalField::ParticipantIdentities);
    test.server.commit_batch(batch).await.unwrap();
}
