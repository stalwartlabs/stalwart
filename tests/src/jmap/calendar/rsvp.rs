/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::conformance::{dav_get, event_dav_path};
use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use calcard::jscalendar::JSCalendarProperty;
use groupware::cache::GroupwareCache;
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
use std::{fmt::Debug, time::Duration};
use store::write::now;
use types::id::Id;

const JOHN: &str = "8584f8f9-5414-55e3-8a1c-ad6fc2f3ffb6";
const JANE: &str = "a0171748-fe8d-57d8-879e-56036a5251d1";
const BILL: &str = "86720268-d67c-58c3-9217-03df7d7ee4d8";
const POLL_ATTEMPTS: usize = 20;
const POLL_INTERVAL_MS: u64 = 250;

pub async fn test(test: &TestServer) {
    println!("Running Calendar sharee RSVP scheduling tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let bill = test.account("bill@example.com");
    let mut issues = Vec::new();

    for attendee in [jane, bill] {
        attendee
            .jmap_create(
                MethodObject::Calendar,
                [json!({"name": "Invitations"})],
                [("onSuccessSetIsDefault", "#i0")],
            )
            .await
            .created(0);
    }

    for via_dav in [false, true] {
        let uid = format!("rsvp-origin-{via_dav}");
        let john_event_id = invite(test, john, jane, &uid).await;
        let jane_event_id = event_id_by_uid(jane, &uid).await;
        let bill_notifications = notification_count(bill).await;

        if via_dav {
            let dav = jane.webdav_client();
            let path = event_dav_path(test, john, &john_event_id).await;
            let ical = dav_get(&dav, &path).await;
            let reply = with_partstat(&ical, "jane.smith@example.com", "TENTATIVE");
            let response = dav.request("PUT", &path, reply.as_str()).await;
            if response.status != StatusCode::NO_CONTENT {
                issues.push(format!(
                    "CalDAV sharee RSVP on the organizer copy rejected: {response:?}"
                ));
            }
        } else {
            let response = jane
                .jmap_method_call(
                    "CalendarEvent/set",
                    json!({
                        "accountId": john.id_string(),
                        "update": {
                            &john_event_id: { format!("participants/{JANE}/participationStatus"): "tentative" }
                        },
                        "sendSchedulingMessages": true
                    }),
                )
                .await;
            if let Some(error) = response.method_response()["notUpdated"].get(&john_event_id) {
                issues.push(format!(
                    "JMAP sharee RSVP on the organizer copy rejected: {error}"
                ));
            }
        }
        settle(test).await;

        let label = if via_dav { "CalDAV" } else { "JMAP" };
        expect(
            &mut issues,
            format!("{label} sharee RSVP on the organizer copy: organizer copy"),
            status(john, john, &john_event_id, JANE).await,
            "tentative",
        );
        expect(
            &mut issues,
            format!("{label} sharee RSVP on the organizer copy: attendee copy"),
            status(jane, jane, &jane_event_id, JANE).await,
            "tentative",
        );
        expect(
            &mut issues,
            format!("{label} sharee RSVP on the organizer copy: other attendee notified"),
            notification_count(bill).await > bill_notifications,
            true,
        );

        let uid = format!("rsvp-attendee-{via_dav}");
        let john_event_id = invite(test, john, jane, &uid).await;
        let jane_event_id = event_id_by_uid(jane, &uid).await;
        let jane_calendar_id = jane
            .jmap_get(
                MethodObject::CalendarEvent,
                [JSCalendarProperty::<Id>::CalendarIds],
                [&jane_event_id],
            )
            .await
            .list()[0]["calendarIds"]
            .as_object()
            .and_then(|ids| ids.keys().next().cloned())
            .unwrap();
        for (rights, participant, partstat, organizer_partstat) in [
            (
                json!({"mayReadItems": true, "mayRSVP": true}),
                BILL,
                "declined",
                "needs-action",
            ),
            (
                json!({"mayReadItems": true, "mayWriteAll": true}),
                JANE,
                "accepted",
                "accepted",
            ),
        ] {
            jane.jmap_update(
                MethodObject::Calendar,
                [(
                    &jane_calendar_id,
                    json!({ "shareWith": { bill.id_string(): rights } }),
                )],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .updated(&jane_calendar_id);

            if via_dav {
                let dav = bill.webdav_client();
                let path = event_dav_path(test, jane, &jane_event_id).await;
                let ical = dav_get(&dav, &path).await;
                let address = if participant == BILL {
                    "bill@example.com"
                } else {
                    "jane.smith@example.com"
                };
                let reply = with_partstat(&ical, address, &partstat.to_ascii_uppercase());
                let response = dav.request("PUT", &path, reply.as_str()).await;
                if response.status != StatusCode::NO_CONTENT {
                    issues.push(format!(
                        "CalDAV sharee RSVP for {participant} on an attendee copy rejected: {response:?}"
                    ));
                }
            } else {
                let response = bill
                    .jmap_method_call(
                        "CalendarEvent/set",
                        json!({
                            "accountId": jane.id_string(),
                            "update": {
                                &jane_event_id: { format!("participants/{participant}/participationStatus"): partstat }
                            },
                            "sendSchedulingMessages": true
                        }),
                    )
                    .await;
                if let Some(error) = response.method_response()["notUpdated"].get(&jane_event_id) {
                    issues.push(format!(
                        "JMAP sharee RSVP for {participant} on an attendee copy rejected: {error}"
                    ));
                }
            }
            settle(test).await;

            let who = if participant == BILL {
                "sharee's own participant (mayRSVP)"
            } else {
                "owner's participant (mayWriteAll)"
            };
            expect(
                &mut issues,
                format!("{label} sharee RSVP for the {who} on an attendee copy: attendee copy"),
                status(bill, jane, &jane_event_id, participant).await,
                partstat,
            );
            expect(
                &mut issues,
                format!("{label} sharee RSVP for the {who} on an attendee copy: organizer copy"),
                status(john, john, &john_event_id, participant).await,
                organizer_partstat,
            );
        }
        jane.jmap_update(
            MethodObject::Calendar,
            [(&jane_calendar_id, json!({ "shareWith": null }))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&jane_calendar_id);
    }

    hidden_attendees_and_instances(test, john, jane, bill, &mut issues).await;
    privacy_kept_on_new_instances(test, john, jane, &mut issues).await;
    sequence_incremented_once(test, john, jane, &mut issues).await;
    excluded_occurrence_sends_a_cancel(test, john, jane, &mut issues).await;
    itip_notifications_replace_the_oldest(test, john, &mut issues).await;
    default_calendar_recreated_for_an_invitation(test, john, jane, &mut issues).await;

    test.wait_for_tasks().await;
    for client in [john, jane, bill] {
        client.destroy_all_calendars().await;
        client.destroy_all_event_notifications().await;
        test.destroy_all_mailboxes(client).await;
    }

    assert!(issues.is_empty(), "\n{}", issues.join("\n"));
    test.assert_is_empty().await;
}

async fn hidden_attendees_and_instances(
    test: &TestServer,
    john: &Account,
    jane: &Account,
    bill: &Account,
    issues: &mut Vec<String>,
) {
    let uid = "hidden-attendees";
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": uid})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let participant = |address: &str, roles: Value| {
        json!({
            "@type": "Participant",
            "calendarAddress": address,
            "roles": roles,
            "participationStatus": "needs-action",
            "expectReply": true
        })
    };
    john.jmap_create(
        MethodObject::CalendarEvent,
        [json!({
            "calendarIds": { &calendar_id: true },
            "uid": uid,
            "title": "Hidden",
            "timeZone": "Etc/UTC",
            "start": "2030-06-01T09:00:00",
            "duration": "PT1H",
            "recurrenceRule": {"frequency": "daily", "count": 3},
            "hideAttendees": true,
            "organizerCalendarAddress": "mailto:jdoe@example.com",
            "participants": {
                JOHN: participant("mailto:jdoe@example.com", json!({"owner": true, "chair": true})),
                JANE: participant("mailto:jane.smith@example.com", json!({"attendee": true}))
            },
            "recurrenceOverrides": {
                "2030-06-02T09:00:00": {
                    format!("participants/{BILL}"): participant("mailto:bill@example.com", json!({"attendee": true}))
                },
                "2030-06-03T09:00:00": {
                    format!("participants/{JANE}"): null
                }
            }
        })],
        [("sendSchedulingMessages", true)],
    )
    .await
    .created(0);
    settle(test).await;

    let copy = async |account: &Account| {
        let id = event_id_by_uid(account, uid).await;
        account
            .jmap_get(
                MethodObject::CalendarEvent,
                [
                    JSCalendarProperty::<Id>::Participants,
                    JSCalendarProperty::RecurrenceRule,
                    JSCalendarProperty::RecurrenceOverrides,
                    JSCalendarProperty::RecurrenceId,
                ],
                [&id],
            )
            .await
            .list()[0]
            .clone()
    };

    let jane_copy = copy(jane).await;
    let jane_json = jane_copy.to_string();
    expect(
        issues,
        format!("hideAttendees: attendee copy hides other attendees: {jane_json}"),
        jane_json.contains("bill@example.com"),
        false,
    );
    expect(
        issues,
        format!("per-instance: removed occurrence is excluded: {jane_json}"),
        jane_copy["recurrenceOverrides"]["2030-06-03T09:00:00"]["excluded"].clone(),
        json!(true),
    );

    let bill_copy = copy(bill).await;
    let bill_json = bill_copy.to_string();
    expect(
        issues,
        format!("hideAttendees: single-instance copy hides other attendees: {bill_json}"),
        bill_json.contains("jane.smith@example.com"),
        false,
    );
    expect(
        issues,
        format!("per-instance: single-instance attendee gets no series: {bill_json}"),
        bill_copy["recurrenceRule"].is_null(),
        true,
    );

    for (account, address, other) in [
        (jane, "jane.smith@example.com", "bill@example.com"),
        (bill, "bill@example.com", "jane.smith@example.com"),
    ] {
        let bodies = eventually(async || {
            let bodies = email_bodies(account, "Hidden").await;
            (!bodies.is_empty()).then_some(bodies)
        })
        .await
        .unwrap_or_default();
        expect(
            issues,
            format!("hideAttendees: invitation email delivered to {address}"),
            bodies.is_empty(),
            false,
        );
        for body in bodies {
            expect(
                issues,
                format!("hideAttendees: invitation email to {address} hides {other}: {body}"),
                body.contains(other),
                false,
            );
        }
    }
}

async fn privacy_kept_on_new_instances(
    test: &TestServer,
    john: &Account,
    jane: &Account,
    issues: &mut Vec<String>,
) {
    let uid = "privacy-new-instance";
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": uid})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let john_event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "uid": uid,
                "title": "Series",
                "timeZone": "Etc/UTC",
                "start": "2030-06-01T09:00:00",
                "duration": "PT1H",
                "recurrenceRule": {"frequency": "daily", "count": 3},
                "organizerCalendarAddress": "mailto:jdoe@example.com",
                "participants": {
                    JOHN: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jdoe@example.com",
                        "roles": {"owner": true, "chair": true},
                        "participationStatus": "accepted"
                    },
                    JANE: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jane.smith@example.com",
                        "roles": {"attendee": true},
                        "participationStatus": "needs-action",
                        "expectReply": true
                    }
                }
            })],
            [("sendSchedulingMessages", true)],
        )
        .await
        .created(0)
        .id()
        .to_string();
    settle(test).await;

    let jane_event_id = event_id_by_uid(jane, uid).await;
    jane.jmap_update(
        MethodObject::CalendarEvent,
        [(&jane_event_id, json!({ "privacy": "private" }))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&jane_event_id);

    john.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &john_event_id,
            json!({ "recurrenceOverrides": { "2030-06-02T09:00:00": { "title": "Moved" } } }),
        )],
        [("sendSchedulingMessages", true)],
    )
    .await
    .updated(&john_event_id);
    settle(test).await;

    let jane_copy = eventually(async || {
        let copy = jane
            .jmap_get(
                MethodObject::CalendarEvent,
                [
                    JSCalendarProperty::<Id>::Privacy,
                    JSCalendarProperty::RecurrenceOverrides,
                ],
                [&jane_event_id],
            )
            .await
            .list()[0]
            .clone();
        (copy["recurrenceOverrides"]["2030-06-02T09:00:00"]["title"] == "Moved").then_some(copy)
    })
    .await
    .unwrap_or_default();
    expect(
        issues,
        format!("privacy: new instance delivered to the attendee copy: {jane_copy}"),
        jane_copy["recurrenceOverrides"]["2030-06-02T09:00:00"]["title"].clone(),
        json!("Moved"),
    );
    expect(
        issues,
        format!("privacy: attendee copy keeps its privacy: {jane_copy}"),
        jane_copy["privacy"].clone(),
        json!("private"),
    );
    expect(
        issues,
        format!("privacy: new instance inherits the stored privacy: {jane_copy}"),
        jane_copy["recurrenceOverrides"]["2030-06-02T09:00:00"]
            .get("privacy")
            .cloned(),
        None::<Value>,
    );

    let ical = dav_get(
        &jane.webdav_client(),
        &event_dav_path(test, jane, &jane_event_id).await,
    )
    .await;
    expect(
        issues,
        format!("privacy: every instance of the attendee copy is private: {ical}"),
        ical.matches("CLASS:PRIVATE").count(),
        ical.matches("BEGIN:VEVENT").count(),
    );
}

async fn sequence_incremented_once(
    test: &TestServer,
    john: &Account,
    jane: &Account,
    issues: &mut Vec<String>,
) {
    let uid = "sequence-once";
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": uid})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let john_event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "uid": uid,
                "title": "Series",
                "timeZone": "Etc/UTC",
                "start": "2030-06-01T09:00:00",
                "duration": "PT1H",
                "recurrenceRule": {"frequency": "daily", "count": 3},
                "locations": {"room": {"@type": "Location", "name": "Room 1"}},
                "recurrenceOverrides": {
                    "2030-06-02T09:00:00": { "locations/room/name": "Room 9" }
                },
                "organizerCalendarAddress": "mailto:jdoe@example.com",
                "participants": {
                    JOHN: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jdoe@example.com",
                        "roles": {"owner": true, "chair": true},
                        "participationStatus": "accepted"
                    },
                    JANE: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jane.smith@example.com",
                        "roles": {"attendee": true},
                        "participationStatus": "needs-action",
                        "expectReply": true
                    }
                }
            })],
            [("sendSchedulingMessages", true)],
        )
        .await
        .created(0)
        .id()
        .to_string();
    settle(test).await;

    let sequence = async |account: &Account, event_id: &str| {
        account
            .jmap_get(
                MethodObject::CalendarEvent,
                [JSCalendarProperty::<Id>::Sequence],
                [event_id],
            )
            .await
            .list()[0]["sequence"]
            .as_u64()
            .unwrap_or_default()
    };
    let jane_event_id = event_id_by_uid(jane, uid).await;
    let initial = sequence(john, &john_event_id).await;

    john.jmap_update(
        MethodObject::CalendarEvent,
        [(&john_event_id, json!({ "locations/room/name": "Room 2" }))],
        [("sendSchedulingMessages", true)],
    )
    .await
    .updated(&john_event_id);
    settle(test).await;

    expect(
        issues,
        "sequence: stored master after a location change".to_string(),
        sequence(john, &john_event_id).await,
        initial + 1,
    );
    let delivered = eventually(async || {
        let delivered = sequence(jane, &jane_event_id).await;
        (delivered > initial).then_some(delivered)
    })
    .await;
    expect(
        issues,
        "sequence: master in the REQUEST after a location change".to_string(),
        delivered,
        Some(initial + 1),
    );
    let ical = dav_get(
        &john.webdav_client(),
        &event_dav_path(test, john, &john_event_id).await,
    )
    .await;
    expect(
        issues,
        format!("sequence: every stored component raised once: {ical}"),
        ical.matches(&format!("SEQUENCE:{}\r\n", initial + 1))
            .count(),
        ical.matches("BEGIN:VEVENT").count(),
    );
}

async fn excluded_occurrence_sends_a_cancel(
    test: &TestServer,
    john: &Account,
    jane: &Account,
    issues: &mut Vec<String>,
) {
    let uid = "excluded-occurrence";
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": uid})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let john_event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "uid": uid,
                "title": "Standup",
                "timeZone": "Etc/UTC",
                "start": "2030-07-01T09:00:00",
                "duration": "PT1H",
                "recurrenceRule": {"frequency": "daily", "count": 5},
                "organizerCalendarAddress": "mailto:jdoe@example.com",
                "participants": {
                    JOHN: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jdoe@example.com",
                        "roles": {"owner": true, "chair": true},
                        "participationStatus": "accepted"
                    },
                    JANE: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jane.smith@example.com",
                        "roles": {"attendee": true},
                        "participationStatus": "needs-action",
                        "expectReply": true
                    }
                }
            })],
            [("sendSchedulingMessages", true)],
        )
        .await
        .created(0)
        .id()
        .to_string();
    settle(test).await;
    let jane_event_id = event_id_by_uid(jane, uid).await;
    let delivered = email_bodies(jane, "Standup").await.len();

    john.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &john_event_id,
            json!({ "recurrenceOverrides": {
                "2030-07-02T09:00:00": { "excluded": true },
                "2030-07-03T09:00:00": { "excluded": true }
            } }),
        )],
        [("sendSchedulingMessages", true)],
    )
    .await
    .updated(&john_event_id);
    settle(test).await;

    let dav = jane.webdav_client();
    let path = event_dav_path(test, jane, &jane_event_id).await;
    let ical = eventually(async || {
        let ical = dav_get(&dav, &path).await;
        (ical.matches("STATUS:CANCELLED").count() == 2).then_some(ical)
    })
    .await
    .unwrap_or_default();
    expect(
        issues,
        format!("exclusion: the attendee receives both cancelled occurrences: {ical}"),
        ical.contains("20300702T090000") && ical.contains("20300703T090000"),
        true,
    );
    expect(
        issues,
        format!("exclusion: the attendee series is not re-requested: {ical}"),
        ical.contains("EXDATE"),
        false,
    );
    settle(test).await;
    expect(
        issues,
        "exclusion: both occurrences share one scheduling message".to_string(),
        email_bodies(jane, "Standup").await.len(),
        delivered + 1,
    );
}

async fn itip_notifications_replace_the_oldest(
    test: &TestServer,
    john: &Account,
    issues: &mut Vec<String>,
) {
    let uid = "itip-notification-limit";
    let admin = test.account("admin@example.com");
    let limited = admin
        .create_user_account(
            "itip-limited@example.com",
            "itip limited + extra safety",
            "iTIP Limited",
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

    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": uid})],
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
                "title": "Limited 0",
                "timeZone": "Etc/UTC",
                "start": "2030-06-01T09:00:00",
                "duration": "PT1H",
                "organizerCalendarAddress": "mailto:jdoe@example.com",
                "participants": {
                    JOHN: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jdoe@example.com",
                        "roles": {"owner": true, "chair": true},
                        "participationStatus": "accepted"
                    },
                    "limited": {
                        "@type": "Participant",
                        "calendarAddress": "mailto:itip-limited@example.com",
                        "roles": {"attendee": true},
                        "participationStatus": "needs-action",
                        "expectReply": true
                    }
                }
            })],
            [("sendSchedulingMessages", true)],
        )
        .await
        .created(0)
        .id()
        .to_string();
    settle(test).await;
    for idx in 1..=3 {
        john.jmap_update(
            MethodObject::CalendarEvent,
            [(&event_id, json!({"title": format!("Limited {idx}")}))],
            [("sendSchedulingMessages", true)],
        )
        .await
        .updated(&event_id);
        settle(test).await;
    }

    let titles = async || {
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
            .map(|notification| {
                notification["eventPatch"]["title"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect::<Vec<_>>();
        titles.sort_unstable();
        titles
    };
    eventually(async || {
        titles()
            .await
            .iter()
            .any(|title| title == "Limited 3")
            .then_some(())
    })
    .await;
    expect(
        issues,
        "iTIP notifications at the limit replace the oldest".to_string(),
        titles().await,
        ["Limited 2", "Limited 3"],
    );

    test.wait_for_tasks().await;
    limited.destroy_all_calendars().await;
    limited.destroy_all_event_notifications().await;
    test.destroy_all_mailboxes(&limited).await;
    admin
        .registry_destroy(ObjectType::Account, [limited.id()])
        .await;
}

async fn default_calendar_recreated_for_an_invitation(
    test: &TestServer,
    john: &Account,
    jane: &Account,
    issues: &mut Vec<String>,
) {
    jane.destroy_all_calendars().await;
    settle(test).await;
    expect(
        issues,
        "default calendar: every calendar destroyed".to_string(),
        calendar_names(jane).await.len(),
        0,
    );

    let uid = "rsvp-recreate-default";
    invite(test, john, jane, uid).await;
    let copy = eventually(async || {
        let response = jane
            .jmap_method_call(
                "CalendarEvent/query",
                json!({ "accountId": jane.id_string(), "filter": { "uid": uid } }),
            )
            .await;
        response.method_response()["ids"][0]
            .as_str()
            .map(str::to_string)
    })
    .await;
    expect(
        issues,
        "default calendar: the invitation is stored".to_string(),
        copy.is_some(),
        true,
    );
    expect(
        issues,
        "default calendar: one calendar is recreated".to_string(),
        calendar_names(jane).await.len(),
        1,
    );

    jane.destroy_all_calendars().await;
    settle(test).await;
    let account = test
        .server
        .account(jane.id().document_id())
        .await
        .expect("account");
    let (first, second) = tokio::join!(
        test.server
            .get_or_create_default_calendar(&account, &account),
        test.server
            .get_or_create_default_calendar(&account, &account)
    );
    settle(test).await;
    let first = first.expect("default calendar");
    let second = second.expect("default calendar");
    expect(
        issues,
        "default calendar: concurrent ingests agree".to_string(),
        first.is_some() && first == second,
        true,
    );
    expect(
        issues,
        "default calendar: concurrent ingests create one calendar".to_string(),
        calendar_names(jane).await.len(),
        1,
    );
}

async fn calendar_names(account: &Account) -> Vec<String> {
    let mut names = account
        .jmap_method_call(
            "Calendar/get",
            json!({ "accountId": account.id_string(), "ids": null, "properties": ["name"] }),
        )
        .await
        .list()
        .iter()
        .filter_map(|calendar| calendar["name"].as_str().map(str::to_string))
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

async fn eventually<T>(check: impl AsyncFn() -> Option<T>) -> Option<T> {
    for _ in 0..POLL_ATTEMPTS {
        if let Some(value) = check().await {
            return Some(value);
        }
        tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
    None
}

async fn email_bodies(account: &Account, subject: &str) -> Vec<String> {
    let ids = account
        .jmap_query(
            MethodObject::Email,
            Vec::<(&str, Value)>::new(),
            Vec::<&str>::new(),
            Vec::<(&str, Value)>::new(),
        )
        .await
        .ids()
        .map(str::to_string)
        .collect::<Vec<_>>();
    account
        .jmap_method_call(
            "Email/get",
            json!({
                "accountId": account.id_string(),
                "ids": ids,
                "properties": ["subject", "bodyValues"],
                "fetchAllBodyValues": true
            }),
        )
        .await
        .list()
        .iter()
        .filter(|email| {
            email["subject"]
                .as_str()
                .is_some_and(|value| value.contains(subject))
        })
        .map(|email| {
            email["bodyValues"]
                .as_object()
                .into_iter()
                .flat_map(|values| values.values())
                .filter_map(|value| value["value"].as_str())
                .collect::<String>()
        })
        .collect()
}

async fn invite(test: &TestServer, john: &Account, jane: &Account, uid: &str) -> String {
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": uid,
                "shareWith": { jane.id_string(): {"mayReadItems": true, "mayRSVP": true} }
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
                "calendarIds": { &calendar_id: true },
                "uid": uid,
                "title": "RSVP",
                "timeZone": "Etc/UTC",
                "start": DateTime::from_timestamp(now() as i64 + 86400)
                    .to_rfc3339()
                    .trim_end_matches('Z'),
                "duration": "PT1H",
                "organizerCalendarAddress": "mailto:jdoe@example.com",
                "participants": {
                    JOHN: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jdoe@example.com",
                        "roles": {"owner": true, "chair": true},
                        "participationStatus": "accepted"
                    },
                    JANE: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jane.smith@example.com",
                        "roles": {"attendee": true},
                        "participationStatus": "needs-action",
                        "expectReply": true
                    },
                    BILL: {
                        "@type": "Participant",
                        "calendarAddress": "mailto:bill@example.com",
                        "roles": {"attendee": true},
                        "participationStatus": "needs-action",
                        "expectReply": true
                    }
                }
            })],
            [("sendSchedulingMessages", true)],
        )
        .await
        .created(0)
        .id()
        .to_string();
    settle(test).await;
    event_id
}

async fn settle(test: &TestServer) {
    tokio::time::sleep(Duration::from_millis(600)).await;
    test.wait_for_tasks().await;
}

async fn event_id_by_uid(account: &Account, uid: &str) -> String {
    let response = account
        .jmap_method_call(
            "CalendarEvent/query",
            json!({ "accountId": account.id_string(), "filter": { "uid": uid } }),
        )
        .await;
    response.method_response()["ids"][0]
        .as_str()
        .unwrap_or_else(|| panic!("no copy of {uid}: {response:?}"))
        .to_string()
}

async fn notification_count(account: &Account) -> usize {
    account
        .jmap_method_call(
            "CalendarEventNotification/get",
            json!({ "accountId": account.id_string(), "ids": null, "properties": ["id"] }),
        )
        .await
        .list()
        .len()
}

async fn status(caller: &Account, owner: &Account, event_id: &str, participant: &str) -> String {
    let response = caller
        .jmap_get_account(
            owner,
            MethodObject::CalendarEvent,
            [JSCalendarProperty::<Id>::Participants],
            [event_id],
        )
        .await;
    let status: &Value = &response.list()[0]["participants"][participant]["participationStatus"];
    status.as_str().unwrap_or("needs-action").to_string()
}

fn with_partstat(ical: &str, address: &str, partstat: &str) -> String {
    ical.lines()
        .map(|line| {
            if line.starts_with("ATTENDEE") && line.to_ascii_lowercase().contains(address) {
                match line.split_once("PARTSTAT=") {
                    Some((before, after)) => {
                        let rest =
                            after.trim_start_matches(|c: char| c.is_ascii_alphabetic() || c == '-');
                        format!("{before}PARTSTAT={partstat}{rest}")
                    }
                    None => line.replacen("ATTENDEE", &format!("ATTENDEE;PARTSTAT={partstat}"), 1),
                }
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn expect<T: PartialEq<U> + Debug, U: Debug>(
    issues: &mut Vec<String>,
    label: String,
    actual: T,
    expected: U,
) {
    if actual != expected {
        issues.push(format!("{label}: expected {expected:?}, got {actual:?}"));
    }
}
