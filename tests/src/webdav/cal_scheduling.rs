/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::WebDavTest;
use crate::{
    jmap::mail::mailbox::destroy_all_mailboxes_for_account,
    webdav::{DummyWebDavClient, prop::ALL_DAV_PROPERTIES},
};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendarDay, ICalendarFrequency, ICalendarMethod, ICalendarParticipationStatus,
        ICalendarProperty, ICalendarRecurrenceRule, ICalendarWeekday,
    },
};
use common::{Server, auth::AccessToken};
use dav_proto::schema::property::{CalDavProperty, DavProperty, WebDavProperty};
use email::cache::MessageCacheFetch;
use groupware::{
    cache::GroupwareCache,
    scheduling::{
        ArchivedItipSummary, ItipField, ItipParticipant, ItipSummary, ItipTime, ItipValue,
    },
};
use hyper::StatusCode;
use mail_parser::{DateTime, MessageParser};
use services::task_manager::imip::build_itip_template;
use std::str::FromStr;
use store::write::now;
use types::collection::SyncCollection;

pub async fn test(test: &WebDavTest) {
    println!("Running calendar scheduling tests...");
    let bill_client = test.client("bill");
    let jane_client = test.client("jane");
    let john_client = test.client("john");

    // Validate hierarchy of scheduling resources
    let response = jane_client
        .propfind_with_headers("/dav/itip/jane/", ALL_DAV_PROPERTIES, [("depth", "1")])
        .await;
    let properties = response
        .with_hrefs([
            "/dav/itip/jane/",
            "/dav/itip/jane/inbox/",
            "/dav/itip/jane/outbox/",
        ])
        .properties("/dav/itip/jane/inbox/");

    // Validate schedule inbox properties
    properties
        .get(DavProperty::WebDav(WebDavProperty::ResourceType))
        .with_values(["D:collection", "A:schedule-inbox"]);
    properties
        .get(DavProperty::CalDav(
            CalDavProperty::ScheduleDefaultCalendarURL,
        ))
        .with_values(["D:href:/dav/cal/jane/default/"])
        .with_status(StatusCode::OK);
    properties
        .get(DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet))
        .with_some_values([
            "D:supported-privilege.D:privilege.D:all",
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:privilege.D:read"
            ),
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:privilege.A:schedule-deliver"
            ),
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:supported-privilege.D:privilege.A:schedule-deliver-invite"
            ),
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:supported-privilege.D:privilege.A:schedule-deliver-reply"
            ),
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:supported-privilege.D:privilege.A:schedule-query-freebusy"
            ),
        ]);
    properties
        .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
        .with_values([
            "D:privilege.D:write-properties",
            "D:privilege.A:schedule-deliver-invite",
            "D:privilege.D:write-content",
            "D:privilege.A:schedule-deliver",
            "D:privilege.D:read",
            "D:privilege.D:all",
            "D:privilege.A:schedule-query-freebusy",
            "D:privilege.D:read-acl",
            "D:privilege.D:write-acl",
            "D:privilege.A:schedule-deliver-reply",
            "D:privilege.D:write",
            "D:privilege.D:read-current-user-privilege-set",
        ]);

    // Validate schedule outbox properties
    let properties = response.properties("/dav/itip/jane/outbox/");
    properties
        .get(DavProperty::WebDav(WebDavProperty::ResourceType))
        .with_values(["D:collection", "A:schedule-outbox"]);
    properties
        .get(DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet))
        .with_some_values([
            "D:supported-privilege.D:privilege.D:all",
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:privilege.D:read"
            ),
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:privilege.A:schedule-send"
            ),
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:supported-privilege.D:privilege.A:schedule-send-invite"
            ),
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:supported-privilege.D:privilege.A:schedule-send-reply"
            ),
            concat!(
                "D:supported-privilege.D:supported-privilege.",
                "D:supported-privilege.D:privilege.A:schedule-send-freebusy"
            ),
        ]);
    properties
        .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
        .with_values([
            "D:privilege.D:write-properties",
            "D:privilege.A:schedule-send-invite",
            "D:privilege.D:write-content",
            "D:privilege.A:schedule-send",
            "D:privilege.D:read",
            "D:privilege.D:all",
            "D:privilege.A:schedule-send-freebusy",
            "D:privilege.D:read-acl",
            "D:privilege.D:write-acl",
            "D:privilege.A:schedule-send-reply",
            "D:privilege.D:write",
            "D:privilege.D:read-current-user-privilege-set",
        ]);

    // Send invitation to Bill and Mike
    let test_itip = TEST_ITIP
        .replace(
            "$START",
            &DateTime::from_timestamp(now() as i64 + 60 * 60)
                .to_rfc3339()
                .replace(['-', ':'], ""),
        )
        .replace(
            "$END",
            &DateTime::from_timestamp(now() as i64 + 5 * 60 * 60)
                .to_rfc3339()
                .replace(['-', ':'], ""),
        );
    john_client
        .request_with_headers(
            "PUT",
            "/dav/cal/john/default/itip.ics",
            [("content-type", "text/calendar; charset=utf-8")],
            &test_itip,
        )
        .await
        .with_status(StatusCode::CREATED);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Check that the invitation was received by Bill and Mike
    for client in [bill_client, jane_client] {
        let messages = test
            .server
            .get_cached_messages(client.account_id)
            .await
            .unwrap();
        assert_eq!(messages.emails.items.len(), 1);
        let access_token = test
            .server
            .get_access_token(client.account_id)
            .await
            .unwrap();
        let events = test
            .server
            .fetch_dav_resources(&access_token, client.account_id, SyncCollection::Calendar)
            .await
            .unwrap();
        assert_eq!(events.resources.len(), 2);
        let events = test
            .server
            .fetch_dav_resources(
                &access_token,
                client.account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await
            .unwrap();
        assert_eq!(events.resources.len(), 3);
    }

    // Validate iTIP
    let itips = fetch_and_remove_itips(jane_client).await;
    assert_eq!(itips.len(), 1);
    let itip = itips.first().unwrap();
    assert!(
        itip.contains("SUMMARY:Lunch") && itip.contains("METHOD:REQUEST"),
        "failed for itip: {itip}"
    );

    // Fetch added calendar entry
    let cals = fetch_icals(jane_client).await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();

    // Using an invalid schedule tag should fail
    let rsvp_ical = cal.ical.replace(
        "PARTSTAT=NEEDS-ACTION:mailto:jane.smith",
        "PARTSTAT=ACCEPTED:mailto:jane.smith",
    );
    jane_client
        .request_with_headers(
            "PUT",
            &cal.href,
            [
                ("content-type", "text/calendar; charset=utf-8"),
                ("if-schedule-tag-match", "\"9999999\""),
            ],
            &rsvp_ical,
        )
        .await
        .with_status(StatusCode::PRECONDITION_FAILED);

    // RSVP the invitation
    jane_client
        .request_with_headers(
            "PUT",
            &cal.href,
            [
                ("content-type", "text/calendar; charset=utf-8"),
                ("if-schedule-tag-match", cal.schedule_tag.as_str()),
            ],
            &rsvp_ical,
        )
        .await
        .with_status(StatusCode::NO_CONTENT);

    // Make sure that the schedule has not changed
    assert_eq!(
        fetch_icals(jane_client).await[0].schedule_tag,
        cal.schedule_tag
    );

    // Check that John received the RSVP
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    test.wait_for_index().await;
    let itips = fetch_and_remove_itips(john_client).await;
    assert_eq!(itips.len(), 1);
    assert!(
        itips[0].contains("METHOD:REPLY")
            && itips[0].contains("PARTSTAT=ACCEPTED:mailto:jane.smith"),
        "failed for itip: {}",
        itips[0]
    );
    let cals = fetch_icals(john_client).await;
    assert_eq!(cals.len(), 1);
    assert!(
        cals[0]
            .ical
            .contains("PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:jane"),
        "failed for cal: {}",
        cals[0].ical
    );

    // Changing the event name should not trigger a new iTIP
    let updated_ical = rsvp_ical.replace("Lunch", "Dinner");
    jane_client
        .request_with_headers(
            "PUT",
            &cal.href,
            [("content-type", "text/calendar; charset=utf-8")],
            &updated_ical,
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        fetch_and_remove_itips(john_client).await,
        Vec::<String>::new()
    );

    // Deleting the event should send a cancellation
    jane_client
        .request("DELETE", &cal.href, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let itips = fetch_and_remove_itips(john_client).await;
    assert_eq!(itips.len(), 1);
    assert!(
        itips[0].contains("METHOD:REPLY")
            && itips[0].contains("PARTSTAT=DECLINED:mailto:jane.smith"),
        "failed for itip: {}",
        itips[0]
    );
    let cals = fetch_icals(john_client).await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();
    assert!(
        cal.ical.contains("PARTSTAT=DECLINED:mailto:jane"),
        "failed for cal: {}",
        cal.ical
    );

    // Fetch Bill's email invitation and RSVP via HTTP
    let document_id = test
        .server
        .get_cached_messages(bill_client.account_id)
        .await
        .unwrap()
        .emails
        .items[0]
        .document_id;
    let contents = test.fetch_email(bill_client.account_id, document_id).await;
    let message = MessageParser::new().parse(&contents).unwrap();
    let contents = message
        .html_bodies()
        .next()
        .unwrap()
        .text_contents()
        .unwrap();
    let url = contents
        .split("href=\"")
        .filter_map(|s| {
            let url = s.split_once('\"').map(|(url, _)| url)?;
            if url.contains("m=ACCEPTED") {
                Some(url.strip_prefix("https://webdav.example.org").unwrap())
            } else {
                None
            }
        })
        .next()
        .unwrap_or_else(|| {
            panic!("Failed to find RSVP link in email contents: {contents}");
        });
    let response = jane_client
        .request("GET", url, "")
        .await
        .with_status(StatusCode::OK)
        .body
        .unwrap();
    assert!(
        response.contains("Lunch") && response.contains("RSVP has been recorded"),
        "failed for response: {response}"
    );
    let cals = fetch_icals(john_client).await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();
    assert!(
        cal.ical.contains("PARTSTAT=ACCEPTED:mailto:bill"),
        "failed for cal: {}",
        cal.ical
    );

    // Test the schedule outbox
    let test_outbox = TEST_FREEBUSY
        .replace(
            "$START",
            &DateTime::from_timestamp(now() as i64)
                .to_rfc3339()
                .replace(['-', ':'], ""),
        )
        .replace(
            "$END",
            &DateTime::from_timestamp(now() as i64 + 100 * 60 * 60)
                .to_rfc3339()
                .replace(['-', ':'], ""),
        );
    let response = john_client
        .request_with_headers(
            "POST",
            "/dav/itip/john/outbox/",
            [("content-type", "text/calendar; charset=utf-8")],
            &test_outbox,
        )
        .await
        .with_status(StatusCode::OK);
    let mut account = "";
    let mut found_data = false;
    for (key, value) in &response.xml {
        match key.as_str() {
            "A:schedule-response.A:response.A:recipient.D:href" => {
                account = value.strip_prefix("mailto:").unwrap();
            }
            "A:schedule-response.A:response.A:request-status" => {
                if account == "unknown@example.com" {
                    assert_eq!(
                        value,
                        "3.7;Invalid calendar user or insufficient permissions"
                    );
                } else {
                    assert_eq!(value, "2.0;Success");
                }
            }
            "A:schedule-response.A:response.A:calendar-data" => {
                assert!(
                    value.contains("BEGIN:VFREEBUSY"),
                    "missing freebusy data in response: {response:?}"
                );
                if account == "jdoe@example.com" {
                    assert!(
                        value.contains("FREEBUSY;FBTYPE=BUSY:"),
                        "missing freebusy data in response: {response:?}"
                    );
                    found_data = true;
                }
            }
            _ => {}
        }
    }
    assert!(
        found_data,
        "Missing calendar data in response: {response:?}"
    );

    // Modifying john's event should only send updates to bill
    let updated_ical = cal.ical.replace("Lunch", "Breakfast at Tiffany's");
    john_client
        .request_with_headers(
            "PUT",
            &cal.href,
            [("content-type", "text/calendar; charset=utf-8")],
            &updated_ical,
        )
        .await
        .with_status(StatusCode::NO_CONTENT);

    // Make sure that the schedule has changed
    assert_ne!(
        fetch_icals(john_client).await[0].schedule_tag,
        cal.schedule_tag
    );
    let main_event_href = cal.href;

    // Check that Bill received the update
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    test.wait_for_index().await;
    let mut itips = fetch_and_remove_itips(bill_client).await;
    itips.sort_unstable_by(|a, _| {
        if a.contains("Lunch") {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    assert_eq!(itips.len(), 2);
    assert!(
        itips[0].contains("METHOD:REQUEST") && itips[0].contains("Lunch"),
        "failed for itip: {}",
        itips[0]
    );
    assert!(
        itips[1].contains("METHOD:REQUEST") && itips[1].contains("Breakfast at Tiffany's"),
        "failed for itip: {}",
        itips[1]
    );
    let cals = fetch_icals(bill_client).await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();
    assert!(
        cal.ical.contains("SUMMARY:Breakfast at Tiffany's")
            && cal.ical.contains("PARTSTAT=ACCEPTED:mailto:bill"),
        "failed for cal: {}",
        cal.ical
    );
    let attendee_href = cal.href;
    assert_eq!(
        fetch_and_remove_itips(jane_client).await,
        Vec::<String>::new()
    );

    // Removing the event should from John's calendar send a cancellation to Bill
    john_client
        .request("DELETE", &main_event_href, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let itips = fetch_and_remove_itips(bill_client).await;
    assert_eq!(itips.len(), 1);
    assert!(
        itips[0].contains("METHOD:CANCEL") && itips[0].contains("STATUS:CANCELLED"),
        "failed for itip: {}",
        itips[0]
    );
    let cals = fetch_icals(bill_client).await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();
    assert!(
        cal.ical.contains("STATUS:CANCELLED"),
        "failed for cal: {}",
        cal.ical
    );
    assert_eq!(
        fetch_and_remove_itips(jane_client).await,
        Vec::<String>::new()
    );

    // Delete the event from Bill's calendar disabling schedule replies
    bill_client
        .request_with_headers("DELETE", &attendee_href, [("Schedule-Reply", "F")], "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        fetch_and_remove_itips(john_client).await,
        Vec::<String>::new()
    );

    for client in [bill_client, jane_client, john_client] {
        client.delete_default_containers().await;
        destroy_all_mailboxes_for_account(client.account_id).await;
    }

    test.assert_is_empty().await;
}

async fn fetch_and_remove_itips(client: &DummyWebDavClient) -> Vec<String> {
    let inbox_href = format!("/dav/itip/{}/inbox/", client.name);
    let response = client
        .propfind_with_headers(&inbox_href, ALL_DAV_PROPERTIES, [("depth", "1")])
        .await;
    let mut itips = vec![];

    for href in response.hrefs.keys().filter(|&href| href != &inbox_href) {
        let itip = client
            .request("GET", href, "")
            .await
            .with_status(StatusCode::OK)
            .body
            .expect("Missing body");
        client
            .request("DELETE", href, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        itips.push(itip);
    }

    itips
}

#[derive(Debug)]
struct CalEntry {
    href: String,
    ical: String,
    schedule_tag: String,
}

async fn fetch_icals(client: &DummyWebDavClient) -> Vec<CalEntry> {
    let cal_inbox = format!("/dav/cal/{}/default/", client.name);
    let response = client
        .propfind_with_headers(&cal_inbox, ALL_DAV_PROPERTIES, [("depth", "1")])
        .await;
    let mut cals = vec![];

    for href in response.hrefs.keys().filter(|&href| href != &cal_inbox) {
        let ical = client
            .request("GET", href, "")
            .await
            .with_status(StatusCode::OK)
            .body
            .expect("Missing body");
        let properties = response.properties(href);

        assert!(
            !ical.contains("METHOD:"),
            "iTIP method found in calendar entry: {ical}"
        );

        cals.push(CalEntry {
            href: href.to_string(),
            ical,
            schedule_tag: properties
                .get(DavProperty::CalDav(CalDavProperty::ScheduleTag))
                .value()
                .to_string(),
        });
    }

    cals
}

pub async fn test_build_itip_templates(server: &Server) {
    let dummy_access_token = AccessToken::from_id(0);

    for (idx, summary) in [
        ItipSummary::Invite(vec![
            ItipField {
                name: ICalendarProperty::Summary,
                value: ItipValue::Text("Lunch".to_string()),
            },
            ItipField {
                name: ICalendarProperty::Description,
                value: ItipValue::Text("Lunch at the cafe".to_string()),
            },
            ItipField {
                name: ICalendarProperty::Location,
                value: ItipValue::Text("Cafe Corner".to_string()),
            },
            ItipField {
                name: ICalendarProperty::Dtstart,
                value: ItipValue::Time(ItipTime {
                    start: 1750616068,
                    tz_id: Tz::from_str("New Zealand").unwrap().as_id(),
                }),
            },
            ItipField {
                name: ICalendarProperty::Attendee,
                value: ItipValue::Participants(vec![
                    ItipParticipant {
                        email: "jdoe@domain.com".to_string(),
                        name: Some("John Doe".to_string()),
                        is_organizer: true,
                    },
                    ItipParticipant {
                        email: "jane@domain.com".to_string(),
                        name: Some("Jane Smith".to_string()),
                        is_organizer: false,
                    },
                ]),
            },
        ]),
        ItipSummary::Cancel(vec![
            ItipField {
                name: ICalendarProperty::Summary,
                value: ItipValue::Text("Lunch".to_string()),
            },
            ItipField {
                name: ICalendarProperty::Description,
                value: ItipValue::Text("Lunch at the cafe".to_string()),
            },
            ItipField {
                name: ICalendarProperty::Location,
                value: ItipValue::Text("Cafe Corner".to_string()),
            },
            ItipField {
                name: ICalendarProperty::Dtstart,
                value: ItipValue::Time(ItipTime {
                    start: 1750616068,
                    tz_id: Tz::from_str("New Zealand").unwrap().as_id(),
                }),
            },
        ]),
        ItipSummary::Rsvp {
            part_stat: ICalendarParticipationStatus::Accepted,
            current: vec![
                ItipField {
                    name: ICalendarProperty::Summary,
                    value: ItipValue::Text("Lunch".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Description,
                    value: ItipValue::Text("Lunch at the cafe".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Location,
                    value: ItipValue::Text("Cafe Corner".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Dtstart,
                    value: ItipValue::Time(ItipTime {
                        start: 1750616068,
                        tz_id: Tz::from_str("New Zealand").unwrap().as_id(),
                    }),
                },
                ItipField {
                    name: ICalendarProperty::Rrule,
                    value: ItipValue::Rrule(Box::new(ICalendarRecurrenceRule {
                        freq: ICalendarFrequency::Weekly,
                        until: None,
                        count: Some(2),
                        interval: Some(3),
                        bysecond: Default::default(),
                        byday: vec![
                            ICalendarDay {
                                ordwk: None,
                                weekday: ICalendarWeekday::Monday,
                            },
                            ICalendarDay {
                                ordwk: None,
                                weekday: ICalendarWeekday::Wednesday,
                            },
                        ],
                        ..Default::default()
                    })),
                },
            ],
        },
        ItipSummary::Rsvp {
            part_stat: ICalendarParticipationStatus::Declined,
            current: vec![
                ItipField {
                    name: ICalendarProperty::Summary,
                    value: ItipValue::Text("Lunch".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Description,
                    value: ItipValue::Text("Lunch at the cafe".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Location,
                    value: ItipValue::Text("Cafe Corner".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Dtstart,
                    value: ItipValue::Time(ItipTime {
                        start: 1750616068,
                        tz_id: Tz::from_str("New Zealand").unwrap().as_id(),
                    }),
                },
            ],
        },
        ItipSummary::Update {
            method: ICalendarMethod::Request,
            current: vec![
                ItipField {
                    name: ICalendarProperty::Summary,
                    value: ItipValue::Text("Lunch".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Description,
                    value: ItipValue::Text("Lunch at the cafe".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Location,
                    value: ItipValue::Text("Cafe Corner".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Dtstart,
                    value: ItipValue::Time(ItipTime {
                        start: 1750616068,
                        tz_id: Tz::from_str("New Zealand").unwrap().as_id(),
                    }),
                },
                ItipField {
                    name: ICalendarProperty::Attendee,
                    value: ItipValue::Participants(vec![
                        ItipParticipant {
                            email: "jdoe@domain.com".to_string(),
                            name: Some("John Doe".to_string()),
                            is_organizer: true,
                        },
                        ItipParticipant {
                            email: "jane@domain.com".to_string(),
                            name: Some("Jane Smith".to_string()),
                            is_organizer: false,
                        },
                    ]),
                },
            ],
            previous: vec![
                ItipField {
                    name: ICalendarProperty::Summary,
                    value: ItipValue::Text("Dinner".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Description,
                    value: ItipValue::Text("Dinner at the cafe".to_string()),
                },
                ItipField {
                    name: ICalendarProperty::Dtstart,
                    value: ItipValue::Time(ItipTime {
                        start: 1750916068,
                        tz_id: Tz::from_str("New Zealand").unwrap().as_id(),
                    }),
                },
            ],
        },
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&summary)
            .unwrap()
            .to_vec();
        let summary = rkyv::access::<ArchivedItipSummary, rkyv::rancor::Error>(&bytes).unwrap();

        let html = build_itip_template(
            server,
            &dummy_access_token,
            0,
            1,
            "john.doe@example.org",
            "jane.smith@example.net",
            summary,
            "124",
        )
        .await;

        println!("iTIP template {idx}: {}", html.subject);
        std::fs::write(format!("itip_template_{idx}.html"), html.body)
            .expect("Failed to write iTIP template to file");
    }
}

const TEST_ITIP: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VEVENT
UID:9263504FD3AD
SEQUENCE:0
DTSTART:$START
DTEND:$END
DTSTAMP:20090602T170000Z
TRANSP:OPAQUE
SUMMARY:Lunch
ORGANIZER:mailto:jdoe@example.com
ATTENDEE;CUTYPE=INDIVIDUAL:mailto:jane.smith@example.com
ATTENDEE;CUTYPE=INDIVIDUAL:mailto:bill@example.com
END:VEVENT
END:VCALENDAR
"#;

const TEST_FREEBUSY: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
METHOD:REQUEST
BEGIN:VFREEBUSY
UID:4FD3AD926350
DTSTAMP:20090602T190420Z
DTSTART:$START
DTEND:$END
ORGANIZER:mailto:jdoe@example.com
ATTENDEE:mailto:jdoe@example.com
ATTENDEE:mailto:jane.smith@example.com
ATTENDEE:mailto:bill@example.com
ATTENDEE:mailto:unknown@example.com
END:VFREEBUSY
END:VCALENDAR
"#;
