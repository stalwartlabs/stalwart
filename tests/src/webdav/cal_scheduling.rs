/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    utils::{server::TestServer, webdav::DummyWebDavClient},
    webdav::prop::ALL_DAV_PROPERTIES,
};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendarDay, ICalendarFrequency, ICalendarMethod, ICalendarParticipationStatus,
        ICalendarProperty, ICalendarRecurrenceRule, ICalendarWeekday,
    },
};
use dav_proto::schema::property::{CalDavProperty, DavProperty, WebDavProperty};
use email::cache::MessageCacheFetch;
use groupware::{
    cache::GroupwareCache,
    calendar::{CalendarEvent, EVENT_HIDE_ATTENDEES, itip::ItipIngest},
    scheduling::{ItipField, ItipParticipant, ItipSummary, ItipTime, ItipValue},
};
use hyper::StatusCode;
use mail_parser::{DateTime, MessageParser};
use serde_json::{Value, json};
use services::task_manager::tasks::imip::build_itip_template;
use std::str::FromStr;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder, now},
};
use types::collection::{Collection, SyncCollection};

async fn set_hide_attendees(test: &TestServer, account_id: u32, document_id: u32) {
    let archive = test
        .server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            Collection::CalendarEvent,
            document_id,
        ))
        .await
        .unwrap()
        .expect("Missing event");
    let previous = archive.to_unarchived::<CalendarEvent>().unwrap();
    let mut event = previous.deserialize::<CalendarEvent>().unwrap();
    event.flags |= EVENT_HIDE_ATTENDEES;

    let account_info = test.server.account_info(account_id).await.unwrap();
    let mut batch = BatchBuilder::new();
    event
        .update_meta(
            account_info.account_tenant_ids(),
            previous,
            account_id,
            document_id,
            None,
            &mut batch,
        )
        .unwrap();
    test.server.commit_batch(batch).await.unwrap();
}

async fn rsvp_request(client: &DummyWebDavClient, body: &Value) -> Value {
    let response = client
        .request_with_headers(
            "POST",
            "/api/calendar/rsvp",
            [("content-type", "application/json")],
            body.to_string(),
        )
        .await
        .with_status(StatusCode::OK)
        .body
        .unwrap();

    serde_json::from_str(&response).expect("Invalid JSON in RSVP response")
}

fn unfold(ical: &str) -> String {
    ical.replace("\r\n ", "")
}

pub async fn test(test: &TestServer) {
    println!("Running calendar scheduling tests...");
    let bill = test.account("bill@example.com");
    let jane = test.account("jane@example.com");
    let john = test.account("john@example.com");
    let bill_client = bill.webdav_client();
    let jane_client = jane.webdav_client();
    let john_client = john.webdav_client();

    // Validate hierarchy of scheduling resources
    let response = jane_client
        .propfind_with_headers(
            "/dav/itip/jane%40example.com/",
            ALL_DAV_PROPERTIES,
            [("depth", "1")],
        )
        .await;
    let properties = response
        .with_hrefs([
            "/dav/itip/jane%40example.com/",
            "/dav/itip/jane%40example.com/inbox/",
            "/dav/itip/jane%40example.com/outbox/",
        ])
        .properties("/dav/itip/jane%40example.com/inbox/");

    // Validate schedule inbox properties
    properties
        .get(DavProperty::WebDav(WebDavProperty::ResourceType))
        .with_values(["D:collection", "A:schedule-inbox"]);
    properties
        .get(DavProperty::CalDav(
            CalDavProperty::ScheduleDefaultCalendarURL,
        ))
        .with_values(["D:href:/dav/cal/jane%40example.com/default/"])
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
    let properties = response.properties("/dav/itip/jane%40example.com/outbox/");
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
            "/dav/cal/john%40example.com/default/itip.ics",
            [("content-type", "text/calendar; charset=utf-8")],
            &test_itip,
        )
        .await
        .with_status(StatusCode::CREATED);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Check that the invitation was received by Bill and Mike
    for client in [&bill_client, &jane_client] {
        let messages = test
            .server
            .get_cached_messages(client.account_id)
            .await
            .unwrap();
        assert_eq!(messages.emails.len(), 1);
        let events = test
            .server
            .fetch_groupware_resources(
                client.account_id,
                client.account_id,
                SyncCollection::Calendar,
            )
            .await
            .unwrap();
        assert_eq!(events.resources.len(), 2);
        let events = test
            .server
            .fetch_groupware_resources(
                client.account_id,
                client.account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await
            .unwrap();
        assert_eq!(events.resources.len(), 3);
    }

    // Validate iTIP
    let itips = jane_client.fetch_and_remove_itips().await;
    assert_eq!(itips.len(), 1);
    let itip = itips.first().unwrap();
    assert!(
        unfold(itip).contains("SUMMARY:Lunch") && unfold(itip).contains("METHOD:REQUEST"),
        "failed for itip: {itip}"
    );

    // Fetch added calendar entry
    let cals = jane_client.fetch_icals().await;
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
        jane_client.fetch_icals().await[0].schedule_tag,
        cal.schedule_tag
    );

    // Check that John received the RSVP
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    test.wait_for_tasks().await;
    let itips = john_client.fetch_and_remove_itips().await;
    assert_eq!(itips.len(), 1);
    assert!(
        unfold(&itips[0]).contains("METHOD:REPLY")
            && unfold(&itips[0]).contains("PARTSTAT=ACCEPTED:mailto:jane.smith"),
        "failed for itip: {}",
        itips[0]
    );
    let cals = john_client.fetch_icals().await;
    assert_eq!(cals.len(), 1);
    assert!(
        unfold(&cals[0].ical).contains("PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:jane"),
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
        john_client.fetch_and_remove_itips().await,
        Vec::<String>::new()
    );

    // Deleting the event should send a cancellation
    jane_client
        .request("DELETE", &cal.href, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let itips = john_client.fetch_and_remove_itips().await;
    assert_eq!(itips.len(), 1);
    assert!(
        unfold(&itips[0]).contains("METHOD:REPLY")
            && unfold(&itips[0]).contains("PARTSTAT=DECLINED:mailto:jane.smith"),
        "failed for itip: {}",
        itips[0]
    );
    let cals = john_client.fetch_icals().await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();
    assert!(
        unfold(&cal.ical).contains("PARTSTAT=DECLINED;SCHEDULE-STATUS=2.0:mailto:jane"),
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
        .at(0)
        .unwrap()
        .document_id();
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
    let bill_token = reqwest::Url::parse(&format!("https://webdav.example.org{url}"))
        .expect("Invalid RSVP URL")
        .query_pairs()
        .find(|(key, _)| key == "i")
        .map(|(_, token)| token.into_owned())
        .expect("Missing RSVP token");
    let details = rsvp_request(&jane_client, &json!({ "token": bill_token })).await;
    assert_eq!(details["type"], "invitation", "failed for {details}");
    assert_eq!(details["summary"], "Lunch", "failed for {details}");
    let recorded = rsvp_request(
        &jane_client,
        &json!({ "token": bill_token, "partstat": "accepted", "comment": "Bringing dessert" }),
    )
    .await;
    assert_eq!(recorded["type"], "recorded", "failed for {recorded}");

    // The attendee's own copy reflects the response
    let cals = bill_client.fetch_icals().await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();
    assert!(
        unfold(&cal.ical).contains("PARTSTAT=ACCEPTED:mailto:bill"),
        "failed for cal: {}",
        cal.ical
    );

    // The reply lands in the organizer's scheduling inbox, carrying the attendee's comment
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let itips = john_client.fetch_and_remove_itips().await;
    assert_eq!(itips.len(), 1);
    assert!(
        unfold(&itips[0]).contains("METHOD:REPLY")
            && unfold(&itips[0]).contains("PARTSTAT=ACCEPTED:mailto:bill")
            && unfold(&itips[0]).contains("COMMENT:Bringing dessert")
            && unfold(&itips[0]).contains("REQUEST-STATUS:2.0;Success"),
        "failed for itip: {}",
        itips[0]
    );
    let cals = john_client.fetch_icals().await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();
    assert!(
        unfold(&cal.ical).contains("PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:bill"),
        "failed for cal: {}",
        cal.ical
    );

    // RSVP on behalf of an attendee that has no local account
    let test_itip_external = TEST_ITIP_EXTERNAL
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
            "/dav/cal/john%40example.com/default/external.ics",
            [("content-type", "text/calendar; charset=utf-8")],
            &test_itip_external,
        )
        .await
        .with_status(StatusCode::CREATED);
    let external_document_id = test
        .server
        .fetch_groupware_resources(
            john_client.account_id,
            john_client.account_id,
            SyncCollection::Calendar,
        )
        .await
        .unwrap()
        .by_path("default/external.ics")
        .unwrap()
        .document_id();
    let url = test
        .server
        .http_rsvp_url(
            john_client.account_id,
            "john@example.com",
            external_document_id,
            "carol@remote.org",
        )
        .await
        .unwrap()
        .url(&ICalendarParticipationStatus::Accepted);
    let rsvp_token = reqwest::Url::parse(&url)
        .expect("Invalid RSVP URL")
        .query_pairs()
        .find(|(key, _)| key == "i")
        .map(|(_, token)| token.into_owned())
        .expect("Missing RSVP token");

    // The RSVP page is static and must never record a response by itself
    let page = john_client
        .request("GET", "/calendar/rsvp", "")
        .await
        .with_status(StatusCode::OK)
        .body
        .unwrap();
    assert!(
        page.contains("/api/calendar/rsvp"),
        "failed for page: {page}"
    );

    // Fetching the invitation details must not change the participation status
    let details = rsvp_request(&john_client, &json!({ "token": rsvp_token })).await;
    assert_eq!(details["type"], "invitation", "failed for {details}");
    assert_eq!(details["summary"], "Brunch", "failed for {details}");
    assert_eq!(details["partstat"], "NEEDS-ACTION", "failed for {details}");
    assert_eq!(
        details["attendee"]["email"], "carol@remote.org",
        "failed for {details}"
    );

    // An unknown token is rejected without leaking whether the event exists
    let invalid = rsvp_request(&john_client, &json!({ "token": "not-a-token" })).await;
    assert_eq!(invalid["type"], "error", "failed for {invalid}");
    assert_eq!(invalid["reason"], "invalidLink", "failed for {invalid}");

    // An unparseable participation status is an error, not a silent details response
    let bad_status = rsvp_request(
        &john_client,
        &json!({ "token": rsvp_token, "partstat": "accpeted" }),
    )
    .await;
    assert_eq!(bad_status["type"], "error", "failed for {bad_status}");
    assert_eq!(
        bad_status["reason"], "invalidPartStat",
        "failed for {bad_status}"
    );

    // Record the response
    let recorded = rsvp_request(
        &john_client,
        &json!({ "token": rsvp_token, "partstat": "accepted", "comment": "See you there" }),
    )
    .await;
    assert_eq!(recorded["type"], "recorded", "failed for {recorded}");
    assert_eq!(recorded["partstat"], "ACCEPTED", "failed for {recorded}");
    let external_cal = john_client
        .fetch_icals()
        .await
        .into_iter()
        .find(|cal| cal.href.ends_with("external.ics"))
        .expect("Missing external event");
    assert!(
        unfold(&external_cal.ical)
            .contains("PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:carol@remote.org"),
        "failed for cal: {}",
        external_cal.ical
    );

    // The reply from an external attendee also reaches the organizer's scheduling inbox
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let itips = john_client.fetch_and_remove_itips().await;
    assert_eq!(itips.len(), 1);
    assert!(
        unfold(&itips[0]).contains("METHOD:REPLY")
            && unfold(&itips[0]).contains("PARTSTAT=ACCEPTED:mailto:carol@remote.org")
            && unfold(&itips[0]).contains("COMMENT:See you there")
            && unfold(&itips[0]).contains("REQUEST-STATUS:2.0;Success"),
        "failed for itip: {}",
        itips[0]
    );

    // Re-sending the same response is a no-op that produces no further reply
    let repeated = rsvp_request(
        &john_client,
        &json!({ "token": rsvp_token, "partstat": "accepted" }),
    )
    .await;
    assert_eq!(repeated["type"], "recorded", "failed for {repeated}");

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        john_client.fetch_and_remove_itips().await,
        Vec::<String>::new()
    );
    john_client
        .request("DELETE", &external_cal.href, "")
        .await
        .with_status(StatusCode::NO_CONTENT);

    // A recurring event is answered as a whole: the master and every overridden
    // instance the attendee appears in must all be updated by a single RSVP
    let ts = now() as i64;
    let stamp = |offset: i64| {
        DateTime::from_timestamp(ts + offset)
            .to_rfc3339()
            .replace(['-', ':'], "")
    };
    let test_itip_recurring = TEST_ITIP_RECURRING
        .replace("$START", &stamp(60 * 60))
        .replace("$END", &stamp(2 * 60 * 60))
        .replace("$SECOND_END", &stamp(7 * 24 * 60 * 60 + 3 * 60 * 60))
        .replace("$SECOND", &stamp(7 * 24 * 60 * 60 + 60 * 60));
    john_client
        .request_with_headers(
            "PUT",
            "/dav/cal/john%40example.com/default/recurring.ics",
            [("content-type", "text/calendar; charset=utf-8")],
            &test_itip_recurring,
        )
        .await
        .with_status(StatusCode::CREATED);
    let recurring_document_id = test
        .server
        .fetch_groupware_resources(
            john_client.account_id,
            john_client.account_id,
            SyncCollection::Calendar,
        )
        .await
        .unwrap()
        .by_path("default/recurring.ics")
        .unwrap()
        .document_id();
    let recurring_url = test
        .server
        .http_rsvp_url(
            john_client.account_id,
            "john@example.com",
            recurring_document_id,
            "carol@remote.org",
        )
        .await
        .unwrap()
        .url(&ICalendarParticipationStatus::Accepted);
    let recurring_token = reqwest::Url::parse(&recurring_url)
        .expect("Invalid RSVP URL")
        .query_pairs()
        .find(|(key, _)| key == "i")
        .map(|(_, token)| token.into_owned())
        .expect("Missing RSVP token");

    let recorded = rsvp_request(
        &john_client,
        &json!({ "token": recurring_token, "partstat": "declined" }),
    )
    .await;
    assert_eq!(recorded["type"], "recorded", "failed for {recorded}");

    let recurring_cal = john_client
        .fetch_icals()
        .await
        .into_iter()
        .find(|cal| cal.href.ends_with("recurring.ics"))
        .expect("Missing recurring event");
    let recurring_ical = unfold(&recurring_cal.ical);
    assert_eq!(
        recurring_ical
            .matches("PARTSTAT=DECLINED;SCHEDULE-STATUS=2.0:mailto:carol@remote.org")
            .count(),
        2,
        "both the master and the override must be updated: {recurring_ical}"
    );

    // Repeating the same answer is still reported as recorded, but sends no second reply
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    john_client.fetch_and_remove_itips().await;
    let repeated = rsvp_request(
        &john_client,
        &json!({ "token": recurring_token, "partstat": "declined" }),
    )
    .await;
    assert_eq!(repeated["type"], "recorded", "failed for {repeated}");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        john_client.fetch_and_remove_itips().await,
        Vec::<String>::new(),
        "a repeated RSVP must not produce another reply"
    );
    john_client
        .request("DELETE", &recurring_cal.href, "")
        .await
        .with_status(StatusCode::NO_CONTENT);

    // hideAttendees restricts the RSVP response to the organizer and the requester
    let test_itip_hidden = TEST_ITIP_HIDDEN
        .replace("$START", &stamp(60 * 60))
        .replace("$END", &stamp(2 * 60 * 60));
    john_client
        .request_with_headers(
            "PUT",
            "/dav/cal/john%40example.com/default/hidden.ics",
            [("content-type", "text/calendar; charset=utf-8")],
            &test_itip_hidden,
        )
        .await
        .with_status(StatusCode::CREATED);
    let hidden_document_id = test
        .server
        .fetch_groupware_resources(
            john_client.account_id,
            john_client.account_id,
            SyncCollection::Calendar,
        )
        .await
        .unwrap()
        .by_path("default/hidden.ics")
        .unwrap()
        .document_id();
    let hidden_url = test
        .server
        .http_rsvp_url(
            john_client.account_id,
            "john@example.com",
            hidden_document_id,
            "carol@remote.org",
        )
        .await
        .unwrap()
        .url(&ICalendarParticipationStatus::Accepted);
    let hidden_token = reqwest::Url::parse(&hidden_url)
        .expect("Invalid RSVP URL")
        .query_pairs()
        .find(|(key, _)| key == "i")
        .map(|(_, token)| token.into_owned())
        .expect("Missing RSVP token");

    // With the flag clear every participant is listed
    let details = rsvp_request(&john_client, &json!({ "token": hidden_token })).await;
    let emails = |details: &Value| {
        details["attendees"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["email"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        emails(&details),
        vec![
            "jdoe@example.com".to_string(),
            "carol@remote.org".to_string(),
            "dave@remote.org".to_string()
        ],
        "failed for {details}"
    );

    // With it set, the other attendee is withheld
    set_hide_attendees(test, john_client.account_id, hidden_document_id).await;
    let details = rsvp_request(&john_client, &json!({ "token": hidden_token })).await;
    assert_eq!(
        emails(&details),
        vec![
            "jdoe@example.com".to_string(),
            "carol@remote.org".to_string()
        ],
        "dave must not be disclosed when hideAttendees is set: {details}"
    );
    john_client
        .request(
            "DELETE",
            "/dav/cal/john%40example.com/default/hidden.ics",
            "",
        )
        .await
        .with_status(StatusCode::NO_CONTENT);

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
            "/dav/itip/john%40example.com/outbox/",
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
                    unfold(value).contains("BEGIN:VFREEBUSY"),
                    "missing freebusy data in response: {response:?}"
                );
                if account == "jdoe@example.com" {
                    assert!(
                        unfold(value).contains("FREEBUSY;FBTYPE=BUSY:"),
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
        john_client.fetch_icals().await[0].schedule_tag,
        cal.schedule_tag
    );
    let main_event_href = cal.href;

    // Check that Bill received the update
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    test.wait_for_tasks().await;
    let mut itips = bill_client.fetch_and_remove_itips().await;
    itips.sort_unstable_by(|a, _| {
        if unfold(a).contains("Lunch") {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    assert_eq!(itips.len(), 2);
    assert!(
        unfold(&itips[0]).contains("METHOD:REQUEST") && unfold(&itips[0]).contains("Lunch"),
        "failed for itip: {}",
        itips[0]
    );
    assert!(
        unfold(&itips[1]).contains("METHOD:REQUEST")
            && unfold(&itips[1]).contains("Breakfast at Tiffany's"),
        "failed for itip: {}",
        itips[1]
    );
    let cals = bill_client.fetch_icals().await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();
    assert!(
        unfold(&cal.ical).contains("SUMMARY:Breakfast at Tiffany's")
            && unfold(&cal.ical).contains("PARTSTAT=ACCEPTED:mailto:bill"),
        "failed for cal: {}",
        cal.ical
    );
    let attendee_href = cal.href;
    assert_eq!(
        jane_client.fetch_and_remove_itips().await,
        Vec::<String>::new()
    );

    // Removing the event should from John's calendar send a cancellation to Bill
    john_client
        .request("DELETE", &main_event_href, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let itips = bill_client.fetch_and_remove_itips().await;
    assert_eq!(itips.len(), 1);
    assert!(
        unfold(&itips[0]).contains("METHOD:CANCEL")
            && unfold(&itips[0]).contains("STATUS:CANCELLED"),
        "failed for itip: {}",
        itips[0]
    );
    let cals = bill_client.fetch_icals().await;
    assert_eq!(cals.len(), 1);
    let cal = cals.into_iter().next().unwrap();
    assert!(
        unfold(&cal.ical).contains("STATUS:CANCELLED"),
        "failed for cal: {}",
        cal.ical
    );
    assert_eq!(
        jane_client.fetch_and_remove_itips().await,
        Vec::<String>::new()
    );

    // Delete the event from Bill's calendar disabling schedule replies
    bill_client
        .request_with_headers("DELETE", &attendee_href, [("Schedule-Reply", "F")], "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        john_client.fetch_and_remove_itips().await,
        Vec::<String>::new()
    );

    for client in [bill_client, jane_client, john_client] {
        client.delete_default_containers().await;
    }
    for account in [bill, jane, john] {
        test.destroy_all_mailboxes(account).await;
    }

    test.assert_is_empty().await;
}

impl DummyWebDavClient {
    async fn fetch_and_remove_itips(&self) -> Vec<String> {
        let inbox_href = format!("/dav/itip/{}/inbox/", self.name.replace('@', "%40"));
        let response = self
            .propfind_with_headers(&inbox_href, ALL_DAV_PROPERTIES, [("depth", "1")])
            .await;
        let mut itips = vec![];

        for href in response.hrefs.keys().filter(|&href| href != &inbox_href) {
            let itip = self
                .request("GET", href, "")
                .await
                .with_status(StatusCode::OK)
                .body
                .expect("Missing body");
            self.request("DELETE", href, "")
                .await
                .with_status(StatusCode::NO_CONTENT);
            itips.push(itip);
        }

        itips
    }
}

#[derive(Debug)]
struct CalEntry {
    href: String,
    ical: String,
    schedule_tag: String,
}

impl DummyWebDavClient {
    async fn fetch_icals(&self) -> Vec<CalEntry> {
        let cal_inbox = format!("/dav/cal/{}/default/", self.name.replace('@', "%40"));
        let response = self
            .propfind_with_headers(&cal_inbox, ALL_DAV_PROPERTIES, [("depth", "1")])
            .await;
        let mut cals = vec![];

        for href in response.hrefs.keys().filter(|&href| href != &cal_inbox) {
            let ical = self
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
}

pub async fn test_build_itip_templates(test: &TestServer) {
    let account = test.account("john@example.com");
    let account_id = account.id().document_id();
    let account_info = test.server.account_info(account_id).await.unwrap();
    let out_dir = super::template_out_dir().expect("ITIP_TEMPLATES must be set");

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
                name: ICalendarProperty::Conference,
                value: ItipValue::Text("https://meet.example.com/lunch".to_string()),
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
                    name: ICalendarProperty::Conference,
                    value: ItipValue::Text("https://meet.example.com/lunch".to_string()),
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
                    name: ICalendarProperty::Conference,
                    value: ItipValue::Text("https://meet.example.com/dinner".to_string()),
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
        let html = build_itip_template(
            &test.server,
            &account_info,
            account_id,
            1,
            "john.doe@example.org",
            "jane.smith@example.net",
            &summary,
            "124",
        )
        .await
        .expect("Failed to build iTIP template");

        let path = out_dir.join(format!("itip_template_{idx}.html"));
        std::fs::write(&path, html.body).expect("Failed to write iTIP template to file");
        println!(
            "iTIP template {idx}: {} -> {}",
            html.subject,
            path.display()
        );
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

const TEST_ITIP_EXTERNAL: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VEVENT
UID:AD9263504FD3
SEQUENCE:0
DTSTART:$START
DTEND:$END
DTSTAMP:20090602T170000Z
TRANSP:OPAQUE
SUMMARY:Brunch
ORGANIZER:mailto:jdoe@example.com
ATTENDEE;CUTYPE=INDIVIDUAL:mailto:carol@remote.org
END:VEVENT
END:VCALENDAR
"#;

const TEST_ITIP_HIDDEN: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VEVENT
UID:HID9263504FD3
SEQUENCE:0
DTSTART:$START
DTEND:$END
DTSTAMP:20090602T170000Z
TRANSP:OPAQUE
SUMMARY:All hands
ORGANIZER:mailto:jdoe@example.com
ATTENDEE;CUTYPE=INDIVIDUAL:mailto:carol@remote.org
ATTENDEE;CUTYPE=INDIVIDUAL:mailto:dave@remote.org
END:VEVENT
END:VCALENDAR
"#;

const TEST_ITIP_RECURRING: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VEVENT
UID:REC9263504FD3
SEQUENCE:0
DTSTART:$START
DTEND:$END
DTSTAMP:20090602T170000Z
RRULE:FREQ=WEEKLY;COUNT=4
TRANSP:OPAQUE
SUMMARY:Weekly sync
ORGANIZER:mailto:jdoe@example.com
ATTENDEE;CUTYPE=INDIVIDUAL:mailto:carol@remote.org
END:VEVENT
BEGIN:VEVENT
UID:REC9263504FD3
SEQUENCE:0
RECURRENCE-ID:$SECOND
DTSTART:$SECOND
DTEND:$SECOND_END
DTSTAMP:20090602T170000Z
TRANSP:OPAQUE
SUMMARY:Weekly sync (moved)
ORGANIZER:mailto:jdoe@example.com
ATTENDEE;CUTYPE=INDIVIDUAL:mailto:carol@remote.org
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
