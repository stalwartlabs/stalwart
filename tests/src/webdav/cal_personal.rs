/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use dav_proto::schema::property::{DavProperty, WebDavProperty};
use groupware::{DavResourceName, cache::GroupwareCache};
use hyper::StatusCode;
use serde_json::json;
use types::{collection::SyncCollection, id::Id};

pub async fn test(test: &TestServer) {
    println!("Running CalDAV personal properties tests...");
    let owner_client = test.account("bill@example.com").webdav_client();
    let sharee_client = test.account("john@example.com").webdav_client();
    let reader_client = test.account("jane@example.com").webdav_client();
    let sharee_principal = format!(
        "{}/john%40example.com/",
        DavResourceName::Principal.base_path()
    );
    let reader_principal = format!(
        "{}/jane%40example.com/",
        DavResourceName::Principal.base_path()
    );
    let folder = format!(
        "{}/bill%40example.com/personal/",
        DavResourceName::Cal.base_path()
    );
    let event = format!("{folder}event.ics");
    let todo = format!("{folder}todo.ics");
    let reader_calendar = format!(
        "{}/jane%40example.com/default/",
        DavResourceName::Cal.base_path()
    );
    let reader_copy = format!("{reader_calendar}copied.ics");

    owner_client
        .request("MKCOL", &folder, "")
        .await
        .with_status(StatusCode::CREATED);
    owner_client
        .request("PUT", &event, ical("Owner alarm", "PT15M"))
        .await
        .with_status(StatusCode::CREATED)
        .etag();
    owner_client
        .request(
            "ACL",
            &folder,
            SHARE_ACL
                .replace("$SHAREE", sharee_principal.as_str())
                .replace("$READER", reader_principal.as_str()),
        )
        .await
        .with_status(StatusCode::OK);

    // Sharees see the owner's properties without the owner's alarms
    let body = get(&sharee_client, &event).await;
    assert!(body.contains("COLOR:red"), "{body}");
    assert!(!body.contains("VALARM"), "{body}");

    // Sharees store their own alarms, and the ETag matches the view they are served
    let put_etag = sharee_client
        .request("PUT", &event, ical("Sharee alarm", "PT45M"))
        .await
        .with_status(StatusCode::NO_CONTENT)
        .etag()
        .to_string();
    assert_eq!(
        put_etag,
        sharee_client
            .request("GET", &event, "")
            .await
            .with_status(StatusCode::OK)
            .etag()
    );
    let body = get(&owner_client, &event).await;
    assert!(body.contains("Owner alarm"), "{body}");
    assert!(!body.contains("Sharee alarm"), "{body}");
    let body = get(&sharee_client, &event).await;
    assert!(body.contains("Sharee alarm"), "{body}");
    assert!(!body.contains("Owner alarm"), "{body}");
    assert!(body.contains("COLOR:red"), "{body}");
    sharee_client
        .propfind(
            &event,
            [DavProperty::WebDav(WebDavProperty::GetContentLength)],
        )
        .await
        .properties(&event)
        .get(DavProperty::WebDav(WebDavProperty::GetContentLength))
        .with_values([body.len().to_string().as_str()]);
    for (client, start, end, hrefs) in [
        (
            &owner_client,
            "101000",
            "102000",
            [event.as_str()].as_slice(),
        ),
        (&owner_client, "104000", "105000", [].as_slice()),
        (&sharee_client, "101000", "102000", [].as_slice()),
        (
            &sharee_client,
            "104000",
            "105000",
            [event.as_str()].as_slice(),
        ),
    ] {
        client
            .request(
                "REPORT",
                &folder,
                ALARM_QUERY.replace("$START", start).replace("$END", end),
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(hrefs.iter().copied());
    }

    owner_client
        .request("PUT", &todo, UNDATED_TODO)
        .await
        .with_status(StatusCode::CREATED);
    let body = get(&sharee_client, &todo).await;
    assert!(!body.contains("VALARM"), "{body}");
    owner_client
        .request("DELETE", &todo, "")
        .await
        .with_status(StatusCode::NO_CONTENT);

    // Personal alarms never reference components of the shared event
    owner_client
        .request(
            "PUT",
            &event,
            ical("Owner alarm", "PT15M").replace(
                "END:VEVENT",
                concat!(
                    "BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Owner second alarm\r\n",
                    "TRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT"
                ),
            ),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    sharee_client
        .request(
            "PUT",
            &event,
            ical("Arrival alarm", "PT45M").replace(
                "END:VALARM",
                "BEGIN:VLOCATION\r\nUID:location-1\r\nNAME:Office\r\nEND:VLOCATION\r\nEND:VALARM",
            ),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    let body = get(&sharee_client, &event).await;
    assert!(body.contains("Arrival alarm"), "{body}");
    assert!(!body.contains("Owner"), "{body}");
    assert_eq!(body.matches("BEGIN:VALARM").count(), 1, "{body}");
    assert_eq!(
        body.matches("BEGIN:").count(),
        body.matches("END:").count(),
        "{body}"
    );
    let body = get(&owner_client, &event).await;
    assert!(body.contains("Owner alarm"), "{body}");
    assert!(body.contains("Owner second alarm"), "{body}");
    assert!(!body.contains("Arrival alarm"), "{body}");

    // Owner properties edited over CalDAV change the shared event
    sharee_client
        .request(
            "PUT",
            &event,
            ical("Sharee alarm", "PT45M").replace("COLOR:red", "COLOR:blue"),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    for client in [&owner_client, &sharee_client] {
        let body = get(client, &event).await;
        assert!(body.contains("COLOR:blue"), "{body}");
    }
    sharee_client
        .request("PUT", &event, ical("Sharee alarm", "PT45M"))
        .await
        .with_status(StatusCode::NO_CONTENT);
    let body = get(&owner_client, &event).await;
    assert!(body.contains("COLOR:red"), "{body}");
    assert!(body.contains("Owner second alarm"), "{body}");

    // Property and parameter filters only match the alarms the caller is served
    owner_client
        .request(
            "PUT",
            &event,
            ical("Owner alarm", "PT15M").replace(
                "DESCRIPTION:Owner alarm",
                "DESCRIPTION;LANGUAGE=en:Owner alarm",
            ),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    for (client, query, hrefs) in [
        (
            &owner_client,
            ALARM_PROP_QUERY.replace("$TEXT", "Owner alarm"),
            [event.as_str()].as_slice(),
        ),
        (
            &sharee_client,
            ALARM_PROP_QUERY.replace("$TEXT", "Owner alarm"),
            [].as_slice(),
        ),
        (
            &sharee_client,
            ALARM_PROP_QUERY.replace("$TEXT", "Sharee alarm"),
            [event.as_str()].as_slice(),
        ),
        (
            &owner_client,
            ALARM_PROP_QUERY.replace("$TEXT", "Sharee alarm"),
            [].as_slice(),
        ),
        (
            &owner_client,
            ALARM_PARAM_QUERY.to_string(),
            [event.as_str()].as_slice(),
        ),
        (&sharee_client, ALARM_PARAM_QUERY.to_string(), [].as_slice()),
    ] {
        client
            .request("REPORT", &folder, query)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(hrefs.iter().copied());
    }

    reader_client
        .request_with_headers("COPY", &event, [("destination", reader_copy.as_str())], "")
        .await
        .with_status(StatusCode::CREATED);
    reader_client
        .acl(&reader_calendar, sharee_principal.as_str(), ["read"])
        .await
        .with_status(StatusCode::OK);
    let body = get(&sharee_client, &reader_copy).await;
    assert!(!body.contains("VALARM"), "{body}");
    reader_client
        .request("DELETE", &reader_calendar, "")
        .await
        .with_status(StatusCode::NO_CONTENT);

    // A failed conditional update returns the sharee's view
    let body = sharee_client
        .request_with_headers(
            "PUT",
            &event,
            [
                ("content-type", "text/calendar; charset=utf-8"),
                ("if", "([\"3827\"])"),
                ("prefer", "return=representation"),
            ],
            ical("Conflicting alarm", "PT45M"),
        )
        .await
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_header("preference-applied", "return=representation")
        .expect_body()
        .to_string();
    assert!(body.contains("Sharee alarm"), "{body}");
    assert!(!body.contains("Owner alarm"), "{body}");

    email_default_alert_etag(test, &owner_client).await;

    owner_client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    sharee_client.delete_default_containers().await;
    owner_client.delete_default_containers().await;
    for account in ["bill@example.com", "john@example.com"] {
        test.account(account)
            .destroy_all_event_notifications()
            .await;
    }
    test.assert_is_empty().await;
}

async fn email_default_alert_etag(
    test: &TestServer,
    owner_client: &crate::utils::webdav::DummyWebDavClient,
) {
    let owner = test.account("bill@example.com");
    let account_id = owner.id().document_id();
    let folder = format!(
        "{}/bill%40example.com/alerts/",
        DavResourceName::Cal.base_path()
    );
    let event = format!("{folder}event.ics");
    owner_client
        .request("MKCOL", &folder, "")
        .await
        .with_status(StatusCode::CREATED);
    owner_client
        .request("PUT", &event, EMAIL_ALERT_EVENT)
        .await
        .with_status(StatusCode::CREATED);

    let resources = test
        .server
        .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .expect("calendar resources");
    let calendar_id = Id::from(
        resources
            .by_path("alerts")
            .expect("alerts calendar")
            .document_id(),
    )
    .to_string();
    let event_id = Id::from(
        resources
            .by_path("alerts/event.ics")
            .expect("alerts event")
            .document_id(),
    )
    .to_string();
    owner
        .jmap_method_call(
            "Calendar/set",
            json!({
                "accountId": owner.id_string(),
                "update": {
                    &calendar_id: {
                        "defaultAlertsWithTime": {
                            "a1": {
                                "@type": "Alert",
                                "trigger": { "@type": "OffsetTrigger", "offset": "-PT30M" },
                                "action": "email"
                            }
                        }
                    }
                }
            }),
        )
        .await
        .updated(&calendar_id);
    owner
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": owner.id_string(),
                "update": { &event_id: { "useDefaultAlerts": true } }
            }),
        )
        .await
        .updated(&event_id);

    let body = get(owner_client, &event).await;
    assert!(body.contains("ACTION:EMAIL"), "{body}");
    assert!(body.contains("ATTENDEE:mailto:"), "{body}");

    // The body the server serves back is stored verbatim, so the ETag is exact
    let put_etag = owner_client
        .request("PUT", &event, body.clone())
        .await
        .with_status(StatusCode::NO_CONTENT)
        .etag()
        .to_string();
    assert_eq!(
        put_etag,
        owner_client
            .request("GET", &event, "")
            .await
            .with_status(StatusCode::OK)
            .etag()
    );

    // A body without the alert recipient is not what the server will serve
    let response = owner_client
        .request(
            "PUT",
            &event,
            body.split_inclusive("\r\n")
                .filter(|line| !line.starts_with("ATTENDEE"))
                .collect::<String>(),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert!(!response.headers.contains_key("etag"), "{response:?}");

    owner_client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

async fn get(client: &crate::utils::webdav::DummyWebDavClient, path: &str) -> String {
    client
        .request("GET", path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string()
}

fn ical(alarm: &str, trigger: &str) -> String {
    format!(
        concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:-//Stalwart//Test//EN\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:dav-personal\r\n",
            "DTSTAMP:20240101T000000Z\r\n",
            "DTSTART:20240301T100000Z\r\n",
            "DURATION:PT1H\r\n",
            "SUMMARY:Planning\r\n",
            "COLOR:red\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "DESCRIPTION:{alarm}\r\n",
            "TRIGGER:{trigger}\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ),
        alarm = alarm,
        trigger = trigger
    )
}

const EMAIL_ALERT_EVENT: &str = concat!(
    "BEGIN:VCALENDAR\r\n",
    "VERSION:2.0\r\n",
    "PRODID:-//Stalwart//Test//EN\r\n",
    "BEGIN:VEVENT\r\n",
    "UID:dav-personal-alerts\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "DTSTART:20240401T100000Z\r\n",
    "DURATION:PT1H\r\n",
    "SUMMARY:Budget review\r\n",
    "END:VEVENT\r\n",
    "END:VCALENDAR\r\n"
);

const UNDATED_TODO: &str = concat!(
    "BEGIN:VCALENDAR\r\n",
    "VERSION:2.0\r\n",
    "PRODID:-//Stalwart//Test//EN\r\n",
    "BEGIN:VTODO\r\n",
    "UID:dav-personal-todo\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "SUMMARY:Supplies\r\n",
    "BEGIN:VALARM\r\n",
    "ACTION:DISPLAY\r\n",
    "DESCRIPTION:Todo alarm\r\n",
    "TRIGGER;VALUE=DATE-TIME:20240301T090000Z\r\n",
    "END:VALARM\r\n",
    "END:VTODO\r\n",
    "END:VCALENDAR\r\n"
);

const SHARE_ACL: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <D:acl xmlns:D="DAV:">
     <D:ace>
       <D:principal>
         <D:href>$SHAREE</D:href>
       </D:principal>
       <D:grant>
         <D:privilege><D:read/></D:privilege>
         <D:privilege><D:write/></D:privilege>
       </D:grant>
     </D:ace>
     <D:ace>
       <D:principal>
         <D:href>$READER</D:href>
       </D:principal>
       <D:grant>
         <D:privilege><D:read/></D:privilege>
       </D:grant>
     </D:ace>
   </D:acl>"#;

const ALARM_PROP_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop><D:getetag/></D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:comp-filter name="VALARM">
             <C:prop-filter name="DESCRIPTION">
               <C:text-match collation="i;ascii-casemap">$TEXT</C:text-match>
             </C:prop-filter>
           </C:comp-filter>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>"#;

const ALARM_PARAM_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop><D:getetag/></D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:comp-filter name="VALARM">
             <C:prop-filter name="DESCRIPTION">
               <C:param-filter name="LANGUAGE">
                 <C:text-match collation="i;ascii-casemap">en</C:text-match>
               </C:param-filter>
             </C:prop-filter>
           </C:comp-filter>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>"#;

const ALARM_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop><D:getetag/></D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:comp-filter name="VALARM">
             <C:time-range start="20240301T$STARTZ" end="20240301T$ENDZ"/>
           </C:comp-filter>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>"#;
