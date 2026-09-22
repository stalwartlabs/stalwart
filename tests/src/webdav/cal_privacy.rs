/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{server::TestServer, webdav::DummyWebDavClient};
use dav_proto::{
    Depth,
    schema::property::{DavProperty, WebDavProperty},
};
use groupware::DavResourceName;
use hyper::StatusCode;

pub async fn test(test: &TestServer) {
    println!("Running CalDAV privacy tests...");
    let owner_client = test.account("bill@example.com").webdav_client();
    let sharee_client = test.account("john@example.com").webdav_client();
    let sharee_principal = format!(
        "{}/john%40example.com/",
        DavResourceName::Principal.base_path()
    );
    let owner_base_path = format!("{}/bill%40example.com/", DavResourceName::Cal.base_path());
    let folder = format!("{owner_base_path}privacy/");
    let public_event = format!("{folder}public.ics");
    let private_event = format!("{folder}private.ics");
    let secret_event = format!("{folder}secret.ics");
    let events = [
        (&public_event, "dav-privacy-public", "PUBLIC", "10"),
        (&private_event, "dav-privacy-private", "PRIVATE", "12"),
        (&secret_event, "dav-privacy-secret", "CONFIDENTIAL", "14"),
    ];

    owner_client
        .request("MKCOL", &folder, "")
        .await
        .with_status(StatusCode::CREATED);
    for (path, uid, class, hour) in events {
        owner_client
            .request("PUT", path, event(uid, class, hour))
            .await
            .with_status(StatusCode::CREATED);
    }
    owner_client
        .proppatch(
            &private_event,
            [(DavProperty::WebDav(WebDavProperty::DisplayName), "Doctor")],
            [],
            [],
        )
        .await
        .with_status(StatusCode::MULTI_STATUS);

    owner_client
        .acl(&folder, sharee_principal.as_str(), ["read"])
        .await
        .with_status(StatusCode::OK);
    for (path, status) in [
        (&private_event, StatusCode::FORBIDDEN),
        (&secret_event, StatusCode::NOT_FOUND),
    ] {
        sharee_client
            .request("DELETE", path, "")
            .await
            .with_status(status);
        sharee_client
            .proppatch(
                path,
                [(DavProperty::WebDav(WebDavProperty::DisplayName), "Renamed")],
                [],
                [],
            )
            .await
            .with_status(status);
    }
    owner_client
        .request(
            "ACL",
            &folder,
            SHARE_ACL.replace("$HREF", sharee_principal.as_str()),
        )
        .await
        .with_status(StatusCode::OK);

    // Secret events are not listed
    sharee_client
        .propfind(&folder, [DavProperty::WebDav(WebDavProperty::GetETag)])
        .await
        .with_hrefs([
            folder.as_str(),
            public_event.as_str(),
            private_event.as_str(),
        ]);
    sharee_client
        .request("REPORT", &folder, CALENDAR_QUERY_ANY_VEVENT)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([public_event.as_str(), private_event.as_str()]);
    sharee_client
        .request("GET", &secret_event, "")
        .await
        .with_status(StatusCode::NOT_FOUND);

    sharee_client
        .request("REPORT", &folder, CALENDAR_QUERY_SUMMARY_DETAILS)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([public_event.as_str()]);

    // Private events only expose the allowed properties
    let private_body = get_body(&sharee_client, &private_event).await;
    assert_private_view(&private_body);
    let response = sharee_client
        .multiget_calendar(&folder, &[&private_event])
        .await;
    assert_private_view(
        response
            .properties(&private_event)
            .with_status(StatusCode::OK)
            .calendar_data()
            .value(),
    );

    let public_body = get_body(&sharee_client, &public_event).await;
    assert!(!public_body.contains("VALARM"), "{public_body}");
    let response = sharee_client
        .propfind(
            &folder,
            [
                DavProperty::WebDav(WebDavProperty::GetContentLength),
                DavProperty::WebDav(WebDavProperty::DisplayName),
            ],
        )
        .await;
    for (path, body) in [
        (&public_event, &public_body),
        (&private_event, &private_body),
    ] {
        response
            .properties(path)
            .get(DavProperty::WebDav(WebDavProperty::GetContentLength))
            .with_values([body.len().to_string().as_str()]);
    }
    response
        .properties(&private_event)
        .get(DavProperty::WebDav(WebDavProperty::DisplayName))
        .with_status(StatusCode::NOT_FOUND);

    // Owners see everything
    let body = get_body(&owner_client, &private_event).await;
    assert!(body.contains("SUMMARY:Details for dav-privacy-private"));
    owner_client
        .propfind(
            &private_event,
            [DavProperty::WebDav(WebDavProperty::DisplayName)],
        )
        .await
        .properties(&private_event)
        .get(DavProperty::WebDav(WebDavProperty::DisplayName))
        .with_values(["Doctor"]);

    for path in [&private_event, &secret_event] {
        let etag = owner_client
            .request("GET", path, "")
            .await
            .with_status(StatusCode::OK)
            .etag()
            .to_string();
        let condition = format!("<{path}> ([{etag}])");
        for (client, status) in [
            (&owner_client, StatusCode::OK),
            (&sharee_client, StatusCode::PRECONDITION_FAILED),
        ] {
            client
                .request_with_headers("GET", &public_event, [("if", condition.as_str())], "")
                .await
                .with_status(status);
        }
    }

    let sharee_free_busy = free_busy(&sharee_client, &folder).await;
    assert!(
        sharee_free_busy
            .contains("FREEBUSY;FBTYPE=BUSY-TENTATIVE:20240301T100000Z/20240301T110000Z\r\n"),
        "{sharee_free_busy}"
    );
    assert!(
        sharee_free_busy.contains("FREEBUSY;FBTYPE=BUSY:20240301T120000Z/20240301T130000Z\r\n"),
        "{sharee_free_busy}"
    );
    assert!(
        !sharee_free_busy.contains("20240301T140000Z"),
        "{sharee_free_busy}"
    );
    let owner_free_busy = free_busy(&owner_client, &folder).await;
    assert!(
        owner_free_busy.contains(concat!(
            "FREEBUSY;FBTYPE=BUSY-TENTATIVE:20240301T100000Z/20240301T110000Z,",
            "20240301T120000Z/20240301T130000Z,20240301T140000Z/20240301T150000Z\r\n"
        )),
        "{owner_free_busy}"
    );

    let sync_token = sharee_client
        .sync_collection(&folder, "", Depth::One, None, ["D:getetag"])
        .await
        .sync_token()
        .to_string();
    for (path, uid, class, hour) in events
        .into_iter()
        .filter(|(path, ..)| *path != &private_event)
    {
        owner_client
            .request(
                "PUT",
                path,
                event(uid, class, hour).replace("DESCRIPTION:Notes", "DESCRIPTION:New notes"),
            )
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    let response = sharee_client
        .sync_collection(&folder, &sync_token, Depth::One, None, ["D:getetag"])
        .await;
    assert_eq!(
        response.hrefs(),
        vec![public_event.as_str(), secret_event.as_str()]
    );
    response.with_value(
        "D:multistatus.D:response.D:status",
        "HTTP/1.1 404 Not Found",
    );

    // Sharees cannot modify private or secret events
    sharee_client
        .request(
            "PUT",
            &private_event,
            event("dav-privacy-private", "PRIVATE", "12"),
        )
        .await
        .with_status(StatusCode::FORBIDDEN);
    for (path, status) in [
        (&private_event, StatusCode::FORBIDDEN),
        (&secret_event, StatusCode::NOT_FOUND),
    ] {
        sharee_client
            .request("DELETE", path, "")
            .await
            .with_status(status);
        sharee_client
            .proppatch(
                path,
                [(DavProperty::WebDav(WebDavProperty::DisplayName), "Renamed")],
                [],
                [],
            )
            .await
            .with_status(status);
    }
    sharee_client
        .request(
            "PUT",
            &format!("{folder}sharee.ics"),
            event("dav-privacy-sharee", "PRIVATE", "16"),
        )
        .await
        .with_status(StatusCode::FORBIDDEN);
    sharee_client
        .request(
            "PUT",
            &public_event,
            event("dav-privacy-public", "PRIVATE", "10"),
        )
        .await
        .with_status(StatusCode::FORBIDDEN);

    let sharee_calendars = format!("{}/john%40example.com/", DavResourceName::Cal.base_path());
    for (source, destination, status) in [
        (
            &private_event,
            format!("{sharee_calendars}default/private.ics"),
            StatusCode::FORBIDDEN,
        ),
        (
            &secret_event,
            format!("{sharee_calendars}default/secret.ics"),
            StatusCode::NOT_FOUND,
        ),
        (
            &folder,
            format!("{sharee_calendars}privacy-copy/"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        for method in ["COPY", "MOVE"] {
            sharee_client
                .request_with_headers(method, source, [("destination", destination.as_str())], "")
                .await
                .with_status(status);
        }
    }

    for method in ["COPY", "MOVE"] {
        for (destination, status) in [
            (&private_event, StatusCode::FORBIDDEN),
            (&secret_event, StatusCode::NOT_FOUND),
        ] {
            sharee_client
                .request_with_headers(
                    method,
                    &public_event,
                    [("destination", destination.as_str())],
                    "",
                )
                .await
                .with_status(status);
        }
    }
    sharee_client
        .request_with_headers(
            "COPY",
            &public_event,
            [("destination", secret_event.as_str()), ("overwrite", "F")],
            "",
        )
        .await
        .with_status(StatusCode::NOT_FOUND);
    for (path, uid, _, _) in events {
        let body = get_body(&owner_client, path).await;
        assert!(
            body.contains(&format!("SUMMARY:Details for {uid}")),
            "{body}"
        );
    }

    let conflict_event = format!("{folder}conflict.ics");
    sharee_client
        .request(
            "PUT",
            &conflict_event,
            event("dav-privacy-secret", "PUBLIC", "16"),
        )
        .await
        .with_status(StatusCode::FORBIDDEN);
    sharee_client
        .request(
            "PUT",
            &conflict_event,
            event("dav-privacy-private", "PUBLIC", "16"),
        )
        .await
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_failed_precondition("A:no-uid-conflict.D:href", &private_event);

    sharee_client
        .request(
            "PUT",
            &public_event,
            event("dav-privacy-public", "PUBLIC", "10"),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);

    sharee_client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::FORBIDDEN);

    // Expanding a private recurring event keeps the occurrences of hidden overrides
    let recurring_event = format!("{folder}recurring.ics");
    owner_client
        .request("PUT", &recurring_event, RECURRING_PRIVATE_EVENT)
        .await
        .with_status(StatusCode::CREATED);
    for client in [&owner_client, &sharee_client] {
        let body = client
            .request("REPORT", &folder, EXPAND_QUERY)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .expect_body()
            .replace("\r\n ", "");
        for start in [
            "DTSTART:20240506T070000Z",
            "DTSTART:20240513T070000Z",
            "DTSTART:20240520T070000Z",
        ] {
            assert!(body.contains(start), "{start} missing:\n{body}");
        }
    }
    owner_client
        .request("DELETE", &recurring_event, "")
        .await
        .with_status(StatusCode::NO_CONTENT);

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

async fn get_body(client: &DummyWebDavClient, path: &str) -> String {
    client
        .request("GET", path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string()
}

async fn free_busy(client: &DummyWebDavClient, path: &str) -> String {
    client
        .request("REPORT", path, FREE_BUSY_QUERY)
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .replace("\r\n ", "")
}

fn assert_private_view(ical: &str) {
    for removed in [
        "SUMMARY",
        "DESCRIPTION",
        "LOCATION",
        "STATUS",
        "VALARM",
        "X-NOTE",
        "Vendor note",
        "LAST-MODIFIED",
    ] {
        assert!(!ical.contains(removed), "{removed} leaked:\n{ical}");
    }
    for kept in ["UID:dav-privacy-private", "DTSTART", "CLASS:PRIVATE"] {
        assert!(ical.contains(kept), "{kept} missing:\n{ical}");
    }
}

const RECURRING_PRIVATE_EVENT: &str = concat!(
    "BEGIN:VCALENDAR\r\n",
    "VERSION:2.0\r\n",
    "PRODID:-//Stalwart//Test//EN\r\n",
    "BEGIN:VEVENT\r\n",
    "UID:dav-privacy-recurring\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "DTSTART;TZID=Europe/Berlin:20240506T090000\r\n",
    "DURATION:PT1H\r\n",
    "RRULE:FREQ=WEEKLY;COUNT=3\r\n",
    "SUMMARY:Weekly sync\r\n",
    "CLASS:PRIVATE\r\n",
    "END:VEVENT\r\n",
    "BEGIN:VEVENT\r\n",
    "UID:dav-privacy-recurring\r\n",
    "RECURRENCE-ID;TZID=Europe/Berlin:20240513T090000\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "DTSTART;TZID=Europe/Berlin:20240513T090000\r\n",
    "DURATION:PT1H\r\n",
    "SUMMARY:Weekly sync with the lawyer\r\n",
    "DESCRIPTION:Divorce papers\r\n",
    "CLASS:PRIVATE\r\n",
    "END:VEVENT\r\n",
    "END:VCALENDAR\r\n"
);

const EXPAND_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop>
       <C:calendar-data>
         <C:expand start="20240501T000000Z" end="20240601T000000Z"/>
       </C:calendar-data>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:time-range start="20240501T000000Z" end="20240601T000000Z"/>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>"#;

fn event(uid: &str, class: &str, hour: &str) -> String {
    format!(
        concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:-//Stalwart//Test//EN\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:{uid}\r\n",
            "DTSTAMP:20240101T000000Z\r\n",
            "LAST-MODIFIED:20240102T000000Z\r\n",
            "DTSTART;X-NOTE=Vendor note:20240301T{hour}0000Z\r\n",
            "DURATION:PT1H\r\n",
            "SUMMARY:Details for {uid}\r\n",
            "DESCRIPTION:Notes\r\n",
            "LOCATION:Room 7\r\n",
            "STATUS:TENTATIVE\r\n",
            "CLASS:{class}\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "DESCRIPTION:Reminder\r\n",
            "TRIGGER:-PT15M\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ),
        uid = uid,
        class = class,
        hour = hour
    )
}

const SHARE_ACL: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <D:acl xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:ace>
       <D:principal>
         <D:href>$HREF</D:href>
       </D:principal>
       <D:grant>
         <D:privilege><D:read/></D:privilege>
         <D:privilege><D:write/></D:privilege>
         <D:privilege><C:read-free-busy/></D:privilege>
       </D:grant>
     </D:ace>
   </D:acl>"#;

const FREE_BUSY_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">
     <C:time-range start="20240301T000000Z" end="20240302T000000Z"/>
   </C:free-busy-query>"#;

const CALENDAR_QUERY_ANY_VEVENT: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop><D:getetag/></D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT"/>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>"#;

const CALENDAR_QUERY_SUMMARY_DETAILS: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop><D:getetag/></D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:prop-filter name="SUMMARY">
             <C:text-match>Details</C:text-match>
           </C:prop-filter>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>"#;
