/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use dav_proto::Depth;
use hyper::StatusCode;

use super::WebDavTest;

pub async fn test(test: &WebDavTest) {
    println!("Running basic tests...");
    let john = test.client("john");
    let jane = test.client("jane");

    // Test OPTIONS request
    john.request("OPTIONS", "/dav/file", "")
        .await
        .with_header(
            "dav",
            concat!(
                "1, 2, 3, access-control, extended-mkcol, calendar-access, ",
                "calendar-auto-schedule, calendar-no-timezone, addressbook"
            ),
        )
        .with_header(
            "allow",
            concat!(
                "OPTIONS, GET, HEAD, POST, PUT, DELETE, COPY, MOVE, ",
                "MKCALENDAR, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, REPORT, ACL"
            ),
        );

    // Test Discovery
    john.request("PROPFIND", "/.well-known/carddav", "")
        .await
        .with_values(
            "D:multistatus.D:response.D:href",
            ["/dav/card/", "/dav/card/john/"],
        );
    jane.request("PROPFIND", "/.well-known/caldav", "")
        .await
        .with_values(
            "D:multistatus.D:response.D:href",
            ["/dav/cal/", "/dav/cal/jane/", "/dav/cal/support/"],
        );

    // Test 404 responses
    jane.sync_collection(
        "/dav/cal/jane/default/",
        "",
        Depth::Infinity,
        None,
        ["D:getetag"],
    )
    .await;
    jane.sync_collection(
        "/dav/cal/jane/test-404/",
        "",
        Depth::Infinity,
        None,
        ["D:getetag"],
    )
    .await;
    jane.request("PROPFIND", "/dav/cal/jane/default/", "")
        .await
        .with_status(StatusCode::MULTI_STATUS);
    jane.request(
        "REPORT",
        "/dav/cal/jane/default/",
        concat!(
            r#"<CAL:calendar-query xmlns="DAV:" "#,
            r#"xmlns:CAL="urn:ietf:params:xml:ns:caldav"><prop><getetag />"#,
            r#"</prop><CAL:filter><CAL:comp-filter name="VCALENDAR">"#,
            r#"<CAL:comp-filter name="VTODO" /></CAL:comp-filter></CAL:filter>"#,
            r#"</CAL:calendar-query>"#
        ),
    )
    .await
    .with_status(StatusCode::MULTI_STATUS);
    jane.request(
        "REPORT",
        "/dav/cal/jane/test-404/",
        concat!(
            r#"<CAL:calendar-query xmlns="DAV:" "#,
            r#"xmlns:CAL="urn:ietf:params:xml:ns:caldav"><prop><getetag />"#,
            r#"</prop><CAL:filter><CAL:comp-filter name="VCALENDAR">"#,
            r#"<CAL:comp-filter name="VTODO" /></CAL:comp-filter></CAL:filter>"#,
            r#"</CAL:calendar-query>"#
        ),
    )
    .await
    .with_status(StatusCode::MULTI_STATUS);
    jane.request("PROPFIND", "/dav/cal/jane/test-404/", "")
        .await
        .with_status(StatusCode::NOT_FOUND);

    john.delete_default_containers().await;
    jane.delete_default_containers().await;
    jane.delete_default_containers_by_account("support").await;
    test.assert_is_empty().await;
}
