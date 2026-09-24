/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use types::collection::Collection;

use crate::utils::server::TestServer;

use crate::utils::webdav::GenerateTestDavResource;
use crate::webdav::*;

pub async fn test(test: &TestServer) {
    println!("Running PUT/GET tests...");
    let client = test.account("john@example.com").webdav_client();

    // Simple PUT
    let mut files = AHashMap::new();
    for (path, ct, content) in [
        (
            "/dav/file/john%40example.com/file1.txt",
            "text/plain",
            TEST_FILE_1,
        ),
        (
            "/dav/file/john%40example.com/file2.txt",
            "text/x-other",
            TEST_FILE_2,
        ),
        (
            "/dav/card/john%40example.com/default/card1.vcf",
            "text/vcard; charset=utf-8",
            TEST_VCARD_1,
        ),
        (
            "/dav/card/john%40example.com/default/card2.vcf",
            "text/vcard; charset=utf-8",
            TEST_VCARD_2,
        ),
        (
            "/dav/cal/john%40example.com/default/event1.ics",
            "text/calendar; charset=utf-8",
            TEST_ICAL_1,
        ),
        (
            "/dav/cal/john%40example.com/default/event2.ics",
            "text/calendar; charset=utf-8",
            TEST_ICAL_2,
        ),
    ] {
        let content = content.replace("\n", "\r\n");
        let etag = client
            .request_with_headers("PUT", path, [("content-type", ct)], &content)
            .await
            .with_status(StatusCode::CREATED)
            .etag()
            .to_string();
        files.insert(path, (content, ct, etag));
    }

    // Test GET
    for (path, (content, ct, etag)) in &files {
        client
            .request("GET", path, "")
            .await
            .with_status(StatusCode::OK)
            .with_header("etag", etag)
            .with_header("content-type", ct)
            .with_body(content);
    }

    // Test GET with a Range header
    let path = "/dav/file/john%40example.com/file1.txt";
    let (content, _, etag) = files.get(path).unwrap();
    let size = content.len();

    for (range, expect_content_range, expect_body) in [
        ("bytes=0-4", format!("bytes 0-4/{size}"), &content[..5]),
        ("bytes=0-0", format!("bytes 0-0/{size}"), &content[..1]),
        (
            "bytes=5-",
            format!("bytes 5-{}/{size}", size - 1),
            &content[5..],
        ),
        (
            "bytes=-6",
            format!("bytes {}-{}/{size}", size - 6, size - 1),
            &content[size - 6..],
        ),
        (
            "bytes=0-100000",
            format!("bytes 0-{}/{size}", size - 1),
            &content[..],
        ),
    ] {
        client
            .request_with_headers("GET", path, [("range", range)], "")
            .await
            .with_status(StatusCode::PARTIAL_CONTENT)
            .with_header("content-range", &expect_content_range)
            .with_header("content-length", &expect_body.len().to_string())
            .with_header("accept-ranges", "bytes")
            .with_header("etag", etag)
            .with_body(expect_body);
    }

    // Ranges outside the resource should fail
    for range in ["bytes=100000-", &format!("bytes={size}-"), "bytes=-0"] {
        client
            .request_with_headers("GET", path, [("range", range)], "")
            .await
            .with_status(StatusCode::RANGE_NOT_SATISFIABLE)
            .with_header("content-range", &format!("bytes */{size}"));
    }

    // Multiple, invalid or unknown ranges should be ignored
    for range in ["bytes=0-4,6-8", "items=0-4", "bytes=4-2", "bytes=abc"] {
        client
            .request_with_headers("GET", path, [("range", range)], "")
            .await
            .with_status(StatusCode::OK)
            .with_header("accept-ranges", "bytes")
            .with_body(content);
    }

    // Ranges should be ignored on HEAD requests
    client
        .request_with_headers("HEAD", path, [("range", "bytes=0-4")], "")
        .await
        .with_status(StatusCode::OK)
        .with_header("content-length", &size.to_string())
        .with_empty_body();

    // Ranges should only be served when the If-Range validator matches
    let weak_etag = format!("W/{etag}");
    let last_modified = client
        .request("HEAD", path, "")
        .await
        .with_status(StatusCode::OK)
        .header("last-modified")
        .to_string();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    for (if_range, expect_status) in [
        (etag.as_str(), StatusCode::PARTIAL_CONTENT),
        (last_modified.as_str(), StatusCode::PARTIAL_CONTENT),
        (weak_etag.as_str(), StatusCode::OK),
        ("\"invalid-etag\"", StatusCode::OK),
        ("Sun, 09 Aug 2020 12:00:00 GMT", StatusCode::OK),
    ] {
        client
            .request_with_headers(
                "GET",
                path,
                [("range", "bytes=0-4"), ("if-range", if_range)],
                "",
            )
            .await
            .with_status(expect_status);
    }

    // If-Range without a Range header should be ignored
    client
        .request_with_headers("GET", path, [("if-range", "\"invalid-etag\"")], "")
        .await
        .with_status(StatusCode::OK)
        .with_body(content);

    // Ranges on empty files should be ignored
    let empty_path = "/dav/file/john%40example.com/empty.txt";
    client
        .request_with_headers("PUT", empty_path, [("content-type", "text/plain")], "")
        .await
        .with_status(StatusCode::CREATED);
    for range in ["bytes=0-4", "bytes=-5", "bytes=0-"] {
        client
            .request_with_headers("GET", empty_path, [("range", range)], "")
            .await
            .with_status(StatusCode::OK)
            .with_header("accept-ranges", "bytes")
            .with_empty_body();
    }
    client
        .request("DELETE", empty_path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);

    // PUT under a non-existing parent should fail
    for (path, contents) in [
        ("/dav/file/john%40example.com/foo/file1.txt", TEST_FILE_1),
        ("/dav/card/john%40example.com/foo/card1.vcf", TEST_VCARD_1),
        ("/dav/cal/john%40example.com/foo/event1.ics", TEST_ICAL_1),
    ] {
        client
            .request("PUT", path, contents)
            .await
            .with_status(StatusCode::CONFLICT);
    }

    // PUT under resources should fail
    for (path, contents, expected_status) in [
        (
            "/dav/file/john%40example.com/file1.txt/other-file.txt",
            TEST_FILE_1,
            StatusCode::CONFLICT,
        ),
        (
            "/dav/card/john%40example.com/default/card1.vcf/other-file.vcf",
            TEST_VCARD_1,
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "/dav/cal/john%40example.com/default/event1.ics/other-file.ical",
            TEST_ICAL_1,
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        client
            .request("PUT", path, contents)
            .await
            .with_status(expected_status);
    }

    // PUT a non-vCard/iCalendar file should fail
    for (path, ct, content, precondition) in [
        (
            "/dav/card/john%40example.com/card3.vcf",
            "text/vcard; charset=utf-8",
            TEST_FILE_1,
            "B:supported-address-data",
        ),
        (
            "/dav/cal/john%40example.com/event3.ics",
            "text/calendar; charset=utf-8",
            TEST_FILE_2,
            "A:supported-calendar-data",
        ),
    ] {
        client
            .request_with_headers("PUT", path, [("content-type", ct)], content)
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_failed_precondition(precondition, "");
    }

    // Exceeding the configured file limits should fail
    let conf = &test.server.core.groupware;
    for (path, contents, max_size, expect) in [
        (
            "/dav/file/john%40example.com/chunky-file1.txt",
            TEST_FILE_1,
            conf.max_file_size,
            None,
        ),
        (
            "/dav/card/john%40example.com/chunky-card1.vcf",
            TEST_VCARD_1,
            conf.max_vcard_size,
            Some("B:max-resource-size"),
        ),
        (
            "/dav/cal/john%40example.com/chunky-event1.ics",
            TEST_ICAL_1,
            conf.max_ical_size,
            Some("A:max-resource-size"),
        ),
    ] {
        let mut chunky_contents = String::with_capacity(max_size + contents.len());
        while chunky_contents.len() < max_size {
            chunky_contents.push_str(contents);
        }
        let response = client
            .request("PUT", path, chunky_contents)
            .await
            .with_status(
                expect
                    .map(|_| StatusCode::PRECONDITION_FAILED)
                    .unwrap_or(StatusCode::PAYLOAD_TOO_LARGE),
            );
        if let Some(expect) = expect {
            response.with_failed_precondition(expect, &max_size.to_string());
        }
    }

    // PUT requests cannot exceed quota
    let mike_noquota = test.account("mike@example.com").webdav_client();
    for resource_type in [
        DavResourceName::File,
        DavResourceName::Card,
        DavResourceName::Cal,
    ] {
        let path = format!(
            "{}/mike%40example.com/quota-test/",
            resource_type.base_path()
        );
        mike_noquota
            .mkcol("MKCOL", &path, [], [])
            .await
            .with_status(StatusCode::CREATED);
        let mut num_success = 0;
        let mut did_fail = false;

        for i in 0..100 {
            let content = resource_type.generate();
            let available = mike_noquota.available_quota(&path).await;

            let response = mike_noquota
                .request_with_headers("PUT", &format!("{path}file{i}"), [], &content)
                .await;
            if available >= content.len() as u64 {
                num_success += 1;
                response.with_status(StatusCode::CREATED);
            } else {
                response
                    .with_status(StatusCode::PRECONDITION_FAILED)
                    .with_failed_precondition("D:quota-not-exceeded", "");
                did_fail = true;
                break;
            }
        }
        if !did_fail {
            panic!("Quota test failed: {} files created", num_success);
        }
        if num_success == 0 {
            panic!("Quota test failed: no files created");
        }

        mike_noquota
            .request("DELETE", &path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    // PUT precondition enforcement
    let modseq = [
        test.resources("john@example.com", Collection::FileNode)
            .await
            .highest_change_id,
        test.resources("john@example.com", Collection::Calendar)
            .await
            .highest_change_id,
        test.resources("john@example.com", Collection::AddressBook)
            .await
            .highest_change_id,
    ];
    for (path, ct, content) in [
        (
            "/dav/file/john%40example.com/file1.txt",
            "text/plain",
            TEST_FILE_1,
        ),
        (
            "/dav/card/john%40example.com/default/card1.vcf",
            "text/vcard; charset=utf-8",
            TEST_VCARD_1,
        ),
        (
            "/dav/cal/john%40example.com/default/event1.ics",
            "text/calendar; charset=utf-8",
            TEST_ICAL_1,
        ),
    ] {
        let content = content.replace("\n", "\r\n");
        client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", ct), ("if-none-match", "*")],
                &content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED);

        client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", ct), ("overwrite", "F")],
                &content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED);

        client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", ct), ("if", "([\"3827\"])")],
                &content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED);

        client
            .request_with_headers(
                "PUT",
                path,
                [
                    ("content-type", ct),
                    ("if", "([\"3827\"])"),
                    ("prefer", "return=representation"),
                ],
                &content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_header("preference-applied", "return=representation")
            .with_body(&content);
    }
    assert_eq!(
        [
            test.resources("john@example.com", Collection::FileNode)
                .await
                .highest_change_id,
            test.resources("john@example.com", Collection::Calendar)
                .await
                .highest_change_id,
            test.resources("john@example.com", Collection::AddressBook)
                .await
                .highest_change_id,
        ],
        modseq
    );

    // Update files using etags
    for (path, (content, ct, etag)) in &mut files {
        let condition = format!("([{}])", etag);
        *content = content.replace("X-TEST:SEQ1", "X-TEST:SEQ2");
        *etag = client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", &**ct), ("if", condition.as_str())],
                content.as_str(),
            )
            .await
            .with_status(StatusCode::NO_CONTENT)
            .etag()
            .to_string();
    }

    // Test GET
    for (path, (content, ct, etag)) in &files {
        client
            .request("GET", path, "")
            .await
            .with_status(StatusCode::OK)
            .with_header("etag", etag)
            .with_header("content-type", ct)
            .with_body(content);
    }

    // PUT requests require unique UIDs
    for (path, ct, content, precond_key, precond_value) in [
        (
            "/dav/card/john%40example.com/default/card5.vcf",
            "text/vcard; charset=utf-8",
            TEST_VCARD_1,
            "B:no-uid-conflict.D:href",
            "/dav/card/john%40example.com/default/card1.vcf",
        ),
        (
            "/dav/cal/john%40example.com/default/event5.ics",
            "text/calendar; charset=utf-8",
            TEST_ICAL_1,
            "A:no-uid-conflict.D:href",
            "/dav/cal/john%40example.com/default/event1.ics",
        ),
    ] {
        client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", ct), ("if-none-match", "*")],
                content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_failed_precondition(precond_key, precond_value);
    }
    card_uid_changes(test).await;

    // iCal containing different component types should fail
    client
        .request_with_headers(
            "PUT",
            "/dav/cal/john%40example.com/default/invalid.ics",
            [
                ("content-type", "text/calendar; charset=utf-8"),
                ("if-none-match", "*"),
            ],
            r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:1234567890
SUMMARY:Test Event
DTSTART;TZID=Europe/London:20231001T120000
DTEND;TZID=Europe/London:20231001T130000
END:VEVENT
BEGIN:VTODO
UID:1234567890
SUMMARY:Test Task
DTSTART;TZID=Europe/London:20231001T120000
DTEND;TZID=Europe/London:20231001T130000
END:VTODO
END:VCALENDAR
"#,
        )
        .await
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_failed_precondition("A:valid-calendar-object-resource", "");

    // iCal referencing more than one UID should fail
    client
        .request_with_headers(
            "PUT",
            "/dav/cal/john%40example.com/default/invalid.ics",
            [
                ("content-type", "text/calendar; charset=utf-8"),
                ("if-none-match", "*"),
            ],
            r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:1234567890
SUMMARY:Test Event 1
DTSTART;TZID=Europe/London:20231001T120000
DTEND;TZID=Europe/London:20231001T130000
END:VEVENT
BEGIN:VEVENT
UID:1234567891
SUMMARY:Test Event 2
DTSTART;TZID=Europe/London:20231001T120000
DTEND;TZID=Europe/London:20231001T130000
END:VEVENT
END:VCALENDAR
"#,
        )
        .await
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_failed_precondition("A:valid-calendar-object-resource", "");

    // Deleting unknown/invalid destinations should fail
    for (path, expect) in [
        (
            "/dav/file/john%40example.com/unknown.txt",
            StatusCode::NOT_FOUND,
        ),
        (
            "/dav/card/john%40example.com/default/unknown.txt",
            StatusCode::NOT_FOUND,
        ),
        (
            "/dav/cal/john%40example.com/default/unknown.txt",
            StatusCode::NOT_FOUND,
        ),
        ("/dav/file/john%40example.com", StatusCode::FORBIDDEN),
        ("/dav/cal/john%40example.com", StatusCode::FORBIDDEN),
        ("/dav/card/john%40example.com", StatusCode::FORBIDDEN),
        (
            "/dav/pal/john%40example.com",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        ("/dav/file", StatusCode::FORBIDDEN),
        ("/dav/cal", StatusCode::FORBIDDEN),
        ("/dav/card", StatusCode::FORBIDDEN),
        ("/dav/pal", StatusCode::METHOD_NOT_ALLOWED),
    ] {
        client.request("DELETE", path, "").await.with_status(expect);
    }

    // Resource names containing characters that are legal in a path segment
    for (resource_type, container, name) in [
        (DavResourceName::Cal, "default", "foo+bar(1)&x:y@z.ics"),
        (DavResourceName::Card, "default", "foo+bar(1)&x:y@z.vcf"),
        (DavResourceName::Cal, "cal+1(a)", "event.ics"),
        (DavResourceName::Card, "book+1(a)", "card.vcf"),
    ] {
        let container_path = format!(
            "{}/john%40example.com/{container}",
            resource_type.base_path()
        );
        if container != "default" {
            client
                .request("MKCOL", &container_path, "")
                .await
                .with_status(StatusCode::CREATED);
        }
        let path = format!("{container_path}/{name}");
        let content = resource_type.generate();
        client
            .request("PUT", &path, &content)
            .await
            .with_status(StatusCode::CREATED);
        client
            .propfind(&path, ["D:getetag"])
            .await
            .with_hrefs([path.as_str()]);
        client
            .request("GET", &path, "")
            .await
            .with_status(StatusCode::OK)
            .with_body(&content);
        client
            .request("DELETE", &path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        if container != "default" {
            client
                .request("DELETE", &container_path, "")
                .await
                .with_status(StatusCode::NO_CONTENT);
        }
    }

    // Delete files
    for (path, (_, _, etag)) in &files {
        client
            .request_with_headers("DELETE", path, [("if", "([\"3827\"])")], "")
            .await
            .with_status(StatusCode::PRECONDITION_FAILED);

        let condition = format!("([{}])", etag);
        client
            .request_with_headers("DELETE", path, [("if", condition.as_str())], "")
            .await
            .with_status(StatusCode::NO_CONTENT);

        client
            .request("DELETE", path, "")
            .await
            .with_status(StatusCode::NOT_FOUND);
    }

    client.delete_default_containers().await;
    mike_noquota.delete_default_containers().await;
    test.assert_is_empty().await;
}

async fn card_uid_changes(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();
    let urn_path = "/dav/card/john%40example.com/default/uid-urn.vcf";
    let bare_path = "/dav/card/john%40example.com/default/uid-bare.vcf";
    let text_path = "/dav/card/john%40example.com/default/uid-text.vcf";
    let missing_path = "/dav/card/john%40example.com/default/uid-missing.vcf";
    let urn_uid = "urn:uuid:cddccf70-dc55-4cad-a171-f55f1c5c0162";
    let bare_uid = "0f5a3c8e-2b7d-4e91-a6c4-9d8e7f6a5b43";
    let vcard = |uid: &str, title: &str| {
        format!(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{uid}\r\nFN:UID Test\r\nTITLE:{title}\r\nEND:VCARD\r\n"
        )
    };
    let vcard_without_uid = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:UID Test\r\nEND:VCARD\r\n";

    for (path, content) in [
        (urn_path, vcard(urn_uid, "Created")),
        (bare_path, vcard(bare_uid, "Created")),
        (text_path, vcard("foo", "Created")),
        (missing_path, vcard_without_uid.to_string()),
    ] {
        client
            .request_with_headers("PUT", path, [("if-none-match", "*")], content)
            .await
            .with_status(StatusCode::CREATED);
    }

    // Other spellings of the stored UUID are accepted and the stored spelling is kept
    for (idx, (path, stored_uid, uid)) in [
        (urn_path, urn_uid, "cddccf70-dc55-4cad-a171-f55f1c5c0162"),
        (urn_path, urn_uid, "CDDCCF70-DC55-4CAD-A171-F55F1C5C0162"),
        (
            urn_path,
            urn_uid,
            "URN:UUID:CDDCCF70-DC55-4CAD-A171-F55F1C5C0162",
        ),
        (
            bare_path,
            bare_uid,
            "urn:uuid:0f5a3c8e-2b7d-4e91-a6c4-9d8e7f6a5b43",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let title = format!("Edit {idx}");
        let response = client
            .request("PUT", path, vcard(uid, &title))
            .await
            .with_status(StatusCode::NO_CONTENT);
        assert!(!response.headers.contains_key("etag"), "{response:?}");
        client
            .request("GET", path, "")
            .await
            .with_status(StatusCode::OK)
            .with_body(vcard(stored_uid, &title));
    }
    assert!(
        !client
            .request("PUT", urn_path, vcard(urn_uid, "Same spelling"))
            .await
            .with_status(StatusCode::NO_CONTENT)
            .etag()
            .is_empty()
    );

    // A different UUID, or a non-UUID behind a urn:uuid: prefix, is a UID change
    for (path, uid) in [
        (urn_path, "urn:uuid:0ddccf70-dc55-4cad-a171-f55f1c5c0162"),
        (text_path, "urn:uuid:foo"),
    ] {
        client
            .request("PUT", path, vcard(uid, "Conflict"))
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_failed_precondition("B:no-uid-conflict.D:href", path);
    }

    // A UID added to a card without one has to be unique, and cannot be removed
    client
        .request("PUT", missing_path, vcard(urn_uid, "Taken"))
        .await
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_failed_precondition("B:no-uid-conflict.D:href", urn_path);
    client
        .request(
            "PUT",
            missing_path,
            vcard("urn:uuid:7e4b9d20-1a6c-4c8f-b3e5-2d9f8a0c6b17", "Added"),
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    client
        .request("PUT", missing_path, vcard_without_uid)
        .await
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_failed_precondition("B:no-uid-conflict.D:href", missing_path);

    for path in [urn_path, bare_path, text_path, missing_path] {
        client
            .request("DELETE", path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
}
