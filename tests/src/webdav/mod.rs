/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use ahash::AHashMap;
use common::GroupwareResources;
use groupware::DavResourceName;
use hyper::StatusCode;
use registry::{
    schema::{
        enums::{Permission, StorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            AddressBook as AddressBookSettings, Calendar as CalendarSettings, CalendarAlarm,
            CalendarScheduling, Expression, MtaStageAuth, Sharing, SystemSettings, WebDav,
        },
    },
    types::EnumImpl,
};
use serde_json::json;
use std::str;
use std::time::Instant;

pub mod acl;
pub mod basic;
pub mod cal_alarm;
pub mod cal_itip;
pub mod cal_personal;
pub mod cal_privacy;
pub mod cal_query;
pub mod cal_scheduling;
pub mod card_query;
pub mod compliance;
pub mod copy_move;
pub mod dav_search;
pub mod lock;
pub mod mkcol;
pub mod multiget;
pub mod principals;
pub mod prop;
pub mod put_get;
pub mod storage_split;
pub mod sync;

#[tokio::test(flavor = "multi_thread")]
pub async fn webdav_tests() {
    // Prepare settings
    let assisted_discovery = std::env::var("ASSISTED_DISCOVERY").unwrap_or_default() == "1";

    let mut test = TestServerBuilder::new("webdav_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;

    // Create admin account
    let admin = test.create_admin_account("admin@example.com").await;

    // Create test users
    for (name, secret, description, aliases) in [
        (
            "john@example.com",
            "secret2 + some more text",
            "John Doe",
            &["jdoe@example.com"],
        ),
        (
            "jane@example.com",
            "secret3 + some more text",
            "Jane Doe-Smith",
            &["jane.smith@example.com"],
        ),
        (
            "bill@example.com",
            "secret4 + some more text",
            "Bill Foobar",
            &["bill@example.com"],
        ),
        (
            "mike@example.com",
            "secret5 + some more text",
            "Mike Noquota",
            &["mike@example.com"],
        ),
    ] {
        let account = admin
            .create_user_account(
                name,
                secret,
                description,
                aliases,
                vec![
                    Permission::UnlimitedRequests,
                    Permission::UnlimitedUploads,
                    Permission::DavPrincipalList,
                    Permission::DavPrincipalSearch,
                ],
            )
            .await;
        if name == "mike@example.com" {
            admin
                .registry_update_object(
                    ObjectType::Account,
                    account.id(),
                    json!({
                        Property::Quotas: { StorageQuota::MaxDiskQuota.as_str(): 1024}
                    }),
                )
                .await;
        }

        test.insert_account(account);
    }

    // Create test group
    test.insert_account(
        admin
            .create_group_account("support@example.com", "Support Group", &[])
            .await,
    );

    // Add Jane to the Support group
    let support_id = test.account("support@example.com").id();
    admin
        .registry_update_object(
            ObjectType::Account,
            test.account("jane@example.com").id(),
            json!({
                "memberGroupIds": { support_id: true },
            }),
        )
        .await;

    // Add test settings
    admin
        .registry_update_setting(
            SystemSettings {
                default_hostname: "webdav.example.org".to_string(),
                ..Default::default()
            },
            &[Property::DefaultHostname],
        )
        .await;
    admin
        .registry_create_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(CalendarAlarm {
            min_trigger_interval: 1000u64.into(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Sharing {
            allow_directory_queries: true,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(CalendarScheduling {
            auto_add_invitations: true,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(WebDav {
            enable_assisted_discovery: assisted_discovery,
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;

    test.insert_account(admin);

    let start_time = Instant::now();
    if std::env::var("ITIP_TEMPLATES").is_ok() {
        cal_scheduling::test_build_itip_templates(&test).await;
    }
    basic::test(&test).await;
    put_get::test(&test).await;
    embedded_size_limits(&test).await;
    supported_calendar_components(&test).await;
    mkcol::test(&test).await;
    copy_move::test(&test, assisted_discovery).await;
    prop::test(&test, assisted_discovery).await;
    multiget::test(&test).await;
    sync::test(&test).await;
    lock::test(&test).await;
    principals::test(&test, assisted_discovery).await;
    acl::test(&test).await;
    cal_privacy::test(&test).await;
    cal_personal::test(&test).await;
    card_query::test(&test).await;
    cal_query::test(&test).await;
    dav_search::test(&test).await;
    cal_alarm::test(&test).await;
    storage_split::test(&test).await;
    cal_itip::test();
    cal_scheduling::test(&test).await;

    // Print elapsed time
    let elapsed = start_time.elapsed();
    println!(
        "Elapsed: {}.{:03}s",
        elapsed.as_secs(),
        elapsed.subsec_millis()
    );

    // Remove test data
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

async fn embedded_size_limits(test: &TestServer) {
    println!("Running embedded size limit tests...");
    const LIMIT: u64 = 64;
    let admin = test.account("admin@example.com");
    let client = test.account("john@example.com").webdav_client();
    let data = "AAAA".repeat(32);

    update_embedded_limits(admin, LIMIT, LIMIT).await;
    for (path, contents, precondition) in [
        (
            "/dav/cal/john%40example.com/default/attachment.ics",
            ICAL_WITH_ATTACHMENT.replace("$DATA", &data),
            "A:max-resource-size",
        ),
        (
            "/dav/card/john%40example.com/default/media.vcf",
            VCARD_WITH_MEDIA.replace("$DATA", &data),
            "B:max-resource-size",
        ),
    ] {
        client
            .request("PUT", path, contents)
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_failed_precondition(precondition, &LIMIT.to_string());
    }
    update_embedded_limits(
        admin,
        CalendarSettings::default().max_attachments_size,
        AddressBookSettings::default().max_media_size,
    )
    .await;

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}

async fn update_embedded_limits(admin: &Account, attachments_size: u64, media_size: u64) {
    admin
        .registry_update_setting(
            CalendarSettings {
                max_attachments_size: attachments_size,
                ..Default::default()
            },
            &[Property::MaxAttachmentsSize],
        )
        .await;
    admin
        .registry_update_setting(
            AddressBookSettings {
                max_media_size: media_size,
                ..Default::default()
            },
            &[Property::MaxMediaSize],
        )
        .await;
    admin.reload_settings().await;
}

async fn supported_calendar_components(test: &TestServer) {
    println!("Running supported calendar component tests...");
    let client = test.account("john@example.com").webdav_client();
    let calendar = "/dav/cal/john%40example.com/tasks-only";

    client
        .mkcol(
            "MKCALENDAR",
            calendar,
            [],
            [(
                "A:supported-calendar-component-set",
                "<A:comp name=\"VTODO\"/>",
            )],
        )
        .await
        .with_status(StatusCode::CREATED);
    client
        .request(
            "PUT",
            &format!("{calendar}/event.ics"),
            ICAL_WITH_ATTACHMENT.replace("$DATA", "AAAA"),
        )
        .await
        .with_status(StatusCode::FORBIDDEN)
        .with_failed_precondition("A:supported-calendar-component", "");
    client
        .request("PUT", &format!("{calendar}/task.ics"), ICAL_TODO)
        .await
        .with_status(StatusCode::CREATED);

    let default_event = "/dav/cal/john%40example.com/default/component-event.ics";
    let default_task = "/dav/cal/john%40example.com/default/component-task.ics";
    for (path, contents) in [
        (default_event, ICAL_WITH_ATTACHMENT.replace("$DATA", "AAAA")),
        (
            default_task,
            ICAL_TODO.replace("dav-supported-component", "dav-supported-component-moved"),
        ),
    ] {
        client
            .request("PUT", path, contents)
            .await
            .with_status(StatusCode::CREATED);
    }
    for method in ["COPY", "MOVE"] {
        client
            .request_with_headers(
                method,
                default_event,
                [("destination", format!("{calendar}/event.ics").as_str())],
                "",
            )
            .await
            .with_status(StatusCode::FORBIDDEN)
            .with_failed_precondition("A:supported-calendar-component", "");
    }
    client
        .request_with_headers(
            "MOVE",
            default_task,
            [("destination", format!("{calendar}/moved-task.ics").as_str())],
            "",
        )
        .await
        .with_status(StatusCode::CREATED);

    client
        .request("DELETE", calendar, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    client.delete_default_containers().await;
    test.assert_is_empty().await;
}

const ICAL_TODO: &str = concat!(
    "BEGIN:VCALENDAR\r\n",
    "VERSION:2.0\r\n",
    "PRODID:-//Stalwart//Test//EN\r\n",
    "BEGIN:VTODO\r\n",
    "UID:dav-supported-component\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "SUMMARY:Task only\r\n",
    "END:VTODO\r\n",
    "END:VCALENDAR\r\n"
);

const ICAL_WITH_ATTACHMENT: &str = concat!(
    "BEGIN:VCALENDAR\r\n",
    "VERSION:2.0\r\n",
    "PRODID:-//Stalwart//Test//EN\r\n",
    "BEGIN:VEVENT\r\n",
    "UID:dav-attachment-limit\r\n",
    "DTSTAMP:20240101T000000Z\r\n",
    "DTSTART:20240301T100000Z\r\n",
    "DURATION:PT1H\r\n",
    "SUMMARY:Attachment limit\r\n",
    "ATTACH;ENCODING=BASE64;VALUE=BINARY:$DATA\r\n",
    "END:VEVENT\r\n",
    "END:VCALENDAR\r\n"
);

const VCARD_WITH_MEDIA: &str = concat!(
    "BEGIN:VCARD\r\n",
    "VERSION:4.0\r\n",
    "UID:dav-media-limit\r\n",
    "FN:Media Limit\r\n",
    "PHOTO:data:image/png;base64,$DATA\r\n",
    "END:VCARD\r\n"
);

pub trait GroupwareResourcesTest {
    fn items(&self) -> Vec<u32>;
}

impl GroupwareResourcesTest for GroupwareResources {
    fn items(&self) -> Vec<u32> {
        self.resources.iter().map(|r| r.document_id()).collect()
    }
}

pub fn template_out_dir() -> Option<std::path::PathBuf> {
    if std::env::var("ITIP_TEMPLATES").is_err() {
        return None;
    }

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.ignore/itip_templates");
    std::fs::create_dir_all(&dir).expect("Failed to create template output directory");

    Some(dir.canonicalize().unwrap_or(dir))
}

pub const TEST_VCARD_1: &str = r#"BEGIN:VCARD
VERSION:4.0
UID:18F098B5-7383-4FD6-B482-48F2181D73AA
X-TEST:SEQ1
N:Coyote;Wile;E.;;
FN:Wile E. Coyote
ORG:ACME Inc.;
END:VCARD
"#;

pub const TEST_VCARD_2: &str = r#"BEGIN:VCARD
VERSION:4.0
UID:6exhjr32bt783wwlr9u0sr8lfqse5x7zqc8y
X-TEST:SEQ1
FN:Joe Citizen
N:Citizen;Joe;;;
NICKNAME:human_being
EMAIL;TYPE=pref:jcitizen@foo.com
REV:20200411T072429Z
END:VCARD
"#;

pub const TEST_ICAL_1: &str = r#"BEGIN:VCALENDAR
SOURCE;VALUE=URI:http://calendar.example.com/event_with_html.ics
X-TEST:SEQ1
BEGIN:VEVENT
UID: 2371c2d9-a136-43b0-bba3-f6ab249ad46e
SUMMARY:What a nice present: 🎁
DTSTART;TZID=America/New_York:20190221T170000
DTEND;TZID=America/New_York:20190221T180000
LOCATION:Germany
DESCRIPTION:<html><body><h1>Title</h1><p><ul><li><b>first</b> Row </li><li>
 <i>second</i> Row</li></ul></p></body></html>
END:VEVENT
END:VCALENDAR
"#;

pub const TEST_ICAL_2: &str = r#"BEGIN:VCALENDAR
X-TEST:SEQ1
BEGIN:VEVENT
UID:0000001
SUMMARY:Treasure Hunting
DTSTART;TZID=America/Los_Angeles:20150706T120000
DTEND;TZID=America/Los_Angeles:20150706T130000
RRULE:FREQ=DAILY;COUNT=10
EXDATE;TZID=America/Los_Angeles:20150708T120000
EXDATE;TZID=America/Los_Angeles:20150710T120000
END:VEVENT
BEGIN:VEVENT
UID:0000001
SUMMARY:More Treasure Hunting
LOCATION:The other island
DTSTART;TZID=America/Los_Angeles:20150709T150000
DTEND;TZID=America/Los_Angeles:20150707T160000
RECURRENCE-ID;TZID=America/Los_Angeles:20150707T120000
END:VEVENT
END:VCALENDAR
"#;

pub const TEST_FILE_1: &str = r#"this is a test file
with some text
and some more text

X-TEST:SEQ1
"#;

pub const TEST_FILE_2: &str = r#"another test file
with amazing content
and some more text

X-TEST:SEQ1
"#;

pub const TEST_VTIMEZONE_1: &str = r#"BEGIN:VCALENDAR
PRODID:-//Example Corp.//CalDAV Client//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:US-Eastern
LAST-MODIFIED:19870101T000000Z
BEGIN:STANDARD
DTSTART:19671029T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
TZNAME:Eastern Standard Time (US Canada)
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19870405T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
TZNAME:Eastern Daylight Time (US Canada)
END:DAYLIGHT
END:VTIMEZONE
END:VCALENDAR
"#;
