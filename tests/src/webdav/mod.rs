/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServerBuilder;
use ahash::AHashMap;
use common::{DavResource, DavResources};
use groupware::DavResourceName;
use hyper::StatusCode;
use registry::{
    schema::{
        enums::{Permission, StorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            CalendarAlarm, CalendarScheduling, Expression, MtaStageAuth, Sharing, SystemSettings,
            WebDav,
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
pub mod cal_query;
pub mod cal_scheduling;
pub mod card_query;
pub mod copy_move;
pub mod lock;
pub mod mkcol;
pub mod multiget;
pub mod principals;
pub mod prop;
pub mod put_get;
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
    //test_build_itip_templates(&test).await;
    basic::test(&test).await;
    put_get::test(&test).await;
    mkcol::test(&test).await;
    copy_move::test(&test, assisted_discovery).await;
    prop::test(&test, assisted_discovery).await;
    multiget::test(&test).await;
    sync::test(&test).await;
    lock::test(&test).await;
    principals::test(&test, assisted_discovery).await;
    acl::test(&test).await;
    card_query::test(&test).await;
    cal_query::test(&test).await;
    cal_alarm::test(&test).await;
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

pub trait DavResourcesTest {
    fn items(&self) -> Vec<DavResource>;
}

impl DavResourcesTest for DavResources {
    fn items(&self) -> Vec<DavResource> {
        self.resources.clone()
    }
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
DESCRIPTION:<html><body><h1>Title</h1><p><ul><li><b>first</b> Row </li><li><
 i>second</i> Row</li></ul></p></body></html>
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
