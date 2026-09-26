/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{account::Account, server::TestServer, webdav::DummyWebDavClient};
use dav_proto::schema::property::{DavProperty, WebDavProperty};
use groupware::DavResourceName;
use hyper::StatusCode;
use jmap_client::email;
use mail_parser::DateTime;
use std::time::Duration;
use store::write::now;

const DELIVERY_ATTEMPTS: usize = 300;
const DELIVERY_INTERVAL: Duration = Duration::from_millis(100);
const INVITE_START_OFFSET: i64 = 86_400;
const BATCH_TEST_CARDS: usize = 300;
const FIRST_BATCH_ODD_CARDS: usize = 128;
const INVITE_DURATION: i64 = 3_600;

pub async fn test(test: &TestServer) {
    println!("Running DAV search tests...");
    card_search(test).await;
    calendar_search(test).await;
    scheduling_inbox_search(test).await;
    principal_search(test).await;
    batch_boundaries(test).await;
}

async fn card_search(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();
    let book = format!(
        "{}/john%40example.com/default/",
        DavResourceName::Card.base_path()
    );
    let grouped = format!("{book}grouped.vcf");
    let org = format!("{book}org.vcf");
    let person = format!("{book}person.vcf");
    for (href, card) in [
        (&grouped, CARD_GROUPED),
        (&org, CARD_ORG),
        (&person, CARD_PERSON),
    ] {
        client
            .request("PUT", href, card.replace('\n', "\r\n"))
            .await
            .with_status(StatusCode::CREATED);
    }
    test.wait_for_tasks().await;

    for (filter, expected) in [
        (
            r#"<C:filter><C:prop-filter name="EMAIL"><C:text-match>grouped.example</C:text-match></C:prop-filter></C:filter>"#,
            vec![grouped.as_str()],
        ),
        (
            r#"<C:filter><C:prop-filter name="item2.EMAIL"><C:text-match>grouped</C:text-match></C:prop-filter></C:filter>"#,
            vec![],
        ),
        (
            r#"<C:filter><C:prop-filter name="FN"><C:text-match>holdings</C:text-match></C:prop-filter></C:filter>"#,
            vec![org.as_str()],
        ),
        (
            r#"<C:filter><C:prop-filter name="FN"><C:text-match>anna</C:text-match></C:prop-filter><C:prop-filter name="NICKNAME"><C:text-match>nobody</C:text-match></C:prop-filter></C:filter>"#,
            vec![grouped.as_str()],
        ),
        (
            r#"<C:filter test="anyof"><C:prop-filter name="FN" test="allof"><C:text-match>carl</C:text-match></C:prop-filter><C:prop-filter name="TEL"><C:text-match>000</C:text-match></C:prop-filter></C:filter>"#,
            vec![person.as_str()],
        ),
        (
            r#"<C:filter><C:prop-filter name="ADR"/></C:filter>"#,
            vec![person.as_str()],
        ),
        (
            r#"<C:filter><C:prop-filter name="NICKNAME"><C:is-not-defined/></C:prop-filter></C:filter>"#,
            vec![org.as_str(), person.as_str()],
        ),
        (
            r#"<C:filter><C:prop-filter name="UID"><C:text-match match-type="equals" collation="i;octet">urn:uuid:search-org</C:text-match></C:prop-filter></C:filter>"#,
            vec![org.as_str()],
        ),
        (
            r#"<C:filter test="allof"><C:prop-filter name="EMAIL" test="allof"><C:text-match>example</C:text-match><C:param-filter name="TYPE"><C:text-match match-type="equals">home</C:text-match></C:param-filter></C:prop-filter></C:filter>"#,
            vec![grouped.as_str()],
        ),
    ] {
        client
            .request("REPORT", &book, card_query(filter))
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(expected);
    }

    let email_query = r#"<C:filter><C:prop-filter name="EMAIL"><C:text-match>example</C:text-match></C:prop-filter></C:filter><C:limit><C:nresults>LIMIT</C:nresults></C:limit>"#;
    client
        .request(
            "REPORT",
            &book,
            card_query(&email_query.replace("LIMIT", "2")),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([grouped.as_str(), person.as_str()]);
    client
        .request(
            "REPORT",
            &book,
            card_query(&email_query.replace("LIMIT", "1")),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_href_count(2)
        .with_value(
            "D:multistatus.D:response.D:error.D:number-of-matches-within-limits",
            "",
        );

    client
        .request(
            "REPORT",
            &book,
            card_query(
                r#"<C:filter><C:prop-filter name="FN"><C:text-match collation="i;x-bogus">a</C:text-match></C:prop-filter></C:filter>"#,
            ),
        )
        .await
        .with_status(StatusCode::FORBIDDEN)
        .with_failed_precondition("B:supported-collation", "i;x-bogus");

    let body = client
        .request("REPORT", &book, ADDRESS_DATA_EMAIL_QUERY)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([grouped.as_str()])
        .expect_body()
        .to_string();
    assert!(body.contains("item1.EMAIL"), "{body}");
    assert!(!body.contains("NICKNAME"), "{body}");

    client
        .request("REPORT", &book, PROPNAME_CARD_QUERY)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([person.as_str()]);

    for (text, expected) in [("anna", vec![grouped.as_str()]), ("carl", vec![])] {
        client
            .request_with_headers(
                "REPORT",
                &grouped,
                [("depth", "0")],
                card_query(&format!(
                    r#"<C:filter><C:prop-filter name="FN"><C:text-match>{text}</C:text-match></C:prop-filter></C:filter>"#
                )),
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(expected);
    }

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}

async fn calendar_search(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();
    let calendar = format!(
        "{}/john%40example.com/default/",
        DavResourceName::Cal.base_path()
    );
    let planning = format!("{calendar}planning.ics");
    let todo = format!("{calendar}todo.ics");
    let long_uid = format!("{calendar}long-uid.ics");
    let renewal = format!("{calendar}renewal.ics");
    let long_uid_value = format!("search-{}", "x".repeat(300));
    for (href, ical) in [
        (&planning, EVENT_PLANNING.to_string()),
        (&todo, TODO_REPORT.to_string()),
        (&long_uid, EVENT_LONG_UID.replace("$UID", &long_uid_value)),
        (&renewal, EVENT_REPEATING_ALARM.to_string()),
    ] {
        client
            .request("PUT", href, ical.replace('\n', "\r\n"))
            .await
            .with_status(StatusCode::CREATED);
    }
    test.wait_for_tasks().await;

    let long_uid_filter = in_vevent(&format!(
        r#"<C:prop-filter name="UID"><C:text-match collation="i;octet">{long_uid_value}</C:text-match></C:prop-filter>"#
    ));
    for (filter, expected) in [
        (
            in_vevent(
                r#"<C:prop-filter name="SUMMARY"><C:text-match>quarterly</C:text-match></C:prop-filter>"#,
            ),
            vec![planning.as_str()],
        ),
        (
            in_vevent(
                r#"<C:prop-filter name="SUMMARY"><C:text-match>Quart</C:text-match></C:prop-filter>"#,
            ),
            vec![planning.as_str()],
        ),
        (
            in_vevent(&attendee_partstat("mailto:lisa@example.com")),
            vec![],
        ),
        (
            in_vevent(&attendee_partstat("mailto:bob@example.com")),
            vec![planning.as_str()],
        ),
        (
            in_vevent(
                r#"<C:prop-filter name="ATTENDEE"><C:param-filter name="PARTSTAT"><C:text-match>NEEDS-ACTION</C:text-match></C:param-filter></C:prop-filter><C:prop-filter name="SUMMARY"><C:text-match>planning</C:text-match></C:prop-filter>"#,
            ),
            vec![planning.as_str()],
        ),
        (
            in_vtodo(
                r#"<C:prop-filter name="COMPLETED"><C:time-range start="20250305T000000Z" end="20250306T000000Z"/></C:prop-filter>"#,
            ),
            vec![todo.as_str()],
        ),
        (
            in_vtodo(r#"<C:prop-filter name="LOCATION"><C:is-not-defined/></C:prop-filter>"#),
            vec![todo.as_str()],
        ),
        (
            in_vevent(r#"<C:prop-filter name="LOCATION"/>"#),
            vec![planning.as_str()],
        ),
        (long_uid_filter, vec![long_uid.as_str()]),
        (
            in_vevent(
                r#"<C:comp-filter name="VALARM"><C:time-range start="20250716T000000Z" end="20250716T120000Z"/></C:comp-filter>"#,
            ),
            vec![renewal.as_str()],
        ),
        (
            in_vevent(
                r#"<C:comp-filter name="VALARM"><C:time-range start="20250713T000000Z" end="20250714T000000Z"/></C:comp-filter>"#,
            ),
            vec![],
        ),
    ] {
        client
            .request("REPORT", &calendar, calendar_query(&filter))
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(expected);
    }

    client
        .request(
            "REPORT",
            &calendar,
            calendar_query(&in_vtodo(r#"<C:comp-filter name="VEVENT"/>"#)),
        )
        .await
        .with_status(StatusCode::FORBIDDEN)
        .with_failed_precondition("A:valid-filter", "");
    client
        .request(
            "REPORT",
            &calendar,
            calendar_query(&in_vevent(
                r#"<C:prop-filter name="SUMMARY"><C:text-match collation="i;ascii-numeric">1</C:text-match></C:prop-filter>"#,
            )),
        )
        .await
        .with_status(StatusCode::FORBIDDEN)
        .with_failed_precondition("A:supported-collation", "i;ascii-numeric");

    for (text, expected) in [("quarterly", vec![planning.as_str()]), ("nothing", vec![])] {
        client
            .request_with_headers(
                "REPORT",
                &planning,
                [("depth", "0")],
                calendar_query(&in_vevent(&format!(
                    r#"<C:prop-filter name="SUMMARY"><C:text-match>{text}</C:text-match></C:prop-filter>"#
                ))),
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(expected);
    }

    client
        .request("REPORT", &calendar, PROPNAME_CALENDAR_QUERY)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([todo.as_str()]);

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}

async fn scheduling_inbox_search(test: &TestServer) {
    let john = test.account("john@example.com");
    let jane = test.account("jane@example.com");
    let john_client = john.webdav_client();
    let jane_client = jane.webdav_client();
    let inbox = "/dav/itip/jane%40example.com/inbox/";

    let start = now() as i64 + INVITE_START_OFFSET;
    let utc = |timestamp: i64| {
        DateTime::from_timestamp(timestamp)
            .to_rfc3339()
            .replace(['-', ':'], "")
    };
    john_client
        .request(
            "PUT",
            &format!(
                "{}/john%40example.com/default/invite.ics",
                DavResourceName::Cal.base_path()
            ),
            EVENT_INVITE
                .replace("$START", &utc(start))
                .replace("$END", &utc(start + INVITE_DURATION))
                .replace('\n', "\r\n"),
        )
        .await
        .with_status(StatusCode::CREATED);
    test.wait_for_tasks().await;

    let messages = jane_client.wait_for_scheduling_inbox(inbox).await;
    assert_eq!(messages.len(), 1, "{messages:?}");
    let message = messages[0].as_str();

    for (filter, expected) in [
        (
            in_vevent(
                r#"<C:prop-filter name="SUMMARY"><C:text-match>inbox search</C:text-match></C:prop-filter>"#,
            ),
            vec![message],
        ),
        (
            in_vevent(
                r#"<C:prop-filter name="SUMMARY"><C:text-match>unrelated</C:text-match></C:prop-filter>"#,
            ),
            vec![],
        ),
        (
            in_vevent(&format!(
                r#"<C:time-range start="{}" end="{}"/>"#,
                utc(start - INVITE_DURATION),
                utc(start + INVITE_DURATION)
            )),
            vec![message],
        ),
        (
            in_vevent(&format!(
                r#"<C:time-range start="{}" end="{}"/>"#,
                utc(start + INVITE_START_OFFSET),
                utc(start + 2 * INVITE_START_OFFSET)
            )),
            vec![],
        ),
    ] {
        jane_client
            .request("REPORT", inbox, calendar_query(&filter))
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(expected);
    }

    jane_client
        .request("REPORT", inbox, CALENDAR_MULTIGET.replace("$HREF", message))
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([message])
        .with_value(
            "D:multistatus.D:response.D:propstat.D:status",
            "HTTP/1.1 200 OK",
        );

    for message in jane_client.scheduling_inbox(inbox).await {
        jane_client
            .request("DELETE", &message, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    jane.wait_for_email().await;
    for client in [&john_client, &jane_client] {
        client.delete_default_containers_without_scheduling().await;
    }
    for account in [john, jane] {
        test.destroy_all_mailboxes(account).await;
    }
    test.assert_is_empty().await;
}

async fn principal_search(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();
    let principals = DavResourceName::Principal.collection_path();
    let jane = format!(
        "{}/jane%40example.com/",
        DavResourceName::Principal.base_path()
    );
    let bill = format!(
        "{}/bill%40example.com/",
        DavResourceName::Principal.base_path()
    );
    let john = format!(
        "{}/john%40example.com/",
        DavResourceName::Principal.base_path()
    );

    for (query, expected) in [
        (
            principal_query(
                "",
                r#"<D:prop><C:calendar-user-address-set/></D:prop><D:match>mailto:jane.smith@example.com</D:match>"#,
            ),
            vec![jane.as_str()],
        ),
        (
            principal_query(
                r#" test="anyof""#,
                r#"<D:prop><D:displayname/></D:prop><D:match>foobar</D:match></D:property-search><D:property-search><D:prop><C:calendar-user-address-set/></D:prop><D:match>mailto:jane@example.com</D:match>"#,
            ),
            vec![jane.as_str(), bill.as_str()],
        ),
        (
            principal_query(
                "",
                r#"<D:prop><D:displayname/></D:prop><D:match>foobar</D:match></D:property-search><D:property-search><D:prop><C:calendar-user-address-set/></D:prop><D:match>mailto:jane@example.com</D:match>"#,
            ),
            vec![],
        ),
        (
            principal_query(
                "",
                r#"<D:prop><D:displayname/><D:getetag/></D:prop><D:match>doe</D:match>"#,
            ),
            vec![],
        ),
        (
            principal_query(
                "",
                r#"<D:prop><D:displayname/></D:prop><D:match>Doe</D:match>"#,
            ),
            vec![john.as_str(), jane.as_str()],
        ),
        (
            principal_query(
                "",
                r#"<D:prop><D:displayname/></D:prop><D:match>nobody doe</D:match>"#,
            ),
            vec![],
        ),
        (
            principal_query(
                "",
                r#"<D:prop><C:calendar-user-address-set/></D:prop><D:match>mailto:nobody@example.com</D:match>"#,
            ),
            vec![],
        ),
    ] {
        client
            .request("REPORT", principals, query)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(expected);
    }

    client
        .request(
            "REPORT",
            principals,
            r#"<?xml version="1.0" encoding="utf-8" ?><D:principal-search-property-set xmlns:D="DAV:"/>"#,
        )
        .await
        .with_status(StatusCode::OK)
        .with_values(
            "D:principal-search-property-set.D:principal-search-property.D:description",
            ["Account or Group name", "Calendar user address"],
        );

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}

async fn batch_boundaries(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();
    let book = format!(
        "{}/john%40example.com/default/",
        DavResourceName::Card.base_path()
    );
    let cards = (0..BATCH_TEST_CARDS)
        .map(|number| format!("{book}batch-{number:03}.vcf"))
        .collect::<Vec<_>>();
    for (number, href) in cards.iter().enumerate() {
        client
            .request(
                "PUT",
                href,
                CARD_BATCH
                    .replace("$NUMBER", &number.to_string())
                    .replace("$PARITY", if number % 2 == 0 { "even" } else { "odd" })
                    .replace('\n', "\r\n"),
            )
            .await
            .with_status(StatusCode::CREATED);
    }
    test.wait_for_tasks().await;

    let odd = cards
        .iter()
        .skip(1)
        .step_by(2)
        .map(String::as_str)
        .collect::<Vec<_>>();
    let odd_filter = r#"<C:filter><C:prop-filter name="TITLE"><C:text-match match-type="equals">odd</C:text-match></C:prop-filter></C:filter>"#;
    client
        .request("REPORT", &book, card_query(odd_filter))
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs(odd.iter().copied());
    client
        .request(
            "REPORT",
            &book,
            card_query(&format!(
                "{odd_filter}<C:limit><C:nresults>{}</C:nresults></C:limit>",
                odd.len()
            )),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs(odd.iter().copied());
    for limit in [odd.len() - 1, FIRST_BATCH_ODD_CARDS] {
        client
            .request(
                "REPORT",
                &book,
                card_query(&format!(
                    "{odd_filter}<C:limit><C:nresults>{limit}</C:nresults></C:limit>"
                )),
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_href_count(limit + 1)
            .with_value(
                "D:multistatus.D:response.D:error.D:number-of-matches-within-limits",
                "",
            );
    }

    let listing = client
        .propfind_with_headers(
            &book,
            [DavProperty::WebDav(WebDavProperty::GetETag)],
            [("depth", "1")],
        )
        .await;
    assert_eq!(listing.hrefs.len(), BATCH_TEST_CARDS + 1);

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}

impl DummyWebDavClient {
    async fn scheduling_inbox(&self, inbox: &str) -> Vec<String> {
        self.propfind_with_headers(
            inbox,
            [DavProperty::WebDav(WebDavProperty::GetETag)],
            [("depth", "1")],
        )
        .await
        .hrefs
        .into_keys()
        .filter(|href| href != inbox)
        .collect()
    }

    async fn wait_for_scheduling_inbox(&self, inbox: &str) -> Vec<String> {
        for _ in 0..DELIVERY_ATTEMPTS {
            let messages = self.scheduling_inbox(inbox).await;
            if !messages.is_empty() {
                return messages;
            }
            tokio::time::sleep(DELIVERY_INTERVAL).await;
        }
        panic!("No iTIP message was delivered to {inbox}");
    }
}

impl Account {
    async fn wait_for_email(&self) {
        let client = self.jmap_client().await;
        for _ in 0..DELIVERY_ATTEMPTS {
            if !client
                .email_query(None::<email::query::Filter>, None::<Vec<_>>)
                .await
                .expect("Email/query failed")
                .ids()
                .is_empty()
            {
                return;
            }
            tokio::time::sleep(DELIVERY_INTERVAL).await;
        }
        panic!("No iMIP message was delivered to {}", self.name());
    }
}

fn card_query(filter: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8" ?><C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop><D:getetag/></D:prop>{filter}</C:addressbook-query>"#
    )
}

fn calendar_query(filter: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8" ?><C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/></D:prop><C:filter>{filter}</C:filter></C:calendar-query>"#
    )
}

fn principal_query(test: &str, search: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8" ?><D:principal-property-search xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"{test}><D:property-search>{search}</D:property-search><D:prop><D:displayname/></D:prop></D:principal-property-search>"#
    )
}

fn in_vevent(filter: &str) -> String {
    format!(
        r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">{filter}</C:comp-filter></C:comp-filter>"#
    )
}

fn in_vtodo(filter: &str) -> String {
    format!(
        r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VTODO">{filter}</C:comp-filter></C:comp-filter>"#
    )
}

fn attendee_partstat(address: &str) -> String {
    format!(
        r#"<C:prop-filter name="ATTENDEE"><C:text-match>{address}</C:text-match><C:param-filter name="PARTSTAT"><C:text-match>NEEDS-ACTION</C:text-match></C:param-filter></C:prop-filter>"#
    )
}

const ADDRESS_DATA_EMAIL_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop>
    <C:address-data>
      <C:prop name="EMAIL"/>
    </C:address-data>
  </D:prop>
  <C:filter>
    <C:prop-filter name="UID">
      <C:text-match match-type="equals">urn:uuid:search-grouped</C:text-match>
    </C:prop-filter>
  </C:filter>
</C:addressbook-query>"#;

const PROPNAME_CARD_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:propname/>
  <C:filter>
    <C:prop-filter name="FN">
      <C:text-match>carl</C:text-match>
    </C:prop-filter>
  </C:filter>
</C:addressbook-query>"#;

const PROPNAME_CALENDAR_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:propname/>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VTODO">
        <C:prop-filter name="SUMMARY">
          <C:text-match>report</C:text-match>
        </C:prop-filter>
      </C:comp-filter>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>"#;

const CALENDAR_MULTIGET: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag/>
    <C:calendar-data/>
  </D:prop>
  <D:href>$HREF</D:href>
</C:calendar-multiget>"#;

const CARD_BATCH: &str = "BEGIN:VCARD
VERSION:4.0
UID:urn:uuid:search-batch-$NUMBER
FN:Batch Contact $NUMBER
TITLE:$PARITY
END:VCARD
";

const CARD_GROUPED: &str = "BEGIN:VCARD
VERSION:4.0
UID:urn:uuid:search-grouped
FN:Anna Grouped
N:Grouped;Anna;;;
NICKNAME:Nanna
item1.EMAIL;TYPE=work:anna@grouped.example
item1.X-ABLABEL:Office
EMAIL;TYPE=home:anna@home.example
END:VCARD
";

const CARD_ORG: &str = "BEGIN:VCARD
VERSION:4.0
UID:urn:uuid:search-org
KIND:org
FN:Acme Holdings
ORG:Acme Holdings
END:VCARD
";

const CARD_PERSON: &str = "BEGIN:VCARD
VERSION:4.0
UID:urn:uuid:search-person
FN:Carl Person
N:Person;Carl;;;
EMAIL;TYPE=work:carl@example.org
TEL;TYPE=cell:+1 555 0199
ADR;TYPE=work:;;1 Main St;Springfield;;;
END:VCARD
";

const EVENT_PLANNING: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Stalwart//Search Test//EN
BEGIN:VEVENT
UID:search-planning
DTSTAMP:20250101T000000Z
DTSTART:20250310T100000Z
DTEND:20250310T110000Z
SUMMARY:Quarterly planning
LOCATION:Room 7
ORGANIZER:mailto:cyrus@example.net
ATTENDEE;PARTSTAT=ACCEPTED:mailto:lisa@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com
END:VEVENT
END:VCALENDAR
";

const TODO_REPORT: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Stalwart//Search Test//EN
BEGIN:VTODO
UID:search-todo
DTSTAMP:20250101T000000Z
DUE:20250601T100000Z
COMPLETED:20250305T120000Z
STATUS:COMPLETED
SUMMARY:Send report
END:VTODO
END:VCALENDAR
";

const EVENT_LONG_UID: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Stalwart//Search Test//EN
BEGIN:VEVENT
UID:$UID
DTSTAMP:20250101T000000Z
DTSTART:20250401T100000Z
DTEND:20250401T110000Z
SUMMARY:Long identifier
END:VEVENT
END:VCALENDAR
";

const EVENT_REPEATING_ALARM: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Stalwart//Search Test//EN
BEGIN:VEVENT
UID:search-renewal
DTSTAMP:20250101T000000Z
DTSTART:20250710T100000Z
DTEND:20250710T110000Z
SUMMARY:Renewal
BEGIN:VALARM
ACTION:DISPLAY
DESCRIPTION:Renewal reminder
TRIGGER:-PT1H
REPEAT:3
DURATION:P2D
END:VALARM
END:VEVENT
END:VCALENDAR
";

const EVENT_INVITE: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Stalwart//Search Test//EN
BEGIN:VEVENT
UID:search-invite
DTSTAMP:20250101T000000Z
DTSTART:$START
DTEND:$END
SUMMARY:Inbox search review
ORGANIZER:mailto:john@example.com
ATTENDEE;PARTSTAT=ACCEPTED:mailto:john@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:jane@example.com
END:VEVENT
END:VCALENDAR
";
