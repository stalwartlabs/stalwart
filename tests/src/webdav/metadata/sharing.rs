/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavKind, create_collection, home};
use crate::utils::{dav_xml::XmlElement, server::TestServer, webdav::DummyWebDavClient};
use groupware::DavResourceName;
use hyper::StatusCode;

const NS: &str = "urn:example:sharing";

const HOSTILE_VALUES: [&str; 8] = [
    "<D:href xmlns:D=\"urn:evil\">rebinds D</D:href>",
    concat!(
        "<a0:x xmlns:a0=\"urn:one\" xmlns:q=\"urn:two\" q:attr=\"v\">",
        "<a1:y xmlns:a1=\"urn:three\" q:b=\"1\" xmlns:z=\"urn:four\" z:c=\"2\"/></a0:x>"
    ),
    "<x xmlns=\"urn:default\"><y xmlns=\"\"><z xmlns=\"urn:default\"/></y></x>",
    "]]&gt; &lt;/D:prop&gt; &amp;amp; <![CDATA[</D:multistatus>]]>",
    "<e a=\"&quot;&lt;&#10;&#9;&#13;&gt;'\" b='\"'>&#13;\n\t </e>",
    "<A:calendar-data xmlns:A=\"urn:other\" xmlns:B=\"urn:other2\" B:x=\"1\"/>",
    " \n ",
    "<!-- comment -->a<?pi data?>b",
];

pub async fn test(test: &TestServer) {
    println!("Running WebDAV dead property sharing tests...");
    let owner = test.account("john@example.com").webdav_client();
    let sharee = test.account("jane@example.com").webdav_client();

    hostile_values(&owner, &sharee).await;
    private_events(&owner, &sharee).await;

    super::cleanup(test, &[&owner, &sharee]).await;
}

fn principal(client: &DummyWebDavClient) -> String {
    format!(
        "{}/{}/",
        DavResourceName::Principal.base_path(),
        client.name.replace('@', "%40")
    )
}

fn set_mark(value: &str) -> String {
    format!("<D:set><D:prop><S:mark xmlns:S=\"{NS}\">{value}</S:mark></D:prop></D:set>")
}

async fn hostile_values(owner: &DummyWebDavClient, sharee: &DummyWebDavClient) {
    let folder = format!("{}/meta-hostile/", home(DavKind::Folder, owner.name));
    create_collection(owner, DavKind::Folder, &folder).await;
    owner
        .acl(&folder, principal(sharee).as_str(), ["read"])
        .await
        .with_status(StatusCode::OK);

    for (n, value) in HOSTILE_VALUES.into_iter().enumerate() {
        let name = format!("h{n}");
        owner
            .proppatch_xml(
                &folder,
                &format!(
                    concat!(
                        "<D:set><D:prop><S:{name} xmlns:S=\"{ns}\" xml:lang=\"de\" ",
                        "S:own=\"1\" plain=\"2\">{value}</S:{name}></D:prop></D:set>"
                    ),
                    name = name,
                    ns = NS,
                    value = value
                ),
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .xml_tree()
            .expect_property(&folder, NS, &name)
            .with_status(StatusCode::OK);
        let expected = XmlElement::parse(&format!(
            concat!(
                "<S:{name} xmlns:S=\"{ns}\" xmlns:D=\"DAV:\" xml:lang=\"de\" ",
                "S:own=\"1\" plain=\"2\">{value}</S:{name}>"
            ),
            name = name,
            ns = NS,
            value = value
        ));
        let named = format!("<S:{name} xmlns:S=\"{NS}\"/>");
        for (reader, label) in [(owner, "owner"), (sharee, "sharee")] {
            for (request, tree) in [
                ("allprop", reader.propfind_allprop(&folder, "0").await),
                ("named", reader.propfind_named(&folder, "0", &named).await),
            ] {
                tree.expect_property(&folder, NS, &name)
                    .element
                    .assert_equivalent(&expected, &format!("{label} {request} value {n}"));
            }
        }
    }

    owner
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

async fn private_events(owner: &DummyWebDavClient, sharee: &DummyWebDavClient) {
    let calendar = format!("{}/meta-privacy/", home(DavKind::Event, owner.name));
    create_collection(owner, DavKind::Event, &calendar).await;
    let mut events = Vec::new();
    for class in ["PUBLIC", "PRIVATE", "CONFIDENTIAL"] {
        let path = format!("{calendar}{}.ics", class.to_lowercase());
        owner
            .request_with_headers(
                "PUT",
                &path,
                [("content-type", "text/calendar; charset=utf-8")],
                format!(
                    concat!(
                        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Stalwart//Metadata//EN\r\n",
                        "BEGIN:VEVENT\r\nUID:meta-privacy-{class}\r\nSUMMARY:Privacy {class}\r\n",
                        "CLASS:{class}\r\nDTSTART:20240101T120000Z\r\nDTEND:20240101T130000Z\r\n",
                        "END:VEVENT\r\nEND:VCALENDAR\r\n"
                    ),
                    class = class
                ),
            )
            .await
            .with_status(StatusCode::CREATED);
        owner
            .proppatch_xml(&path, &set_mark(class))
            .await
            .with_status(StatusCode::MULTI_STATUS);
        events.push((class, path));
    }
    owner
        .proppatch_xml(&calendar, &set_mark("calendar"))
        .await
        .with_status(StatusCode::MULTI_STATUS);
    owner
        .acl(&calendar, principal(sharee).as_str(), ["read"])
        .await
        .with_status(StatusCode::OK);

    let named = format!("<S:mark xmlns:S=\"{NS}\"/>");
    for (request, tree) in [
        ("allprop", sharee.propfind_allprop(&calendar, "1").await),
        ("named", sharee.propfind_named(&calendar, "1", &named).await),
        ("propname", sharee.propfind_propname(&calendar, "1").await),
    ] {
        for (class, path) in &events {
            let visible = tree
                .property(path, NS, "mark")
                .is_some_and(|prop| prop.status.is_success());
            assert_eq!(
                visible,
                *class == "PUBLIC",
                "sharee {request}: dead property of the {class} event visible={visible}"
            );
        }
        assert!(
            tree.property(&calendar, NS, "mark")
                .is_some_and(|prop| prop.status.is_success()),
            "sharee {request}: the shared calendar's dead property must be visible"
        );
    }
    for (class, path) in &events {
        let status = sharee.proppatch_xml(path, &set_mark("sharee")).await.status;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
            "a read-only sharee PROPPATCH of the {class} event answered {status}"
        );
    }

    owner
        .request("DELETE", &calendar, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}
