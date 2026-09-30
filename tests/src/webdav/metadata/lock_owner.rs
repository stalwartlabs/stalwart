/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavKind, home};
use crate::utils::{
    dav_xml::{DAV_NS, XmlElement},
    server::TestServer,
    webdav::DummyWebDavClient,
};
use hyper::StatusCode;

const OWNERS: [&str; 3] = [
    "<D:href>http://example.com/~john/</D:href>",
    concat!(
        "<X:contact xmlns:X=\"urn:example:owner\" X:role=\"editor\">",
        "<D:href>mailto:john@example.com</D:href>",
        "<X:name>John &amp; Co</X:name>",
        "</X:contact>"
    ),
    "plain text owner",
];

pub async fn test(test: &TestServer) {
    println!("Running WebDAV lock owner tests...");
    let client = test.account("john@example.com").webdav_client();
    let folder = format!("{}/meta-locks/", home(DavKind::Folder, client.name));
    client
        .mkcol("MKCOL", &folder, [], [])
        .await
        .with_status(StatusCode::CREATED);

    for (n, owner) in OWNERS.iter().enumerate() {
        let path = format!("{folder}locked-{n}.txt");
        client
            .request("PUT", &path, "locked content")
            .await
            .with_status(StatusCode::CREATED);
        round_trip(&client, &path, owner).await;
    }

    client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    super::cleanup(test, &[&client]).await;
}

fn expected_owner(owner: &str) -> XmlElement {
    XmlElement::parse(&format!("<D:owner xmlns:D=\"DAV:\">{owner}</D:owner>"))
}

fn active_owner(prop: &XmlElement) -> &XmlElement {
    prop.child(DAV_NS, "lockdiscovery")
        .and_then(|discovery| discovery.child(DAV_NS, "activelock"))
        .and_then(|lock| lock.child(DAV_NS, "owner"))
        .unwrap_or_else(|| panic!("No lock owner in {prop}"))
}

async fn round_trip(client: &DummyWebDavClient, path: &str, owner: &str) {
    let response = client
        .request_with_headers(
            "LOCK",
            path,
            [("depth", "0"), ("timeout", "Second-300")],
            format!(
                concat!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                    "<D:lockinfo xmlns:D=\"DAV:\">",
                    "<D:lockscope><D:exclusive/></D:lockscope>",
                    "<D:locktype><D:write/></D:locktype>",
                    "<D:owner>{}</D:owner>",
                    "</D:lockinfo>"
                ),
                owner
            ),
        )
        .await
        .with_status(StatusCode::OK);
    let lock_token = response.lock_token().to_string();
    let expected = expected_owner(owner);
    active_owner(&response.xml_tree()).assert_equivalent(&expected, "LOCK response");

    let tree = client.propfind_named(path, "0", "<D:lockdiscovery/>").await;
    let prop = tree.expect_property(path, DAV_NS, "lockdiscovery");
    let owner_element = prop
        .element
        .child(DAV_NS, "activelock")
        .and_then(|lock| lock.child(DAV_NS, "owner"))
        .unwrap_or_else(|| panic!("No lock owner in {}", prop.element));
    owner_element.assert_equivalent(&expected, "lockdiscovery");

    client
        .unlock(path, &lock_token)
        .await
        .with_status(StatusCode::NO_CONTENT);
}
