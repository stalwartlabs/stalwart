/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavKind, home};
use crate::utils::{dav_xml::XmlElement, server::TestServer, webdav::DummyWebDavClient};
use encodify::base64::STANDARD;
use hyper::StatusCode;
use store::rand::{RngExt, rng};

pub const MICROSOFT_NS: &str = "urn:schemas-microsoft-com:";
pub const APPLE_NS: &str = "http://www.apple.com/webdav_fs/props/";

pub const WINDOWS_PROPERTIES: [(&str, &str); 4] = [
    ("Win32CreationTime", "Mon, 01 Jan 2024 10:00:00 GMT"),
    ("Win32LastAccessTime", "Tue, 02 Jan 2024 11:30:00 GMT"),
    ("Win32LastModifiedTime", "Tue, 02 Jan 2024 11:30:00 GMT"),
    ("Win32FileAttributes", "00000020"),
];

pub struct PropertySet {
    pub label: &'static str,
    pub namespace: &'static str,
    pub values: Vec<(&'static str, String)>,
}

impl PropertySet {
    pub fn windows() -> Self {
        PropertySet {
            label: "Windows Explorer",
            namespace: MICROSOFT_NS,
            values: WINDOWS_PROPERTIES
                .iter()
                .map(|(name, value)| (*name, value.to_string()))
                .collect(),
        }
    }

    pub fn macos() -> Self {
        let mut rng = rng();
        let header = (0..3000).map(|_| rng.random::<u8>()).collect::<Vec<_>>();
        PropertySet {
            label: "macOS Finder",
            namespace: APPLE_NS,
            values: vec![("appledoubleheader", STANDARD.encode(header))],
        }
    }

    pub fn set_body(&self) -> String {
        let mut body = String::from("<D:set><D:prop>");
        for (name, value) in &self.values {
            body.push_str(&format!(
                "<P:{name} xmlns:P=\"{}\">{value}</P:{name}>",
                self.namespace
            ));
        }
        body.push_str("</D:prop></D:set>");
        body
    }

    pub fn named_body(&self) -> String {
        self.values
            .iter()
            .map(|(name, _)| format!("<P:{name} xmlns:P=\"{}\"/>", self.namespace))
            .collect()
    }

    pub fn assert_in(&self, tree: &XmlElement, path: &str, context: &str) {
        for (name, value) in &self.values {
            let prop = tree.expect_property(path, self.namespace, name);
            prop.with_status(StatusCode::OK);
            assert_eq!(
                &prop.element.text(),
                value,
                "{} {context}: {name} changed",
                self.label
            );
        }
    }

    pub fn assert_absent(&self, tree: &XmlElement, path: &str) {
        for (name, _) in &self.values {
            tree.assert_property_absent(path, self.namespace, name);
        }
    }

    pub async fn assert_on(&self, client: &DummyWebDavClient, path: &str, context: &str) {
        let allprop = client.propfind_allprop(path, "0").await;
        self.assert_in(&allprop, path, &format!("{context} (allprop)"));
        let named = client.propfind_named(path, "0", &self.named_body()).await;
        self.assert_in(&named, path, &format!("{context} (named)"));
    }
}

pub async fn test(test: &TestServer) {
    println!("Running WebDAV file dead property tests...");
    let client = test.account("john@example.com").webdav_client();
    let folder = format!("{}/meta-files/", home(DavKind::Folder, client.name));
    client
        .mkcol("MKCOL", &folder, [], [])
        .await
        .with_status(StatusCode::CREATED);

    for set in [PropertySet::windows(), PropertySet::macos()] {
        lifecycle(&client, &folder, &set).await;
    }

    client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    super::cleanup(test, &[&client]).await;
}

async fn lifecycle(client: &DummyWebDavClient, folder: &str, set: &PropertySet) {
    let slug = set.label.replace(' ', "-").to_lowercase();
    let path = format!("{folder}{slug}.docx");
    let copy = format!("{folder}{slug}-copy.docx");
    let moved = format!("{folder}{slug}-moved.docx");

    client
        .request_with_headers(
            "PUT",
            &path,
            [("content-type", "application/octet-stream")],
            "first content",
        )
        .await
        .with_status(StatusCode::CREATED);
    let response = client
        .proppatch_xml(&path, &set.set_body())
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree();
    for (name, _) in &set.values {
        response
            .expect_property(&path, set.namespace, name)
            .with_status(StatusCode::OK);
    }
    set.assert_on(client, &path, "after PROPPATCH").await;

    let depth_one = client.propfind_allprop(folder, "1").await;
    set.assert_in(&depth_one, &path, "depth 1 allprop");

    client
        .request_with_headers("COPY", &path, [("destination", copy.as_str())], "")
        .await
        .with_status(StatusCode::CREATED);
    set.assert_on(client, &copy, "on the COPY destination")
        .await;
    set.assert_on(client, &path, "on the COPY source").await;

    client
        .request_with_headers("MOVE", &copy, [("destination", moved.as_str())], "")
        .await
        .with_status(StatusCode::CREATED);
    set.assert_on(client, &moved, "after MOVE").await;
    client
        .request("GET", &copy, "")
        .await
        .with_status(StatusCode::NOT_FOUND);

    client
        .request_with_headers(
            "PUT",
            &path,
            [("content-type", "application/octet-stream")],
            "second content, longer than the first one",
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    set.assert_on(client, &path, "after a PUT of new content")
        .await;

    client
        .request_with_headers(
            "COPY",
            &moved,
            [("destination", path.as_str()), ("overwrite", "T")],
            "",
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    set.assert_on(client, &path, "after an overwriting COPY")
        .await;

    for target in [&path, &moved] {
        client
            .request("DELETE", target, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    client
        .request_with_headers(
            "PUT",
            &path,
            [("content-type", "application/octet-stream")],
            "recreated",
        )
        .await
        .with_status(StatusCode::CREATED);
    let tree = client.propfind_allprop(&path, "0").await;
    set.assert_absent(&tree, &path);
    client
        .request("DELETE", &path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}
