/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavKind, DavResource, home};
use crate::utils::{
    dav_xml::{DAV_NS, XmlElement},
    server::TestServer,
    webdav::DummyWebDavClient,
};
use hyper::StatusCode;
use std::fmt::Write;
use store::rand::{RngExt, distr::Alphanumeric, rng};

const NS_LIMITS: &str = "urn:example:limits";

pub async fn test(test: &TestServer) {
    println!("Running WebDAV dead property limit tests...");
    let client = test.account("john@example.com").webdav_client();
    let limits = &test.server.core.metadata;

    for kind in DavKind::ALL {
        let resource = DavResource::create(
            &client,
            kind,
            &format!("meta-limits-{kind:?}").to_lowercase(),
        )
        .await;
        let path = resource.path.as_str();
        let displayname_before = displayname(&client, path).await;

        let oversized = format!(
            "<L:big xmlns:L=\"{NS_LIMITS}\">{}</L:big>",
            "b".repeat(limits.max_entry_size + 16)
        );
        let response = client
            .proppatch_xml(
                path,
                &format!(
                    concat!(
                        "<D:set><D:prop>",
                        "<D:displayname>must not be applied</D:displayname>",
                        "<L:small xmlns:L=\"{}\">ok</L:small>{}",
                        "</D:prop></D:set>"
                    ),
                    NS_LIMITS, oversized
                ),
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .xml_tree();
        response
            .expect_property(path, NS_LIMITS, "big")
            .with_status(StatusCode::INSUFFICIENT_STORAGE);
        for (namespace, name) in [(NS_LIMITS, "small"), (DAV_NS, "displayname")] {
            response
                .expect_property(path, namespace, name)
                .with_status(StatusCode::FAILED_DEPENDENCY);
        }
        assert_nothing_written(&client, path, &["small", "big"]).await;
        assert_eq!(
            displayname(&client, path).await,
            displayname_before,
            "{kind:?}: a failed PROPPATCH changed displayname"
        );

        let chunk = limits.max_entry_size / 2;
        let count = limits.max_size / chunk + 2;
        let mut properties = String::new();
        let mut names = Vec::with_capacity(count);
        for n in 0..count {
            let name = format!("chunk{n}");
            let _ = write!(
                properties,
                "<L:{name} xmlns:L=\"{NS_LIMITS}\">{}</L:{name}>",
                random_text(chunk)
            );
            names.push(name);
        }
        assert_all_failed(&client, path, &properties, &names, "container size").await;

        let mut properties = String::new();
        let mut names = Vec::with_capacity(limits.max_entries + 1);
        for n in 0..=limits.max_entries {
            let name = format!("entry{n}");
            let _ = write!(
                properties,
                "<L:{name} xmlns:L=\"{NS_LIMITS}\">{n}</L:{name}>"
            );
            names.push(name);
        }
        assert_all_failed(&client, path, &properties, &names, "entry count").await;

        resource.delete(&client).await;
    }

    let mike = test.account("mike@example.com").webdav_client();
    quota_exhaustion(&mike).await;
    super::cleanup(test, &[&client, &mike]).await;
}

async fn displayname(client: &DummyWebDavClient, path: &str) -> Option<String> {
    let tree = client.propfind_named(path, "0", "<D:displayname/>").await;
    tree.property(path, DAV_NS, "displayname")
        .filter(|prop| prop.status == StatusCode::OK)
        .map(|prop| prop.element.text())
}

async fn assert_nothing_written(client: &DummyWebDavClient, path: &str, names: &[&str]) {
    let tree = client.propfind_allprop(path, "0").await;
    for name in names {
        tree.assert_property_absent(path, NS_LIMITS, name);
    }
}

async fn assert_all_failed(
    client: &DummyWebDavClient,
    path: &str,
    properties: &str,
    names: &[String],
    limit: &str,
) {
    let response: XmlElement = client
        .proppatch_xml(
            path,
            &format!("<D:set><D:prop>{properties}</D:prop></D:set>"),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree();
    let mut insufficient = 0;
    for name in names {
        let prop = response.expect_property(path, NS_LIMITS, name);
        match prop.status {
            StatusCode::INSUFFICIENT_STORAGE => insufficient += 1,
            StatusCode::FAILED_DEPENDENCY => (),
            status => panic!("{limit}: property {name} got {status}, expected 507 or 424"),
        }
    }
    assert!(
        insufficient > 0,
        "{limit}: exceeding the limit must report 507 on at least one property"
    );
    let names = names.iter().map(String::as_str).collect::<Vec<_>>();
    assert_nothing_written(client, path, &names).await;
}

async fn quota_exhaustion(client: &DummyWebDavClient) {
    let path = format!("{}/meta-quota/", home(DavKind::Folder, client.name));
    client
        .mkcol("MKCOL", &path, [], [])
        .await
        .with_status(StatusCode::CREATED);

    let response = client
        .proppatch_xml(
            &path,
            &format!(
                "<D:set><D:prop><L:heavy xmlns:L=\"{NS_LIMITS}\">{}</L:heavy></D:prop></D:set>",
                random_text(4000)
            ),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS);
    let body = response.expect_body().to_string();
    let tree = response.xml_tree();
    tree.expect_property(&path, NS_LIMITS, "heavy")
        .with_status(StatusCode::INSUFFICIENT_STORAGE);
    assert!(
        body.contains("quota-not-exceeded"),
        "quota exhaustion must report DAV:quota-not-exceeded: {body}"
    );
    assert_nothing_written(client, &path, &["heavy"]).await;

    client
        .request("DELETE", &path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

fn random_text(len: usize) -> String {
    let mut rng = rng();
    (0..len).map(|_| rng.sample(Alphanumeric) as char).collect()
}
