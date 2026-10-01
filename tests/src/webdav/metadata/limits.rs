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
use registry::schema::{prelude::Property, structs::Metadata};
use std::{
    fmt::Write,
    time::{Duration, Instant},
};
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

    many_properties(&client).await;
    over_limit_container(test, &client).await;

    let mike = test.account("mike@example.com").webdav_client();
    quota_exhaustion(&mike).await;
    move_overwrite_at_quota(&mike).await;
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

async fn move_overwrite_at_quota(client: &DummyWebDavClient) {
    let root = format!("{}/", home(DavKind::Folder, client.name));
    let folder = format!("{root}meta-quota-move/");
    client
        .mkcol("MKCOL", &folder, [], [])
        .await
        .with_status(StatusCode::CREATED);
    let source = format!("{folder}source.txt");
    let target = format!("{folder}target.txt");
    for (path, content) in [(&source, "s"), (&target, "t")] {
        client
            .request_with_headers("PUT", path, [("content-type", "text/plain")], content)
            .await
            .with_status(StatusCode::CREATED);
    }
    client
        .proppatch_xml(
            &source,
            &format!(
                "<D:set><D:prop><L:mark xmlns:L=\"{NS_LIMITS}\">{}</L:mark></D:prop></D:set>",
                random_text(300)
            ),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS);

    let filler = format!("{folder}filler.txt");
    let mut size = client.available_quota(&root).await as usize;
    while size > 0 {
        let response = client
            .request_with_headers(
                "PUT",
                &filler,
                [("content-type", "text/plain")],
                "f".repeat(size),
            )
            .await;
        if response.status.is_success() {
            break;
        }
        assert_eq!(
            response.status,
            StatusCode::INSUFFICIENT_STORAGE,
            "a PUT over quota must answer 507 (RFC 4331 section 6)"
        );
        size -= size.min(16);
    }
    assert!(
        client.available_quota(&root).await < 300,
        "the quota filler did not fill the quota"
    );

    client
        .request_with_headers("MOVE", &source, [("destination", target.as_str())], "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    let tree = client
        .propfind_named(&target, "0", &format!("<L:mark xmlns:L=\"{NS_LIMITS}\"/>"))
        .await;
    tree.expect_property(&target, NS_LIMITS, "mark")
        .with_status(StatusCode::OK);

    client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

async fn timed_proppatch(
    client: &DummyWebDavClient,
    path: &str,
    body: String,
) -> (StatusCode, f64) {
    let start = Instant::now();
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(900))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("http client")
        .request(
            reqwest::Method::from_bytes(b"PROPPATCH").expect("method"),
            format!("https://127.0.0.1:8899{path}"),
        )
        .header("authorization", client.credentials.as_str())
        .body(body)
        .send()
        .await
        .expect("PROPPATCH response");
    let status = response.status();
    let _ = response.bytes().await;
    (status, start.elapsed().as_secs_f64())
}

fn many_body(count: usize, descending: bool, removes: bool) -> String {
    let mut body = String::with_capacity(count * 32 + 256);
    body.push_str(concat!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:L=\"urn:example:limits\">",
        "<D:set><D:prop>"
    ));
    for n in 0..count {
        let n = if descending { count - n } else { n };
        let _ = write!(body, "<L:p{n:08}/>");
    }
    body.push_str("</D:prop></D:set>");
    if removes {
        body.push_str("<D:remove><D:prop>");
        for n in 0..count {
            let _ = write!(body, "<L:q{n:08}/>");
        }
        body.push_str("</D:prop></D:remove>");
    }
    body.push_str("</D:propertyupdate>");
    body
}

async fn many_properties(client: &DummyWebDavClient) {
    const COUNT: usize = 100_000;
    let folder = format!("{}/meta-many/", home(DavKind::Folder, client.name));
    client
        .mkcol("MKCOL", &folder, [], [])
        .await
        .with_status(StatusCode::CREATED);

    for removes in [false, true] {
        let mut elapsed = [0.0; 2];
        for (descending, seconds) in [false, true].into_iter().zip(elapsed.iter_mut()) {
            let (status, taken) =
                timed_proppatch(client, &folder, many_body(COUNT, descending, removes)).await;
            assert_eq!(status, StatusCode::MULTI_STATUS);
            *seconds = taken;
        }
        let [ascending, descending] = elapsed;
        assert!(
            descending < ascending * 3.0 + 2.0,
            "a PROPPATCH with {COUNT} properties in descending order (removes: {removes}) took {descending:.2}s against {ascending:.2}s ascending"
        );
        assert!(
            dead_names(client, &folder).await.is_empty(),
            "a PROPPATCH over the entry limit (removes: {removes}) stored properties"
        );
    }

    client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

async fn set_max_entries(test: &TestServer, max_entries: u64) {
    let admin = test.account("admin@example.com");
    admin
        .registry_update_setting(
            Metadata {
                max_entries,
                ..Default::default()
            },
            &[Property::MaxEntries],
        )
        .await;
    admin.reload_settings().await;
}

fn set_body(names: &[&str]) -> String {
    let mut body = String::from("<D:set><D:prop>");
    for name in names {
        let _ = write!(body, "<L:{name} xmlns:L=\"{NS_LIMITS}\">{name}</L:{name}>");
    }
    body.push_str("</D:prop></D:set>");
    body
}

fn remove_body(names: &[&str]) -> String {
    let mut body = String::from("<D:remove><D:prop>");
    for name in names {
        let _ = write!(body, "<L:{name} xmlns:L=\"{NS_LIMITS}\"/>");
    }
    body.push_str("</D:prop></D:remove>");
    body
}

async fn dead_names(client: &DummyWebDavClient, path: &str) -> Vec<String> {
    let tree = client.propfind_propname(path, "0").await;
    let mut names = tree
        .props(path)
        .filter(|prop| prop.element.namespace.as_deref() == Some(NS_LIMITS))
        .map(|prop| prop.element.name.clone())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

async fn over_limit_container(test: &TestServer, client: &DummyWebDavClient) {
    let folder = format!("{}/meta-over-limit/", home(DavKind::Folder, client.name));
    client
        .mkcol("MKCOL", &folder, [], [])
        .await
        .with_status(StatusCode::CREATED);
    client
        .proppatch_xml(
            &folder,
            &set_body(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"]),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS);

    set_max_entries(test, 10).await;

    for (body, expected) in [
        (set_body(&["c"]), StatusCode::OK),
        (
            format!("{}{}", remove_body(&["a"]), set_body(&["m"])),
            StatusCode::OK,
        ),
    ] {
        let response = client
            .proppatch_xml(&folder, &body)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .xml_tree();
        for prop in response.props(&folder) {
            assert!(
                prop.status == expected,
                "an edit that keeps an over-limit container at its size must succeed: {response}"
            );
        }
    }
    let kept = ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m"];
    assert_eq!(dead_names(client, &folder).await, kept);

    let response = client
        .proppatch_xml(&folder, &set_body(&["b", "n", "o"]))
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree();
    response
        .expect_property(&folder, NS_LIMITS, "n")
        .with_status(StatusCode::INSUFFICIENT_STORAGE);
    for name in ["b", "o"] {
        response
            .expect_property(&folder, NS_LIMITS, name)
            .with_status(if name == "o" {
                StatusCode::INSUFFICIENT_STORAGE
            } else {
                StatusCode::FAILED_DEPENDENCY
            });
    }
    assert_eq!(dead_names(client, &folder).await, kept);

    at_limit_container(client).await;

    set_max_entries(test, Metadata::default().max_entries).await;
    client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

async fn at_limit_container(client: &DummyWebDavClient) {
    let folder = format!("{}/meta-at-limit/", home(DavKind::Folder, client.name));
    client
        .mkcol("MKCOL", &folder, [], [])
        .await
        .with_status(StatusCode::CREATED);
    client
        .proppatch_xml(
            &folder,
            &set_body(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree()
        .expect_property(&folder, NS_LIMITS, "j")
        .with_status(StatusCode::OK);

    let response = client
        .proppatch_xml(
            &folder,
            &format!("{}{}", set_body(&["k"]), remove_body(&["a"])),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree();
    for name in ["k", "a"] {
        response
            .expect_property(&folder, NS_LIMITS, name)
            .with_status(StatusCode::OK);
    }
    let kept = ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k"];
    assert_eq!(dead_names(client, &folder).await, kept);

    let response = client
        .proppatch_xml(
            &folder,
            &format!("{}{}", set_body(&["l", "m"]), remove_body(&["b"])),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree();
    for (name, status) in [
        ("l", StatusCode::FAILED_DEPENDENCY),
        ("m", StatusCode::INSUFFICIENT_STORAGE),
        ("b", StatusCode::FAILED_DEPENDENCY),
    ] {
        response
            .expect_property(&folder, NS_LIMITS, name)
            .with_status(status);
    }
    assert_eq!(dead_names(client, &folder).await, kept);

    client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}
