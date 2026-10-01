/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavKind, create_collection, delete_defaults, home, item_name, put_item};
use crate::utils::{server::TestServer, webdav::DummyWebDavClient};
use dav_proto::schema::property::{DavProperty, WebDavProperty};
use hyper::StatusCode;

const NS: &str = "urn:example:transfer";
const GROUP: &str = "support@example.com";

pub async fn test(test: &TestServer) {
    println!("Running WebDAV dead property COPY and MOVE tests...");
    let john = test.account("john@example.com").webdav_client();
    let jane = test.account("jane@example.com").webdav_client();

    file_overwrites(&john).await;
    folder_copy_move(&jane).await;
    for kind in [DavKind::Event, DavKind::Card] {
        collection_copy_move(&jane, kind).await;
    }

    delete_defaults(&jane, GROUP).await;
    super::cleanup(test, &[&john, &jane]).await;
}

fn set(name: &str, value: &str) -> String {
    format!("<D:set><D:prop><R:{name} xmlns:R=\"{NS}\">{value}</R:{name}></D:prop></D:set>")
}

async fn value_of(client: &DummyWebDavClient, path: &str, name: &str) -> Option<String> {
    let tree = client
        .propfind_named(path, "0", &format!("<R:{name} xmlns:R=\"{NS}\"/>"))
        .await;
    tree.property(path, NS, name)
        .filter(|prop| prop.status == StatusCode::OK)
        .map(|prop| prop.element.text())
}

async fn used_bytes(client: &DummyWebDavClient, collection: &str) -> i64 {
    client
        .propfind(
            collection,
            [DavProperty::WebDav(WebDavProperty::QuotaUsedBytes)],
        )
        .await
        .properties(collection)
        .get(DavProperty::WebDav(WebDavProperty::QuotaUsedBytes))
        .value()
        .parse()
        .expect("numeric quota")
}

async fn put_file(client: &DummyWebDavClient, path: &str, content: &str) {
    let status = client
        .request_with_headers("PUT", path, [("content-type", "text/plain")], content)
        .await
        .status;
    assert!(status.is_success(), "PUT {path}: {status}");
}

async fn file_overwrites(client: &DummyWebDavClient) {
    let root = format!("{}/", home(DavKind::Folder, client.name));
    let folder = format!("{root}meta-overwrite/");
    create_collection(client, DavKind::Folder, &folder).await;
    let base = used_bytes(client, &root).await;

    for method in ["COPY", "MOVE"] {
        for (source_props, dest_props) in [(true, false), (false, true), (true, true)] {
            let context = format!("{method} overwrite source={source_props} dest={dest_props}");
            let source = format!("{folder}src.txt");
            let dest = format!("{folder}dst.txt");
            put_file(client, &source, "source content").await;
            put_file(client, &dest, "destination content").await;
            if source_props {
                client
                    .proppatch_xml(&source, &set("from", &"s".repeat(600)))
                    .await
                    .with_status(StatusCode::MULTI_STATUS);
            }
            if dest_props {
                client
                    .proppatch_xml(&dest, &set("to", &"d".repeat(900)))
                    .await
                    .with_status(StatusCode::MULTI_STATUS);
            }
            let (dest_etag, _) = super::items::etag_and_last_modified(client, &dest).await;

            let response = client
                .request_with_headers(method, &source, [("destination", dest.as_str())], "")
                .await;
            assert!(
                response.status == StatusCode::NO_CONTENT,
                "{}",
                format!("{context}: answered {}", response.status)
            );

            let from = value_of(client, &dest, "from").await;
            let to = value_of(client, &dest, "to").await;
            assert!(
                from.is_some() == source_props,
                "{}",
                format!("{context}: source property on destination is {from:?}")
            );
            assert!(
                to.is_none(),
                "{}",
                format!("{context}: the overwritten destination kept its own property {to:?}")
            );
            let (new_etag, _) = super::items::etag_and_last_modified(client, &dest).await;
            assert!(
                new_etag != dest_etag,
                "{}",
                format!("{context}: overwriting did not move the destination ETag")
            );
            if method == "COPY" {
                let source_after = value_of(client, &source, "from").await;
                assert!(
                    source_after.is_some() == source_props,
                    "{}",
                    format!("{context}: COPY changed the source property to {source_after:?}")
                );
                client
                    .request("DELETE", &source, "")
                    .await
                    .with_status(StatusCode::NO_CONTENT);
            }
            client
                .request("DELETE", &dest, "")
                .await
                .with_status(StatusCode::NO_CONTENT);
            let after = used_bytes(client, &root).await;
            assert!(
                after == base,
                "{}",
                format!("{context}: quota drifted by {} bytes", after - base)
            );
        }
    }

    client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

async fn folder_copy_move(client: &DummyWebDavClient) {
    let own_root = format!("{}/", home(DavKind::Folder, client.name));
    let group_root = format!("{}/", home(DavKind::Folder, GROUP));
    let own_base = used_bytes(client, &own_root).await;
    let group_base = used_bytes(client, &group_root).await;

    let tree = format!("{own_root}meta-tree-a/");
    create_collection(client, DavKind::Folder, &tree).await;
    create_collection(client, DavKind::Folder, &format!("{tree}sub/")).await;
    let members = [
        ("", true),
        ("a.txt", true),
        ("b.txt", false),
        ("sub/", true),
        ("sub/c.txt", true),
        ("sub/d.txt", false),
    ];
    for (member, flagged) in members {
        let path = format!("{tree}{member}");
        if !member.is_empty() && !member.ends_with('/') {
            put_file(client, &path, member).await;
        }
        if flagged {
            client
                .proppatch_xml(&path, &set("mark", &format!("{member}{}", "x".repeat(400))))
                .await
                .with_status(StatusCode::MULTI_STATUS);
        }
    }
    let charged = used_bytes(client, &own_root).await - own_base;

    let assert_members = async |root: &str, context: &str| {
        for (member, flagged) in members {
            let path = format!("{root}{member}");
            let found = value_of(client, &path, "mark").await;
            let expected = flagged.then(|| format!("{member}{}", "x".repeat(400)));
            assert!(
                found == expected,
                "{}",
                format!(
                    "{context}: {path} has mark {:?}",
                    found.as_ref().map(|value| value.len())
                )
            );
        }
    };

    let copy = format!("{own_root}meta-tree-b/");
    client
        .request_with_headers(
            "COPY",
            &tree,
            [("destination", copy.as_str()), ("depth", "infinity")],
            "",
        )
        .await
        .with_status(StatusCode::CREATED);
    assert_members(&copy, "same-account folder COPY").await;
    assert_members(&tree, "same-account folder COPY source").await;
    let after_copy = used_bytes(client, &own_root).await - own_base;
    assert!(
        after_copy == charged * 2,
        "{}",
        format!(
            "same-account folder COPY charged {after_copy}, expected {}",
            charged * 2
        )
    );

    let moved = format!("{group_root}meta-tree-c/");
    client
        .request_with_headers("MOVE", &copy, [("destination", moved.as_str())], "")
        .await
        .with_status(StatusCode::CREATED);
    assert_members(&moved, "cross-account folder MOVE").await;
    let own_after = used_bytes(client, &own_root).await - own_base;
    let group_after = used_bytes(client, &group_root).await - group_base;
    assert!(
        own_after == charged,
        "{}",
        format!(
            "cross-account folder MOVE left {own_after} bytes on the source account, expected {charged}"
        )
    );
    assert!(
        group_after == charged,
        "{}",
        format!(
            "cross-account folder MOVE charged {group_after} bytes to the destination, expected {charged}"
        )
    );

    let overwritten = format!("{own_root}meta-tree-d/");
    create_collection(client, DavKind::Folder, &overwritten).await;
    put_file(client, &format!("{overwritten}old.txt"), "old").await;
    client
        .proppatch_xml(
            &format!("{overwritten}old.txt"),
            &set("old", &"o".repeat(700)),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS);
    client
        .proppatch_xml(&overwritten, &set("old", &"o".repeat(700)))
        .await
        .with_status(StatusCode::MULTI_STATUS);
    client
        .request_with_headers(
            "MOVE",
            &moved,
            [("destination", overwritten.as_str()), ("overwrite", "T")],
            "",
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_members(&overwritten, "cross-account folder MOVE with overwrite").await;
    let stale = value_of(client, &overwritten, "old").await;
    assert!(
        stale.is_none(),
        "{}",
        "folder MOVE with overwrite kept the destination's dead property".to_string()
    );
    let group_after = used_bytes(client, &group_root).await - group_base;
    assert!(
        group_after == 0,
        "{}",
        format!("folder MOVE back left {group_after} bytes on the group account")
    );

    for path in [&tree, &overwritten] {
        client
            .request("DELETE", path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    let own_after = used_bytes(client, &own_root).await - own_base;
    assert!(
        own_after == 0,
        "{}",
        format!("folder DELETE with flagged members left {own_after} bytes of quota")
    );
}

async fn collection_copy_move(client: &DummyWebDavClient, kind: DavKind) {
    let own_home = home(kind, client.name);
    let group_home = home(kind, GROUP);
    let source = format!("{own_home}/meta-col/");
    create_collection(client, kind, &source).await;
    let flagged = format!("{source}{}", item_name(kind, "flagged"));
    let plain = format!("{source}{}", item_name(kind, "plain"));
    put_item(client, kind, &flagged, &format!("meta-{kind:?}-flagged")).await;
    put_item(client, kind, &plain, &format!("meta-{kind:?}-plain")).await;
    client
        .proppatch_xml(&flagged, &set("mark", "item"))
        .await
        .with_status(StatusCode::MULTI_STATUS);
    client
        .proppatch_xml(&source, &set("mark", "collection"))
        .await
        .with_status(StatusCode::MULTI_STATUS);

    let check = async |root: &str, context: &str| {
        for (path, expected) in [
            (root.to_string(), Some("collection")),
            (
                format!("{root}{}", item_name(kind, "flagged")),
                Some("item"),
            ),
            (format!("{root}{}", item_name(kind, "plain")), None),
        ] {
            let found = value_of(client, &path, "mark").await;
            assert!(
                found.as_deref() == expected,
                "{}",
                format!("{kind:?} {context}: {path} has mark {found:?}, expected {expected:?}")
            );
        }
    };

    let copy = format!("{group_home}/meta-col-copy/");
    client
        .request_with_headers(
            "COPY",
            &source,
            [("destination", copy.as_str()), ("depth", "infinity")],
            "",
        )
        .await
        .with_status(StatusCode::CREATED);
    check(&copy, "cross-account collection COPY").await;
    check(&source, "cross-account collection COPY source").await;

    let existing = format!("{own_home}/meta-col-existing/");
    create_collection(client, kind, &existing).await;
    let old = format!("{existing}{}", item_name(kind, "old"));
    put_item(client, kind, &old, &format!("meta-{kind:?}-old")).await;
    for path in [&existing, &old] {
        client
            .proppatch_xml(path, &set("old", "old"))
            .await
            .with_status(StatusCode::MULTI_STATUS);
    }
    let response = client
        .request_with_headers(
            "MOVE",
            &copy,
            [("destination", existing.as_str()), ("overwrite", "T")],
            "",
        )
        .await;
    assert!(
        response.status == StatusCode::NO_CONTENT,
        "{}",
        format!(
            "{kind:?} cross-account collection MOVE with overwrite answered {}",
            response.status
        )
    );
    if response.status == StatusCode::NO_CONTENT {
        check(&existing, "cross-account collection MOVE with overwrite").await;
        let stale = value_of(client, &existing, "old").await;
        assert!(
            stale.is_none(),
            "{}",
            format!("{kind:?} collection MOVE with overwrite kept the destination's dead property")
        );
        client
            .request("GET", &copy, "")
            .await
            .with_status(StatusCode::NOT_FOUND);
    } else {
        client.request("DELETE", &copy, "").await;
    }

    let renamed = format!("{own_home}/meta-col-renamed/");
    client
        .request_with_headers("MOVE", &source, [("destination", renamed.as_str())], "")
        .await
        .with_status(StatusCode::CREATED);
    check(&renamed, "same-account collection MOVE").await;

    for path in [&renamed, &existing] {
        client
            .request("DELETE", path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
}
