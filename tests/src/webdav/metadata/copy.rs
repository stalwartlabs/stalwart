/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    DavKind, create_collection, delete_defaults, files::PropertySet, home, item_name, put_item,
};
use crate::utils::{server::TestServer, webdav::DummyWebDavClient};
use dav_proto::schema::property::{DavProperty, WebDavProperty};
use hyper::StatusCode;

const GROUP: &str = "support@example.com";

pub async fn test(test: &TestServer) {
    println!("Running WebDAV cross-account dead property COPY tests...");
    let client = test.account("jane@example.com").webdav_client();

    for kind in [DavKind::File, DavKind::Event, DavKind::Card] {
        cross_account(&client, kind).await;
    }

    delete_defaults(&client, GROUP).await;
    super::cleanup(test, &[&client]).await;
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

async fn delete_freed(client: &DummyWebDavClient, path: &str, collection: &str) -> i64 {
    let before = used_bytes(client, collection).await;
    client
        .request("DELETE", path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    before - used_bytes(client, collection).await
}

async fn cross_account(client: &DummyWebDavClient, kind: DavKind) {
    let source_collection = format!("{}/meta-copy-src/", home(kind, client.name));
    let target_collection = format!("{}/meta-copy-dst/", home(kind, GROUP));
    create_collection(client, kind, &source_collection).await;
    create_collection(client, kind, &target_collection).await;

    let annotated = format!("{source_collection}{}", item_name(kind, "annotated"));
    let plain = format!("{source_collection}{}", item_name(kind, "plainitem"));
    put_item(client, kind, &annotated, "meta-copy-annotated").await;
    put_item(client, kind, &plain, "meta-copy-plainitem").await;

    let set = PropertySet::macos();
    client
        .proppatch_xml(&annotated, &set.set_body())
        .await
        .with_status(StatusCode::MULTI_STATUS);

    let before = used_bytes(client, &target_collection).await;
    let plain_target = format!("{target_collection}{}", item_name(kind, "plainitem"));
    client
        .request_with_headers("COPY", &plain, [("destination", plain_target.as_str())], "")
        .await
        .with_status(StatusCode::CREATED);
    let plain_delta = used_bytes(client, &target_collection).await - before;

    let before = used_bytes(client, &target_collection).await;
    let annotated_target = format!("{target_collection}{}", item_name(kind, "annotated"));
    client
        .request_with_headers(
            "COPY",
            &annotated,
            [("destination", annotated_target.as_str())],
            "",
        )
        .await
        .with_status(StatusCode::CREATED);
    let annotated_delta = used_bytes(client, &target_collection).await - before;
    assert!(
        annotated_delta > plain_delta + 1000,
        "{kind:?}: copying dead properties must charge the destination ({annotated_delta} bytes with, {plain_delta} without)"
    );

    set.assert_on(
        client,
        &annotated_target,
        "on the cross-account COPY destination",
    )
    .await;
    set.assert_on(client, &annotated, "on the cross-account COPY source")
        .await;

    let freed = delete_freed(client, &annotated_target, &target_collection).await;
    let plain_freed = delete_freed(client, &plain_target, &target_collection).await;
    assert!(
        freed - plain_freed >= annotated_delta - plain_delta,
        "{kind:?}: DELETE must return the dead-property bytes ({freed} freed with, {plain_freed} without; {annotated_delta} charged with, {plain_delta} without)"
    );

    for collection in [&source_collection, &target_collection] {
        client
            .request("DELETE", collection, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
}
