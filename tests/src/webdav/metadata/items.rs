/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavKind, DavResource, home, item_body};
use crate::utils::{server::TestServer, webdav::DummyWebDavClient};
use dav_proto::{
    Depth,
    schema::property::{DavProperty, WebDavProperty},
};
use hyper::StatusCode;
use std::time::Duration;

const NS_SYNC: &str = "urn:example:sync";

pub async fn test(test: &TestServer) {
    println!("Running WebDAV dead property item tests...");
    let client = test.account("john@example.com").webdav_client();

    for kind in [DavKind::Event, DavKind::Card, DavKind::File] {
        let resource = DavResource::create(
            &client,
            kind,
            &format!("meta-items-{kind:?}").to_lowercase(),
        )
        .await;
        untouched_by_proppatch(&client, &resource).await;
        resource.delete(&client).await;
    }
    for kind in [DavKind::Folder, DavKind::File] {
        let resource =
            DavResource::create(&client, kind, &format!("meta-name-{kind:?}").to_lowercase()).await;
        display_name(&client, &resource).await;
        resource.delete(&client).await;
    }

    super::cleanup(test, &[&client]).await;
}

pub async fn etag_and_last_modified(client: &DummyWebDavClient, path: &str) -> (String, String) {
    let response = client
        .propfind(
            path,
            [
                DavProperty::WebDav(WebDavProperty::GetETag),
                DavProperty::WebDav(WebDavProperty::GetLastModified),
            ],
        )
        .await;
    let properties = response.properties(path);
    (
        properties
            .get(DavProperty::WebDav(WebDavProperty::GetETag))
            .value()
            .to_string(),
        properties
            .get(DavProperty::WebDav(WebDavProperty::GetLastModified))
            .value()
            .to_string(),
    )
}

async fn sync_token(client: &DummyWebDavClient, kind: DavKind) -> String {
    client
        .sync_collection(
            &format!("{}/", home(kind, client.name)),
            "",
            Depth::Infinity,
            None,
            ["D:getetag"],
        )
        .await
        .sync_token()
        .to_string()
}

async fn assert_synced(client: &DummyWebDavClient, kind: DavKind, token: &str, path: &str) {
    let response = client
        .sync_collection(
            &format!("{}/", home(kind, client.name)),
            token,
            Depth::Infinity,
            None,
            ["D:getetag"],
        )
        .await;
    assert!(
        response.hrefs().contains(&path),
        "{kind:?}: sync-collection did not report the dead-property change of {path}: {:?}",
        response.hrefs()
    );
}

async fn marker(client: &DummyWebDavClient, path: &str) -> Option<String> {
    let tree = client
        .propfind_named(path, "0", "<S:marker xmlns:S=\"urn:example:sync\"/>")
        .await;
    tree.property(path, NS_SYNC, "marker")
        .filter(|prop| prop.status == StatusCode::OK)
        .map(|prop| prop.element.text())
}

async fn untouched_by_proppatch(client: &DummyWebDavClient, resource: &DavResource) {
    let kind = resource.kind;
    let path = resource.path.as_str();
    let (etag, modified) = etag_and_last_modified(client, path).await;
    let body = client
        .request("GET", path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    let token = sync_token(client, kind).await;

    tokio::time::sleep(Duration::from_millis(1100)).await;

    client
        .proppatch_xml(
            path,
            "<D:set><D:prop><S:marker xmlns:S=\"urn:example:sync\">one</S:marker></D:prop></D:set>",
        )
        .await
        .with_status(StatusCode::MULTI_STATUS);

    let (patched_etag, patched_modified) = etag_and_last_modified(client, path).await;
    assert_eq!(etag, patched_etag, "{kind:?}: PROPPATCH moved the ETag");
    assert_eq!(
        modified, patched_modified,
        "{kind:?}: PROPPATCH moved getlastmodified"
    );
    client
        .request("GET", path, "")
        .await
        .with_status(StatusCode::OK)
        .with_header("etag", &etag)
        .with_body(&body);
    assert_synced(client, kind, &token, path).await;
    assert_eq!(marker(client, path).await.as_deref(), Some("one"));

    let (new_body, content_type) = item_body(kind, &format!("{}-v2", path.len()));
    let new_body = match kind {
        DavKind::File => new_body,
        _ => body.replace("Metadata ", "Metadata v2 "),
    };
    client
        .request_with_headers(
            "PUT",
            path,
            [("content-type", content_type), ("if-match", etag.as_str())],
            new_body,
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    let (put_etag, put_modified) = etag_and_last_modified(client, path).await;
    assert_ne!(etag, put_etag, "{kind:?}: PUT did not move the ETag");
    assert_ne!(
        modified, put_modified,
        "{kind:?}: PUT did not move getlastmodified"
    );
    assert_eq!(
        marker(client, path).await.as_deref(),
        Some("one"),
        "{kind:?}: PUT must keep dead properties"
    );

    let token = sync_token(client, kind).await;
    client
        .proppatch_xml(
            path,
            "<D:remove><D:prop><S:marker xmlns:S=\"urn:example:sync\"/></D:prop></D:remove>",
        )
        .await
        .with_status(StatusCode::MULTI_STATUS);
    assert_synced(client, kind, &token, path).await;
    assert_eq!(marker(client, path).await, None);
    assert_eq!(
        etag_and_last_modified(client, path).await,
        (put_etag, put_modified),
        "{kind:?}: removing a dead property moved the ETag or getlastmodified"
    );
}

async fn display_name(client: &DummyWebDavClient, resource: &DavResource) {
    let kind = resource.kind;
    let path = resource.path.as_str();
    let displayname = async || {
        let response = client
            .propfind(path, [DavProperty::WebDav(WebDavProperty::DisplayName)])
            .await;
        let properties = response.properties(path);
        let prop = properties.get(DavProperty::WebDav(WebDavProperty::DisplayName));
        (
            prop.prop.status,
            prop.values.first().cloned().unwrap_or_default(),
        )
    };

    assert_eq!(
        displayname().await.0,
        StatusCode::NOT_FOUND,
        "{kind:?}: a node without a custom display name must answer 404"
    );
    client
        .patch_and_check(
            path,
            [(
                DavProperty::WebDav(WebDavProperty::DisplayName),
                "Custom display name",
            )],
        )
        .await;
    assert_eq!(
        displayname().await,
        (StatusCode::OK, "Custom display name".to_string())
    );
    let allprop = client.propfind_allprop(path, "0").await;
    assert_eq!(
        allprop
            .expect_property(path, "DAV:", "displayname")
            .element
            .text(),
        "Custom display name"
    );

    client
        .patch_and_check(
            path,
            [(DavProperty::WebDav(WebDavProperty::DisplayName), "")],
        )
        .await;
    assert_eq!(displayname().await.0, StatusCode::NOT_FOUND);
}
