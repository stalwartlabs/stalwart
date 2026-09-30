/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavKind, create_collection, files::PropertySet, home, item_name, put_item};
use crate::{
    jmap::metadata::{
        fixture::{Ctx, MetaType, Using, response_ids},
        performance::stored,
    },
    utils::{server::TestServer, webdav::DummyWebDavClient},
};
use hyper::StatusCode;
use serde_json::json;
use store::dispatch::StoreOps;

const ITEMS: usize = 8;
const RUNS: usize = 4;

const NAMED: &str = concat!(
    "<D:getetag/><D:getcontentlength/><D:getlastmodified/>",
    "<D:resourcetype/><D:displayname/>"
);

pub async fn test(test: &TestServer) {
    println!("Running WebDAV dead property performance guards...");
    let client = test.account("john@example.com").webdav_client();

    for kind in [DavKind::File, DavKind::Event, DavKind::Card] {
        guards(test, &client, kind).await;
    }
    for kind in [DavKind::Event, DavKind::Card] {
        archives_untouched(test, &client, kind).await;
    }

    super::cleanup(test, &[&client]).await;
}

fn clear_cache(test: &TestServer, kind: DavKind) {
    let cache = &test.server.inner.cache;
    match kind {
        DavKind::Event | DavKind::Calendar => cache.events.clear(),
        DavKind::Card | DavKind::AddressBook => cache.contacts.clear(),
        DavKind::File | DavKind::Folder => cache.files.clear(),
    }
}

async fn min_ops(
    test: &TestServer,
    client: &DummyWebDavClient,
    kind: DavKind,
    path: &str,
    body: &str,
    cold: bool,
) -> usize {
    test.wait_for_tasks().await;
    let mut lowest = usize::MAX;
    for _ in 0..RUNS {
        if cold {
            clear_cache(test, kind);
        }
        StoreOps::take();
        client.propfind_xml(path, "1", body).await;
        lowest = lowest.min(StoreOps::take().total());
    }
    lowest
}

struct Measures {
    cold: usize,
    named: usize,
    allprop: usize,
}

async fn measure(
    test: &TestServer,
    client: &DummyWebDavClient,
    kind: DavKind,
    collection: &str,
) -> Measures {
    let named = format!("<D:prop>{NAMED}</D:prop>");
    Measures {
        cold: min_ops(test, client, kind, collection, &named, true).await,
        named: min_ops(test, client, kind, collection, &named, false).await,
        allprop: min_ops(test, client, kind, collection, "<D:allprop/>", false).await,
    }
}

async fn guards(test: &TestServer, client: &DummyWebDavClient, kind: DavKind) {
    let collection = format!(
        "{}/meta-perf-{}/",
        home(kind, client.name),
        format!("{kind:?}").to_lowercase()
    );
    create_collection(client, kind, &collection).await;
    let mut items = Vec::with_capacity(ITEMS);
    for n in 0..ITEMS {
        let path = format!("{collection}{}", item_name(kind, &format!("perf{n}")));
        put_item(client, kind, &path, &format!("meta-perf-{kind:?}-{n}")).await;
        items.push(path);
    }

    let before = measure(test, client, kind, &collection).await;

    let set = PropertySet::windows();
    for path in &items {
        client
            .proppatch_xml(path, &set.set_body())
            .await
            .with_status(StatusCode::MULTI_STATUS);
    }

    let after = measure(test, client, kind, &collection).await;
    assert!(
        after.cold <= before.cold,
        "{kind:?}: a cache build read dead-property containers ({} reads, {} without dead properties)",
        after.cold,
        before.cold
    );
    assert!(
        after.named <= before.named,
        "{kind:?}: a PROPFIND without dead properties read containers ({} reads, {} without dead properties)",
        after.named,
        before.named
    );
    assert!(
        after.allprop > before.allprop && after.allprop <= before.allprop + 1,
        "{kind:?}: allprop must read the containers of flagged resources in one bulk call ({} reads, {} without dead properties)",
        after.allprop,
        before.allprop
    );

    client
        .request("DELETE", &collection, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

async fn archives_untouched(test: &TestServer, client: &DummyWebDavClient, kind: DavKind) {
    let owner = test.account("john@example.com");
    let ctx = Ctx::new(test);
    let ty = match kind {
        DavKind::Event => MetaType::CalendarEvent,
        _ => MetaType::ContactCard,
    };
    let uid = format!("meta-archive-{}", format!("{kind:?}").to_lowercase());
    let collection = format!("{}/{uid}/", home(kind, client.name));
    let path = format!("{collection}{}", item_name(kind, &uid));
    create_collection(client, kind, &collection).await;
    put_item(client, kind, &path, &uid).await;

    let ids = response_ids(
        &ctx.query(owner, owner, ty, json!({"uid": uid}), Using::Plain)
            .await,
    );
    let [id] = ids.as_slice() else {
        panic!("{kind:?} {uid} not found: {ids:?}")
    };

    let (_, content) = stored(test, owner, ty, id).await;
    assert!(content.is_some(), "{kind:?}: content archive missing");

    let set = PropertySet::windows();
    client
        .proppatch_xml(&path, &set.set_body())
        .await
        .with_status(StatusCode::MULTI_STATUS);
    let (main_flagged, content_flagged) = stored(test, owner, ty, id).await;
    assert_eq!(
        content, content_flagged,
        "{kind:?}: a dead-property PROPPATCH rewrote the content archive"
    );

    for body in [
        concat!(
            "<D:set><D:prop><M:extra xmlns:M=\"urn:example:archive\">more</M:extra>",
            "</D:prop></D:set>"
        ),
        concat!(
            "<D:remove><D:prop><M:extra xmlns:M=\"urn:example:archive\"/>",
            "</D:prop></D:remove>"
        ),
    ] {
        client
            .proppatch_xml(&path, body)
            .await
            .with_status(StatusCode::MULTI_STATUS);
        let (main, current) = stored(test, owner, ty, id).await;
        assert_eq!(
            current, content,
            "{kind:?}: a dead-property PROPPATCH rewrote the content archive"
        );
        assert_eq!(
            main, main_flagged,
            "{kind:?}: a PROPPATCH that kept dead-property presence rewrote the main archive"
        );
    }

    client
        .request("DELETE", &collection, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}
