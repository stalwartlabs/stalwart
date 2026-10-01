/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavKind, create_collection, files::PropertySet, home, item_name, put_item};
use crate::{
    jmap::metadata::{
        fixture::{Ctx, MetaType, Using, response_ids},
        performance::{min_ops, stored},
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

async fn min_propfind_ops(
    test: &TestServer,
    client: &DummyWebDavClient,
    kind: DavKind,
    path: &str,
    body: &str,
    cold: bool,
) -> usize {
    min_ops(test, async || {
        if cold {
            clear_cache(test, kind);
        }
        client.propfind_xml(path, "1", body).await;
    })
    .await
}

struct Measures {
    cold: usize,
    named: usize,
    allprop: usize,
    propname: usize,
    sync: usize,
    multiget: usize,
    proppatch: usize,
    copy: usize,
    delete: usize,
}

async fn min_request_ops(
    test: &TestServer,
    client: &DummyWebDavClient,
    method: &str,
    path: &str,
    headers: &[(&'static str, &str)],
    body: &str,
) -> usize {
    min_ops(test, async || {
        let status = client
            .request_with_headers(method, path, headers.iter().copied(), body)
            .await
            .status;
        assert!(status.is_success(), "{method} {path}: {status}");
    })
    .await
}

async fn copy_delete_ops(
    test: &TestServer,
    client: &DummyWebDavClient,
    source: &str,
    target: &str,
) -> (usize, usize) {
    let (mut copy, mut delete) = (usize::MAX, usize::MAX);
    for _ in 0..RUNS {
        test.wait_for_tasks().await;
        StoreOps::take();
        client
            .request_with_headers("COPY", source, [("destination", target)], "")
            .await
            .with_status(StatusCode::CREATED);
        copy = copy.min(StoreOps::take().total());
        test.wait_for_tasks().await;
        StoreOps::take();
        client
            .request("DELETE", target, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        delete = delete.min(StoreOps::take().total());
    }
    (copy, delete)
}

#[allow(clippy::too_many_arguments)]
async fn measure(
    test: &TestServer,
    client: &DummyWebDavClient,
    kind: DavKind,
    collection: &str,
    items: &[String],
    unflagged: &str,
    patched: &str,
    copy_target: &str,
) -> Measures {
    let named = format!("<D:prop>{NAMED}</D:prop>");
    let depth = [("depth", "1")];
    let sync = concat!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<D:sync-collection xmlns:D=\"DAV:\"><D:sync-token/>",
        "<D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"
    );
    let hrefs = items
        .iter()
        .map(|path| format!("<D:href>{path}</D:href>"))
        .collect::<String>();
    let multiget = match kind {
        DavKind::Event => Some(format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><C:calendar-multiget xmlns:D=\"DAV:\" ",
                "xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:prop><D:getetag/></D:prop>",
                "{}</C:calendar-multiget>"
            ),
            hrefs
        )),
        DavKind::Card => Some(format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><C:addressbook-multiget xmlns:D=\"DAV:\" ",
                "xmlns:C=\"urn:ietf:params:xml:ns:carddav\"><D:prop><D:getetag/></D:prop>",
                "{}</C:addressbook-multiget>"
            ),
            hrefs
        )),
        _ => None,
    };
    let proppatch = concat!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:propertyupdate xmlns:D=\"DAV:\">",
        "<D:set><D:prop><D:creationdate>2024-01-01T00:00:00Z</D:creationdate>",
        "</D:prop></D:set></D:propertyupdate>"
    );
    let (copy, delete) = copy_delete_ops(test, client, unflagged, copy_target).await;
    Measures {
        cold: min_propfind_ops(test, client, kind, collection, &named, true).await,
        named: min_propfind_ops(test, client, kind, collection, &named, false).await,
        allprop: min_propfind_ops(test, client, kind, collection, "<D:allprop/>", false).await,
        propname: min_propfind_ops(test, client, kind, collection, "<D:propname/>", false).await,
        sync: min_request_ops(test, client, "REPORT", collection, &depth, sync).await,
        multiget: match &multiget {
            Some(body) => min_request_ops(test, client, "REPORT", collection, &depth, body).await,
            None => 0,
        },
        proppatch: min_request_ops(test, client, "PROPPATCH", patched, &[], proppatch).await,
        copy,
        delete,
    }
}

async fn guards(test: &TestServer, client: &DummyWebDavClient, kind: DavKind) {
    let collection = format!(
        "{}/meta-perf-{}/",
        home(kind, client.name),
        format!("{kind:?}").to_lowercase()
    );
    create_collection(client, kind, &collection).await;
    let copies = format!(
        "{}/meta-perf-{}-copies/",
        home(kind, client.name),
        format!("{kind:?}").to_lowercase()
    );
    create_collection(client, kind, &copies).await;
    let copy_target = format!("{copies}{}", item_name(kind, "perf-copy"));
    let mut items = Vec::with_capacity(ITEMS);
    for n in 0..ITEMS {
        let path = format!("{collection}{}", item_name(kind, &format!("perf{n}")));
        put_item(client, kind, &path, &format!("meta-perf-{kind:?}-{n}")).await;
        items.push(path);
    }

    let before = measure(
        test,
        client,
        kind,
        &collection,
        &items,
        &items[0],
        &items[1],
        &copy_target,
    )
    .await;

    let set = PropertySet::windows();
    for path in items.iter().skip(1) {
        client
            .proppatch_xml(path, &set.set_body())
            .await
            .with_status(StatusCode::MULTI_STATUS);
    }
    if kind == DavKind::File {
        client
            .proppatch_xml(&collection, &set.set_body())
            .await
            .with_status(StatusCode::MULTI_STATUS);
    }

    let after = measure(
        test,
        client,
        kind,
        &collection,
        &items,
        &items[0],
        &items[1],
        &copy_target,
    )
    .await;
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
    for (label, flagged, plain) in [
        ("allprop", after.allprop, before.allprop),
        ("propname", after.propname, before.propname),
    ] {
        assert!(
            flagged > plain && flagged <= plain + 1,
            "{kind:?}: {label} must read the containers of flagged resources in one bulk call ({flagged} reads, {plain} without dead properties)"
        );
    }
    for (label, flagged, plain) in [
        ("sync-collection", after.sync, before.sync),
        ("multiget", after.multiget, before.multiget),
        (
            "PROPPATCH of a live property",
            after.proppatch,
            before.proppatch,
        ),
        ("COPY of an unflagged item", after.copy, before.copy),
        ("DELETE of an unflagged item", after.delete, before.delete),
    ] {
        assert!(
            flagged <= plain,
            "{kind:?}: {label} read dead-property containers ({flagged} reads, {plain} without dead properties)"
        );
    }

    for path in [&collection, &copies] {
        client
            .request("DELETE", path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
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
