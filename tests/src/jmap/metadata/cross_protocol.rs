/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    fixture::{Ctx, MetaType, Using, response_ids},
    performance::min_ops,
};
use crate::utils::{
    account::Account,
    imap::{AssertResult, ImapConnection, Type},
    server::TestServer,
    webdav::DummyWebDavClient,
};
use dav_proto::{
    Depth,
    schema::property::{DavProperty, WebDavProperty},
};
use hyper::StatusCode;
use imap_proto::ResponseType;
use serde_json::{Value, json};

const WINDOWS_PROPS: &str = concat!(
    "<D:set><D:prop>",
    "<Z:Win32CreationTime xmlns:Z=\"urn:schemas-microsoft-com:\">Mon, 01 Jan 2024 10:00:00 GMT</Z:Win32CreationTime>",
    "<Z:Win32FileAttributes xmlns:Z=\"urn:schemas-microsoft-com:\">00000020</Z:Win32FileAttributes>",
    "</D:prop></D:set>"
);

pub async fn test(test: &TestServer) {
    println!("Running cross-protocol metadata tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let client = owner.webdav_client();

    dav_entries_are_invisible_to_jmap(&ctx, owner, &client).await;
    jmap_writes_reach_dav_sync(&ctx, owner, &client).await;
    imap_entries_are_invisible_to_jmap(&ctx, owner).await;
    email_presence_moves_modseq(&ctx, owner).await;

    ctx.cleanup(&[owner]).await;
}

async fn node_id(ctx: &Ctx<'_>, owner: &Account, filter: Value) -> Vec<String> {
    response_ids(
        &ctx.query(owner, owner, MetaType::FileNode, filter, Using::Plain)
            .await,
    )
}

async fn dav_entries_are_invisible_to_jmap(
    ctx: &Ctx<'_>,
    owner: &Account,
    client: &DummyWebDavClient,
) {
    let folder = format!(
        "/dav/file/{}/meta-dav-only/",
        client.name.replace('@', "%40")
    );
    client
        .mkcol("MKCOL", &folder, [], [])
        .await
        .with_status(StatusCode::CREATED);
    let mut paths = Vec::new();
    for n in 0..4 {
        let path = format!("{folder}document-{n}.docx");
        client
            .request("PUT", &path, format!("document {n}"))
            .await
            .with_status(StatusCode::CREATED);
        paths.push(path);
    }

    let folder_ids = node_id(ctx, owner, json!({"name": "meta-dav-only"})).await;
    let [folder_id] = folder_ids.as_slice() else {
        panic!("folder not found: {folder_ids:?}")
    };
    let ids = node_id(ctx, owner, json!({"parentId": folder_id})).await;
    assert_eq!(ids.len(), paths.len());
    let ids = ids.iter().map(String::as_str).collect::<Vec<_>>();
    let selected = async || {
        ctx.get(
            owner,
            owner,
            MetaType::FileNode,
            &ids,
            Some(&["id", "metadata", "privateMetadata"]),
            Using::Metadata,
        )
        .await;
    };

    let before = min_ops(ctx.test, selected).await;
    for path in &paths {
        client
            .proppatch_xml(path, WINDOWS_PROPS)
            .await
            .with_status(StatusCode::MULTI_STATUS);
    }
    let after = min_ops(ctx.test, selected).await;
    assert!(
        after <= before,
        "JMAP /get read containers that only hold WebDAV entries ({after} reads, {before} before)"
    );
    for id in &ids {
        ctx.assert_metadata(owner, owner, MetaType::FileNode, id, json!({}), json!({}))
            .await;
    }

    ctx.update_ok(
        owner,
        owner,
        MetaType::FileNode,
        ids[0],
        json!({"metadata/x.example": {"jmap": true}}),
    )
    .await;
    let tree = client.propfind_allprop(&paths[0], "0").await;
    assert_eq!(
        tree.expect_property(
            &paths[0],
            "urn:schemas-microsoft-com:",
            "Win32FileAttributes"
        )
        .element
        .text(),
        "00000020",
        "a JMAP metadata write must keep the WebDAV entries of the same container"
    );
    assert!(
        !tree.to_string().contains("x.example"),
        "JMAP entries leaked into WebDAV: {tree}"
    );

    client
        .request("DELETE", &folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

async fn jmap_writes_reach_dav_sync(ctx: &Ctx<'_>, owner: &Account, client: &DummyWebDavClient) {
    let home = format!("/dav/cal/{}/", client.name.replace('@', "%40"));
    let calendar = format!("{home}meta-sync/");
    let event = format!("{calendar}meta-sync.ics");
    client
        .request("MKCALENDAR", &calendar, "")
        .await
        .with_status(StatusCode::CREATED);
    client
        .request_with_headers(
            "PUT",
            &event,
            [("content-type", "text/calendar; charset=utf-8")],
            concat!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Stalwart//Metadata//EN\r\n",
                "BEGIN:VEVENT\r\nUID:meta-sync-event\r\nSUMMARY:Sync\r\n",
                "DTSTART:20240101T120000Z\r\nDTEND:20240101T130000Z\r\n",
                "END:VEVENT\r\nEND:VCALENDAR\r\n"
            ),
        )
        .await
        .with_status(StatusCode::CREATED);

    let ids = response_ids(
        &ctx.query(
            owner,
            owner,
            MetaType::CalendarEvent,
            json!({"uid": "meta-sync-event"}),
            Using::Plain,
        )
        .await,
    );
    let [id] = ids.as_slice() else {
        panic!("event not found: {ids:?}")
    };

    let etag = client
        .propfind(&event, [DavProperty::WebDav(WebDavProperty::GetETag)])
        .await
        .properties(&event)
        .get(DavProperty::WebDav(WebDavProperty::GetETag))
        .value()
        .to_string();
    let token = client
        .sync_collection(&home, "", Depth::Infinity, None, ["D:getetag"])
        .await
        .sync_token()
        .to_string();

    ctx.update_ok(
        owner,
        owner,
        MetaType::CalendarEvent,
        id,
        json!({"metadata/x.example": {"from": "jmap"}}),
    )
    .await;

    let response = client
        .sync_collection(&home, &token, Depth::Infinity, None, ["D:getetag"])
        .await;
    assert!(
        response.hrefs().contains(&event.as_str()),
        "a JMAP metadata write must be reported by sync-collection: {:?}",
        response.hrefs()
    );
    client
        .request("GET", &event, "")
        .await
        .with_status(StatusCode::OK)
        .with_header("etag", &etag);

    let token = response.sync_token().to_string();
    ctx.update_ok(
        owner,
        owner,
        MetaType::CalendarEvent,
        id,
        json!({"privateMetadata/x.example": {"from": "jmap"}}),
    )
    .await;
    let response = client
        .sync_collection(&home, &token, Depth::Infinity, None, ["D:getetag"])
        .await;
    assert!(
        !response.hrefs().contains(&event.as_str()),
        "private metadata must not be reported by the shared WebDAV sync: {:?}",
        response.hrefs()
    );

    client
        .request("DELETE", &calendar, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

async fn imap_entries_are_invisible_to_jmap(ctx: &Ctx<'_>, owner: &Account) {
    let mailbox_name = ctx.unique(MetaType::Mailbox);
    let response = ctx
        .method(
            owner,
            Using::Metadata,
            "Mailbox/set",
            json!({
                "accountId": owner.id_string(),
                "create": {"m": {
                    "name": mailbox_name,
                    "metadata": {"x.example": {"jmap": "value"}}
                }}
            }),
        )
        .await;
    let id = response
        .pointer("/methodResponses/0/1/created/m/id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("Mailbox not created: {response:?}"))
        .to_string();

    let mut imap = owner.imap_client().await;
    imap.send(&format!(
        "SETMETADATA \"{mailbox_name}\" (/shared/comment \"imap comment\" /private/comment \"imap private\")"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send(&format!(
        "GETMETADATA \"{mailbox_name}\" (/shared/comment /private/comment)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("imap comment")
        .assert_not_contains("jmap");

    ctx.assert_metadata(
        owner,
        owner,
        MetaType::Mailbox,
        &id,
        json!({"x.example": {"jmap": "value"}}),
        json!({}),
    )
    .await;

    ctx.update_ok(
        owner,
        owner,
        MetaType::Mailbox,
        &id,
        json!({"metadata": {}}),
    )
    .await;
    imap.send(&format!("GETMETADATA \"{mailbox_name}\" /shared/comment"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("imap comment");

    imap.send("LOGOUT").await;
    imap.assert_read(Type::Untagged, ResponseType::Bye).await;
    ctx.destroy(owner, MetaType::Mailbox, &[&id]).await;
}

async fn changed_since(imap: &mut ImapConnection, modseq: &str) -> Vec<String> {
    imap.send(&format!("FETCH 1:* (FLAGS) (CHANGEDSINCE {modseq})"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await
}

fn flags(lines: &[String]) -> String {
    lines
        .iter()
        .find_map(|line| {
            line.split_once("FLAGS (")
                .and_then(|(_, flags)| flags.split_once(')'))
                .map(|(flags, _)| format!("FLAGS ({flags})"))
        })
        .unwrap_or_else(|| panic!("No FLAGS in {lines:?}"))
}

async fn email_presence_moves_modseq(ctx: &Ctx<'_>, owner: &Account) {
    let mailbox_name = ctx.unique(MetaType::Mailbox);
    let response = ctx
        .method(
            owner,
            Using::Plain,
            "Mailbox/set",
            json!({
                "accountId": owner.id_string(),
                "create": {"m": {"name": mailbox_name}}
            }),
        )
        .await;
    let mailbox = response
        .pointer("/methodResponses/0/1/created/m/id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("Mailbox not created: {response:?}"))
        .to_string();
    let response = ctx
        .method(
            owner,
            Using::Plain,
            "Email/set",
            json!({
                "accountId": owner.id_string(),
                "create": {"e": {
                    "mailboxIds": {mailbox.as_str(): true},
                    "subject": "modseq",
                    "from": [{"email": "metadata@example.com"}],
                    "bodyValues": {"1": {"value": "modseq"}},
                    "textBody": [{"partId": "1", "type": "text/plain"}]
                }}
            }),
        )
        .await;
    let email = response
        .pointer("/methodResponses/0/1/created/e/id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("Email not created: {response:?}"))
        .to_string();

    let mut imap = owner.imap_client().await;
    imap.send(&format!("SELECT \"{mailbox_name}\" (CONDSTORE)"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("FETCH 1 (FLAGS MODSEQ)").await;
    let lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let initial_flags = flags(&lines);
    let mut modseq = lines.into_modseq();

    for (patch, moves) in [
        (json!({"metadata/x.example": {"k": 1}}), true),
        (json!({"metadata/x.example/k": 2}), false),
        (json!({"metadata/y.example": {"a": 1}}), false),
        (json!({"privateMetadata/p.example": {"a": 1}}), false),
        (json!({"metadata/y.example": null}), false),
        (json!({"privateMetadata/p.example": null}), false),
        (json!({"metadata/x.example": null}), true),
        (json!({"privateMetadata/p.example": {"only": true}}), false),
    ] {
        ctx.update_ok(owner, owner, MetaType::Email, &email, patch.clone())
            .await;
        let lines = changed_since(&mut imap, &modseq).await;
        if moves {
            let lines = lines
                .assert_contains("* 1 FETCH")
                .assert_contains(&initial_flags);
            let new_modseq = lines.into_modseq();
            assert!(
                new_modseq.parse::<u64>().expect("numeric modseq")
                    > modseq.parse::<u64>().expect("numeric modseq"),
                "{patch}: MODSEQ must move when presence changes ({modseq} to {new_modseq})"
            );
            modseq = new_modseq;
        } else {
            lines.assert_not_contains("* 1 FETCH");
        }
    }

    imap.send("LOGOUT").await;
    imap.assert_read(Type::Untagged, ResponseType::Bye).await;
    ctx.destroy(owner, MetaType::Mailbox, &[&mailbox]).await;
}
