/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Ctx, MetaType, Parents};
use crate::utils::{account::Account, server::TestServer, webdav::DummyWebDavClient};
use common::auth::AccessToken;
use email::{
    cache::MessageCacheFetch,
    mailbox::destroy::MailboxDestroy,
    message::{
        copy::EmailCopy,
        delete::EmailDeletion,
        ingest::{EmailIngest, IngestEmail, IngestSource},
    },
    sieve::delete::SieveScriptDelete,
};
use groupware::cache::GroupwareCache;
use hyper::StatusCode;
use mail_parser::MessageParser;
use serde_json::{Value, json};
use std::str::FromStr;
use store::{
    ValueKey,
    dispatch::StoreOps,
    roaring::RoaringBitmap,
    write::{
        BatchBuilder, Operation, ValueClass, ValueOp, metadata::MetadataClass, serialize::RawValue,
    },
};
use types::{
    collection::{Collection, SyncCollection},
    id::Id,
};

const DEAD_PROPERTY: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
    "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:X=\"urn:example:objects\">",
    "<D:set><D:prop><X:color>red</X:color></D:prop></D:set></D:propertyupdate>"
);

pub async fn test(test: &TestServer) {
    println!("Running object layer metadata guards...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let other = ctx.account("jane.smith@example.com");
    let parents = ctx.parents(owner).await;
    let other_parents = ctx.parents(other).await;

    email_paths(&ctx, owner, other, &parents, &other_parents).await;
    for ty in [
        MetaType::Email,
        MetaType::Mailbox,
        MetaType::SieveScript,
        MetaType::Calendar,
        MetaType::AddressBook,
        MetaType::FileNode,
    ] {
        presence_writes(&ctx, owner, &parents, ty).await;
    }
    for kind in [DavKind::File, DavKind::Calendar, DavKind::AddressBook] {
        dav_paths(&ctx, owner, other, kind).await;
    }

    ctx.cleanup(&[owner, other]).await;
}

async fn metadata_reads<T>(test: &TestServer, measure: impl AsyncFnOnce() -> T) -> (T, usize) {
    test.wait_for_tasks().await;
    StoreOps::take();
    let result = measure().await;
    (result, StoreOps::take().metadata)
}

fn document_id(id: &str) -> u32 {
    Id::from_str(id).expect("valid id").document_id()
}

async fn main_archive(test: &TestServer, owner: &Account, ty: MetaType, id: &str) -> Vec<u8> {
    let collection = match ty {
        MetaType::Email => Collection::Email,
        MetaType::Mailbox => Collection::Mailbox,
        MetaType::SieveScript => Collection::SieveScript,
        MetaType::Calendar => Collection::Calendar,
        MetaType::CalendarEvent => Collection::CalendarEvent,
        MetaType::AddressBook => Collection::AddressBook,
        MetaType::ContactCard => Collection::ContactCard,
        MetaType::FileNode => Collection::FileNode,
    };
    test.server
        .store()
        .get_value::<RawValue>(ValueKey::archive(
            owner.id().document_id(),
            collection,
            document_id(id),
        ))
        .await
        .expect("store read")
        .map(|value| value.0)
        .unwrap_or_else(|| panic!("{} {id} has no archive", ty.name()))
}

async fn presence_writes(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let test = ctx.test;
    let name = ty.name();
    let id = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    let plain = main_archive(test, owner, ty, &id).await;
    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/x.example": {"v": 1}}),
    )
    .await;
    let flagged = main_archive(test, owner, ty, &id).await;
    assert_ne!(
        plain, flagged,
        "{name}: the first namespace did not rewrite the presence flag"
    );
    for patch in [
        json!({"metadata/x.example/v": 2}),
        json!({"metadata/y.example": {"w": true}}),
        json!({"privateMetadata/p.example": {"v": 1}}),
        json!({"privateMetadata/p.example/v": 2}),
        json!({"metadata/y.example": null}),
    ] {
        ctx.update_ok(owner, owner, ty, &id, patch.clone()).await;
        assert_eq!(
            main_archive(test, owner, ty, &id).await,
            flagged,
            "{name}: {patch} rewrote the main archive although presence did not change"
        );
    }
    ctx.update_ok(owner, owner, ty, &id, json!({"metadata/x.example": null}))
        .await;
    assert_ne!(
        main_archive(test, owner, ty, &id).await,
        flagged,
        "{name}: removing the last namespace did not clear the presence flag"
    );
    ctx.destroy(owner, ty, &[&id]).await;
}

fn flag() -> Value {
    json!({"metadata": {"x.example": {"flag": true}}})
}

#[derive(Default, Debug, PartialEq, Eq)]
struct ContainerOps {
    asserts: usize,
    clears: usize,
    sets: usize,
    other: usize,
}

fn container_ops(batch: &BatchBuilder) -> ContainerOps {
    let mut ops = ContainerOps::default();
    for op in batch.ops() {
        match op {
            Operation::AssertValue {
                class: ValueClass::Metadata(MetadataClass::Shared),
                ..
            } => ops.asserts += 1,
            Operation::Value {
                class: ValueClass::Metadata(MetadataClass::Shared),
                op: ValueOp::Clear,
            } => ops.clears += 1,
            Operation::Value {
                class: ValueClass::Metadata(MetadataClass::Shared),
                op: ValueOp::Set(_),
            } => ops.sets += 1,
            Operation::AssertValue {
                class: ValueClass::Metadata(_),
                ..
            }
            | Operation::Value {
                class: ValueClass::Metadata(_),
                ..
            } => ops.other += 1,
            _ => {}
        }
    }
    ops
}

async fn email_paths(
    ctx: &Ctx<'_>,
    owner: &Account,
    other: &Account,
    parents: &Parents,
    other_parents: &Parents,
) {
    let test = ctx.test;
    let server = &test.server;
    let account_id = owner.id().document_id();
    let token = AccessToken::from_id_maybe_invalid(account_id);
    let inbox = document_id(&parents.mailboxes[0]);

    let mut plain = Vec::new();
    let mut flagged = Vec::new();
    for _ in 0..3 {
        plain.push(document_id(
            &ctx.create_ok(owner, MetaType::Email, parents, 0, json!({}))
                .await,
        ));
        flagged.push(document_id(
            &ctx.create_ok(owner, MetaType::Email, parents, 0, flag())
                .await,
        ));
    }

    let (_, reads) = metadata_reads(test, async || {
        let raw = b"From: guard@example.com\r\nSubject: guard\r\n\r\nguard\r\n";
        server
            .email_ingest(IngestEmail {
                raw_message: raw,
                message: MessageParser::new().parse(raw),
                blob_hash: None,
                access_token: &token,
                mailbox_ids: vec![inbox],
                keywords: vec![],
                received_at: None,
                source: IngestSource::Restore,
                metadata: None,
                session_id: 0,
            })
            .await
            .expect("ingest")
    })
    .await;
    assert_eq!(reads, 0, "ingest without metadata read metadata keys");

    let (_, reads) = metadata_reads(test, async || {
        server.inner.cache.messages.remove(&account_id);
        server.get_cached_messages(account_id).await.expect("cache")
    })
    .await;
    assert_eq!(reads, 0, "a message cache build read metadata keys");

    let (copied, reads) = metadata_reads(test, async || {
        server
            .copy_message(
                account_id,
                plain[0],
                other.id().document_id(),
                vec![document_id(&other_parents.mailboxes[0])],
                vec![],
                1_700_000_000,
                None,
                0,
            )
            .await
            .expect("copy")
    })
    .await;
    assert!(copied.is_ok(), "copy failed");
    assert_eq!(
        reads, 0,
        "copying a message without metadata read metadata keys"
    );

    for (ids, expected_reads, label) in
        [(&plain[1..], 0, "unflagged"), (&flagged[..2], 1, "flagged")]
    {
        let ids = ids.to_vec();
        let (batch, reads) = metadata_reads(test, async || {
            let mut batch = BatchBuilder::new();
            server
                .emails_delete(account_id, None, &mut batch, RoaringBitmap::from_iter(ids))
                .await
                .expect("delete");
            batch
        })
        .await;
        assert_eq!(
            reads, expected_reads,
            "deleting {label} messages read {reads} metadata keys"
        );
        let count = if expected_reads == 0 { 0 } else { 2 };
        assert_eq!(
            container_ops(&batch),
            ContainerOps {
                asserts: count,
                clears: count * 2,
                sets: 0,
                other: 0
            },
            "container operations when deleting {label} messages"
        );
        server.commit_batch(batch).await.expect("commit");
    }

    let plain_mailbox = ctx
        .create_ok(owner, MetaType::Mailbox, parents, 0, json!({}))
        .await;
    let flagged_mailbox = ctx
        .create_ok(owner, MetaType::Mailbox, parents, 0, flag())
        .await;
    let mixed_mailbox = ctx
        .create_ok(owner, MetaType::Mailbox, parents, 0, json!({}))
        .await;
    for (mailbox, with_flagged) in [(&plain_mailbox, false), (&mixed_mailbox, true)] {
        let scoped = Parents {
            mailboxes: [mailbox.clone(), mailbox.clone()],
            calendars: parents.calendars.clone(),
            address_books: parents.address_books.clone(),
            folders: parents.folders.clone(),
        };
        ctx.create_ok(owner, MetaType::Email, &scoped, 0, json!({}))
            .await;
        if with_flagged {
            ctx.create_ok(owner, MetaType::Email, &scoped, 0, flag())
                .await;
        }
    }
    for (mailbox, expected_reads, label) in [
        (
            &plain_mailbox,
            0,
            "an unflagged mailbox with unflagged messages",
        ),
        (
            &mixed_mailbox,
            1,
            "an unflagged mailbox with one flagged message",
        ),
        (&flagged_mailbox, 1, "an empty flagged mailbox"),
    ] {
        let (result, reads) = metadata_reads(test, async || {
            server
                .mailbox_destroy(account_id, document_id(mailbox), &token, true, None)
                .await
                .expect("destroy")
        })
        .await;
        assert!(result.is_ok(), "destroying {label} failed");
        assert_eq!(
            reads, expected_reads,
            "destroying {label} read {reads} metadata keys"
        );
    }

    let plain_script = ctx
        .create_ok(owner, MetaType::SieveScript, parents, 0, json!({}))
        .await;
    let flagged_script = ctx
        .create_ok(owner, MetaType::SieveScript, parents, 0, flag())
        .await;
    for (script, expected_reads) in [(&plain_script, 0), (&flagged_script, 1)] {
        let (batch, reads) = metadata_reads(test, async || {
            let mut batch = BatchBuilder::new();
            assert!(
                server
                    .sieve_script_delete(account_id, document_id(script), &token, &mut batch)
                    .await
                    .expect("delete")
            );
            batch
        })
        .await;
        assert_eq!(
            reads, expected_reads,
            "deleting a sieve script read {reads} metadata keys"
        );
        server.commit_batch(batch).await.expect("commit");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DavKind {
    File,
    Calendar,
    AddressBook,
}

impl DavKind {
    fn home(self, account: &Account) -> String {
        let root = match self {
            DavKind::File => "file",
            DavKind::Calendar => "cal",
            DavKind::AddressBook => "card",
        };
        format!("/dav/{root}/{}", account.name().replace('@', "%40"))
    }

    fn collection(self) -> SyncCollection {
        match self {
            DavKind::File => SyncCollection::FileNode,
            DavKind::Calendar => SyncCollection::Calendar,
            DavKind::AddressBook => SyncCollection::AddressBook,
        }
    }

    async fn create(self, client: &DummyWebDavClient, path: &str) {
        match self {
            DavKind::File => client.mkcol("MKCOL", path, [], []).await,
            DavKind::Calendar => client.request("MKCALENDAR", path, "").await,
            DavKind::AddressBook => {
                client
                    .mkcol("MKCOL", path, ["D:collection", "B:addressbook"], [])
                    .await
            }
        }
        .with_status(StatusCode::CREATED);
    }

    async fn put(self, client: &DummyWebDavClient, collection: &str, name: &str) -> String {
        let (path, body, content_type) = match self {
            DavKind::File => (
                format!("{collection}{name}.txt"),
                format!("guard {name}\n"),
                "text/plain",
            ),
            DavKind::Calendar => (
                format!("{collection}{name}.ics"),
                format!(
                    concat!(
                        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Stalwart//Guard//EN\r\n",
                        "BEGIN:VEVENT\r\nUID:{name}\r\nSUMMARY:{name}\r\n",
                        "DTSTART:20240101T120000Z\r\nDTEND:20240101T130000Z\r\n",
                        "END:VEVENT\r\nEND:VCALENDAR\r\n"
                    ),
                    name = name
                ),
                "text/calendar; charset=utf-8",
            ),
            DavKind::AddressBook => (
                format!("{collection}{name}.vcf"),
                format!("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{name}\r\nFN:{name}\r\nEND:VCARD\r\n"),
                "text/vcard; charset=utf-8",
            ),
        };
        client
            .request_with_headers("PUT", &path, [("content-type", content_type)], body)
            .await
            .with_status(StatusCode::CREATED);
        path
    }
}

async fn flag_dav(client: &DummyWebDavClient, path: &str) {
    client
        .request("PROPPATCH", path, DEAD_PROPERTY)
        .await
        .with_status(StatusCode::MULTI_STATUS);
}

async fn dav_paths(ctx: &Ctx<'_>, owner: &Account, other: &Account, kind: DavKind) {
    let test = ctx.test;
    let server = &test.server;
    let client = owner.webdav_client();
    let home = kind.home(owner);
    let account_id = owner.id().document_id();

    let mixed = format!("{home}/guard-mixed/");
    kind.create(&client, &mixed).await;
    let plain_item = kind.put(&client, &mixed, "plain").await;
    let flagged_item = kind.put(&client, &mixed, "flagged").await;
    kind.put(&client, &mixed, "kept").await;
    flag_dav(&client, &flagged_item).await;

    let plain = format!("{home}/guard-plain/");
    kind.create(&client, &plain).await;
    for name in ["a", "b", "c"] {
        kind.put(&client, &plain, name).await;
    }

    let flagged = format!("{home}/guard-flagged/");
    kind.create(&client, &flagged).await;
    kind.put(&client, &flagged, "child").await;
    flag_dav(&client, &flagged).await;

    for (caller, label) in [(account_id, "own"), (other.id().document_id(), "shared")] {
        let (_, reads) = metadata_reads(test, async || {
            match kind {
                DavKind::File => server.inner.cache.files.clear(),
                DavKind::Calendar => server.inner.cache.events.clear(),
                DavKind::AddressBook => server.inner.cache.contacts.clear(),
            }
            server
                .fetch_groupware_resources(caller, account_id, kind.collection())
                .await
                .expect("resources")
        })
        .await;
        assert_eq!(
            reads, 0,
            "{kind:?}: a {label} resource cache build read metadata keys"
        );
    }

    for (path, expected_reads, label) in [
        (
            &plain_item,
            Some(0),
            "an unflagged item next to a flagged one",
        ),
        (&flagged_item, None, "a flagged item"),
        (&plain, Some(0), "a collection of unflagged items"),
        (
            &flagged,
            Some(1),
            "a flagged collection with an unflagged item",
        ),
    ] {
        let (response, reads) =
            metadata_reads(test, async || client.request("DELETE", path, "").await).await;
        response.with_status(StatusCode::NO_CONTENT);
        match expected_reads {
            Some(expected) => assert_eq!(
                reads, expected,
                "{kind:?}: deleting {label} read {reads} metadata keys"
            ),
            None => assert!(
                reads > 0,
                "{kind:?}: deleting {label} did not read its container"
            ),
        }
    }

    client
        .request("DELETE", &mixed, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}
