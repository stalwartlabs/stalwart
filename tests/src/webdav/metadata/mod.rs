/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{server::TestServer, webdav::DummyWebDavClient};
use hyper::StatusCode;

pub mod copy;
pub mod dead_props;
pub mod files;
pub mod items;
pub mod limits;
pub mod lock_owner;
pub mod performance;

pub async fn test(test: &TestServer) {
    let only = std::env::var("DAV_METADATA_TESTS").ok();
    let enabled = |group: &str| {
        only.as_deref()
            .is_none_or(|groups| groups.split(',').any(|g| g.trim() == group))
    };

    if enabled("dead_props") {
        dead_props::test(test).await;
    }
    if enabled("limits") {
        limits::test(test).await;
    }
    if enabled("items") {
        items::test(test).await;
    }
    if enabled("files") {
        files::test(test).await;
    }
    if enabled("copy") {
        copy::test(test).await;
    }
    if enabled("lock_owner") {
        lock_owner::test(test).await;
    }
    if enabled("performance") {
        performance::test(test).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavKind {
    Calendar,
    Event,
    AddressBook,
    Card,
    Folder,
    File,
}

impl DavKind {
    pub const ALL: [DavKind; 6] = [
        DavKind::Calendar,
        DavKind::Event,
        DavKind::AddressBook,
        DavKind::Card,
        DavKind::Folder,
        DavKind::File,
    ];

    pub fn is_collection(self) -> bool {
        matches!(
            self,
            DavKind::Calendar | DavKind::AddressBook | DavKind::Folder
        )
    }

    pub fn collection(self) -> DavKind {
        match self {
            DavKind::Event => DavKind::Calendar,
            DavKind::Card => DavKind::AddressBook,
            DavKind::File => DavKind::Folder,
            other => other,
        }
    }

    fn home(self) -> &'static str {
        match self.collection() {
            DavKind::Calendar => "cal",
            DavKind::AddressBook => "card",
            _ => "file",
        }
    }
}

pub async fn cleanup(test: &TestServer, clients: &[&DummyWebDavClient]) {
    for client in clients {
        delete_defaults(client, client.name).await;
    }
    test.assert_is_empty().await;
}

pub async fn delete_defaults(client: &DummyWebDavClient, account: &str) {
    for kind in [DavKind::Calendar, DavKind::AddressBook] {
        client
            .request("DELETE", &format!("{}/default", home(kind, account)), "")
            .await;
    }
}

pub fn home(kind: DavKind, account: &str) -> String {
    format!("/dav/{}/{}", kind.home(), account.replace('@', "%40"))
}

pub async fn create_collection(client: &DummyWebDavClient, kind: DavKind, path: &str) {
    match kind.collection() {
        DavKind::Calendar => client
            .request("MKCALENDAR", path, "")
            .await
            .with_status(StatusCode::CREATED),
        DavKind::AddressBook => client
            .mkcol("MKCOL", path, ["D:collection", "B:addressbook"], [])
            .await
            .with_status(StatusCode::CREATED),
        _ => client
            .mkcol("MKCOL", path, [], [])
            .await
            .with_status(StatusCode::CREATED),
    };
}

pub fn item_body(kind: DavKind, uid: &str) -> (String, &'static str) {
    match kind {
        DavKind::Event => (
            format!(
                concat!(
                    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Stalwart//Metadata//EN\r\n",
                    "BEGIN:VEVENT\r\nUID:{uid}\r\nSUMMARY:Metadata {uid}\r\n",
                    "DTSTART:20240101T120000Z\r\nDTEND:20240101T130000Z\r\n",
                    "END:VEVENT\r\nEND:VCALENDAR\r\n"
                ),
                uid = uid
            ),
            "text/calendar; charset=utf-8",
        ),
        DavKind::Card => (
            format!(
                "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{uid}\r\nFN:Metadata {uid}\r\nEND:VCARD\r\n"
            ),
            "text/vcard; charset=utf-8",
        ),
        _ => (format!("Metadata test file {uid}\n"), "text/plain"),
    }
}

pub fn item_name(kind: DavKind, name: &str) -> String {
    match kind {
        DavKind::Event => format!("{name}.ics"),
        DavKind::Card => format!("{name}.vcf"),
        _ => format!("{name}.txt"),
    }
}

pub async fn put_item(client: &DummyWebDavClient, kind: DavKind, path: &str, uid: &str) {
    let (body, content_type) = item_body(kind, uid);
    client
        .request_with_headers("PUT", path, [("content-type", content_type)], body)
        .await
        .with_status(StatusCode::CREATED);
}

pub struct DavResource {
    pub kind: DavKind,
    pub path: String,
    pub collection: String,
}

impl DavResource {
    pub async fn create(client: &DummyWebDavClient, kind: DavKind, name: &str) -> Self {
        let collection = format!("{}/{name}/", home(kind, client.name));
        create_collection(client, kind, &collection).await;
        let path = if kind.is_collection() {
            collection.clone()
        } else {
            let path = format!("{collection}{}", item_name(kind, name));
            put_item(client, kind, &path, name).await;
            path
        };
        DavResource {
            kind,
            path,
            collection,
        }
    }

    pub async fn delete(&self, client: &DummyWebDavClient) {
        client
            .request("DELETE", &self.collection, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
}
