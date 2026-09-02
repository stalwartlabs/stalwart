/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use crate::webdav::*;
use dav_proto::schema::property::{DavProperty, WebDavProperty};
use types::dead_property::DeadElementTag;
use groupware::calendar::{CalendarEvent, EVENT_HAS_DEAD_PROPERTIES};
use groupware::contact::{CARD_HAS_DEAD_PROPERTIES, ContactCard};
use store::{
    SerializeInfallible, ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder, ValueClass},
};
use types::{
    collection::Collection,
    field::{CalendarEventField, ContactField, Field, PrincipalField},
};

const EVENT_PATH: &str = "/dav/cal/john%40example.com/default/split-event.ics";
const CARD_PATH: &str = "/dav/card/john%40example.com/default/split-card.vcf";

pub async fn test(test: &TestServer) {
    println!("Running storage split tests...");

    records_are_written_and_cleared_together(test).await;
    quota_matches_content_length(test).await;
    dead_property_bit_tracks_the_set(test).await;
    etag_changes_on_payload_and_metadata_writes(test).await;
    metadata_only_write_leaves_content_untouched(test).await;
    default_calendar_is_reset_on_destroy(test).await;
}

fn john_id(test: &TestServer) -> u32 {
    test.account("john@example.com").id().document_id()
}

async fn meta_and_content(
    test: &TestServer,
    collection: Collection,
    document_id: u32,
) -> (Option<Archive<ArchiveBytes>>, Option<Archive<ArchiveBytes>>) {
    let account_id = john_id(test);
    let content_field: Field = match collection {
        Collection::CalendarEvent => CalendarEventField::Content.field(),
        Collection::ContactCard => ContactField::Content.field(),
        _ => unreachable!(),
    };

    let meta = test
        .server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            collection,
            document_id,
        ))
        .await
        .unwrap();
    let content = test
        .server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            account_id,
            collection,
            document_id,
            content_field,
        ))
        .await
        .unwrap();

    (meta, content)
}

async fn document_id(test: &TestServer, collection: Collection, path: &str) -> u32 {
    let sync_collection = match collection {
        Collection::CalendarEvent => Collection::Calendar,
        Collection::ContactCard => Collection::AddressBook,
        _ => unreachable!(),
    };
    let resources = test.resources("john@example.com", sync_collection).await;
    let name = path.rsplit('/').next().unwrap();

    resources
        .paths
        .iter()
        .find(|(chunk, path)| {
            std::str::from_utf8(&chunk.bytes[path.path.range()])
                .unwrap_or_default()
                .ends_with(name)
        })
        .map(|(_, path)| path.document_id)
        .unwrap_or_else(|| panic!("Resource {path} not found in cache"))
}

// Test 1: META and CONTENT are written together and cleared together.
async fn records_are_written_and_cleared_together(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();

    for (path, ct, body, collection) in [
        (
            EVENT_PATH,
            "text/calendar; charset=utf-8",
            TEST_ICAL_1,
            Collection::CalendarEvent,
        ),
        (
            CARD_PATH,
            "text/vcard; charset=utf-8",
            TEST_VCARD_1,
            Collection::ContactCard,
        ),
    ] {
        let body = body.replace('\n', "\r\n");
        client
            .request_with_headers("PUT", path, [("content-type", ct)], &body)
            .await
            .with_status(StatusCode::CREATED);

        let id = document_id(test, collection, path).await;
        let (meta, content) = meta_and_content(test, collection, id).await;
        assert!(meta.is_some(), "{path}: META missing after PUT");
        assert!(content.is_some(), "{path}: CONTENT missing after PUT");

        // A payload rewrite keeps both records in step
        let updated = body.replace("SEQ1", "SEQ2");
        client
            .request_with_headers("PUT", path, [("content-type", ct)], &updated)
            .await
            .with_status(StatusCode::NO_CONTENT);

        let (meta, content) = meta_and_content(test, collection, id).await;
        assert!(meta.is_some(), "{path}: META missing after update");
        assert!(content.is_some(), "{path}: CONTENT missing after update");

        client
            .request("DELETE", path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);

        let (meta, content) = meta_and_content(test, collection, id).await;
        assert!(meta.is_none(), "{path}: META survived the delete");
        assert!(content.is_none(), "{path}: CONTENT survived the delete");
    }
}

// Test 3: quota is charged the same bytes getcontentlength reports.
async fn quota_matches_content_length(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();
    let body = TEST_ICAL_1.replace('\n', "\r\n");

    client
        .request_with_headers(
            "PUT",
            EVENT_PATH,
            [("content-type", "text/calendar; charset=utf-8")],
            &body,
        )
        .await
        .with_status(StatusCode::CREATED);

    let id = document_id(test, Collection::CalendarEvent, EVENT_PATH).await;
    let (meta, _) = meta_and_content(test, Collection::CalendarEvent, id).await;
    let size = meta
        .as_ref()
        .unwrap()
        .unarchive::<CalendarEvent>()
        .unwrap()
        .size
        .to_native();

    // getcontentlength, HEAD and the GET body must all agree with the stored size
    let head = client.request("HEAD", EVENT_PATH, "").await;
    assert_eq!(
        head.header("content-length"),
        size.to_string(),
        "HEAD Content-Length disagrees with the stored size"
    );

    let get = client
        .request("GET", EVENT_PATH, "")
        .await
        .with_status(StatusCode::OK);
    assert_eq!(
        get.body.as_ref().unwrap().len(),
        size as usize,
        "GET body length disagrees with the stored size"
    );

    client
        .request("DELETE", EVENT_PATH, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

// Test 4: the dead-property bit tracks the dead-property set.
async fn dead_property_bit_tracks_the_set(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();

    for (path, ct, body, collection) in [
        (
            EVENT_PATH,
            "text/calendar; charset=utf-8",
            TEST_ICAL_1,
            Collection::CalendarEvent,
        ),
        (
            CARD_PATH,
            "text/vcard; charset=utf-8",
            TEST_VCARD_1,
            Collection::ContactCard,
        ),
    ] {
        let body = body.replace('\n', "\r\n");
        client
            .request_with_headers("PUT", path, [("content-type", ct)], &body)
            .await
            .with_status(StatusCode::CREATED);

        let id = document_id(test, collection, path).await;
        assert!(
            !has_dead_property_bit(test, collection, id).await,
            "{path}: dead-property bit set on a fresh object"
        );

        client
            .patch_and_check(
                path,
                [(
                    DavProperty::DeadProperty(DeadElementTag::new(
                        "split-marker".to_string(),
                        Some("xmlns=\"http://example.com/ns/\"".to_string()),
                    )),
                    "hello",
                )],
            )
            .await;

        assert!(
            has_dead_property_bit(test, collection, id).await,
            "{path}: dead-property bit not set after PROPPATCH"
        );

        // The dead property must be readable, which requires the CONTENT second pass
        let propfind = client
            .request(
                "PROPFIND",
                path,
                concat!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                    "<D:propfind xmlns:D=\"DAV:\"><D:allprop/></D:propfind>"
                ),
            )
            .await
            .with_status(StatusCode::MULTI_STATUS);
        assert!(
            propfind.body.as_ref().is_ok_and(|b| b.contains("hello")),
            "{path}: dead property not returned by allprop PROPFIND"
        );

        client
            .patch_and_check(
                path,
                [(
                    DavProperty::DeadProperty(DeadElementTag::new(
                        "split-marker".to_string(),
                        Some("xmlns=\"http://example.com/ns/\"".to_string()),
                    )),
                    "",
                )],
            )
            .await;

        assert!(
            !has_dead_property_bit(test, collection, id).await,
            "{path}: dead-property bit still set after removing the last property"
        );

        client
            .request("DELETE", path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
}

async fn has_dead_property_bit(test: &TestServer, collection: Collection, id: u32) -> bool {
    let (meta, _) = meta_and_content(test, collection, id).await;
    let meta = meta.expect("META missing");

    match collection {
        Collection::CalendarEvent => {
            meta.unarchive::<CalendarEvent>().unwrap().flags.to_native() & EVENT_HAS_DEAD_PROPERTIES
                != 0
        }
        Collection::ContactCard => {
            meta.unarchive::<ContactCard>().unwrap().flags.to_native() & CARD_HAS_DEAD_PROPERTIES
                != 0
        }
        _ => unreachable!(),
    }
}

// Test 5: a payload change, a PROPPATCH and a rename each move the ETag.
async fn etag_changes_on_payload_and_metadata_writes(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();
    let body = TEST_ICAL_1.replace('\n', "\r\n");

    let created = client
        .request_with_headers(
            "PUT",
            EVENT_PATH,
            [("content-type", "text/calendar; charset=utf-8")],
            &body,
        )
        .await
        .with_status(StatusCode::CREATED)
        .etag()
        .to_string();

    // A payload change moves the ETag
    let after_payload = client
        .request_with_headers(
            "PUT",
            EVENT_PATH,
            [("content-type", "text/calendar; charset=utf-8")],
            &body.replace("SEQ1", "SEQ2"),
        )
        .await
        .with_status(StatusCode::NO_CONTENT)
        .etag()
        .to_string();
    assert_ne!(
        created, after_payload,
        "payload change did not move the ETag"
    );

    // A PROPPATCH moves the ETag, because the metadata is in the hash
    client
        .patch_and_check(
            EVENT_PATH,
            [(
                DavProperty::WebDav(WebDavProperty::DisplayName),
                "split display name",
            )],
        )
        .await;
    let after_proppatch = client
        .request("GET", EVENT_PATH, "")
        .await
        .with_status(StatusCode::OK)
        .header("etag")
        .to_string();
    assert_ne!(
        after_payload, after_proppatch,
        "PROPPATCH did not move the ETag"
    );

    // A rename is a metadata-only write and must also move the ETag
    let moved_path = "/dav/cal/john%40example.com/default/split-event-moved.ics";
    client
        .request_with_headers("MOVE", EVENT_PATH, [("destination", moved_path)], "")
        .await
        .with_status(StatusCode::CREATED);
    let after_move = client
        .request("GET", moved_path, "")
        .await
        .with_status(StatusCode::OK)
        .header("etag")
        .to_string();
    assert_ne!(after_proppatch, after_move, "a rename did not move the ETag");

    client
        .request("DELETE", moved_path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}

// Test 10: destroying the default calendar clears the principal property, and
// destroying a different calendar leaves it alone.
async fn default_calendar_is_reset_on_destroy(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();
    let account_id = john_id(test);
    let default_path = "/dav/cal/john%40example.com/split-default/";
    let other_path = "/dav/cal/john%40example.com/split-other/";

    for path in [default_path, other_path] {
        client
            .request("MKCALENDAR", path, "")
            .await
            .with_status(StatusCode::CREATED);
    }

    let resources = test
        .resources("john@example.com", Collection::Calendar)
        .await;
    let default_id = resources
        .by_path("split-default")
        .expect("split-default calendar not found")
        .document_id();

    set_default_calendar(test, account_id, Some(default_id)).await;

    // Destroying an unrelated calendar must leave the property pointing at the default
    client
        .request("DELETE", other_path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_eq!(
        read_default_calendar(test, account_id).await,
        Some(default_id),
        "destroying an unrelated calendar cleared the default"
    );

    // Destroying the default calendar must clear it
    client
        .request("DELETE", default_path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_eq!(
        read_default_calendar(test, account_id).await,
        None,
        "destroying the default calendar left the property pointing at it"
    );
}

async fn read_default_calendar(test: &TestServer, account_id: u32) -> Option<u32> {
    test.server
        .store()
        .get_value::<u32>(ValueKey {
            account_id,
            collection: Collection::Principal.into(),
            document_id: 0,
            class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
        })
        .await
        .unwrap()
}

async fn set_default_calendar(test: &TestServer, account_id: u32, document_id: Option<u32>) {
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Principal)
        .with_document(0);

    match document_id {
        Some(document_id) => {
            batch.set(PrincipalField::DefaultCalendarId, document_id.serialize());
        }
        None => {
            batch.clear(PrincipalField::DefaultCalendarId);
        }
    }

    test.server.commit_batch(batch).await.unwrap();
}

// Test 2: a metadata-only write must not rewrite CONTENT nor disturb the payload.
async fn metadata_only_write_leaves_content_untouched(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();
    let body = TEST_ICAL_1.replace('\n', "\r\n");

    client
        .request_with_headers(
            "PUT",
            EVENT_PATH,
            [("content-type", "text/calendar; charset=utf-8")],
            &body,
        )
        .await
        .with_status(StatusCode::CREATED);

    let id = document_id(test, Collection::CalendarEvent, EVENT_PATH).await;
    let (meta_before, content_before) = meta_and_content(test, Collection::CalendarEvent, id).await;
    let content_before = content_before.expect("CONTENT missing").inner;
    let etag_before = meta_before
        .as_ref()
        .unwrap()
        .unarchive::<CalendarEvent>()
        .unwrap()
        .etag
        .to_native();

    // A rename changes only the metadata record
    let renamed = "/dav/cal/john%40example.com/default/split-event-renamed.ics";
    client
        .request_with_headers("MOVE", EVENT_PATH, [("destination", renamed)], "")
        .await
        .with_status(StatusCode::CREATED);

    let (meta_after, content_after) = meta_and_content(test, Collection::CalendarEvent, id).await;
    let content_after = content_after.expect("CONTENT missing after rename").inner;
    let etag_after = meta_after
        .as_ref()
        .unwrap()
        .unarchive::<CalendarEvent>()
        .unwrap()
        .etag
        .to_native();

    assert_eq!(
        content_before, content_after,
        "a metadata-only write rewrote the CONTENT record"
    );
    assert_ne!(
        etag_before, etag_after,
        "a metadata-only write did not move the ETag"
    );

    // The payload is still readable and unchanged
    client
        .request("GET", renamed, "")
        .await
        .with_status(StatusCode::OK)
        .with_body(&body);

    client
        .request("DELETE", renamed, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
}
