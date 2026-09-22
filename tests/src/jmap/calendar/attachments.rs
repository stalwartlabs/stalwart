/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    account::Account,
    jmap::{JmapResponse, JmapUtils},
    server::TestServer,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use jmap_proto::request::method::MethodObject;
use serde_json::{Map, Value, json};
use std::str::FromStr;
use types::{
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
};

const PNG: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0xFF, 0xFE, 0x01, 0x02, 0x80, 0x90,
];
const PDF: &[u8] = b"%PDF-1.4 embedded attachment \xE2\x28\xA1";
const MAX_RECURRENCE_EXPANSIONS: usize = 3000;
const MAX_ICALENDAR_SIZE: usize = 524_288;
const LARGE_ATTACHMENT_SIZE: usize = 150_000;

pub async fn test(test: &TestServer) {
    println!("Running embedded blob tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let bill = test.account("bill@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();
    let bill_id = bill.id_string().to_string();

    let png_blob = upload(john, PNG, "image/png").await;
    let pdf_blob = upload(john, PDF, "application/pdf").await;
    let jane_blob = upload(jane, PDF, "application/pdf").await;

    // Blob links are embedded in the event and exposed as event blob ids
    let calendar_id = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Attachments",
                "shareWith": {
                    &jane_id: {"mayReadItems": true},
                    &bill_id: {"mayReadFreeBusy": true}
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let event_id = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "title": "Attachments",
                "start": "2030-01-01T09:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1H",
                "links": {
                    "png": {"@type": "Link", "blobId": &png_blob, "contentType": "image/png", "rel": "enclosure"}
                },
                "locations": {
                    "room": {
                        "@type": "Location",
                        "name": "Room",
                        "links": {
                            "map": {"@type": "Link", "blobId": &pdf_blob, "contentType": "application/pdf"}
                        }
                    }
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let event = get_event(john, john, &event_id).await;
    let event_png = event["links"]["png"]["blobId"]
        .as_str()
        .unwrap_or_else(|| panic!("missing embedded blob: {event}"))
        .to_string();
    let event_pdf = event["locations"]["room"]["links"]["map"]["blobId"]
        .as_str()
        .unwrap_or_else(|| panic!("missing embedded blob: {event}"))
        .to_string();
    assert_ne!(event_png, png_blob);
    assert_eq!(event["links"]["png"]["size"], json!(PNG.len()), "{event}");
    assert_eq!(
        blob_data(john, &john_id, &event_png).await,
        Some(PNG.to_vec())
    );
    assert_eq!(
        blob_data(john, &john_id, &event_pdf).await,
        Some(PDF.to_vec())
    );
    assert_eq!(
        download(john, &john_id, &event_png).await,
        Some(PNG.to_vec())
    );

    // Sharees can read attachments of public events only
    assert_eq!(
        blob_data(jane, &jane_id, &event_png).await,
        Some(PNG.to_vec())
    );
    assert_eq!(
        download(jane, &john_id, &event_png).await,
        Some(PNG.to_vec())
    );

    // Sharees that may only read free-busy information get nothing
    assert_eq!(blob_data(bill, &bill_id, &event_png).await, None);
    assert_eq!(download(bill, &john_id, &event_png).await, None);
    assert_eq!(
        copy_blob(bill, &john_id, &event_png).await,
        Err("notFound".to_string())
    );

    // Embedded blobs can be copied to another account
    let copied = copy_blob(jane, &john_id, &event_png)
        .await
        .unwrap_or_else(|err| panic!("blob not copied: {err}"));
    assert_eq!(blob_data(jane, &jane_id, &copied).await, Some(PNG.to_vec()));

    // Embedded blob ids that do not match a binary of the event do not exist
    let mut forged_hash = BlobId::from_str(&event_png).expect("valid blob id");
    forged_hash.hash = BlobHash::generate(b"not an attachment");
    let forged_hash = forged_hash.to_string();
    let mut forged_document = BlobId::from_str(&event_png).expect("valid blob id");
    if let BlobClass::Embedded { document_id, .. } = &mut forged_document.class {
        *document_id = u32::MAX - 1;
    }
    let forged_document = forged_document.to_string();
    let mut forged_linked = BlobId::from_str(&event_png).expect("valid blob id");
    if let BlobClass::Embedded {
        account_id,
        collection,
        document_id,
    } = forged_linked.class
    {
        forged_linked.class = BlobClass::Linked {
            account_id,
            collection,
            document_id,
        };
    }
    let forged_linked = forged_linked.to_string();
    assert_eq!(
        copy_blob(jane, &john_id, &forged_hash).await,
        Err("notFound".to_string())
    );
    assert_eq!(blob_data(john, &john_id, &forged_hash).await, None);

    // Blob/lookup reports every requested type and only existing references
    let response = lookup(
        john,
        &["CalendarEvent", "ContactCard", "FileNode"],
        &[
            &event_png,
            &forged_hash,
            &forged_document,
            &forged_linked,
            &png_blob,
            &jane_blob,
        ],
    )
    .await;
    assert_eq!(
        matched_ids(&response, &event_png),
        &json!({"CalendarEvent": [&event_id], "ContactCard": [], "FileNode": []}),
        "{response:?}"
    );
    assert_eq!(
        matched_ids(&response, &png_blob),
        &json!({"CalendarEvent": [], "ContactCard": [], "FileNode": []}),
        "an uploaded blob that nothing references is found with no matches: {response:?}"
    );
    assert_eq!(
        not_found(&response),
        [&forged_hash, &forged_document, &forged_linked, &jane_blob]
            .map(String::as_str)
            .as_slice(),
        "RFC 9404 Section 3: blobs that do not exist or are not visible are not found: {response:?}"
    );

    // Blobs uploaded in the same request are embedded through creation id references
    let response = john
        .jmap_method_calls(json!([
            [
                "Blob/upload",
                {
                    "accountId": &john_id,
                    "create": { "upload": { "data": [{"data:asBase64": STANDARD.encode(PDF)}], "type": "application/pdf" } }
                },
                "0"
            ],
            [
                "CalendarEvent/set",
                {
                    "accountId": &john_id,
                    "create": { "event": {
                        "calendarIds": { &calendar_id: true },
                        "title": "Uploaded in the same request",
                        "start": "2030-01-02T09:00:00",
                        "timeZone": "Etc/UTC",
                        "links": {
                            "pdf": {"@type": "Link", "blobId": "#upload", "contentType": "application/pdf", "rel": "enclosure"}
                        }
                    } }
                },
                "1"
            ]
        ]))
        .await;
    let referenced_event_id = response.response_at(1)["created"]["event"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("event with a blob id reference not created: {response:?}"))
        .to_string();
    let referenced_event = get_event(john, john, &referenced_event_id).await;
    let referenced_blob = referenced_event["links"]["pdf"]["blobId"]
        .as_str()
        .unwrap_or_else(|| panic!("missing embedded blob: {referenced_event}"))
        .to_string();
    assert_eq!(
        blob_data(john, &john_id, &referenced_blob).await,
        Some(PDF.to_vec())
    );

    // Updates embed the bytes behind embedded blob ids
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": { &event_id: {
                    "title": "Attachments (updated)",
                    "links/png": null,
                    "links/copy": {"@type": "Link", "blobId": &event_png, "contentType": "image/png"}
                } }
            }),
        )
        .await;
    response.updated(&event_id);
    let event = get_event(john, john, &event_id).await;
    assert_eq!(event["links"]["png"], Value::Null, "{event}");
    assert_eq!(
        event["links"]["copy"]["blobId"],
        json!(&event_png),
        "{event}"
    );
    assert_eq!(
        event["locations"]["room"]["links"]["map"]["blobId"],
        json!(&event_pdf),
        "{event}"
    );
    assert_eq!(
        download(john, &john_id, &event_png).await,
        Some(PNG.to_vec())
    );

    // Inaccessible blob ids are reported as not found
    let response = john
        .jmap_method_call(
            "CalendarEvent/set",
            json!({
                "accountId": &john_id,
                "update": { &event_id: {
                    "links/other": {"@type": "Link", "blobId": &jane_blob}
                } }
            }),
        )
        .await;
    let error = &response.method_response()["notUpdated"][&event_id];
    assert_eq!(error["type"], json!("invalidProperties"), "{response:?}");
    assert!(error["notFound"].is_null(), "{response:?}");
    assert!(
        error["description"]
            .as_str()
            .is_some_and(|description| description.contains(jane_blob.as_str())),
        "{response:?}"
    );

    // Attachments copied into recurrence overrides are bounded before they are built
    let large_blob = upload(john, &pdf_of_size(LARGE_ATTACHMENT_SIZE), "application/pdf").await;
    john.jmap_create(
        MethodObject::CalendarEvent,
        [recurring_event(&calendar_id, &large_blob, 1)],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .created(0);
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [recurring_event(&calendar_id, &large_blob, 3)],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "tooLarge", "{response:?}");
    let oversized_blob = upload(
        john,
        &pdf_of_size(MAX_ICALENDAR_SIZE + 1),
        "application/pdf",
    )
    .await;
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [recurring_event(&calendar_id, &oversized_blob, 0)],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "tooLarge", "{response:?}");
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [recurring_data_uri_event(
                &calendar_id,
                LARGE_ATTACHMENT_SIZE,
                4,
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "tooLarge", "{response:?}");
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [recurring_event(
                &calendar_id,
                &png_blob,
                MAX_RECURRENCE_EXPANSIONS + 1,
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let error = response.not_created(0);
    assert_eq!(error.typ(), "invalidProperties", "{response:?}");
    assert_eq!(
        error["properties"],
        json!(["recurrenceOverrides"]),
        "{response:?}"
    );

    // An override patch whose parent does not exist names the key the client sent
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &calendar_id: true },
                "title": "Broken patch",
                "start": "2030-01-01T00:00:00",
                "timeZone": "Etc/UTC",
                "duration": "PT1M",
                "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "daily", "count": 3},
                "recurrenceOverrides": {
                    "2030-01-02T00:00:00": {"links/missing/title": "Minutes"}
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let error = response.not_created(0);
    assert_eq!(error.typ(), "invalidProperties", "{response:?}");
    assert_eq!(
        error["properties"],
        json!(["recurrenceOverrides/2030-01-02T00:00:00/links~1missing~1title"]),
        "RFC 6901 Section 3: the reported path escapes the override patch key: {response:?}"
    );

    // Private events hide their attachments from sharees
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(&event_id, json!({"privacy": "private"}))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&event_id);
    assert_eq!(blob_data(jane, &jane_id, &event_png).await, None);
    assert_eq!(download(jane, &john_id, &event_png).await, None);
    assert_eq!(
        copy_blob(jane, &john_id, &event_png).await,
        Err("notFound".to_string())
    );
    let jane_calendar_id = jane
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Copies"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let response = jane
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "calendarIds": { &jane_calendar_id: true },
                "title": "Copy",
                "start": "2030-01-01T09:00:00",
                "timeZone": "Etc/UTC",
                "links": {
                    "png": {"@type": "Link", "blobId": &event_png, "contentType": "image/png"}
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let error = response.not_created(0);
    assert_eq!(error.typ(), "invalidProperties", "{response:?}");
    assert!(error["notFound"].is_null(), "{response:?}");
    assert!(
        error["description"]
            .as_str()
            .is_some_and(|description| description.contains(event_png.as_str())),
        "{response:?}"
    );
    assert_eq!(
        blob_data(john, &john_id, &event_png).await,
        Some(PNG.to_vec())
    );
    assert_eq!(
        download(john, &john_id, &event_png).await,
        Some(PNG.to_vec())
    );

    // Contact media is embedded the same way
    let book_id = john
        .jmap_create(
            MethodObject::AddressBook,
            [json!({"name": "Media"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let contact_id = john
        .jmap_create(
            MethodObject::ContactCard,
            [json!({
                "addressBookIds": { &book_id: true },
                "name": {"full": "Media"},
                "media": {
                    "photo": {"@type": "Media", "kind": "photo", "blobId": &png_blob, "mediaType": "image/png"}
                }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let contact = john
        .jmap_get(MethodObject::ContactCard, ["media"], [&contact_id])
        .await
        .list()[0]
        .clone();
    let contact_png = contact["media"]["photo"]["blobId"]
        .as_str()
        .unwrap_or_else(|| panic!("missing embedded blob: {contact}"))
        .to_string();
    assert_ne!(contact_png, png_blob);
    assert_eq!(
        blob_data(john, &john_id, &contact_png).await,
        Some(PNG.to_vec())
    );
    assert_eq!(blob_data(jane, &jane_id, &contact_png).await, None);
    let response = lookup(john, &["ContactCard", "CalendarEvent"], &[&contact_png]).await;
    assert_eq!(
        matched_ids(&response, &contact_png),
        &json!({"ContactCard": [&contact_id], "CalendarEvent": []}),
        "{response:?}"
    );

    // Contact media can reference blobs uploaded in the same request
    let response = john
        .jmap_method_calls(json!([
            [
                "Blob/upload",
                {
                    "accountId": &john_id,
                    "create": { "upload": { "data": [{"data:asBase64": STANDARD.encode(PNG)}], "type": "image/png" } }
                },
                "0"
            ],
            [
                "ContactCard/set",
                {
                    "accountId": &john_id,
                    "create": { "card": {
                        "addressBookIds": { &book_id: true },
                        "name": {"full": "Uploaded in the same request"},
                        "media": {
                            "photo": {"@type": "Media", "kind": "photo", "blobId": "#upload", "mediaType": "image/png"}
                        }
                    } }
                },
                "1"
            ]
        ]))
        .await;
    let referenced_contact_id = response.response_at(1)["created"]["card"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("contact with a blob id reference not created: {response:?}"))
        .to_string();
    let referenced_contact = john
        .jmap_get(
            MethodObject::ContactCard,
            ["media"],
            [&referenced_contact_id],
        )
        .await
        .list()[0]
        .clone();
    let referenced_photo = referenced_contact["media"]["photo"]["blobId"]
        .as_str()
        .unwrap_or_else(|| panic!("missing embedded blob: {referenced_contact}"))
        .to_string();
    assert_eq!(
        blob_data(john, &john_id, &referenced_photo).await,
        Some(PNG.to_vec())
    );

    // Blob/lookup only matches file blobs while the node references them
    let node_id = john
        .jmap_create(
            MethodObject::FileNode,
            [json!({
                "name": "attachment-lookup.pdf",
                "parentId": null,
                "blobId": &pdf_blob,
                "type": "application/pdf"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let node_blob = john
        .jmap_get(MethodObject::FileNode, ["blobId"], [&node_id])
        .await
        .list()[0]
        .blob_id()
        .to_string();
    let mut forged_node = BlobId::from_str(&node_blob).expect("valid blob id");
    if let BlobClass::Linked { document_id, .. } = &mut forged_node.class {
        *document_id = u32::MAX - 1;
    }
    let forged_node = forged_node.to_string();
    let response = lookup(
        john,
        &["FileNode", "CalendarEvent"],
        &[&node_blob, &forged_node],
    )
    .await;
    assert_eq!(
        matched_ids(&response, &node_blob),
        &json!({"FileNode": [&node_id], "CalendarEvent": []}),
        "{response:?}"
    );
    assert_eq!(not_found(&response), [forged_node.as_str()], "{response:?}");
    john.jmap_destroy(
        MethodObject::FileNode,
        [&node_id],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .destroyed()
    .for_each(drop);
    let response = lookup(john, &["FileNode"], &[&node_blob]).await;
    assert_eq!(not_found(&response), [node_blob.as_str()], "{response:?}");

    // Media copies are bounded before they are built
    let response = john
        .jmap_create(
            MethodObject::ContactCard,
            [json!({
                "addressBookIds": { &book_id: true },
                "name": {"full": "Copies"},
                "media": (0..4)
                    .map(|index| {
                        (
                            format!("photo{index}"),
                            json!({"@type": "Media", "kind": "photo", "blobId": &large_blob}),
                        )
                    })
                    .collect::<Map<String, Value>>()
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "tooLarge", "{response:?}");

    john.destroy_all_calendars().await;
    john.destroy_all_addressbooks().await;
    jane.destroy_all_calendars().await;
    john.destroy_all_event_notifications().await;
    jane.destroy_all_event_notifications().await;
    bill.destroy_all_event_notifications().await;
    test.wait_for_tasks().await;
}

async fn upload(account: &Account, data: &[u8], content_type: &str) -> String {
    let response = account
        .jmap_method_call(
            "Blob/upload",
            json!({
                "accountId": account.id_string(),
                "create": { "b": { "data": [{"data:asBase64": STANDARD.encode(data)}], "type": content_type } }
            }),
        )
        .await;
    response.method_response()["created"]["b"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("upload failed: {response:?}"))
        .to_string()
}

async fn get_event(caller: &Account, owner: &Account, event_id: &str) -> Value {
    caller
        .jmap_get_account(
            owner,
            MethodObject::CalendarEvent,
            ["links", "locations"],
            [event_id],
        )
        .await
        .list()[0]
        .clone()
}

async fn download(caller: &Account, account_id: &str, blob_id: &str) -> Option<Vec<u8>> {
    let response = caller
        .http_get_raw(
            &format!(
                "{}/jmap/download/{account_id}/{blob_id}/attachment",
                caller.base_url()
            ),
            None,
        )
        .await;
    (response.status == 200).then_some(response.body)
}

async fn copy_blob(
    caller: &Account,
    from_account_id: &str,
    blob_id: &str,
) -> Result<String, String> {
    let response = caller
        .jmap_method_call(
            "Blob/copy",
            json!({
                "fromAccountId": from_account_id,
                "accountId": caller.id_string(),
                "blobIds": [blob_id]
            }),
        )
        .await;
    let result = response.method_response();
    match result["copied"][blob_id].as_str() {
        Some(copied) => Ok(copied.to_string()),
        None => Err(result["notCopied"][blob_id]["type"]
            .as_str()
            .unwrap_or_else(|| panic!("unexpected Blob/copy response: {response:?}"))
            .to_string()),
    }
}

async fn lookup(caller: &Account, type_names: &[&str], blob_ids: &[&str]) -> JmapResponse {
    caller
        .jmap_method_call(
            "Blob/lookup",
            json!({
                "accountId": caller.id_string(),
                "typeNames": type_names,
                "ids": blob_ids
            }),
        )
        .await
}

fn not_found(response: &JmapResponse) -> Vec<&str> {
    response.method_response()["notFound"]
        .as_array()
        .map(|ids| ids.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn matched_ids<'x>(response: &'x JmapResponse, blob_id: &str) -> &'x Value {
    response.method_response()["list"]
        .as_array()
        .and_then(|list| list.iter().find(|info| info["id"] == blob_id))
        .map(|info| &info["matchedIds"])
        .unwrap_or_else(|| panic!("{blob_id} missing from Blob/lookup: {response:?}"))
}

fn pdf_of_size(size: usize) -> Vec<u8> {
    PDF.iter().copied().cycle().take(size).collect()
}

fn recurring_event(calendar_id: &str, blob_id: &str, overrides: usize) -> Value {
    json!({
        "calendarIds": { calendar_id: true },
        "title": "Copies",
        "start": "2030-01-01T00:00:00",
        "timeZone": "Etc/UTC",
        "duration": "PT1M",
        "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "minutely", "count": overrides + 1},
        "links": {
            "attachment": {"@type": "Link", "blobId": blob_id, "rel": "enclosure"}
        },
        "recurrenceOverrides": (1..=overrides)
            .map(|minute| {
                (
                    format!(
                        "2030-01-{:02}T{:02}:{:02}:00",
                        minute / 1440 + 1,
                        minute / 60 % 24,
                        minute % 60
                    ),
                    json!({"title": "Copy"}),
                )
            })
            .collect::<Map<String, Value>>()
    })
}

fn recurring_data_uri_event(calendar_id: &str, size: usize, overrides: usize) -> Value {
    let mut event = recurring_event(calendar_id, "", overrides);
    event["links"]["attachment"] = json!({
        "@type": "Link",
        "rel": "enclosure",
        "href": format!(
            "data:application/pdf;base64,{}",
            STANDARD.encode(pdf_of_size(size))
        )
    });
    event
}

async fn blob_data(caller: &Account, account_id: &str, blob_id: &str) -> Option<Vec<u8>> {
    let response = caller
        .jmap_method_call(
            "Blob/get",
            json!({ "accountId": account_id, "ids": [blob_id], "properties": ["data:asBase64"] }),
        )
        .await;
    response.method_response()["list"]
        .as_array()
        .and_then(|list| list.first())
        .and_then(|blob| blob["data:asBase64"].as_str())
        .map(|data| STANDARD.decode(data).expect("valid base64"))
}
