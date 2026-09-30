/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FULL_ACCESS, assert_error, container, container_with_imap, encode, json, patches_of,
    private_json, shared_json, support, update, update_with,
};
use crate::api::metadata::{MetadataAccess, MetadataPatches, MetadataSupport, MetadataType};
use calcard::jscalendar::{JSCalendarProperty, JSCalendarValue};
use jmap_proto::object::{
    email::{EmailProperty, EmailValue},
    file_node::{FileNodeProperty, FileNodeValue},
    mailbox::{MailboxProperty, MailboxValue},
};
use store::write::metadata::{METADATA_COMPRESS_WATERMARK, MetadataBuf, StoredMetadata};
use types::{
    blob::BlobId,
    id::Id,
    metadata::{MetadataEdit, MetadataKinds, STORAGE_TRAILER_CAPACITY},
};

#[test]
fn draft_patch_single_property() {
    let current = container(
        r#"{"acme.example.com": {"color": "blue", "owner": "team-alpha"}, "other.example": {"a": 1}}"#,
    );

    let result = update(
        r#"{"metadata/acme.example.com/color": "green"}"#,
        Some(&current),
    )
    .expect("valid patch");
    assert_eq!(
        shared_json(&result),
        json(
            r#"{"acme.example.com": {"color": "green", "owner": "team-alpha"}, "other.example": {"a": 1}}"#
        )
    );
    let change = result.shared().expect("changed");
    assert_eq!(
        change.previous().map(|previous| previous.size),
        Some(current.stored_len())
    );

    let result = update(
        r#"{"metadata/acme.example.com/color": null}"#,
        Some(&current),
    )
    .expect("valid patch");
    assert_eq!(
        shared_json(&result),
        json(r#"{"acme.example.com": {"owner": "team-alpha"}, "other.example": {"a": 1}}"#)
    );
}

#[test]
fn draft_create_email_with_private_metadata() {
    let patches = patches_of::<EmailProperty, EmailValue>(
        MetadataPatches::for_create(),
        r#"{
            "privateMetadata": {
                "acme.example.com": {
                    "workflowState": "pending-review",
                    "assignedTo": "carol@example.com"
                }
            }
        }"#,
    )
    .expect("valid create");
    assert!(patches.has_private() && !patches.has_shared());
    let support = MetadataSupport {
        object: MetadataType::Email,
        ..support()
    };
    let result = patches
        .apply::<EmailProperty>(&support, FULL_ACCESS, None, None)
        .expect("valid create");
    assert!(result.shared().is_none());
    assert_eq!(
        private_json(&result),
        json(
            r#"{"acme.example.com": {"workflowState": "pending-review", "assignedTo": "carol@example.com"}}"#
        )
    );
    let change = result.private().expect("private change");
    assert!(change.previous().is_none());
    assert_eq!(
        change.next().map(|next| next.kinds()),
        Some(MetadataKinds::JMAP)
    );
}

#[test]
fn draft_file_node_photography() {
    let support = MetadataSupport {
        object: MetadataType::FileNode,
        ..support()
    };
    let request = |namespace: &str| {
        format!(
            r#"{{"metadata/{namespace}": {{
                "geoLocation": {{"latitude": 46.362, "longitude": 14.090}},
                "cameraMake": "Canon",
                "iso": 400,
                "imageSize": {{"width": 6000, "height": 4000}}
            }}}}"#
        )
    };

    let result = patches_of::<FileNodeProperty, FileNodeValue>(
        MetadataPatches::for_update(),
        &request("photography"),
    )
    .expect("valid patch")
    .apply::<FileNodeProperty>(&support, FULL_ACCESS, None, None);
    assert_error(result, "invalidProperties", "metadata/photography");

    let result = patches_of::<FileNodeProperty, FileNodeValue>(
        MetadataPatches::for_update(),
        &request("photography.example"),
    )
    .expect("valid patch")
    .apply::<FileNodeProperty>(&support, FULL_ACCESS, None, None)
    .expect("vendor namespace accepted");
    assert_eq!(
        shared_json(&result),
        json(
            r#"{"photography.example": {
                "geoLocation": {"latitude": 46.362, "longitude": 14.090},
                "cameraMake": "Canon",
                "iso": 400,
                "imageSize": {"width": 6000, "height": 4000}
            }}"#
        )
    );
}

#[test]
fn draft_calendar_event_update_is_atomic() {
    let support = MetadataSupport {
        object: MetadataType::CalendarEvent,
        ..support()
    };
    let current = container(r#"{"acme.example.com": {"approvalStatus": "draft"}}"#);
    let request = r#"{
        "metadata/acme.example.com/lastModifiedReason": "Rescheduled per manager request",
        "metadata/acme.example.com/approvalStatus": "pending"
    }"#;
    let result = patches_of::<JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>(
        MetadataPatches::for_update(),
        request,
    )
    .expect("valid patch")
    .apply::<JSCalendarProperty<Id>>(&support, FULL_ACCESS, Some(&current), None)
    .expect("valid update");
    assert_eq!(
        shared_json(&result),
        json(
            r#"{"acme.example.com": {"approvalStatus": "pending", "lastModifiedReason": "Rescheduled per manager request"}}"#
        )
    );

    let result = patches_of::<JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>(
        MetadataPatches::for_update(),
        r#"{
            "metadata/acme.example.com/approvalStatus": "pending",
            "metadata/missing.example/key": "value"
        }"#,
    )
    .expect("valid patch")
    .apply::<JSCalendarProperty<Id>>(&support, FULL_ACCESS, Some(&current), None);
    assert_error(result, "invalidPatch", "metadata/missing.example/key");
}

#[test]
fn root_and_pointer_forms() {
    let current = container_with_imap(
        r#"{"a.example": {"k": 1}, "b.example": {"k": 2}}"#,
        &[("/comment", "kept")],
    );

    for request in [
        r#"{"metadata": {"c.example": {"k": 3}}}"#,
        r#"{"/metadata": {"c.example": {"k": 3}}}"#,
    ] {
        let result = update(request, Some(&current)).expect("valid replacement");
        assert_eq!(shared_json(&result), json(r#"{"c.example": {"k": 3}}"#));
        let next = result
            .shared()
            .and_then(|change| change.next())
            .expect("kept");
        assert_eq!(next.view().imap_entry("/comment"), Some(&b"kept"[..]));
    }

    for request in [r#"{"metadata": null}"#, r#"{"metadata": {}}"#] {
        let result = update(request, Some(&current)).expect("valid reset");
        let next = result
            .shared()
            .and_then(|change| change.next())
            .expect("kept");
        assert_eq!(next.kinds(), MetadataKinds::IMAP);
    }

    let only_jmap = container(r#"{"a.example": {"k": 1}}"#);
    let result = update(r#"{"metadata": {}}"#, Some(&only_jmap)).expect("valid reset");
    assert!(result.shared().expect("changed").next().is_none());

    let result = update(r#"{"metadata/b.example": null}"#, Some(&current)).expect("valid removal");
    assert_eq!(shared_json(&result), json(r#"{"a.example": {"k": 1}}"#));

    let result = update(
        r#"{"metadata/b.example": {"x": [1, {"y": null}]}}"#,
        Some(&current),
    )
    .expect("valid replacement");
    assert_eq!(
        shared_json(&result),
        json(r#"{"a.example": {"k": 1}, "b.example": {"x": [1, {"y": null}]}}"#)
    );

    let result = update(
        r#"{"metadata/a.example/deep~1key": {"n": true}}"#,
        Some(&current),
    )
    .expect("valid deep patch");
    assert_eq!(
        shared_json(&result),
        json(r#"{"a.example": {"k": 1, "deep/key": {"n": true}}, "b.example": {"k": 2}}"#)
    );

    assert!(
        update(r#"{"metadata/z.example": null}"#, Some(&current))
            .expect("no-op removal")
            .is_empty()
    );
    assert!(
        update(r#"{"metadata/a.example/k": 1}"#, Some(&current))
            .expect("no-op patch")
            .is_empty()
    );
    assert!(
        update(r#"{"metadata": null}"#, None)
            .expect("no-op reset")
            .is_empty()
    );
}

#[test]
fn create_rules() {
    let create = |json: &str| {
        patches_of::<MailboxProperty, MailboxValue>(MetadataPatches::for_create(), json).and_then(
            |patches| patches.apply::<MailboxProperty>(&support(), FULL_ACCESS, None, None),
        )
    };

    assert_error(
        create(r#"{"metadata": null}"#),
        "invalidProperties",
        "metadata",
    );
    assert_error(
        create(r#"{"privateMetadata": null}"#),
        "invalidProperties",
        "privateMetadata",
    );
    assert_error(
        create(r#"{"metadata": []}"#),
        "invalidProperties",
        "metadata",
    );
    assert_error(
        create(r#"{"metadata": {"a.example": "text"}}"#),
        "invalidProperties",
        "metadata/a.example",
    );
    assert_error(
        create(r#"{"metadata/a.example": {}}"#),
        "invalidProperties",
        "metadata",
    );
    let result =
        create(r#"{"metadata": {"a.example": {}}, "/privateMetadata": {}}"#).expect("valid create");
    assert_eq!(shared_json(&result), json(r#"{"a.example": {}}"#));
    assert!(result.private().is_none());
}

#[test]
fn update_value_types() {
    assert_error(
        update(r#"{"metadata": 1}"#, None),
        "invalidProperties",
        "metadata",
    );
    assert_error(
        update(r#"{"metadata/a.example": [1]}"#, None),
        "invalidProperties",
        "metadata/a.example",
    );
    assert_error(
        update(r#"{"metadata": {"a~b/c": "x"}}"#, None),
        "invalidProperties",
        "metadata/a~0b~1c",
    );
}

#[test]
fn patch_conflicts() {
    let current = container(r#"{"a.example": {"k": {"x": 1}, "list": [1, 2], "text": "t"}}"#);
    for (request, property) in [
        (
            r#"{"metadata": {}, "metadata/b.example": {}}"#,
            "metadata/b.example",
        ),
        (r#"{"metadata": {}, "/metadata": {}}"#, "metadata"),
        (
            r#"{"metadata/a.example": {}, "/metadata/a.example": {}}"#,
            "metadata/a.example",
        ),
        (
            r#"{"metadata/a.example": {}, "metadata/a.example/k": 1}"#,
            "metadata/a.example/k",
        ),
        (
            r#"{"metadata/a.example/k": 1, "metadata/a.example/k/x": 2}"#,
            "metadata/a.example/k/x",
        ),
        (r#"{"metadata/a.example/k~": 1}"#, "metadata/a.example/k~"),
        (r#"{"metadata/a.example/k~2": 1}"#, "metadata/a.example/k~2"),
        (r#"{"metadata/b.example/k": 1}"#, "metadata/b.example/k"),
        (
            r#"{"metadata/a.example/missing/x": 1}"#,
            "metadata/a.example/missing/x",
        ),
        (
            r#"{"metadata/a.example/list/0": 5}"#,
            "metadata/a.example/list/0",
        ),
        (
            r#"{"metadata/a.example/text/x": null}"#,
            "metadata/a.example/text/x",
        ),
    ] {
        assert_error(update(request, Some(&current)), "invalidPatch", property);
    }

    let result = update(
        r#"{"metadata/a.example/k/x": 2, "metadata/a.example/kx": 3, "privateMetadata/a.example": {}}"#,
        Some(&current),
    )
    .expect("disjoint patches");
    assert_eq!(
        shared_json(&result),
        json(r#"{"a.example": {"k": {"x": 2}, "list": [1, 2], "text": "t", "kx": 3}}"#)
    );
    assert_eq!(private_json(&result), json(r#"{"a.example": {}}"#));
}

#[test]
fn validation_order() {
    let current = container(r#"{"a.example": {"k": 1}}"#);
    let no_access = MetadataAccess {
        may_write_shared: false,
        may_read: false,
    };
    let read_only = MetadataAccess {
        may_write_shared: false,
        may_read: true,
    };
    let restricted = MetadataSupport {
        vendor_namespaces: false,
        private: false,
        ..support()
    };
    let not_writable = MetadataSupport {
        writable: false,
        ..support()
    };
    let deep = r#"{"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": 1}}}}}}}}}"#;

    for (support, access, request, error_type, property) in [
        (
            &restricted,
            no_access,
            r#"{"metadata": {}, "metadata/b.example": null}"#,
            "invalidPatch",
            "metadata/b.example",
        ),
        (
            &restricted,
            no_access,
            r#"{"metadata/a.example/k~2": 1}"#,
            "invalidPatch",
            "metadata/a.example/k~2",
        ),
        (
            &restricted,
            no_access,
            r#"{"metadata/b.example/k": 1}"#,
            "forbidden",
            "metadata",
        ),
        (
            &support(),
            read_only,
            &format!(r#"{{"metadata/missing.example/k": {deep}}}"#),
            "forbidden",
            "metadata",
        ),
        (
            &restricted,
            no_access,
            r#"{"privateMetadata/a.example": {}}"#,
            "forbidden",
            "privateMetadata",
        ),
        (
            &restricted,
            read_only,
            r#"{"metadata/a.example": {}}"#,
            "forbidden",
            "metadata",
        ),
        (
            &not_writable,
            FULL_ACCESS,
            r#"{"metadata/a.example": {}, "privateMetadata/a.example": {}}"#,
            "forbidden",
            "metadata",
        ),
        (
            &restricted,
            FULL_ACCESS,
            r#"{"privateMetadata/Bad Name": {}}"#,
            "invalidProperties",
            "privateMetadata",
        ),
        (
            &support(),
            FULL_ACCESS,
            &format!(r#"{{"metadata/bad..name": {deep}}}"#),
            "invalidProperties",
            "metadata/bad..name",
        ),
        (
            &support(),
            FULL_ACCESS,
            r#"{"metadata/unregistered": {}}"#,
            "invalidProperties",
            "metadata/unregistered",
        ),
        (
            &restricted,
            FULL_ACCESS,
            r#"{"metadata/b.example/k": 1}"#,
            "invalidProperties",
            "metadata/b.example",
        ),
        (
            &support(),
            FULL_ACCESS,
            &format!(r#"{{"metadata/0.example": {deep}, "metadata/a.example/k/x": 1}}"#),
            "invalidPatch",
            "metadata/a.example/k/x",
        ),
        (
            &support(),
            FULL_ACCESS,
            &format!(r#"{{"metadata/a.example/list": [{deep}], "metadata/a.example/k/x": 1}}"#),
            "invalidPatch",
            "metadata/a.example/k/x",
        ),
        (
            &support(),
            FULL_ACCESS,
            &format!(r#"{{"metadata/b.example": {{"text": "a\u0001b", "deep": {deep}}}}}"#),
            "invalidProperties",
            "metadata/b.example",
        ),
    ] {
        assert_error(
            update_with(support, access, request, Some(&current), None),
            error_type,
            property,
        );
    }

    let result = update_with(
        &support(),
        FULL_ACCESS,
        &format!(r#"{{"metadata/b.example": {{"text": "a\u0001b", "deep": {deep}}}}}"#),
        Some(&current),
        None,
    );
    let description = result
        .err()
        .and_then(|error| error.description().map(str::to_string));
    assert!(
        description
            .as_deref()
            .is_some_and(|text| text.contains("depth")),
        "{description:?}"
    );

    let result = update_with(
        &support(),
        read_only,
        r#"{"privateMetadata/a.example": {"k": 1}}"#,
        None,
        None,
    )
    .expect("private writes need read access only");
    assert_eq!(private_json(&result), json(r#"{"a.example": {"k": 1}}"#));
}

#[test]
fn rights_are_checked_before_containers_are_needed() {
    let patches = |json: &str| {
        patches_of::<MailboxProperty, MailboxValue>(MetadataPatches::for_update(), json)
            .expect("valid patches")
    };
    let no_access = MetadataAccess {
        may_write_shared: false,
        may_read: false,
    };

    let result = patches(r#"{"metadata/missing.example/k": 1}"#)
        .validate::<MailboxProperty>(&support(), no_access)
        .map(|_| ());
    match result {
        Err(error) => assert_eq!(
            super::error_json(error),
            json(r#"{"type": "forbidden", "properties": ["metadata"]}"#)
        ),
        Ok(()) => panic!("expected forbidden"),
    }

    let validated = patches(r#"{"metadata/missing.example/k": 1, "privateMetadata": {}}"#)
        .validate::<MailboxProperty>(&support(), FULL_ACCESS)
        .expect("container-free checks pass");
    assert!(validated.has_shared() && validated.has_private());
    assert_error(
        validated.apply::<MailboxProperty>(None, None),
        "invalidPatch",
        "metadata/missing.example/k",
    );

    let validated = patches(r#"{"metadata/a.example/k": 2}"#)
        .validate::<MailboxProperty>(&support(), FULL_ACCESS)
        .expect("container-free checks pass");
    assert!(validated.has_shared() && !validated.has_private());
    let current = container(r#"{"a.example": {"k": 1}}"#);
    let result = validated
        .apply::<MailboxProperty>(Some(&current), None)
        .expect("valid patch");
    assert_eq!(shared_json(&result), json(r#"{"a.example": {"k": 2}}"#));
}

#[test]
fn withdrawn_namespaces() {
    let withdrawn = MetadataSupport {
        vendor_namespaces: false,
        ..support()
    };
    let current = container(r#"{"a.example": {"k": 1, "list": [1.5, "x"]}, "b.example": {}}"#);
    let apply = |request: &str| update_with(&withdrawn, FULL_ACCESS, request, Some(&current), None);

    let result = apply(r#"{"metadata/a.example": null}"#).expect("removal allowed");
    assert_eq!(shared_json(&result), json(r#"{"b.example": {}}"#));
    let result = apply(r#"{"metadata": {}}"#).expect("replacement dropping it allowed");
    assert!(result.shared().expect("changed").next().is_none());
    let result = apply(r#"{"metadata": {"b.example": {}}}"#).expect("replacement dropping one");
    assert_eq!(shared_json(&result), json(r#"{"b.example": {}}"#));
    assert!(
        apply(r#"{"metadata": {"a.example": {"k": 1, "list": [1.5, "x"]}, "b.example": {}}}"#)
            .expect("unchanged withdrawn namespaces are kept")
            .is_empty()
    );
    let result =
        apply(r#"{"metadata": {"b.example": {}, "a.example": {"k": 1, "list": [1.5, "x"]}}}"#)
            .expect("member order does not matter");
    assert!(result.is_empty());

    for (request, property) in [
        (r#"{"metadata/a.example": {"k": 2}}"#, "metadata/a.example"),
        (r#"{"metadata/a.example/k": null}"#, "metadata/a.example"),
        (r#"{"metadata/a.example/k": 2}"#, "metadata/a.example"),
        (r#"{"metadata/z.example/k": 2}"#, "metadata/z.example"),
        (
            r#"{"metadata": {"a.example": {"k": 2, "list": [1.5, "x"]}}}"#,
            "metadata/a.example",
        ),
        (
            r#"{"metadata": {"a.example": {"list": [1.5, "x"], "k": 1}}}"#,
            "metadata/a.example",
        ),
        (r#"{"metadata": {"z.example": {}}}"#, "metadata/z.example"),
        (
            r#"{"metadata": {"b.example": {}, "z.example": {}}}"#,
            "metadata/z.example",
        ),
    ] {
        assert_error(apply(request), "invalidProperties", property);
    }
    assert_error(
        update_with(
            &withdrawn,
            FULL_ACCESS,
            r#"{"metadata": {"a.example": {}}}"#,
            None,
            None,
        ),
        "invalidProperties",
        "metadata/a.example",
    );
    assert_error(
        apply(r#"{"metadata/bad..name": null}"#),
        "invalidProperties",
        "metadata/bad..name",
    );
    assert!(
        apply(r#"{"metadata/unregistered": null}"#)
            .expect("no-op")
            .is_empty()
    );
}

#[test]
fn server_limits() {
    let limited = MetadataSupport {
        limits: types::metadata::MetadataLimits {
            max_depth: Some(2),
            max_entry_size: 64,
            max_size: 160,
            max_private_size: 48,
            max_entries: 3,
        },
        ..support()
    };
    let apply = |request: &str, current: Option<&store::write::metadata::MetadataBuf>| {
        update_with(&limited, FULL_ACCESS, request, current, None)
    };

    assert!(apply(r#"{"metadata/a.example": {"b": {"c": 1}}}"#, None).is_ok());
    for (request, property) in [
        (
            r#"{"metadata/a.example": {"b": {"c": {}}}}"#,
            "metadata/a.example",
        ),
        (
            r#"{"metadata/a.example": {"b": [{"c": {}}]}}"#,
            "metadata/a.example",
        ),
        (
            r#"{"metadata/a.example": {"b": "0123456789012345678901234567890123456789012345678901234567890123"}}"#,
            "metadata/a.example",
        ),
        (
            r#"{"metadata/a.example": {"b\u0000": 1}}"#,
            "metadata/a.example",
        ),
        (
            r#"{"metadata/a.example": {"b": "\u007f"}}"#,
            "metadata/a.example",
        ),
        (
            r#"{"metadata/a.example": {}, "metadata/b.example": {}, "metadata/c.example": {}, "metadata/d.example": {}}"#,
            "metadata",
        ),
        (
            r#"{"privateMetadata/a.example": {"b": "01234567890123456789012345678901234567890123"}}"#,
            "privateMetadata",
        ),
    ] {
        assert_error(apply(request, None), "invalidProperties", property);
    }
    assert!(apply(r#"{"metadata/a.example": {"tab": "a\tb\r\n"}}"#, None).is_ok());

    let nested = container(r#"{"a.example": {"b": {}}}"#);
    assert_error(
        apply(r#"{"metadata/a.example/b/c": {"d": 1}}"#, Some(&nested)),
        "invalidProperties",
        "metadata/a.example",
    );

    let oversized = container(
        r#"{"a.example": {"k": 1}, "b.example": {"k": 2}, "c.example": {"k": 3}, "d.example": {"k": 4}, "e.example": {"k": 5}}"#,
    );
    let result = apply(r#"{"metadata/e.example": null}"#, Some(&oversized))
        .expect("shrinking an oversized container is allowed");
    assert_eq!(
        shared_json(&result),
        json(
            r#"{"a.example": {"k": 1}, "b.example": {"k": 2}, "c.example": {"k": 3}, "d.example": {"k": 4}}"#
        )
    );
    assert!(apply(r#"{"metadata/e.example/k": 6}"#, Some(&oversized)).is_ok());
    assert_error(
        apply(r#"{"metadata/f.example": {}}"#, Some(&oversized)),
        "invalidProperties",
        "metadata",
    );
    assert!(
        apply(
            r#"{"metadata/e.example/k": "a longer value"}"#,
            Some(&oversized)
        )
        .is_ok()
    );
}

#[test]
fn pointer_items_after_the_root_are_opaque() {
    let result = update(
        r#"{"metadata/1.example": {"0": {"7": "x"}}, "privateMetadata/b.example": {"id": "a"}}"#,
        None,
    )
    .expect("valid update");
    assert_eq!(
        shared_json(&result),
        json(r#"{"1.example": {"0": {"7": "x"}}}"#)
    );
    let current = container(r#"{"1.example": {"0": {"7": "x"}}}"#);
    let result = update(r#"{"metadata/1.example/0/7": "y"}"#, Some(&current)).expect("valid patch");
    assert_eq!(
        shared_json(&result),
        json(r#"{"1.example": {"0": {"7": "y"}}}"#)
    );
}

#[test]
fn preloaded_containers_by_document() {
    let first = container(r#"{"a.example": {"k": 1}}"#);
    let second = container(r#"{"b.example": {"k": 2}}"#);
    let containers = crate::api::metadata::MetadataContainers::new(vec![
        (9, second.clone()),
        (2, first.clone()),
    ]);
    assert_eq!(containers.len(), 2);
    assert_eq!(containers.get(2), Some(&first));
    assert_eq!(containers.get(9), Some(&second));
    assert_eq!(containers.get(5), None);

    let result = update(r#"{"metadata/a.example/k": 3}"#, containers.get(2)).expect("valid patch");
    assert_eq!(shared_json(&result), json(r#"{"a.example": {"k": 3}}"#));
}

#[test]
fn vendor_namespaces_must_be_lowercase() {
    for request in [
        r#"{"metadata/Acme.example": {}}"#,
        r#"{"metadata/acme.EXAMPLE/k": 1}"#,
        r#"{"metadata/Acme.example": null}"#,
        r#"{"metadata": {"Acme.example": {}}}"#,
    ] {
        let result = update(request, None);
        let Err(error) = result else {
            panic!("{request} was accepted");
        };
        assert_eq!(
            super::error_json(error)["type"],
            serde_json::Value::from("invalidProperties"),
            "{request}"
        );
    }
    assert!(update(r#"{"metadata/acme.example": {}}"#, None).is_ok());
}

#[test]
fn private_writes_need_only_the_private_permission() {
    let read_only_token = MetadataSupport {
        writable: false,
        ..support()
    };
    let access = MetadataAccess {
        may_write_shared: true,
        may_read: true,
    };
    let result = update_with(
        &read_only_token,
        access,
        r#"{"privateMetadata/a.example": {"k": 1}}"#,
        None,
        None,
    )
    .expect("private writes do not need jmapMetadataSet");
    assert_eq!(private_json(&result), json(r#"{"a.example": {"k": 1}}"#));
    assert_error(
        update_with(
            &read_only_token,
            access,
            r#"{"metadata/a.example": {"k": 1}}"#,
            None,
            None,
        ),
        "forbidden",
        "metadata",
    );

    let no_private = MetadataSupport {
        private: false,
        ..support()
    };
    assert_error(
        update_with(
            &no_private,
            access,
            r#"{"privateMetadata/a.example": {"k": 1}}"#,
            None,
            None,
        ),
        "invalidProperties",
        "privateMetadata",
    );
}

#[test]
fn removal_patches_at_any_depth_are_removal_only() {
    let current = container_with_imap(
        r#"{"a.example": {"x": 1, "y": {"b": 2, "c": 3}}, "b.example": {"z": 3}}"#,
        &[("/comment", "kept")],
    );
    for (patch, expected) in [
        (r#"{"metadata/a.example": null}"#, MetadataEdit::RemovalOnly),
        (r#"{"metadata": null}"#, MetadataEdit::RemovalOnly),
        (r#"{"metadata": {}}"#, MetadataEdit::RemovalOnly),
        (
            r#"{"metadata/a.example/x": null}"#,
            MetadataEdit::RemovalOnly,
        ),
        (
            r#"{"metadata/a.example/y/b": null}"#,
            MetadataEdit::RemovalOnly,
        ),
        (
            r#"{"metadata/a.example/y/b": null, "metadata/b.example": null}"#,
            MetadataEdit::RemovalOnly,
        ),
        (
            r#"{"metadata/a.example": null, "metadata/b.example": {"z": 3}}"#,
            MetadataEdit::Write,
        ),
        (
            r#"{"metadata/a.example/x": null, "metadata/a.example/y/c": 4}"#,
            MetadataEdit::Write,
        ),
        (
            r#"{"metadata/a.example/y": {"b": null}}"#,
            MetadataEdit::Write,
        ),
        (r#"{"metadata/b.example": {"z": 4}}"#, MetadataEdit::Write),
        (r#"{"metadata/c.example": {}}"#, MetadataEdit::Write),
        (
            r#"{"metadata": {"b.example": {"z": 3}}}"#,
            MetadataEdit::Write,
        ),
    ] {
        let result = update(patch, Some(&current)).expect("valid patch");
        let change = result.shared().expect("changed");
        assert!(change.next().is_some(), "{patch}");
        assert_eq!(change.edit(), expected, "{patch}");
    }

    let private = container(r#"{"a.example": {"x": 1, "y": {"b": 2}}, "b.example": {"z": 3}}"#);
    for (patch, expected) in [
        (
            r#"{"privateMetadata/a.example/y/b": null}"#,
            MetadataEdit::RemovalOnly,
        ),
        (
            r#"{"privateMetadata/b.example": null}"#,
            MetadataEdit::RemovalOnly,
        ),
        (r#"{"privateMetadata/a.example/x": 2}"#, MetadataEdit::Write),
    ] {
        let result =
            update_with(&support(), FULL_ACCESS, patch, None, Some(&private)).expect("valid patch");
        let change = result.private().expect("changed");
        assert!(change.next().is_some(), "{patch}");
        assert_eq!(change.edit(), expected, "{patch}");
    }
}

#[test]
fn deep_removal_that_decompresses_the_container_is_removal_only() {
    let kept = "b".repeat(600);
    let removed = "a".repeat(600);
    let encoded = encode(
        &format!(r#"{{"a.example": {{"kept": "{kept}", "removed": "{removed}"}}}}"#),
        &[],
    )
    .expect("non-empty container");
    let current = MetadataBuf::read(
        &StoredMetadata::new(encoded)
            .expect("serializable")
            .into_bytes(),
    )
    .expect("readable");

    let result =
        update(r#"{"metadata/a.example/removed": null}"#, Some(&current)).expect("valid patch");
    let change = result.shared().expect("changed");
    let previous = change.previous().expect("previous container").size;
    let next = change.next().expect("remaining entries");

    assert_eq!(change.edit(), MetadataEdit::RemovalOnly);
    assert!(current.view().as_bytes().len() >= METADATA_COMPRESS_WATERMARK);
    assert!(next.len() < METADATA_COMPRESS_WATERMARK);
    assert!(
        u32::try_from(next.len() + STORAGE_TRAILER_CAPACITY).expect("small container") > previous
    );
}
