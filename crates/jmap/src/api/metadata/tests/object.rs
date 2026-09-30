/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{container_with_imap, encode, error_json};
use crate::api::metadata::{
    ContainerChange, MetadataPatches, MetadataPreload, PreparedMetadata, filter_containers,
    is_empty_update, prepared::SharedWrite, reject_uncommitted,
};
use common::storage::{
    dav::{DISPLAY_NAME_PROPERTY, FilePresence},
    metadata::{MetadataLog, PrivateMetadataCommit, PrivateMetadataWrite, StoredContainer},
};
use jmap_proto::{
    error::set::SetError,
    method::{query::Filter, set::SetResponse},
    object::{
        calendar::{Calendar, CalendarFilter, CalendarProperty, CalendarValue},
        metadata::{MetadataCondition, MetadataFilter, MetadataPath, MetadataRoot},
    },
    request::MaybeInvalid,
};
use jmap_tools::{Key, Value};
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, Operation, PendingId, ValueClass, ValueOp, metadata::MetadataClass},
};
use types::{
    collection::Collection,
    id::Id,
    metadata::{EncodedMetadata, MetadataBuilder, MetadataEdit, MetadataKinds, XmlName, XmlValue},
};
use utils::map::vec_map::VecMap;

type CalendarObject<'x> = Value<'x, CalendarProperty, CalendarValue>;

fn object(json: &str) -> CalendarObject<'_> {
    CalendarObject::parse_json(json).expect("valid JSON")
}

fn keys(object: &CalendarObject<'_>) -> Vec<String> {
    object
        .as_object()
        .expect("object")
        .keys()
        .map(|key| key.to_string().into_owned())
        .collect()
}

fn error_type(error: SetError<CalendarProperty>) -> serde_json::Value {
    serde_json::to_value(error).expect("serializable")["type"].clone()
}

fn shared_write(next: Option<EncodedMetadata>) -> SharedWrite {
    SharedWrite {
        account_id: 1,
        tenant_id: None,
        collection: Collection::FileNode,
        log: MetadataLog::Item { prefix: None },
        change: ContainerChange::new(None, next, MetadataEdit::Write),
    }
}

#[test]
fn extract_splits_metadata_keys() {
    let mut plain = object(r#"{"name": "Work", "sortOrder": 1}"#);
    assert!(
        MetadataPatches::for_update()
            .extract(&mut plain)
            .expect("valid")
            .is_none()
    );
    assert_eq!(keys(&plain), ["name", "sortOrder"]);

    let mut mixed = object(
        r#"{"name": "Work", "metadata/x.example/k": 1, "privateMetadata": {"y.example": {}}, "color": "red"}"#,
    );
    let patches = MetadataPatches::for_update()
        .extract(&mut mixed)
        .expect("valid")
        .expect("metadata present");
    assert!(patches.has_shared());
    assert!(patches.has_private());
    assert_eq!(keys(&mixed), ["name", "color"]);

    let mut only_metadata = object(r#"{"metadata": {"x.example": {"k": 1}}}"#);
    let patches = MetadataPatches::for_create()
        .extract(&mut only_metadata)
        .expect("valid")
        .expect("metadata present");
    assert!(patches.has_shared() && !patches.has_private());
    assert!(
        only_metadata
            .as_object()
            .is_some_and(|object| object.is_empty())
    );

    let mut invalid = object(r#"{"name": "Work", "metadata": null}"#);
    let error = MetadataPatches::for_create()
        .extract(&mut invalid)
        .expect_err("null metadata on create");
    assert_eq!(error_type(error), "invalidProperties");

    let mut not_an_object = CalendarObject::Null;
    assert!(
        MetadataPatches::for_update()
            .extract(&mut not_an_object)
            .expect("valid")
            .is_none()
    );
}

#[test]
fn unsupported_metadata_lists_every_key_as_sent() {
    let plain = object(r#"{"name": "Work", "sortOrder": 1}"#);
    assert!(MetadataPatches::reject_unsupported(&plain).is_ok());
    assert!(MetadataPatches::reject_unsupported(&CalendarObject::Null).is_ok());

    let sent = r#"{"name": "Work", "metadata/x.example/a": 1, "privateMetadata": {"y.example": {}}, "metadata/a~1b": {}}"#;
    let expected = serde_json::json!({
        "type": "invalidProperties",
        "properties": ["metadata/x.example/a", "privateMetadata", "metadata/a~1b"]
    });
    let error = MetadataPatches::reject_unsupported(&object(sent))
        .expect_err("metadata keys without support");
    assert_eq!(error_json(error), expected);

    let patches = MetadataPatches::for_update()
        .extract(&mut object(sent))
        .expect("valid")
        .expect("metadata present");
    assert_eq!(
        error_json(patches.unsupported::<CalendarProperty>()),
        expected
    );
}

#[test]
fn empty_update_allows_only_the_matching_id() {
    let id = Id::from(7u32);
    let is_empty = |json: &str| {
        let mut update = object(json);
        MetadataPatches::for_update()
            .extract(&mut update)
            .expect("valid");
        update
            .as_object()
            .is_some_and(|update| is_empty_update::<Calendar>(update, id))
    };

    assert!(is_empty(r#"{}"#));
    assert!(is_empty(r#"{"metadata/x.example/k": 1}"#));
    assert!(is_empty(&format!(
        r#"{{"id": "{id}", "metadata/x.example/k": 1}}"#
    )));
    assert!(!is_empty(&format!(
        r#"{{"id": "{}", "metadata/x.example/k": 1}}"#,
        Id::from(8u32)
    )));
    assert!(!is_empty(r#"{"id": null, "metadata/x.example/k": 1}"#));
    assert!(!is_empty(r#"{"name": "Work", "metadata/x.example/k": 1}"#));
    assert!(!is_empty(&format!(
        r#"{{"id": "{id}", "sortOrder": 1, "privateMetadata": {{}}}}"#
    )));
}

#[test]
fn preload_follows_roots_and_stored_flags() {
    let mut update = object(r#"{"metadata/x.example/k": 1, "privateMetadata": {}}"#);
    let patches = MetadataPatches::for_update()
        .extract(&mut update)
        .expect("valid")
        .expect("metadata present");
    let mut preload = MetadataPreload::default();
    assert!(preload.is_empty());
    preload.insert(1, &patches, MetadataKinds::DAV);
    preload.insert(2, &patches, MetadataKinds::NONE);
    preload.insert_source(3, MetadataKinds::JMAP);
    preload.insert_source(4, MetadataKinds::NONE);
    assert_eq!(preload.shared.iter().collect::<Vec<_>>(), [1, 3]);
    assert_eq!(preload.private.iter().collect::<Vec<_>>(), [1, 2, 3, 4]);

    let updates = VecMap::from_iter([
        (
            MaybeInvalid::Value(Id::from(5u32)),
            object(r#"{"metadata/x.example": {}}"#),
        ),
        (
            MaybeInvalid::Value(Id::from(6u32)),
            object(r#"{"name": "Work"}"#),
        ),
        (
            MaybeInvalid::Value(Id::from(9u32)),
            object(r#"{"privateMetadata/x.example": {}}"#),
        ),
    ]);
    let preload = MetadataPreload::from_updates(Some(&updates), |document_id| {
        (document_id != 9).then_some(MetadataKinds::JMAP)
    });
    assert_eq!(preload.shared.iter().collect::<Vec<_>>(), [5]);
    assert!(preload.private.is_empty());
}

#[test]
fn prepared_file_presence_follows_the_next_container() {
    let value = XmlValue::default();
    let mut builder = MetadataBuilder::new();
    builder
        .set_dav(DISPLAY_NAME_PROPERTY, &value)
        .expect("valid entry");
    let named = builder.encode().expect("non-empty");
    builder
        .set_dav(XmlName::borrowed(Some("urn:x"), "color"), &value)
        .expect("valid entry");
    let dead = builder.encode().expect("non-empty");

    let presence = |next| {
        PreparedMetadata {
            shared: Some(shared_write(next)),
            private: None,
        }
        .file_presence()
    };
    assert_eq!(presence(None), Some(FilePresence::NONE));
    assert_eq!(
        presence(Some(named)),
        Some(FilePresence::NONE.with_dav_display_name())
    );
    let dead = presence(Some(dead)).expect("shared write");
    assert!(dead.has_dav_display_name() && dead.has_dead_properties());
    assert!(!dead.kinds().intersects(MetadataKinds::JMAP));
    assert_eq!(
        presence(encode(r#"{"x.example": {}}"#, &[])),
        Some(FilePresence::from_kinds(MetadataKinds::JMAP))
    );
    assert_eq!(PreparedMetadata::default().file_presence(), None);
}

#[test]
fn prepared_writes_take_the_document_at_build_time() {
    let previous = container_with_imap(r#"{"a.example": {"k": 1}}"#, &[("/comment", "x")]);
    let prepared = PreparedMetadata {
        shared: Some(SharedWrite {
            change: ContainerChange::new(
                Some(StoredContainer::from(&previous)),
                encode(r#"{"b.example": {}}"#, &[]),
                MetadataEdit::Write,
            ),
            ..shared_write(None)
        }),
        private: Some(PrivateMetadataWrite {
            owner_id: 1,
            viewer_id: 2,
            viewer_tenant_id: None,
            collection: Collection::FileNode,
            previous: None,
            next: encode(r#"{"c.example": {}}"#, &[]),
            log: MetadataLog::Item { prefix: None },
        }),
    };
    assert!(!prepared.is_empty() && !prepared.is_private_only());
    assert_eq!(prepared.shared_kinds(), Some(MetadataKinds::JMAP));

    let mut batch = BatchBuilder::new();
    let mut commit = PrivateMetadataCommit::default();
    let presence = prepared
        .build(9u32, &mut batch, &mut commit)
        .expect("builds")
        .expect("shared presence");
    assert_eq!(
        presence.before,
        MetadataKinds::JMAP.union(MetadataKinds::IMAP)
    );
    assert_eq!(presence.after, MetadataKinds::JMAP);
    assert!(!commit.is_empty());
    let mut document_id = None;
    let mut written = Vec::new();
    for op in batch.ops() {
        match op {
            Operation::DocumentId { document_id: id } => document_id = Some(*id),
            Operation::Value {
                class:
                    ValueClass::Metadata(
                        class @ (MetadataClass::Shared | MetadataClass::Private { .. }),
                    ),
                op: ValueOp::Set(_),
            } => written.push((document_id, *class)),
            _ => {}
        }
    }
    assert_eq!(
        written,
        [
            (Some(PendingId::Assigned(9)), MetadataClass::Shared),
            (
                Some(PendingId::Assigned(9)),
                MetadataClass::Private { viewer: 2 }
            ),
        ]
    );

    let empty = PreparedMetadata::default();
    assert!(empty.is_empty() && !empty.is_private_only());
    assert_eq!(empty.shared_kinds(), None);
    let mut batch = BatchBuilder::new();
    assert_eq!(
        empty
            .build(9u32, &mut batch, &mut PrivateMetadataCommit::default())
            .expect("builds"),
        None
    );
    assert!(batch.is_empty());
}

#[test]
fn reject_uncommitted_reports_every_id() {
    let mut response = SetResponse::<Calendar> {
        account_id: None,
        old_state: None,
        new_state: None,
        created: Default::default(),
        updated: VecMap::new(),
        destroyed: Vec::new(),
        not_created: VecMap::new(),
        not_updated: VecMap::new(),
        not_destroyed: VecMap::new(),
    };
    response.updated.append(Id::from(1u32), None);
    response.destroyed.push(Id::from(2u32));

    reject_uncommitted(
        &mut response,
        ["c1".to_string(), "c2".to_string()],
        "Another process modified this calendar, please try again.",
    );

    assert!(response.updated.is_empty());
    assert!(response.destroyed.is_empty());
    assert_eq!(response.not_created.len(), 2);
    assert_eq!(response.not_updated.len(), 1);
    assert_eq!(response.not_destroyed.len(), 1);
    let value = serde_json::to_value(&response).expect("serializable");
    assert_eq!(value["notCreated"]["c1"]["type"], "forbidden");
    assert_eq!(
        value["notUpdated"][Id::from(1u32).to_string()]["type"],
        "forbidden"
    );
    assert_eq!(
        value["notDestroyed"][Id::from(2u32).to_string()]["type"],
        "forbidden"
    );
}

#[test]
fn filter_containers_evaluates_the_tree() {
    let leaf = || {
        Filter::Property(CalendarFilter::Metadata(MetadataFilter::Condition {
            root: MetadataRoot::Shared,
            path: MetadataPath {
                namespace: "x.example".into(),
                key: None,
            },
            condition: MetadataCondition::Exists,
        }))
    };
    let bitmap = |ids: &[u32]| ids.iter().copied().collect::<RoaringBitmap>();
    let readable = bitmap(&[1, 2, 3, 4]);

    assert_eq!(
        filter_containers::<CalendarFilter>(&[], Vec::new(), readable.clone()),
        readable
    );
    assert_eq!(
        filter_containers(&[leaf()], vec![bitmap(&[2, 9])], readable.clone()),
        bitmap(&[2])
    );
    assert_eq!(
        filter_containers(
            &[Filter::Or, leaf(), leaf(), Filter::Close],
            vec![bitmap(&[1]), bitmap(&[3])],
            readable.clone()
        ),
        bitmap(&[1, 3])
    );
    assert_eq!(
        filter_containers(
            &[Filter::Not, leaf(), Filter::Close],
            vec![bitmap(&[1, 2])],
            readable.clone()
        ),
        bitmap(&[3, 4])
    );
    assert_eq!(
        filter_containers(
            &[
                Filter::And,
                leaf(),
                Filter::Not,
                leaf(),
                Filter::Close,
                Filter::Close
            ],
            vec![bitmap(&[1, 2, 3]), bitmap(&[2])],
            readable
        ),
        bitmap(&[1, 3])
    );
}

#[test]
fn keys_are_typed_as_properties() {
    let object = object(r#"{"metadata/x.example": {}}"#);
    let key = object
        .as_object()
        .and_then(|object| object.keys().next())
        .expect("one key");
    assert!(matches!(key, Key::Property(CalendarProperty::Pointer(_))));
}
