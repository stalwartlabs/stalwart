/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{container, json, support};
use crate::api::metadata::{
    MetadataDocuments, MetadataGet, MetadataSupport, MetadataValues, get::push_output,
    select_properties,
};
use jmap_proto::{
    method::get::GetRequest,
    object::{
        mailbox::{Mailbox, MailboxProperty, MailboxValue},
        metadata::{MetadataSelection, Selection},
    },
    request::capability::{Capability, CapabilityIds},
};
use jmap_tools::{Key, Map, Value};
use types::metadata::MetadataKinds;

type Outputs = Vec<(u32, Value<'static, MailboxProperty, MailboxValue>)>;

fn selection(names: &[&str]) -> Selection {
    let mut names = names.iter().map(|name| (*name).into()).collect::<Vec<_>>();
    names.sort_unstable();
    Selection::Namespaces(names)
}

fn object_json(object: Map<'static, MailboxProperty, MailboxValue>) -> serde_json::Value {
    serde_json::to_value(Value::Object(object)).expect("serializable")
}

#[test]
fn draft_fetch_mailbox_with_metadata() {
    let mut request = serde_json::from_str::<GetRequest<Mailbox>>(
        r#"{
            "accountId": "a",
            "ids": ["a"],
            "properties": ["id", "name", "metadata/acme.example.com", "privateMetadata/acme.example.com"]
        }"#,
    )
    .expect("valid request");
    let (properties, selection) = select_properties(
        &mut request,
        &[MailboxProperty::Id],
        CapabilityIds::default(),
    )
    .expect("valid properties");
    assert_eq!(properties, vec![MailboxProperty::Id, MailboxProperty::Name]);

    let get = MetadataGet::new(Some(&support()), selection).expect("metadata selected");
    let shared = container(
        r#"{"acme.example.com": {"color": "blue", "owner": "team-alpha"}, "other.example": {"x": 1}}"#,
    );
    let private = container(r#"{"acme.example.com": {"workflowState": "pending-review"}}"#);

    let mut shared_outputs = Outputs::new();
    push_output(&get.shared, 1, &shared.view(), &mut shared_outputs);
    let mut private_outputs = Outputs::new();
    push_output(&get.private, 1, &private.view(), &mut private_outputs);
    let mut values = MetadataValues::new(Some(shared_outputs), Some(private_outputs), Vec::new());

    let mut object = Map::with_capacity(4);
    object.insert_unchecked(
        Key::Property(MailboxProperty::Name),
        Value::Str("Team Inbox".into()),
    );
    values.insert_into(1, &mut object);
    assert_eq!(
        object_json(object),
        json(
            r#"{
                "name": "Team Inbox",
                "metadata": {"acme.example.com": {"color": "blue", "owner": "team-alpha"}},
                "privateMetadata": {"acme.example.com": {"workflowState": "pending-review"}}
            }"#
        )
    );

    let mut object = Map::new();
    values.insert_into(2, &mut object);
    assert_eq!(
        object_json(object),
        json(r#"{"metadata": {}, "privateMetadata": {}}"#)
    );
}

#[test]
fn default_properties_follow_using() {
    let using = [Capability::Core, Capability::Mail, Capability::Metadata]
        .into_iter()
        .collect::<CapabilityIds>();
    let without = [Capability::Core, Capability::Mail]
        .into_iter()
        .collect::<CapabilityIds>();
    let request = |properties: &str| {
        serde_json::from_str::<GetRequest<Mailbox>>(&format!(r#"{{"accountId": "a"{properties}}}"#))
            .expect("valid request")
    };

    for (properties, using, expected) in [
        ("", using, MetadataSelection::all()),
        (r#", "properties": null"#, using, MetadataSelection::all()),
        ("", without, MetadataSelection::default()),
        (
            r#", "properties": ["metadata"]"#,
            without,
            MetadataSelection {
                shared: Selection::All,
                private: Selection::None,
            },
        ),
        (
            r#", "properties": ["name"]"#,
            using,
            MetadataSelection::default(),
        ),
    ] {
        let mut request = request(properties);
        let (list, selection) = select_properties(
            &mut request,
            &[MailboxProperty::Id, MailboxProperty::Name],
            using,
        )
        .expect("valid properties");
        assert_eq!(selection, expected, "{properties}");
        assert!(list.contains(&MailboxProperty::Id), "{properties}");
    }

    let mut request = request(r#", "properties": ["metadata/a/b"]"#);
    assert!(select_properties(&mut request, &[], using).is_err());
}

#[test]
fn selection_resolution() {
    let no_private = MetadataSupport {
        private: false,
        ..support()
    };
    assert_eq!(MetadataGet::new(None, MetadataSelection::all()), None);
    assert_eq!(
        MetadataGet::new(Some(&support()), MetadataSelection::default()),
        None
    );
    assert_eq!(
        MetadataGet::new(
            Some(&no_private),
            MetadataSelection {
                shared: Selection::None,
                private: Selection::All,
            }
        ),
        None
    );
    let get = MetadataGet::new(Some(&no_private), MetadataSelection::all()).expect("selected");
    assert!(get.wants_shared() && !get.wants_private());

    let mut values =
        MetadataValues::<MailboxProperty, MailboxValue>::new(Some(Vec::new()), None, Vec::new());
    let mut object = Map::new();
    values.insert_into(7, &mut object);
    assert_eq!(object_json(object), json(r#"{"metadata": {}}"#));
}

#[test]
fn subselectors_and_withdrawn_namespaces() {
    let stored = container(
        r#"{"a.example": {"k": 1}, "b.example": {"k": 2}, "withdrawn.example": {"k": 3}}"#,
    );
    let view = stored.view();

    let uppercase = MetadataGet::new(
        Some(&support()),
        MetadataSelection {
            shared: selection(&["Upper.example", "upper.example"]),
            private: Selection::None,
        },
    )
    .expect("selected");
    assert_eq!(uppercase.shared, selection(&["upper.example"]));
    let stored_upper = container(r#"{"b.example": {"k": 1}}"#);
    let mut outputs = Outputs::new();
    push_output(&uppercase.shared, 3, &stored_upper.view(), &mut outputs);
    assert!(outputs.is_empty());

    for (selection, expected) in [
        (
            Selection::All,
            Some(
                r#"{"a.example": {"k": 1}, "b.example": {"k": 2}, "withdrawn.example": {"k": 3}}"#,
            ),
        ),
        (
            selection(&["b.example", "missing.example", "bad name"]),
            Some(r#"{"b.example": {"k": 2}}"#),
        ),
        (
            selection(&["withdrawn.example"]),
            Some(r#"{"withdrawn.example": {"k": 3}}"#),
        ),
        (selection(&["missing.example", "photography"]), None),
    ] {
        let mut outputs = Outputs::new();
        push_output(&selection, 3, &view, &mut outputs);
        match expected {
            Some(expected) => {
                let [(3, value)] = outputs.as_slice() else {
                    panic!("unexpected outputs {outputs:?}");
                };
                assert_eq!(
                    serde_json::to_value(value).expect("serializable"),
                    json(expected)
                );
            }
            None => assert!(outputs.is_empty(), "{outputs:?}"),
        }
    }
}

#[test]
fn repeated_ids_keep_their_values() {
    let stored = container(r#"{"a.example": {"k": "v"}}"#);
    let mut documents = MetadataDocuments::default();
    for document_id in [4, 9, 4] {
        documents.insert(document_id, MetadataKinds::JMAP);
    }
    documents.insert(5, MetadataKinds::DAV);
    assert_eq!(documents.shared().iter().collect::<Vec<_>>(), [4, 9]);
    assert_eq!(documents.requested().iter().collect::<Vec<_>>(), [4, 5, 9]);

    let mut outputs = Outputs::new();
    push_output(&Selection::All, 9, &stored.view(), &mut outputs);
    push_output(&Selection::All, 4, &stored.view(), &mut outputs);
    let mut values = MetadataValues::new(Some(outputs), None, documents.repeated.clone());

    for (document_id, expected) in [
        (4, r#"{"metadata": {"a.example": {"k": "v"}}}"#),
        (9, r#"{"metadata": {"a.example": {"k": "v"}}}"#),
        (4, r#"{"metadata": {"a.example": {"k": "v"}}}"#),
        (5, r#"{"metadata": {}}"#),
    ] {
        let mut object = Map::new();
        values.insert_into(document_id, &mut object);
        assert_eq!(object_json(object), json(expected), "{document_id}");
    }
}
