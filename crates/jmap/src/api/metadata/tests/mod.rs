/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod get;
mod object;
mod query;
mod set;

use super::{MetadataAccess, MetadataPatches, MetadataSupport, MetadataType, MetadataUpdate};
use jmap_proto::{
    error::set::SetError,
    object::{
        mailbox::{MailboxProperty, MailboxValue},
        metadata::MetadataProperty,
    },
};
use jmap_tools::{Element, Key, Null, Value};
use std::borrow::Cow;
use store::write::metadata::MetadataBuf;
use types::metadata::{
    EncodedJson, EncodedMetadata, MetadataBuilder, MetadataLimits, MetadataView, Namespace,
};

const FULL_ACCESS: MetadataAccess = MetadataAccess {
    may_write_shared: true,
    may_read: true,
};

fn support() -> MetadataSupport {
    MetadataSupport {
        object: MetadataType::Mailbox,
        vendor_namespaces: true,
        private: true,
        writable: true,
        limits: MetadataLimits::default(),
        query_max_scan: 50_000,
    }
}

fn encode(json: &str, imap: &[(&str, &str)]) -> Option<EncodedMetadata> {
    let value = Value::<Null, Null>::parse_json(json).expect("valid JSON");
    let mut builder = MetadataBuilder::new();
    for (namespace, value) in value.as_object().expect("object").iter() {
        let Key::Borrowed(name) = namespace else {
            panic!("unexpected key {namespace:?}");
        };
        builder.set_jmap(
            Namespace::parse(name).expect("valid namespace"),
            EncodedJson::encode_namespace(value).expect("encodable"),
        );
    }
    for (name, value) in imap {
        builder.set_imap(Cow::Borrowed(*name), value.as_bytes());
    }
    builder.encode()
}

fn container(json: &str) -> MetadataBuf {
    container_with_imap(json, &[])
}

fn container_with_imap(json: &str, imap: &[(&str, &str)]) -> MetadataBuf {
    let encoded = encode(json, imap).expect("non-empty container");
    MetadataBuf::from_view(
        &encoded.view(),
        u32::try_from(encoded.len() + 5).expect("small container"),
        0,
    )
}

fn view_json(view: &MetadataView<'_>) -> serde_json::Value {
    serde_json::Value::Object(
        view.jmap()
            .map(|(namespace, value)| {
                (
                    namespace.name().to_string(),
                    serde_json::to_value(value.to_value::<Null, Null>().expect("decodable"))
                        .expect("serializable"),
                )
            })
            .collect(),
    )
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("valid JSON")
}

fn patches_of<P, E>(
    mut patches: MetadataPatches,
    json: &str,
) -> Result<MetadataPatches, SetError<P>>
where
    P: MetadataProperty,
    E: Element<Property = P>,
{
    let object = Value::<P, E>::parse_json(json).expect("valid JSON");
    for (key, value) in object.into_expanded_object() {
        let Key::Property(property) = key else {
            panic!("untyped key {key:?}");
        };
        patches.push(&property, value)?;
    }
    Ok(patches)
}

fn update_with(
    support: &MetadataSupport,
    access: MetadataAccess,
    json: &str,
    shared: Option<&MetadataBuf>,
    private: Option<&MetadataBuf>,
) -> Result<MetadataUpdate, SetError<MailboxProperty>> {
    patches_of::<MailboxProperty, MailboxValue>(MetadataPatches::for_update(), json)?
        .apply(support, access, shared, private)
}

fn update(
    json: &str,
    shared: Option<&MetadataBuf>,
) -> Result<MetadataUpdate, SetError<MailboxProperty>> {
    update_with(&support(), FULL_ACCESS, json, shared, None)
}

fn error_json<P: MetadataProperty>(error: SetError<P>) -> serde_json::Value {
    let mut value = serde_json::to_value(error).expect("serializable");
    if let Some(object) = value.as_object_mut() {
        object.remove("description");
    }
    value
}

fn assert_error<P: MetadataProperty>(
    result: Result<MetadataUpdate, SetError<P>>,
    error_type: &str,
    property: &str,
) {
    match result {
        Ok(update) => panic!("expected {error_type} on {property}, got {update:?}"),
        Err(error) => assert_eq!(
            error_json(error),
            serde_json::json!({"type": error_type, "properties": [property]}),
        ),
    }
}

fn shared_json(update: &MetadataUpdate) -> serde_json::Value {
    let change = update.shared().expect("shared change");
    change
        .next()
        .map_or_else(|| json("{}"), |next| view_json(&next.view()))
}

fn private_json(update: &MetadataUpdate) -> serde_json::Value {
    let change = update.private().expect("private change");
    change
        .next()
        .map_or_else(|| json("{}"), |next| view_json(&next.view()))
}
