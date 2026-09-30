/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    validate::ValidatedPatches,
    write::{ContainerChange, MetadataUpdate},
};
use jmap_proto::{error::set::SetError, object::metadata::MetadataProperty};
use store::write::metadata::MetadataBuf;
use types::metadata::{MetadataBuilder, MetadataEdit};

impl MetadataUpdate {
    pub fn copied(shared: Option<&MetadataBuf>, private: Option<&MetadataBuf>) -> Self {
        MetadataUpdate::new(copied(None, shared), copied(None, private))
    }
}

impl ValidatedPatches {
    pub fn apply_to_copy<P: MetadataProperty>(
        self,
        shared: Option<&MetadataBuf>,
        private: Option<&MetadataBuf>,
    ) -> Result<MetadataUpdate, SetError<P>> {
        let update = self.apply::<P>(shared, private)?;
        Ok(MetadataUpdate::new(
            copied(update.shared(), shared),
            copied(update.private(), private),
        ))
    }
}

fn copied(
    patched: Option<&ContainerChange>,
    source: Option<&MetadataBuf>,
) -> Option<ContainerChange> {
    match patched {
        Some(change) => change.next().cloned(),
        None => source.and_then(|source| MetadataBuilder::from_view(&source.view()).encode()),
    }
    .map(|next| ContainerChange::new(None, Some(next), MetadataEdit::Write))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::metadata::{MetadataAccess, MetadataPatches, MetadataSupport, MetadataType};
    use jmap_proto::object::calendar::{CalendarProperty, CalendarValue};
    use jmap_tools::{Key, Null, Value};
    use std::borrow::Cow;
    use types::metadata::{EncodedJson, MetadataKinds, MetadataLimits, Namespace};

    const FULL_ACCESS: MetadataAccess = MetadataAccess {
        may_write_shared: true,
        may_read: true,
    };

    fn support(private: bool) -> MetadataSupport {
        MetadataSupport {
            object: MetadataType::CalendarEvent,
            vendor_namespaces: true,
            private,
            writable: true,
            limits: MetadataLimits::default(),
            query_max_scan: 50_000,
        }
    }

    fn container(json: &str, imap: &[(&str, &str)]) -> MetadataBuf {
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
        let encoded = builder.encode().expect("non-empty container");
        MetadataBuf::from_view(
            &encoded.view(),
            u32::try_from(encoded.len() + 5).expect("small container"),
            7,
        )
    }

    fn create_patches(json: &str) -> MetadataPatches {
        let object =
            Value::<CalendarProperty, CalendarValue>::parse_json(json).expect("valid JSON");
        let mut patches = MetadataPatches::for_create();
        for (key, value) in object.into_expanded_object() {
            let Key::Property(property) = key else {
                panic!("untyped key {key:?}");
            };
            patches.push(&property, value).expect("valid patch");
        }
        patches
    }

    fn copy(
        patches: MetadataPatches,
        private: bool,
        shared: Option<&MetadataBuf>,
        private_source: Option<&MetadataBuf>,
    ) -> Result<MetadataUpdate, SetError<CalendarProperty>> {
        patches
            .validate::<CalendarProperty>(&support(private), FULL_ACCESS)?
            .apply_to_copy(shared, private_source)
    }

    fn jmap_json(change: &ContainerChange) -> serde_json::Value {
        let next = change.next().expect("container");
        serde_json::Value::Object(
            next.view()
                .jmap()
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

    #[test]
    fn copies_both_containers_as_new() {
        let shared = container(r#"{"a.example": {"k": 1}}"#, &[("/comment", "kept")]);
        let private = container(r#"{"p.example": {"n": "x"}}"#, &[]);
        let update = copy(
            MetadataPatches::for_create(),
            true,
            Some(&shared),
            Some(&private),
        )
        .expect("valid copy");

        let change = update.shared().expect("shared copied");
        assert!(change.previous().is_none());
        assert_eq!(
            change.next().map(|next| next.view().as_bytes()),
            Some(shared.view().as_bytes())
        );
        assert_eq!(
            change.next().map(|next| next.kinds()),
            Some(MetadataKinds::JMAP.union(MetadataKinds::IMAP))
        );

        let change = update.private().expect("private copied");
        assert!(change.previous().is_none());
        assert_eq!(
            jmap_json(change),
            serde_json::json!({"p.example": {"n": "x"}})
        );
    }

    #[test]
    fn overrides_replace_jmap_entries_only() {
        let shared = container(r#"{"a.example": {"k": 1}}"#, &[("/comment", "kept")]);
        let update = copy(
            create_patches(r#"{"metadata": {"b.example": {"k": 2}}}"#),
            true,
            Some(&shared),
            None,
        )
        .expect("valid override");
        let change = update.shared().expect("shared copied");
        assert!(change.previous().is_none());
        assert_eq!(
            jmap_json(change),
            serde_json::json!({"b.example": {"k": 2}})
        );
        assert_eq!(
            change
                .next()
                .and_then(|next| next.view().imap_entry("/comment")),
            Some(&b"kept"[..])
        );
        assert!(update.private().is_none());

        let jmap_only = container(r#"{"a.example": {"k": 1}}"#, &[]);
        let update = copy(
            create_patches(r#"{"metadata": {}}"#),
            true,
            Some(&jmap_only),
            None,
        )
        .expect("valid reset");
        assert!(update.is_empty());

        let update = copy(
            create_patches(r#"{"metadata": {"a.example": {"k": 1}}}"#),
            true,
            Some(&jmap_only),
            None,
        )
        .expect("identical override");
        assert_eq!(
            update
                .shared()
                .and_then(|change| change.next())
                .map(|next| next.view().as_bytes()),
            Some(jmap_only.view().as_bytes())
        );
    }

    #[test]
    fn copies_without_sources_or_private_support() {
        assert!(
            copy(MetadataPatches::for_create(), true, None, None)
                .expect("nothing to copy")
                .is_empty()
        );

        let update = copy(
            create_patches(r#"{"privateMetadata": {"p.example": {"n": 1}}}"#),
            true,
            None,
            None,
        )
        .expect("private override");
        assert!(update.shared().is_none());
        assert_eq!(
            jmap_json(update.private().expect("private written")),
            serde_json::json!({"p.example": {"n": 1}})
        );

        let result = copy(
            create_patches(r#"{"privateMetadata": {"p.example": {"n": 1}}}"#),
            false,
            None,
            None,
        );
        let error = result.expect_err("private metadata is not supported");
        assert_eq!(
            serde_json::to_value(error).expect("serializable")["type"],
            "invalidProperties"
        );
    }

    #[test]
    fn copies_every_entry_kind_without_patches() {
        let shared = container(r#"{"a.example": {"k": 1}}"#, &[("/comment", "kept")]);
        let private = container(r#"{"p.example": {"n": "x"}}"#, &[]);
        let update = MetadataUpdate::copied(Some(&shared), None);
        let change = update.shared().expect("shared copied");
        assert!(change.previous().is_none());
        assert_eq!(
            change.next().map(|next| next.view().as_bytes()),
            Some(shared.view().as_bytes())
        );
        assert!(update.private().is_none());

        let update = MetadataUpdate::copied(None, Some(&private));
        assert!(update.shared().is_none());
        assert_eq!(
            jmap_json(update.private().expect("private copied")),
            serde_json::json!({"p.example": {"n": "x"}})
        );
        assert!(MetadataUpdate::copied(None, None).is_empty());
    }
}
