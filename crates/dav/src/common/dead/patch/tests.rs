/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DeadOp, DeadPatch, DisplayName, dead_name, text_len};
use common::storage::dav::DISPLAY_NAME_PROPERTY;
use dav_proto::schema::{
    property::{DavProperty, DavValue, WebDavProperty},
    request::{DavPropertyValue, PropertyUpdateOp},
};
use std::borrow::Cow;
use types::metadata::{XmlName, XmlNode, XmlValue};

fn dead(name: &str) -> DavProperty {
    DavProperty::Dead(XmlName::owned(Some("urn:x".to_string()), name.to_string()))
}

fn dead_value(name: &str, text: &str) -> DavPropertyValue {
    DavPropertyValue {
        property: dead(name),
        value: DavValue::Dead(Box::new(XmlValue {
            children: vec![XmlNode::Text(Cow::Owned(text.to_string()))],
            ..Default::default()
        })),
    }
}

fn display_name() -> DavProperty {
    DavProperty::WebDav(WebDavProperty::DisplayName)
}

fn ops() -> Vec<PropertyUpdateOp> {
    vec![
        PropertyUpdateOp::Remove(dead("b")),
        PropertyUpdateOp::Set(dead_value("a", "1")),
        PropertyUpdateOp::Set(DavPropertyValue {
            property: display_name(),
            value: DavValue::String("Report".to_string()),
        }),
        PropertyUpdateOp::Remove(display_name()),
        PropertyUpdateOp::Set(DavPropertyValue {
            property: DavProperty::WebDav(WebDavProperty::CreationDate),
            value: DavValue::Timestamp(0),
        }),
        PropertyUpdateOp::Remove(dead("a")),
    ]
}

fn summary(patch: &DeadPatch) -> Vec<(bool, String)> {
    patch
        .ops
        .iter()
        .map(|op| match op {
            DeadOp::Set { property, .. } => (true, dead_name(property).name().to_string()),
            DeadOp::Remove { property } => (false, dead_name(property).name().to_string()),
        })
        .collect()
}

#[test]
fn stored_display_names_join_the_dead_properties_in_document_order() {
    let mut request = ops();
    let patch = DeadPatch::take(&mut request, DisplayName::Stored);
    assert_eq!(
        summary(&patch),
        vec![
            (false, "b".to_string()),
            (true, "a".to_string()),
            (true, "displayname".to_string()),
            (false, "displayname".to_string()),
            (false, "a".to_string()),
        ]
    );
    assert_eq!(
        request
            .iter()
            .map(PropertyUpdateOp::property)
            .collect::<Vec<_>>(),
        vec![&DavProperty::WebDav(WebDavProperty::CreationDate)]
    );
    let Some(DeadOp::Set { property, value }) = patch.ops.get(2) else {
        panic!("expected the display name set third");
    };
    assert_eq!(property, &display_name());
    assert_eq!(dead_name(property), DISPLAY_NAME_PROPERTY);
    assert_eq!(text_len(value), "Report".len());
}

#[test]
fn live_display_names_stay_with_the_object() {
    let mut request = ops();
    let patch = DeadPatch::take(&mut request, DisplayName::Live);
    assert_eq!(
        summary(&patch),
        vec![
            (false, "b".to_string()),
            (true, "a".to_string()),
            (false, "a".to_string())
        ]
    );
    assert_eq!(
        request
            .iter()
            .map(PropertyUpdateOp::property)
            .collect::<Vec<_>>(),
        vec![
            &display_name(),
            &display_name(),
            &DavProperty::WebDav(WebDavProperty::CreationDate)
        ]
    );

    let mut values = vec![
        dead_value("c", ""),
        DavPropertyValue {
            property: display_name(),
            value: DavValue::Null,
        },
    ];
    let patch = DeadPatch::take_values(&mut values, DisplayName::Stored);
    assert_eq!(
        summary(&patch),
        vec![(true, "c".to_string()), (true, "displayname".to_string())]
    );
    assert!(values.is_empty());
    assert!(!patch.is_empty());
}
