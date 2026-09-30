/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DeadOp, DeadPatch, DisplayName, text_len};
use common::storage::dav::DISPLAY_NAME_PROPERTY;
use dav_proto::schema::{
    property::{DavProperty, DavValue, WebDavProperty},
    request::{DavPropertyValue, PropertyUpdate},
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

fn update(set_first: bool) -> PropertyUpdate {
    PropertyUpdate {
        set: vec![
            dead_value("a", "1"),
            DavPropertyValue {
                property: display_name(),
                value: DavValue::String("Report".to_string()),
            },
            DavPropertyValue {
                property: DavProperty::WebDav(WebDavProperty::CreationDate),
                value: DavValue::Timestamp(0),
            },
        ],
        remove: vec![dead("b"), display_name()],
        set_first,
    }
}

fn summary(patch: &DeadPatch) -> Vec<(bool, String)> {
    patch
        .ops
        .iter()
        .map(|op| match op {
            DeadOp::Set { name, .. } => (true, name.name().to_string()),
            DeadOp::Remove { name, .. } => (false, name.name().to_string()),
        })
        .collect()
}

#[test]
fn stored_display_names_join_the_dead_properties_in_order() {
    let mut request = update(false);
    let patch = DeadPatch::take(&mut request, DisplayName::Stored);
    assert_eq!(
        summary(&patch),
        vec![
            (false, "b".to_string()),
            (false, "displayname".to_string()),
            (true, "a".to_string()),
            (true, "displayname".to_string()),
        ]
    );
    assert_eq!(request.set.len(), 1);
    assert!(request.remove.is_empty());
    let Some(DeadOp::Set {
        property,
        name,
        value,
    }) = patch.ops.last()
    else {
        panic!("expected the display name set last");
    };
    assert_eq!(property, &display_name());
    assert_eq!(name, &DISPLAY_NAME_PROPERTY);
    assert_eq!(text_len(value), "Report".len());

    let mut request = update(true);
    let patch = DeadPatch::take(&mut request, DisplayName::Stored);
    assert_eq!(
        summary(&patch),
        vec![
            (true, "a".to_string()),
            (true, "displayname".to_string()),
            (false, "b".to_string()),
            (false, "displayname".to_string()),
        ]
    );
}

#[test]
fn live_display_names_stay_with_the_object() {
    let mut request = update(true);
    let patch = DeadPatch::take(&mut request, DisplayName::Live);
    assert_eq!(
        summary(&patch),
        vec![(true, "a".to_string()), (false, "b".to_string())]
    );
    assert_eq!(request.set.len(), 2);
    assert_eq!(request.remove, vec![display_name()]);

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
