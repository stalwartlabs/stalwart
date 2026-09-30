/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{dead_properties, dead_property_names};
use crate::common::dead::text_of;
use common::storage::dav::DISPLAY_NAME_PROPERTY;
use dav_proto::schema::property::DavProperty;
use std::borrow::Cow;
use store::write::metadata::MetadataBuf;
use types::{
    collection::Collection,
    metadata::{MetadataBuilder, XmlName, XmlNode, XmlValue},
};

const COLOR: XmlName<'static> =
    XmlName::borrowed(Some("http://apple.com/ns/ical/"), "calendar-color");

fn text(value: &str) -> XmlValue<'static> {
    XmlValue {
        children: vec![XmlNode::Text(Cow::Owned(value.to_string()))],
        ..Default::default()
    }
}

fn container() -> MetadataBuf {
    let mut builder = MetadataBuilder::new();
    builder
        .set_dav(DISPLAY_NAME_PROPERTY, &text("Report"))
        .expect("valid entry");
    builder
        .set_dav(COLOR, &text("#FF0000"))
        .expect("valid entry");
    builder.set_imap("/shared/comment".into(), b"hello");
    let encoded = builder.encode().expect("a non-empty container");
    MetadataBuf::from_view(&encoded.view(), encoded.len() as u32, 0)
}

#[test]
fn file_containers_hide_the_display_name_from_dead_listings() {
    let container = container();

    let file = dead_properties(&container, Collection::FileNode).collect::<Vec<_>>();
    assert_eq!(file.len(), 1);
    assert_eq!(file[0].property, DavProperty::Dead(COLOR));
    assert_eq!(
        file[0].to_string(),
        "<calendar-color xmlns=\"http://apple.com/ns/ical/\">#FF0000</calendar-color>"
    );

    let calendar = dead_properties(&container, Collection::Calendar).collect::<Vec<_>>();
    assert_eq!(calendar.len(), 2);

    let names = dead_property_names(&container, Collection::FileNode)
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["<calendar-color xmlns=\"http://apple.com/ns/ical/\"/>".to_string()]
    );
}

#[test]
fn display_names_are_read_back_as_text() {
    let container = container();
    let view = container
        .view()
        .dav_property(&DISPLAY_NAME_PROPERTY)
        .expect("stored display name");
    assert_eq!(text_of(view).as_deref(), Some("Report"));
}
