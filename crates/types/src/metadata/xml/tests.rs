/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavValueView, XmlAttribute, XmlElement, XmlError, XmlName, XmlNode, XmlValue};
use crate::metadata::{
    MetadataBuilder,
    codec::{write_bytes, write_varint},
    registry::{XML_NAMESPACE as XML, XMLNS_NAMESPACE as XMLNS},
};
use std::borrow::Cow;

fn attribute<'x>(namespace: Option<&'x str>, name: &'x str, value: &'x str) -> XmlAttribute<'x> {
    XmlAttribute {
        name: XmlName::borrowed(namespace, name),
        value: Cow::Borrowed(value),
    }
}

fn element<'x>(
    namespace: Option<&'x str>,
    name: &'x str,
    prefix: Option<&'x str>,
    attributes: Vec<XmlAttribute<'x>>,
    children: Vec<XmlNode<'x>>,
) -> XmlNode<'x> {
    XmlNode::Element(XmlElement {
        name: XmlName::borrowed(namespace, name),
        prefix: prefix.map(Cow::Borrowed),
        attributes,
        children,
    })
}

fn write(value: &XmlValue<'_>, namespace: Option<&str>, name: &str) -> String {
    let encoded = value.to_encoded().expect("encodable XML value");
    let view = DavValueView::parse(encoded.as_bytes()).expect("valid XML value");
    let mut out = String::new();
    view.write_property(&XmlName::borrowed(namespace, name), &mut out)
        .expect("writable XML value");
    out
}

fn attributes_only(attributes: Vec<XmlAttribute<'_>>) -> XmlValue<'_> {
    XmlValue {
        attributes,
        ..Default::default()
    }
}

fn child(node: XmlNode<'_>) -> XmlValue<'_> {
    XmlValue {
        children: vec![node],
        ..Default::default()
    }
}

#[test]
fn stored_prefix_shadowing_a_generated_one_is_redeclared() {
    let value = XmlValue {
        attributes: vec![attribute(Some("urn:y"), "outer", "1")],
        children: vec![element(
            Some("urn:z"),
            "child",
            Some("a0"),
            vec![attribute(Some("urn:y"), "inner", "2")],
            vec![],
        )],
        ..Default::default()
    };
    assert_eq!(
        write(&value, Some("urn:p"), "prop"),
        concat!(
            "<prop xmlns=\"urn:p\" xmlns:a0=\"urn:y\" a0:outer=\"1\">",
            "<a0:child xmlns:a0=\"urn:z\" xmlns:a1=\"urn:y\" a1:inner=\"2\"/>",
            "</prop>"
        )
    );

    let reuse = XmlValue {
        attributes: vec![attribute(Some("urn:y"), "outer", "1")],
        children: vec![element(
            Some("urn:y"),
            "child",
            Some("a0"),
            vec![attribute(Some("urn:y"), "inner", "2")],
            vec![],
        )],
        ..Default::default()
    };
    assert_eq!(
        write(&reuse, Some("urn:p"), "prop"),
        concat!(
            "<prop xmlns=\"urn:p\" xmlns:a0=\"urn:y\" a0:outer=\"1\">",
            "<a0:child a0:inner=\"2\"/>",
            "</prop>"
        ),
        "a stored prefix rendering like a generated one with the same URI is reused"
    );

    for (stored, rebinds) in [("a00", false), ("a01", false), ("a+0", false), ("a0", true)] {
        let value = XmlValue {
            attributes: vec![attribute(Some("urn:y"), "outer", "1")],
            children: vec![element(
                Some("urn:z"),
                "child",
                Some(stored),
                vec![attribute(Some("urn:y"), "inner", "2")],
                vec![],
            )],
            ..Default::default()
        };
        let encoded = value.encode();
        if stored == "a+0" {
            assert_eq!(encoded, Err(XmlError::InvalidPrefix));
            continue;
        }
        let out = write(&value, Some("urn:p"), "prop");
        assert_eq!(out.contains("a1:inner"), rebinds, "{stored}: {out}");
        assert_eq!(out.contains("a0:inner"), !rebinds, "{stored}: {out}");
    }
}

#[test]
fn generated_prefixes_scale_linearly_in_count() {
    const COUNT: usize = 2000;
    let uris = (0..COUNT)
        .map(|index| format!("u{index}"))
        .collect::<Vec<_>>();
    let value = attributes_only(
        uris.iter()
            .map(|uri| attribute(Some(uri.as_str()), "a", ""))
            .collect(),
    );
    let out = write(&value, Some("urn:p"), "prop");
    assert_eq!(out.matches(" xmlns:a").count(), COUNT);
    assert!(out.contains(&format!(" xmlns:a{}=\"u{}\"", COUNT - 1, COUNT - 1)));
    assert!(out.ends_with(&format!(" a{}:a=\"\"/>", COUNT - 1)));
}

#[test]
fn reserved_and_duplicate_attributes_are_rejected() {
    let probe = XmlValue {
        lang: Some(Cow::Borrowed("en")),
        attributes: vec![
            attribute(None, "xmlns", "urn:q"),
            attribute(Some(XML), "lang", "de"),
            attribute(Some("urn:y"), "a", "1"),
            attribute(Some("urn:y"), "a", "2"),
        ],
        children: vec![],
    };
    assert!(probe.encode().is_err());

    for (attributes, error) in [
        (
            vec![attribute(None, "xmlns", "urn:q")],
            XmlError::ReservedAttribute,
        ),
        (
            vec![attribute(Some(XMLNS), "q", "urn:q")],
            XmlError::ReservedAttribute,
        ),
        (
            vec![attribute(Some(XML), "lang", "de")],
            XmlError::ReservedAttribute,
        ),
        (
            vec![
                attribute(Some("urn:y"), "a", "1"),
                attribute(Some("urn:y"), "a", "2"),
            ],
            XmlError::DuplicateAttribute,
        ),
        (
            vec![attribute(None, "a", "1"), attribute(None, "a", "1")],
            XmlError::DuplicateAttribute,
        ),
        (
            vec![attribute(Some(""), "a", "1")],
            XmlError::InvalidNamespace,
        ),
        (vec![attribute(None, "1a", "1")], XmlError::InvalidName),
        (vec![attribute(None, "a:b", "1")], XmlError::InvalidName),
        (vec![attribute(None, "", "1")], XmlError::InvalidName),
        (
            vec![attribute(None, "a", "x\u{1}")],
            XmlError::InvalidCharacter,
        ),
    ] {
        let value = attributes_only(attributes);
        assert_eq!(value.encode(), Err(error), "{value:?}");
        assert_eq!(value.validate(), Err(error), "{value:?}");
    }

    let many = (0..20)
        .map(|index| format!("n{index}"))
        .chain(["n7".to_string()])
        .collect::<Vec<_>>();
    let value = attributes_only(many.iter().map(|name| attribute(None, name, "")).collect());
    assert_eq!(value.encode(), Err(XmlError::DuplicateAttribute));

    let inner_lang = child(element(
        Some("urn:x"),
        "e",
        None,
        vec![attribute(Some(XML), "lang", "de")],
        vec![],
    ));
    assert_eq!(
        write(&inner_lang, Some("urn:p"), "p"),
        "<p xmlns=\"urn:p\"><e xmlns=\"urn:x\" xml:lang=\"de\"/></p>"
    );
}

#[test]
fn element_names_prefixes_and_namespaces_are_validated() {
    for (node, error) in [
        (
            element(Some("urn:x"), "1bad", None, vec![], vec![]),
            XmlError::InvalidName,
        ),
        (
            element(Some("urn:x"), "a:b", None, vec![], vec![]),
            XmlError::InvalidName,
        ),
        (
            element(Some("urn:x"), "e", Some("1x"), vec![], vec![]),
            XmlError::InvalidPrefix,
        ),
        (
            element(Some("urn:x"), "e", Some(""), vec![], vec![]),
            XmlError::InvalidPrefix,
        ),
        (
            element(Some("urn:x"), "e", Some("xmlns"), vec![], vec![]),
            XmlError::InvalidPrefix,
        ),
        (
            element(Some("urn:x"), "e", Some("xml"), vec![], vec![]),
            XmlError::InvalidPrefix,
        ),
        (
            element(Some(XML), "e", None, vec![], vec![]),
            XmlError::InvalidPrefix,
        ),
        (
            element(Some(XML), "e", Some("x"), vec![], vec![]),
            XmlError::InvalidPrefix,
        ),
        (
            element(Some(XMLNS), "e", None, vec![], vec![]),
            XmlError::InvalidNamespace,
        ),
        (
            element(Some(""), "e", None, vec![], vec![]),
            XmlError::InvalidNamespace,
        ),
        (
            XmlNode::Text(Cow::Borrowed("bad\u{FFFF}")),
            XmlError::InvalidCharacter,
        ),
    ] {
        let value = child(node);
        assert_eq!(value.encode(), Err(error), "{value:?}");
    }

    let lang = XmlValue {
        lang: Some(Cow::Borrowed("e\u{0}n")),
        ..Default::default()
    };
    assert_eq!(lang.encode(), Err(XmlError::InvalidCharacter));

    let xml_element = child(element(Some(XML), "e", Some("xml"), vec![], vec![]));
    assert_eq!(
        write(&xml_element, Some("urn:p"), "p"),
        "<p xmlns=\"urn:p\"><xml:e/></p>"
    );
}

#[test]
fn property_names_are_validated() {
    let value = XmlValue::default();
    for (namespace, name, error) in [
        (Some("urn:x"), "", XmlError::InvalidName),
        (Some("urn:x"), "a b", XmlError::InvalidName),
        (Some("urn:x"), "a:b", XmlError::InvalidName),
        (Some(""), "a", XmlError::InvalidNamespace),
        (Some(XML), "a", XmlError::InvalidNamespace),
        (Some(XMLNS), "a", XmlError::InvalidNamespace),
    ] {
        let mut builder = MetadataBuilder::new();
        assert_eq!(
            builder.set_dav(XmlName::borrowed(namespace, name), &value),
            Err(error),
            "{namespace:?} {name}"
        );
        assert!(builder.is_empty());
    }
}

fn raw_value(attributes: &[(Option<&str>, &str, &str)], text: Option<&str>) -> Vec<u8> {
    let mut rest = vec![0];
    write_varint(&mut rest, attributes.len() as u64);
    for (namespace, name, value) in attributes {
        match namespace {
            Some(uri) => {
                rest.push(0xFF);
                write_bytes(&mut rest, uri.as_bytes());
            }
            None => rest.push(0),
        }
        write_bytes(&mut rest, name.as_bytes());
        write_bytes(&mut rest, value.as_bytes());
    }
    match text {
        Some(text) => {
            rest.push(1);
            rest.push(1);
            write_bytes(&mut rest, text.as_bytes());
        }
        None => rest.push(0),
    }
    let mut out = Vec::new();
    write_bytes(&mut out, &rest);
    out
}

#[test]
fn untrusted_bytes_are_validated_like_encoded_values() {
    assert!(DavValueView::parse(&raw_value(&[(None, "a", "1")], Some("t"))).is_some());
    for bytes in [
        raw_value(&[(None, "xmlns", "urn:q")], None),
        raw_value(&[(Some(XML), "lang", "de")], None),
        raw_value(&[(None, "a", "1"), (None, "a", "2")], None),
        raw_value(&[(Some(XMLNS), "a", "1")], None),
        raw_value(&[(None, "1a", "1")], None),
        raw_value(&[(None, "a", "\u{1}")], None),
        raw_value(&[], Some("\u{FFFE}")),
    ] {
        assert!(DavValueView::parse(&bytes).is_none(), "{bytes:?}");
    }
}

#[test]
fn prefixed_and_empty_property_writers() {
    let owner = child(element(
        Some("DAV:"),
        "href",
        Some("D"),
        vec![],
        vec![XmlNode::Text(Cow::Borrowed("mailto:jane@example.com"))],
    ));
    let encoded = owner.to_encoded().expect("encodable");
    let mut out = String::new();
    encoded
        .view()
        .write_property_prefixed(&XmlName::borrowed(Some("DAV:"), "owner"), "D", &mut out)
        .expect("writable");
    assert_eq!(
        out,
        "<D:owner><D:href>mailto:jane@example.com</D:href></D:owner>"
    );
    assert_eq!(encoded.view().to_encoded(), encoded);

    let mut out = String::new();
    XmlName::borrowed(Some("urn:a\"b"), "x")
        .write_empty(&mut out)
        .expect("writable");
    assert_eq!(out, "<x xmlns=\"urn:a&quot;b\"/>");
}
