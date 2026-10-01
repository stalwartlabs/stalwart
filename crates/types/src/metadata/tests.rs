/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    DavValueView, EncodedJson, EncodedMetadata, JsonError, JsonKind, JsonView, LimitViolation,
    MetadataBuilder, MetadataEdit, MetadataKinds, MetadataLimits, MetadataScope, MetadataView,
    Namespace, NamespaceError, REGISTERED_NAMESPACES, RegisteredNamespace,
    STORAGE_TRAILER_CAPACITY, XmlAttribute, XmlElement, XmlName, XmlNode, XmlValue,
    codec::{Reader, varint_len, write_varint},
    registry::{known_xml_namespace, known_xml_namespace_count, known_xml_namespace_id},
};
use jmap_tools::{Null, Value};
use std::{borrow::Cow, collections::BTreeMap};

type JsonValue<'x> = Value<'x, Null, Null>;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 17
    }

    fn below(&mut self, max: u64) -> u64 {
        self.next() % max
    }

    fn pick<'x, T>(&mut self, items: &'x [T]) -> &'x T {
        &items[self.below(items.len() as u64) as usize]
    }
}

fn json(text: &str) -> JsonValue<'_> {
    JsonValue::parse_json(text).expect("valid test JSON")
}

fn encode(text: &str) -> EncodedJson {
    EncodedJson::encode(&json(text)).expect("encodable test JSON")
}

fn vendor(name: &str) -> Namespace<'_> {
    Namespace::parse(name).expect("valid vendor namespace")
}

fn text(value: &str) -> XmlNode<'_> {
    XmlNode::Text(Cow::Borrowed(value))
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

fn attribute<'x>(namespace: Option<&'x str>, name: &'x str, value: &'x str) -> XmlAttribute<'x> {
    XmlAttribute {
        name: XmlName::borrowed(namespace, name),
        value: Cow::Borrowed(value),
    }
}

fn write_property(value: &XmlValue<'_>, namespace: Option<&str>, name: &str) -> String {
    let encoded = value.encode().expect("encodable XML value");
    let view = DavValueView::parse(&encoded).expect("valid XML value");
    let mut out = String::new();
    view.write_property(&XmlName::borrowed(namespace, name), &mut out)
        .expect("writable XML value");
    out
}

#[test]
fn varint_roundtrip_and_rejection() {
    for value in [
        0u64,
        1,
        0x7F,
        0x80,
        0x3FFF,
        0x4000,
        u32::MAX as u64,
        (1 << 56) - 1,
        1 << 63,
        u64::MAX,
    ] {
        let mut out = Vec::new();
        write_varint(&mut out, value);
        assert_eq!(out.len(), varint_len(value), "length of {value}");
        let mut reader = Reader::checked(&out);
        assert_eq!(reader.varint(), Some(value));
        assert!(reader.is_empty());
        for len in 0..out.len() {
            assert_eq!(
                Reader::checked(&out[..len]).varint(),
                None,
                "truncated {value}"
            );
        }
    }

    let overflow = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
    assert_eq!(Reader::checked(&overflow).varint(), None);
    let too_long = [
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    ];
    assert_eq!(Reader::checked(&too_long).varint(), None);
}

#[test]
fn json_roundtrip_every_kind() {
    let text = format!(
        concat!(
            r#"{{"null":null,"f":false,"t":true,"zero":0,"small":63,"medium":64,"#,
            r#""u32":4294967295,"max":{},"minus":-1,"min":{},"float":1.0,"#,
            r#""pi":3.25,"neg_float":-0.5,"empty":"","short":"{}","long":"{}","#,
            r#""unicode":"caf\u00e9 \u65e5\u672c \ud83d\ude00","arr":[1,"two",[3,[]],{{}}],"#,
            r#""obj":{{"z":1,"a":{{"deep":{{"deeper":[{{"x":null}}]}}}}}},"eo":{{}},"ea":[],"#,
            r#""receivedAt":"2024-01-01T00:00:00+00:00","id":"Mxxxxxxxxxxxxxxxxxxxxxxxxx","#,
            r##""ref":"#creation","tabs":"a\tb\nc\rd"}}"##
        ),
        u64::MAX,
        i64::MIN,
        "x".repeat(127),
        "y".repeat(128),
    );
    let original = json(&text);
    let encoded = EncodedJson::encode(&original).expect("encodable");
    let decoded = encoded.view().to_value::<Null, Null>().expect("decodable");

    assert_eq!(original, decoded);
    assert_eq!(original.to_string(), decoded.to_string());

    let view = encoded.view();
    assert_eq!(view.kind(), JsonKind::Object);
    assert_eq!(view.get("null").map(|v| v.kind()), Some(JsonKind::Null));
    assert_eq!(view.get("f").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(view.get("t").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(view.get("small").and_then(|v| v.as_u64()), Some(63));
    assert_eq!(view.get("medium").and_then(|v| v.as_u64()), Some(64));
    assert_eq!(view.get("max").and_then(|v| v.as_u64()), Some(u64::MAX));
    assert_eq!(view.get("min").and_then(|v| v.as_i64()), Some(i64::MIN));
    assert_eq!(view.get("minus").and_then(|v| v.as_i64()), Some(-1));
    assert_eq!(view.get("float").and_then(|v| v.as_f64()), Some(1.0));
    assert_eq!(view.get("float").map(|v| v.kind()), Some(JsonKind::Number));
    assert_eq!(view.get("float").and_then(|v| v.as_u64()), None);
    assert_eq!(view.get("empty").and_then(|v| v.as_str()), Some(""));
    assert_eq!(
        view.get("long").and_then(|v| v.as_str()).map(str::len),
        Some(128)
    );
    assert_eq!(
        view.get("receivedAt").and_then(|v| v.as_str()),
        Some("2024-01-01T00:00:00+00:00")
    );
    assert_eq!(view.get("ref").and_then(|v| v.as_str()), Some("#creation"));
    assert_eq!(view.get("missing").map(|v| v.kind()), None);
    assert!(view.get("eo").is_some_and(|v| v.is_empty_object()));
    assert!(!view.get("obj").is_some_and(|v| v.is_empty_object()));
    assert_eq!(
        view.get("obj")
            .and_then(|v| v.get("a"))
            .and_then(|v| v.get("deep"))
            .and_then(|v| v.get("deeper"))
            .map(|v| v.items().count()),
        Some(1)
    );
    assert_eq!(
        view.get("obj")
            .map(|v| v.members().map(|(key, _)| key).collect::<Vec<_>>()),
        Some(vec!["z", "a"]),
        "member order is kept"
    );
    assert_eq!(
        view.get("arr")
            .map(|v| v.items().map(|item| item.kind()).collect::<Vec<_>>()),
        Some(vec![
            JsonKind::Number,
            JsonKind::String,
            JsonKind::Array,
            JsonKind::Object
        ])
    );
    assert_eq!(view.len(), view.members().count());
}

#[test]
fn json_float_kind_survives() {
    let encoded = encode(r#"{"a":1.0,"b":1}"#);
    let decoded = encoded.view().to_value::<Null, Null>().expect("decodable");
    assert_eq!(decoded.to_string(), r#"{"a":1.0,"b":1}"#);
}

#[test]
fn json_depth_follows_the_draft() {
    for (text, depth) in [
        (r#"{}"#, 1),
        (r#"{"a":1,"b":"x","c":[1,2]}"#, 1),
        (r#"{"x":[{"y":1}]}"#, 2),
        (r#"{"a":{}}"#, 2),
        (r#"{"a":[]}"#, 1),
        (r#"{"a":[[[]]]}"#, 1),
        (r#"{"a":{"b":{"c":1}}}"#, 3),
        (r#"{"a":{"b":1},"c":{"d":{"e":[{"f":{}}]}}}"#, 5),
    ] {
        assert_eq!(encode(text).depth(), depth, "{text}");
    }

    let limits = MetadataLimits {
        max_depth: Some(2),
        ..Default::default()
    };
    assert_eq!(
        limits.check_depth(encode(r#"{"x":[{"y":1}]}"#).depth()),
        Ok(())
    );
    assert_eq!(
        limits.check_depth(encode(r#"{"a":{"b":{"c":1}}}"#).depth()),
        Err(LimitViolation::Depth { depth: 3, max: 2 })
    );
    let unlimited = MetadataLimits {
        max_depth: None,
        ..Default::default()
    };
    assert_eq!(
        unlimited.check_depth(encode(r#"{"a":{"b":{"c":1}}}"#).depth()),
        Ok(())
    );
}

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut bytes = vec![0x00];
    for _ in 0..depth {
        let mut body = Vec::with_capacity(bytes.len() + 1);
        write_varint(&mut body, 1);
        body.extend_from_slice(&bytes);
        bytes.clear();
        bytes.push(0x07);
        write_varint(&mut bytes, body.len() as u64);
        bytes.extend_from_slice(&body);
    }
    bytes
}

#[test]
fn json_decode_depth_is_bounded() {
    let mut accepted = JsonValue::Null;
    for _ in 0..128 {
        accepted = JsonValue::Array(vec![accepted]);
    }
    let encoded = EncodedJson::encode(&accepted).expect("128 levels encode");
    assert_eq!(encoded.as_bytes(), nested_arrays(128).as_slice());
    assert_eq!(
        encoded.view().to_value::<Null, Null>(),
        Some(accepted.clone())
    );
    assert_eq!(
        EncodedJson::encode(&JsonValue::Array(vec![accepted])),
        Err(JsonError::NestingTooDeep)
    );

    for depth in [129, 20_000] {
        let bytes = nested_arrays(depth);
        let view = JsonView::new(unsafe { Reader::trusted(&bytes) });
        assert!(
            view.to_value::<Null, Null>().is_none(),
            "{depth} levels decode"
        );
    }
}

#[test]
fn json_rejects_control_characters_and_non_objects() {
    for text in [
        "{\"a\":\"\\u0000\"}",
        "{\"a\":\"\\u0008\"}",
        "{\"a\":\"\\u000b\"}",
        "{\"a\":\"\\u000c\"}",
        "{\"a\":\"\\u001f\"}",
        "{\"a\":\"\\u007f\"}",
        "{\"\\u0001\":1}",
        "{\"a\":[\"\\u0002\"]}",
    ] {
        assert_eq!(
            EncodedJson::encode(&json(text)),
            Err(JsonError::ControlCharacter),
            "{text}"
        );
    }
    assert!(EncodedJson::encode(&json("{\"a\":\"\\t\\n\\r\"}")).is_ok());
    assert_eq!(
        EncodedJson::encode_namespace(&json("[1]")),
        Err(JsonError::NotAnObject)
    );
    assert_eq!(
        EncodedJson::encode_namespace(&json("null")),
        Err(JsonError::NotAnObject)
    );
    assert!(EncodedJson::encode_namespace(&json("{}")).is_ok());

    let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
    let value = JsonValue::parse_json(&deep);
    if let Ok(value) = value {
        assert_eq!(EncodedJson::encode(&value), Err(JsonError::NestingTooDeep));
    }
}

#[test]
fn namespace_names() {
    assert_eq!(
        Namespace::parse("example.com"),
        Ok(Namespace::Vendor("example.com"))
    );
    assert_eq!(
        Namespace::parse("a-b.c-d.e"),
        Ok(Namespace::Vendor("a-b.c-d.e"))
    );
    assert_eq!(
        Namespace::parse("photos"),
        Err(NamespaceError::Unregistered)
    );
    assert_eq!(
        Namespace::parse(&"a".repeat(64)),
        Err(NamespaceError::Unregistered)
    );
    for invalid in [
        "",
        "-bad.com",
        "bad-.com",
        "a..b",
        ".a",
        "a.",
        "a b.com",
        "a_b.com",
        "photo album",
        "caf\u{e9}.com",
        "Example.COM",
        "example.Com",
        "EXAMPLE.com",
    ] {
        assert_eq!(
            Namespace::parse(invalid),
            Err(NamespaceError::Invalid),
            "{invalid:?}"
        );
    }
    let long_registered = "a".repeat(65);
    assert_eq!(
        Namespace::parse(&long_registered),
        Err(NamespaceError::Invalid)
    );
    let long_label = format!("{}.com", "a".repeat(64));
    assert_eq!(Namespace::parse(&long_label), Err(NamespaceError::Invalid));
    let long_domain = format!("{}.com", vec!["a".repeat(63); 4].join("."));
    assert!(long_domain.len() > 253);
    assert_eq!(Namespace::parse(&long_domain), Err(NamespaceError::Invalid));
}

#[test]
fn known_xml_namespaces_are_consistent() {
    for id in 1..=known_xml_namespace_count() as u8 {
        let uri = known_xml_namespace(id).expect("known id");
        assert_eq!(known_xml_namespace_id(uri), Some(id), "{uri}");
    }
    assert_eq!(known_xml_namespace(0), None);
    assert_eq!(
        known_xml_namespace(known_xml_namespace_count() as u8 + 1),
        None
    );
    assert_ne!(
        known_xml_namespace_id("http://calendarserver.org/ns"),
        known_xml_namespace_id("http://calendarserver.org/ns/")
    );
    assert_eq!(known_xml_namespace_id("dav:"), None);
}

#[test]
fn registered_namespaces_resolve_by_id_and_name() {
    assert!(
        REGISTERED_NAMESPACES.is_sorted_by(|a, b| a.id < b.id),
        "by_id binary-searches the table"
    );
    for namespace in REGISTERED_NAMESPACES {
        assert_eq!(RegisteredNamespace::by_id(namespace.id), Some(namespace));
        assert_eq!(
            RegisteredNamespace::by_name(namespace.name),
            Some(namespace)
        );
    }
}

fn sample_container() -> Vec<u8> {
    let mut builder = MetadataBuilder::new();
    builder.set_imap(Cow::Borrowed("/vendor/cmu/cyrus-imapd/color"), b"#ff0000");
    builder.set_imap(Cow::Borrowed("/comment"), b"\x00binary\xff");
    builder.set_jmap(
        vendor("x.example"),
        encode(r#"{"receivedAt":"2024-01-01T00:00:00+00:00","tags":["a","b"]}"#),
    );
    builder.set_jmap(vendor("acme.example.com"), encode(r#"{"color":"blue"}"#));
    builder
        .set_dav(
            XmlName::borrowed(Some("urn:a"), "foo"),
            &XmlValue {
                children: vec![text("from a")],
                ..Default::default()
            },
        )
        .expect("encodable");
    builder
        .set_dav(
            XmlName::borrowed(Some("urn:b"), "foo"),
            &XmlValue {
                children: vec![text("from b")],
                ..Default::default()
            },
        )
        .expect("encodable");
    builder
        .set_dav(
            XmlName::borrowed(Some("DAV:"), "displayname"),
            &XmlValue {
                lang: Some(Cow::Borrowed("en")),
                children: vec![text("Report")],
                ..Default::default()
            },
        )
        .expect("encodable");
    builder.encode().expect("non-empty").into_bytes()
}

#[test]
fn container_lookups_are_namespace_aware() {
    let bytes = sample_container();
    let view = MetadataView::new(&bytes).expect("valid container");

    assert_eq!(view.len(), 7);
    assert_eq!(
        view.kinds(),
        MetadataKinds::JMAP
            .union(MetadataKinds::DAV)
            .union(MetadataKinds::IMAP)
    );
    assert_eq!(
        view.jmap()
            .map(|(namespace, _)| namespace.name())
            .collect::<Vec<_>>(),
        vec!["acme.example.com", "x.example"]
    );
    assert_eq!(
        view.jmap_namespace(&vendor("acme.example.com"))
            .and_then(|value| value.get("color"))
            .and_then(|value| value.as_str()),
        Some("blue")
    );
    assert!(view.jmap_namespace(&vendor("other.example")).is_none());

    let from_a = view
        .dav_property(&XmlName::borrowed(Some("urn:a"), "foo"))
        .and_then(|value| value.to_value());
    let from_b = view
        .dav_property(&XmlName::borrowed(Some("urn:b"), "foo"))
        .and_then(|value| value.to_value());
    assert_eq!(
        from_a.map(|value| value.children),
        Some(vec![text("from a")])
    );
    assert_eq!(
        from_b.map(|value| value.children),
        Some(vec![text("from b")])
    );
    assert!(view.dav_property(&XmlName::borrowed(None, "foo")).is_none());
    assert_eq!(
        view.dav_property(&XmlName::borrowed(Some("DAV:"), "displayname"))
            .and_then(|value| value.lang()),
        Some("en")
    );

    assert_eq!(
        view.imap().collect::<Vec<_>>(),
        vec![
            ("/comment", b"\x00binary\xff".as_slice()),
            ("/vendor/cmu/cyrus-imapd/color", b"#ff0000".as_slice()),
        ]
    );
    assert_eq!(
        view.imap_entry("/comment"),
        Some(b"\x00binary\xff".as_slice())
    );
    assert_eq!(view.imap_entry("/missing"), None);
}

#[test]
fn kinds_byte_short_circuits_other_protocols() {
    let mut builder = MetadataBuilder::new();
    builder
        .set_dav(
            XmlName::borrowed(Some("urn:schemas-microsoft-com:"), "Win32FileAttributes"),
            &XmlValue {
                children: vec![text("00000020")],
                ..Default::default()
            },
        )
        .expect("encodable");
    let encoded = builder.encode().expect("non-empty");
    let view = encoded.view();
    assert_eq!(view.kinds(), MetadataKinds::DAV);
    assert!(!view.kinds().intersects(MetadataKinds::JMAP));
    assert_eq!(view.jmap().count(), 0);
    assert_eq!(view.imap().count(), 0);
    assert_eq!(view.dav().count(), 1);
}

#[test]
fn encoding_is_unique_and_patchable() {
    let bytes = sample_container();
    let view = MetadataView::new(&bytes).expect("valid");

    let rebuilt = MetadataBuilder::from_view(&view)
        .encode()
        .expect("non-empty")
        .into_bytes();
    assert_eq!(bytes, rebuilt, "a rebuilt container is byte identical");

    let mut patched = MetadataBuilder::from_view(&view);
    patched.set_jmap(vendor("acme.example.com"), encode(r#"{"color":"red"}"#));
    assert!(patched.remove_imap("/comment"));
    assert!(!patched.remove_imap("/comment"));
    assert!(patched.remove_dav(&XmlName::borrowed(Some("urn:b"), "foo")));
    let patched = patched.encode().expect("non-empty");
    let patched_view = patched.view();
    assert_eq!(patched_view.len(), 5);
    assert_eq!(
        patched_view
            .jmap_namespace(&vendor("acme.example.com"))
            .and_then(|value| value.get("color"))
            .and_then(|value| value.as_str()),
        Some("red")
    );
    assert_eq!(
        patched_view
            .jmap_namespace(&vendor("x.example"))
            .map(|value| value.as_bytes()),
        view.jmap_namespace(&vendor("x.example"))
            .map(|value| value.as_bytes()),
        "untouched namespaces are copied verbatim"
    );

    let mut forward = MetadataBuilder::new();
    let mut backward = MetadataBuilder::new();
    let names = ["b.example", "a.example", "c.example", "aa.example"];
    for name in names {
        forward.set_jmap(vendor(name), encode(r#"{"k":1}"#));
    }
    for name in names.iter().rev() {
        backward.set_jmap(vendor(name), encode(r#"{"k":1}"#));
    }
    assert_eq!(forward.encode(), backward.encode());

    let mut cleared = MetadataBuilder::from_view(&view);
    cleared.clear_jmap();
    assert_eq!(
        cleared.kinds(),
        MetadataKinds::DAV.union(MetadataKinds::IMAP)
    );
    assert_eq!(cleared.edit(), MetadataEdit::RemovalOnly);

    let mut jmap_only = MetadataBuilder::new();
    jmap_only.set_jmap(vendor("a.example"), encode(r#"{"k":1}"#));
    jmap_only.clear_jmap();
    assert!(jmap_only.is_empty());
    assert_eq!(jmap_only.encode(), None);
}

#[test]
fn verbatim_copy_matches_a_rebuild() {
    let bytes = sample_container();
    let view = MetadataView::new(&bytes).expect("valid");
    let copied = EncodedMetadata::from_view(&view).expect("non-empty");
    assert_eq!(
        Some(&copied),
        MetadataBuilder::from_view(&view).encode().as_ref()
    );
    assert_eq!(copied.as_bytes(), bytes.as_slice());
    assert_eq!(copied.kinds(), view.kinds());
    assert_eq!(copied.entries(), view.len());
    assert!(
        copied.into_bytes().capacity() >= bytes.len() + STORAGE_TRAILER_CAPACITY,
        "the storage trailer fits without reallocating"
    );

    assert_eq!(EncodedMetadata::from_view(&MetadataView::empty()), None);
}

#[test]
fn builder_reads_back_its_own_entries() {
    let mut builder = MetadataBuilder::new();
    builder.set_jmap(vendor("a.example"), encode(r#"{"x":[1,2]}"#));
    builder.set_imap(Cow::Borrowed("/comment"), b"hello");
    builder
        .set_dav(
            XmlName::borrowed(None, "plain"),
            &XmlValue {
                children: vec![text("v")],
                ..Default::default()
            },
        )
        .expect("encodable");

    assert_eq!(
        builder
            .jmap(&vendor("a.example"))
            .and_then(|value| value.get("x"))
            .map(|value| value.items().count()),
        Some(2)
    );
    assert_eq!(builder.imap("/comment"), Some(b"hello".as_slice()));
    assert!(builder.dav(&XmlName::borrowed(None, "plain")).is_some());
    assert!(
        builder
            .dav(&XmlName::borrowed(Some("DAV:"), "plain"))
            .is_none()
    );
    assert_eq!(
        builder.kinds(),
        MetadataKinds::JMAP
            .union(MetadataKinds::DAV)
            .union(MetadataKinds::IMAP)
    );
    assert_eq!(
        builder.encode().map(|encoded| encoded.entries()),
        Some(builder.len())
    );
    let owned = builder.clone().into_owned();
    assert_eq!(owned.encode(), builder.encode());
}

#[test]
fn builder_reports_whether_an_edit_only_removes_entries() {
    let mut seed = MetadataBuilder::new();
    assert_eq!(seed.edit(), MetadataEdit::RemovalOnly);
    seed.set_jmap(vendor("a.example"), encode(r#"{"x":1}"#));
    seed.set_imap(Cow::Borrowed("/a"), b"1");
    seed.set_imap(Cow::Borrowed("/b"), b"2");
    assert_eq!(seed.edit(), MetadataEdit::Write);
    let stored = seed.encode().expect("non-empty");
    let view = stored.view();

    type Edit = fn(&mut MetadataBuilder<'_>);
    let cases: [(Edit, MetadataEdit); 8] = [
        (|_| {}, MetadataEdit::RemovalOnly),
        (
            |builder| {
                builder.remove_imap("/a");
            },
            MetadataEdit::RemovalOnly,
        ),
        (
            |builder| {
                builder.remove_imap("/missing");
            },
            MetadataEdit::RemovalOnly,
        ),
        (|builder| builder.clear_jmap(), MetadataEdit::RemovalOnly),
        (
            |builder| {
                builder.set_imap(Cow::Borrowed("/a"), b"1");
                builder.set_jmap(vendor("a.example"), encode(r#"{"x":1}"#));
                builder.remove_imap("/b");
            },
            MetadataEdit::RemovalOnly,
        ),
        (
            |builder| builder.set_imap(Cow::Borrowed("/a"), b"changed"),
            MetadataEdit::Write,
        ),
        (
            |builder| {
                builder.remove_imap("/a");
                builder.set_imap(Cow::Borrowed("/c"), b"3");
            },
            MetadataEdit::Write,
        ),
        (
            |builder| builder.set_jmap(vendor("a.example"), encode(r#"{"x":2}"#)),
            MetadataEdit::Write,
        ),
    ];
    for (index, (apply, expected)) in cases.into_iter().enumerate() {
        let mut builder = MetadataBuilder::from_view(&view);
        apply(&mut builder);
        assert_eq!(builder.edit(), expected, "case {index}");
        assert_eq!(builder.into_owned().edit(), expected, "owned case {index}");
    }
}

#[test]
fn xml_value_roundtrip() {
    let value = XmlValue {
        lang: Some(Cow::Borrowed("de-CH")),
        attributes: vec![
            attribute(None, "symbolic-color", "red"),
            attribute(Some("urn:attr"), "kind", "a\"b"),
        ],
        children: vec![
            text("  leading and trailing whitespace  "),
            element(
                Some("DAV:"),
                "href",
                Some("D"),
                vec![],
                vec![text("https://example.com/cal.ics?a=1&b=2")],
            ),
            element(None, "unqualified", None, vec![], vec![]),
            element(
                Some("http://calendarserver.org/ns"),
                "no-slash",
                None,
                vec![attribute(
                    Some("http://www.w3.org/XML/1998/namespace"),
                    "lang",
                    "fr",
                )],
                vec![element(
                    Some("urn:deep"),
                    "deeper",
                    None,
                    vec![],
                    vec![text("<&>")],
                )],
            ),
        ],
    };
    let encoded = value.encode().expect("encodable");
    assert_eq!(encoded.len(), value.encoded_len().expect("measurable"));
    let view = DavValueView::parse(&encoded).expect("valid");
    assert_eq!(view.to_value(), Some(value.clone()));
    assert_eq!(view.lang(), Some("de-CH"));
    assert_eq!(
        DavValueView::parse(&XmlValue::default().encode().expect("encodable"))
            .and_then(|view| view.to_value()),
        Some(XmlValue::default())
    );

    let mut invalid_prefix = value;
    invalid_prefix.children = vec![element(None, "orphan", Some("P"), vec![], vec![])];
    let reencoded = invalid_prefix.encode().expect("encodable");
    let reparsed = DavValueView::parse(&reencoded)
        .and_then(|view| view.to_value())
        .expect("valid");
    assert_eq!(
        reparsed.children,
        vec![element(None, "orphan", None, vec![], vec![])],
        "a prefix without a namespace is dropped"
    );
}

#[test]
fn xml_writer_output() {
    let simple = XmlValue {
        children: vec![text("Hello & <world> \"quoted\"\r")],
        ..Default::default()
    };
    assert_eq!(
        write_property(&simple, Some("DAV:"), "displayname"),
        "<displayname xmlns=\"DAV:\">Hello &amp; &lt;world&gt; \"quoted\"&#13;</displayname>"
    );

    let empty = XmlValue::default();
    assert_eq!(
        write_property(&empty, Some("http://apple.com/ns/ical/"), "calendar-order"),
        "<calendar-order xmlns=\"http://apple.com/ns/ical/\"/>"
    );
    assert_eq!(write_property(&empty, None, "bare"), "<bare xmlns=\"\"/>");

    let subscribed = XmlValue {
        children: vec![element(
            Some("DAV:"),
            "href",
            None,
            vec![],
            vec![text("https://example.com/holidays.ics")],
        )],
        ..Default::default()
    };
    assert_eq!(
        write_property(&subscribed, Some("http://calendarserver.org/ns/"), "source"),
        concat!(
            "<source xmlns=\"http://calendarserver.org/ns/\">",
            "<href xmlns=\"DAV:\">https://example.com/holidays.ics</href>",
            "</source>"
        )
    );

    let nested = XmlValue {
        lang: Some(Cow::Borrowed("en")),
        attributes: vec![
            attribute(None, "symbolic-color", "red"),
            attribute(Some("urn:attr"), "kind", "tab\there\nline"),
            attribute(Some("urn:attr"), "other", "x"),
        ],
        children: vec![
            element(None, "unqualified", None, vec![], vec![text("u")]),
            element(
                Some("urn:x"),
                "prefixed",
                Some("X"),
                vec![attribute(Some("urn:x"), "same", "1")],
                vec![element(Some("urn:x"), "inner", Some("X"), vec![], vec![])],
            ),
            element(Some("urn:parent"), "same-default", None, vec![], vec![]),
        ],
    };
    assert_eq!(
        write_property(&nested, Some("urn:parent"), "prop"),
        concat!(
            "<prop xmlns=\"urn:parent\" xml:lang=\"en\" symbolic-color=\"red\" ",
            "xmlns:a0=\"urn:attr\" a0:kind=\"tab&#9;here&#10;line\" a0:other=\"x\">",
            "<unqualified xmlns=\"\">u</unqualified>",
            "<X:prefixed xmlns:X=\"urn:x\" X:same=\"1\"><X:inner/></X:prefixed>",
            "<same-default/>",
            "</prop>"
        )
    );

    let collision = XmlValue {
        children: vec![element(
            Some("urn:x"),
            "e",
            Some("a0"),
            vec![attribute(Some("urn:y"), "attr", "v")],
            vec![],
        )],
        ..Default::default()
    };
    assert_eq!(
        write_property(&collision, Some("urn:p"), "p"),
        concat!(
            "<p xmlns=\"urn:p\">",
            "<a0:e xmlns:a0=\"urn:x\" xmlns:a1=\"urn:y\" a1:attr=\"v\"/>",
            "</p>"
        ),
        "generated prefixes never shadow stored ones"
    );
}

#[test]
fn xml_nesting_is_bounded() {
    let mut node = text("leaf");
    for _ in 0..70 {
        node = element(Some("urn:x"), "n", None, vec![], vec![node]);
    }
    let value = XmlValue {
        children: vec![node],
        ..Default::default()
    };
    assert!(value.encode().is_err());
}

#[test]
fn truncated_and_corrupted_containers_never_panic() {
    let bytes = sample_container();
    assert!(MetadataView::new(&bytes).is_some());

    for len in 0..bytes.len() {
        assert!(
            MetadataView::new(&bytes[..len]).is_none(),
            "a container truncated to {len} bytes was accepted"
        );
    }

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(MetadataView::new(&trailing).is_none());

    let mut wrong_version = bytes.clone();
    wrong_version[0] = 2;
    assert!(MetadataView::new(&wrong_version).is_none());

    let mut wrong_kinds = bytes.clone();
    wrong_kinds[1] = MetadataKinds::JMAP.bits();
    assert!(MetadataView::new(&wrong_kinds).is_none());

    for position in 0..bytes.len() {
        for flip in [0x01u8, 0x40, 0x80, 0xFF] {
            let mut corrupted = bytes.clone();
            corrupted[position] ^= flip;
            if let Some(view) = MetadataView::new(&corrupted) {
                exercise(&view);
            }
        }
    }

    let mut lcg = Lcg(0xdead_beef);
    for _ in 0..2000 {
        let len = lcg.below(64) as usize;
        let mut garbage: Vec<u8> = (0..len).map(|_| lcg.next() as u8).collect();
        if let Some(first) = garbage.first_mut() {
            *first = 1;
        }
        if let Some(view) = MetadataView::new(&garbage) {
            exercise(&view);
        }
        let _ = DavValueView::parse(&garbage).map(|view| view.to_value());
    }
}

fn exercise(view: &MetadataView<'_>) {
    for (namespace, value) in view.jmap() {
        let _ = namespace.name();
        let _ = value.to_value::<Null, Null>();
        let _ = value.members().count();
    }
    for (name, value) in view.dav() {
        let _ = value.to_value();
        let mut out = String::new();
        let _ = value.write_property(&name, &mut out);
    }
    for (name, value) in view.imap() {
        let _ = (name.len(), value.len());
    }
    let _ = MetadataBuilder::from_view(view).encode();
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ReferenceKey {
    Vendor(String),
    Dav(Option<String>, String),
    Imap(String),
}

#[derive(Debug, Clone, PartialEq)]
enum ReferenceValue {
    Json(String),
    Dav(XmlValue<'static>),
    Imap(Vec<u8>),
}

fn random_json(lcg: &mut Lcg, depth: u32) -> String {
    let keys = ["a", "b", "color", "id", "receivedAt", "x"];
    let members = 1 + lcg.below(3);
    let mut out = String::from("{");
    for index in 0..members {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!("\"{}{index}\":", lcg.pick(&keys)));
        match lcg.below(if depth < 3 { 7 } else { 5 }) {
            0 => out.push_str(&lcg.below(1000).to_string()),
            1 => out.push_str(&format!("-{}", 1 + lcg.below(1_000_000))),
            2 => out.push_str(&format!("\"{}\"", "v".repeat(lcg.below(200) as usize))),
            3 => out.push_str("[true,null,2.5]"),
            4 => out.push_str("false"),
            _ => out.push_str(&random_json(lcg, depth + 1)),
        }
    }
    out.push('}');
    out
}

fn random_xml(lcg: &mut Lcg) -> XmlValue<'static> {
    let namespaces = [
        None,
        Some("DAV:"),
        Some("urn:custom"),
        Some("http://calendarserver.org/ns"),
    ];
    let mut children = Vec::new();
    for _ in 0..lcg.below(3) {
        children.push(if lcg.below(2) == 0 {
            XmlNode::Text(Cow::Owned("t".repeat(lcg.below(20) as usize)))
        } else {
            XmlNode::Element(XmlElement {
                name: XmlName::owned(
                    lcg.pick(&namespaces).map(str::to_string),
                    "child".to_string(),
                ),
                prefix: None,
                attributes: vec![],
                children: vec![XmlNode::Text(Cow::Owned(lcg.below(100).to_string()))],
            })
        });
    }
    XmlValue {
        lang: (lcg.below(3) == 0).then(|| Cow::Owned("en".to_string())),
        attributes: (0..lcg.below(2))
            .map(|index| XmlAttribute {
                name: XmlName::owned(None, format!("attr{index}")),
                value: Cow::Owned(lcg.below(10).to_string()),
            })
            .collect(),
        children,
    }
}

fn assert_matches_reference(
    view: &MetadataView<'_>,
    reference: &BTreeMap<ReferenceKey, ReferenceValue>,
) {
    let mut expected_jmap = Vec::new();
    let mut expected_dav = Vec::new();
    let mut expected_imap = Vec::new();
    for (key, value) in reference {
        match (key, value) {
            (ReferenceKey::Vendor(name), ReferenceValue::Json(text)) => {
                expected_jmap.push((name.clone(), json(text).to_string()))
            }
            (ReferenceKey::Dav(namespace, name), ReferenceValue::Dav(value)) => {
                expected_dav.push((namespace.clone(), name.clone(), value.clone()))
            }
            (ReferenceKey::Imap(name), ReferenceValue::Imap(value)) => {
                expected_imap.push((name.clone(), value.clone()))
            }
            _ => unreachable!(),
        }
    }

    let jmap: Vec<_> = view
        .jmap()
        .map(|(namespace, value)| {
            (
                namespace.name().to_string(),
                value
                    .to_value::<Null, Null>()
                    .expect("decodable")
                    .to_string(),
            )
        })
        .collect();
    let dav: Vec<_> = view
        .dav()
        .map(|(name, value)| {
            (
                name.namespace().map(str::to_string),
                name.name().to_string(),
                value.to_value().expect("decodable").into_owned(),
            )
        })
        .collect();
    let imap: Vec<_> = view
        .imap()
        .map(|(name, value)| (name.to_string(), value.to_vec()))
        .collect();

    assert_eq!(jmap, expected_jmap);
    assert_eq!(dav, expected_dav);
    assert_eq!(imap, expected_imap);

    let mut kinds = MetadataKinds::NONE;
    if !expected_jmap.is_empty() {
        kinds.insert(MetadataKinds::JMAP);
    }
    if !expected_dav.is_empty() {
        kinds.insert(MetadataKinds::DAV);
    }
    if !expected_imap.is_empty() {
        kinds.insert(MetadataKinds::IMAP);
    }
    assert_eq!(view.kinds(), kinds);
    assert_eq!(view.len(), reference.len());
}

#[test]
fn builder_matches_reference_model() {
    let vendors = ["a.example", "b.example", "zz.example", "a.b.example"];
    let dav_names = [
        (None, "foo"),
        (Some("DAV:"), "foo"),
        (Some("urn:x"), "foo"),
        (Some("urn:x"), "bar"),
        (Some("http://calendarserver.org/ns/"), "source"),
        (Some("http://calendarserver.org/ns"), "source"),
    ];
    let imap_names = ["/comment", "/vendor/a/b", "/vendor/a", "/specialuse"];
    let mut lcg = Lcg(0x5eed_1234);

    for _ in 0..300 {
        let mut reference = BTreeMap::new();
        let mut stored: Option<Vec<u8>> = None;

        for _ in 0..(1 + lcg.below(12)) {
            let view = stored
                .as_deref()
                .map(|bytes| MetadataView::new(bytes).expect("valid stored container"))
                .unwrap_or_else(MetadataView::empty);
            let mut builder = MetadataBuilder::from_view(&view);

            for _ in 0..(1 + lcg.below(4)) {
                match lcg.below(6) {
                    0 => {
                        let name: &'static str = lcg.pick(&vendors);
                        let text = random_json(&mut lcg, 0);
                        builder.set_jmap(vendor(name), encode(&text));
                        reference.insert(
                            ReferenceKey::Vendor(name.to_string()),
                            ReferenceValue::Json(text),
                        );
                    }
                    1 => {
                        let name: &'static str = lcg.pick(&vendors);
                        assert_eq!(
                            builder.remove_jmap(&vendor(name)),
                            reference
                                .remove(&ReferenceKey::Vendor(name.to_string()))
                                .is_some()
                        );
                    }
                    2 => {
                        let (namespace, name) = *lcg.pick(&dav_names);
                        let value = random_xml(&mut lcg);
                        builder
                            .set_dav(XmlName::borrowed(namespace, name), &value)
                            .expect("encodable");
                        reference.insert(
                            ReferenceKey::Dav(namespace.map(str::to_string), name.to_string()),
                            ReferenceValue::Dav(value),
                        );
                    }
                    3 => {
                        let (namespace, name) = *lcg.pick(&dav_names);
                        assert_eq!(
                            builder.remove_dav(&XmlName::borrowed(namespace, name)),
                            reference
                                .remove(&ReferenceKey::Dav(
                                    namespace.map(str::to_string),
                                    name.to_string()
                                ))
                                .is_some()
                        );
                    }
                    4 => {
                        let name = lcg.pick(&imap_names).to_string();
                        let value: Vec<u8> = (0..lcg.below(40)).map(|_| lcg.next() as u8).collect();
                        builder.set_imap(Cow::Owned(name.clone()), &value);
                        reference.insert(ReferenceKey::Imap(name), ReferenceValue::Imap(value));
                    }
                    _ => {
                        let name = lcg.pick(&imap_names).to_string();
                        assert_eq!(
                            builder.remove_imap(&name),
                            reference.remove(&ReferenceKey::Imap(name)).is_some()
                        );
                    }
                }
            }

            let encoded = builder.encode();
            assert_eq!(encoded.is_none(), reference.is_empty());
            let next = encoded.map(|encoded| encoded.into_bytes());
            match next.as_deref() {
                Some(bytes) => {
                    let view = MetadataView::new(bytes).expect("encoder output validates");
                    assert_matches_reference(&view, &reference);
                    let rebuilt = MetadataBuilder::from_view(&view)
                        .encode()
                        .map(|encoded| encoded.into_bytes());
                    assert_eq!(rebuilt.as_deref(), Some(bytes), "encoding is canonical");
                }
                None => assert!(reference.is_empty()),
            }
            stored = next;
        }
    }
}

#[test]
fn large_builders_match_reference_model() {
    let vendors: Vec<String> = (0..400).map(|i| format!("v{i:03}.example")).collect();
    let imap_names: Vec<String> = (0..400).map(|i| format!("/shared/n{i:03}")).collect();
    let mut lcg = Lcg(0x0b16_b00b);
    let mut reference = BTreeMap::new();
    let mut stored: Option<Vec<u8>> = None;

    for _ in 0..6 {
        let view = stored
            .as_deref()
            .map(|bytes| MetadataView::new(bytes).expect("valid stored container"))
            .unwrap_or_else(MetadataView::empty);
        let mut builder = MetadataBuilder::from_view(&view);
        let mut written = false;

        for _ in 0..600 {
            match lcg.below(5) {
                0 | 1 => {
                    let name = lcg.pick(&vendors).as_str();
                    let text = random_json(&mut lcg, 0);
                    builder.set_jmap(vendor(name), encode(&text));
                    let value = ReferenceValue::Json(json(&text).to_string());
                    written |= reference
                        .insert(ReferenceKey::Vendor(name.to_string()), value.clone())
                        != Some(value);
                }
                2 => {
                    let name = lcg.pick(&vendors).as_str();
                    assert_eq!(
                        builder.remove_jmap(&vendor(name)),
                        reference
                            .remove(&ReferenceKey::Vendor(name.to_string()))
                            .is_some()
                    );
                }
                3 => {
                    let name = lcg.pick(&imap_names).clone();
                    let value: Vec<u8> = (0..lcg.below(8)).map(|_| lcg.next() as u8).collect();
                    builder.set_imap(Cow::Owned(name.clone()), &value);
                    let value = ReferenceValue::Imap(value);
                    written |=
                        reference.insert(ReferenceKey::Imap(name), value.clone()) != Some(value);
                }
                _ => {
                    let name = lcg.pick(&imap_names).as_str();
                    assert_eq!(
                        builder.remove_imap(name),
                        reference
                            .remove(&ReferenceKey::Imap(name.to_string()))
                            .is_some()
                    );
                }
            }

            let name = lcg.pick(&vendors).as_str();
            assert_eq!(
                builder
                    .jmap(&vendor(name))
                    .and_then(|value| value.to_value::<Null, Null>())
                    .map(|value| value.to_string()),
                match reference.get(&ReferenceKey::Vendor(name.to_string())) {
                    Some(ReferenceValue::Json(text)) => Some(text.clone()),
                    _ => None,
                }
            );
            let name = lcg.pick(&imap_names).as_str();
            assert_eq!(
                builder.imap(name),
                match reference.get(&ReferenceKey::Imap(name.to_string())) {
                    Some(ReferenceValue::Imap(value)) => Some(value.as_slice()),
                    _ => None,
                }
            );
            assert_eq!(builder.len(), reference.len());
        }

        assert_eq!(
            builder.edit(),
            if written {
                MetadataEdit::Write
            } else {
                MetadataEdit::RemovalOnly
            }
        );
        let next = builder.encode().map(|encoded| encoded.into_bytes());
        match next.as_deref() {
            Some(bytes) => {
                let view = MetadataView::new(bytes).expect("encoder output validates");
                assert_matches_reference(&view, &reference);
                let rebuilt = MetadataBuilder::from_view(&view)
                    .encode()
                    .map(|encoded| encoded.into_bytes());
                assert_eq!(rebuilt.as_deref(), Some(bytes), "encoding is canonical");
            }
            None => assert!(reference.is_empty()),
        }
        stored = next;
    }
    assert!(
        reference.len() > 256,
        "the test reaches the tree representation"
    );

    let bytes = stored.expect("non-empty container");
    let view = MetadataView::new(&bytes).expect("valid");
    let mut builder = MetadataBuilder::from_view(&view);
    builder.clear_jmap();
    reference.retain(|key, _| matches!(key, ReferenceKey::Imap(_)));
    let cleared = builder.encode().expect("imap entries remain").into_bytes();
    assert_matches_reference(&MetadataView::new(&cleared).expect("valid"), &reference);
}

#[test]
fn limits_apply_per_scope() {
    let limits = MetadataLimits {
        max_depth: Some(8),
        max_entry_size: 16,
        max_size: 64,
        max_private_size: 32,
        max_entries: 2,
    };
    assert_eq!(limits.check_entry_size(16), Ok(()));
    assert_eq!(
        limits.check_entry_size(17),
        Err(LimitViolation::EntrySize { size: 17, max: 16 })
    );

    let mut builder = MetadataBuilder::new();
    builder.set_imap(Cow::Borrowed("/a"), &[0; 20]);
    let one = builder.encode().expect("non-empty");
    assert_eq!(limits.check_edit(MetadataScope::Shared, 0, 0, &one), Ok(()));
    assert_eq!(
        limits.check_edit(MetadataScope::Private, 0, 0, &one),
        Ok(())
    );

    builder.set_imap(Cow::Borrowed("/b"), &[0; 20]);
    let two = builder.encode().expect("non-empty");
    assert_eq!(limits.check_edit(MetadataScope::Shared, 0, 0, &two), Ok(()));
    assert!(matches!(
        limits.check_edit(MetadataScope::Private, one.len(), 1, &two),
        Err(LimitViolation::ContainerSize { max: 32, .. })
    ));

    builder.set_imap(Cow::Borrowed("/c"), &[]);
    let three = builder.encode().expect("non-empty");
    assert_eq!(
        limits.check_edit(MetadataScope::Shared, two.len(), 2, &three),
        Err(LimitViolation::Entries { count: 3, max: 2 })
    );
    let edit_from = |len, entries| limits.check_edit(MetadataScope::Private, len, entries, &three);
    assert_eq!(edit_from(three.len(), 3), Ok(()));
    assert!(matches!(
        edit_from(three.len() - 1, 3),
        Err(LimitViolation::ContainerSize { max: 32, .. })
    ));
    for (len, entries) in [(three.len(), 2), (0, 0)] {
        assert_eq!(
            edit_from(len, entries),
            Err(LimitViolation::Entries { count: 3, max: 2 })
        );
    }

    let bound = limits.entry_bound(0);
    assert_eq!((bound.check(2, 0), bound.check(3, 1)), (Ok(()), Ok(())));
    assert_eq!(
        bound.check(3, 0),
        Err(LimitViolation::Entries { count: 3, max: 2 })
    );
    assert_eq!(limits.entry_bound(4).check(5, 1), Ok(()));
    assert_eq!(
        limits.entry_bound(4).check(6, 1),
        Err(LimitViolation::Entries { count: 5, max: 2 })
    );
}
