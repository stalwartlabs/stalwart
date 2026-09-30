/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{DavParser, Error, tokenizer::Tokenizer},
    schema::{
        property::{
            ActiveLock, CalDavProperty, DavProperty, DavValue, LockScope, LockType, WebDavProperty,
        },
        request::{DavPropertyValue, LockInfo, MkCol, PropFind, PropertyUpdate},
    },
};
use std::borrow::Cow;
use types::metadata::{
    DavValueView, XmlAttribute, XmlElement, XmlError, XmlName, XmlNode, XmlValue,
};

const XML: &str = "http://www.w3.org/XML/1998/namespace";

fn parse_update(props: &str) -> crate::parser::Result<PropertyUpdate> {
    let xml = format!(
        "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop>{props}</D:prop></D:set></D:propertyupdate>"
    );
    PropertyUpdate::parse(&mut Tokenizer::new(xml.as_bytes()))
}

fn dead_values(update: PropertyUpdate) -> Vec<(XmlName<'static>, XmlValue<'static>)> {
    update
        .set
        .into_iter()
        .map(|property| match (property.property, property.value) {
            (DavProperty::Dead(name), DavValue::Dead(value)) => (name, *value),
            other => panic!("expected a dead property, got {other:?}"),
        })
        .collect()
}

fn single(props: &str) -> (XmlName<'static>, XmlValue<'static>) {
    let mut values = dead_values(parse_update(props).expect("valid request"));
    assert_eq!(values.len(), 1, "{values:?}");
    values.pop().expect("one value")
}

fn write(name: &XmlName<'static>, value: &XmlValue<'static>) -> String {
    DavPropertyValue::new(
        DavProperty::Dead(name.clone()),
        value.to_encoded().expect("encodable"),
    )
    .to_string()
}

fn assert_round_trip(name: &XmlName<'static>, value: &XmlValue<'static>) -> String {
    let written = write(name, value);
    let (reparsed_name, reparsed) = single(&written);
    assert_eq!(&reparsed_name, name, "{written}");
    assert_eq!(&reparsed, value, "{written}");
    written
}

fn text(value: &str) -> XmlNode<'static> {
    XmlNode::Text(Cow::Owned(value.to_string()))
}

fn element(
    namespace: Option<&str>,
    name: &str,
    prefix: Option<&str>,
    attributes: Vec<XmlAttribute<'static>>,
    children: Vec<XmlNode<'static>>,
) -> XmlNode<'static> {
    XmlNode::Element(XmlElement {
        name: XmlName::owned(namespace.map(str::to_string), name.to_string()),
        prefix: prefix.map(|prefix| Cow::Owned(prefix.to_string())),
        attributes,
        children,
    })
}

fn attribute(namespace: Option<&str>, name: &str, value: &str) -> XmlAttribute<'static> {
    XmlAttribute {
        name: XmlName::owned(namespace.map(str::to_string), name.to_string()),
        value: Cow::Owned(value.to_string()),
    }
}

#[test]
fn namespaces_prefixes_and_attribute_namespaces() {
    let (name, value) = single(concat!(
        "<x:author xmlns:x=\"http://example.com/ns\" xmlns:h=\"http://www.w3.org/1999/xhtml\" ",
        "x:kind=\"person\" plain='say \"hi\"'>",
        "<x:name>Jane</x:name>",
        "<h:em h:class=\"strong\">too</h:em>",
        "<note xmlns=\"urn:default\"><inner/><bare xmlns=\"\"/></note>",
        "<unqualified xmlns=\"\"/>",
        "</x:author>"
    ));
    assert_eq!(
        name,
        XmlName::borrowed(Some("http://example.com/ns"), "author")
    );
    assert_eq!(
        value,
        XmlValue {
            lang: None,
            attributes: vec![
                attribute(Some("http://example.com/ns"), "kind", "person"),
                attribute(None, "plain", "say \"hi\""),
            ],
            children: vec![
                element(
                    Some("http://example.com/ns"),
                    "name",
                    Some("x"),
                    vec![],
                    vec![text("Jane")]
                ),
                element(
                    Some("http://www.w3.org/1999/xhtml"),
                    "em",
                    Some("h"),
                    vec![attribute(
                        Some("http://www.w3.org/1999/xhtml"),
                        "class",
                        "strong"
                    )],
                    vec![text("too")]
                ),
                element(
                    Some("urn:default"),
                    "note",
                    None,
                    vec![],
                    vec![
                        element(Some("urn:default"), "inner", None, vec![], vec![]),
                        element(None, "bare", None, vec![], vec![]),
                    ]
                ),
                element(None, "unqualified", None, vec![], vec![]),
            ],
        }
    );
    assert_round_trip(&name, &value);
}

#[test]
fn xml_lang_in_scope() {
    let parse = |xml: &str| {
        dead_values(PropertyUpdate::parse(&mut Tokenizer::new(xml.as_bytes())).expect("valid"))
    };
    let langs = |values: Vec<(XmlName<'static>, XmlValue<'static>)>| {
        values
            .into_iter()
            .map(|(_, value)| value.lang.map(Cow::into_owned))
            .collect::<Vec<_>>()
    };

    assert_eq!(
        langs(parse(concat!(
            "<D:propertyupdate xmlns:D=\"DAV:\" xml:lang=\"en\">",
            "<D:set><D:prop><x:a xmlns:x=\"urn:x\"/></D:prop></D:set>",
            "<D:set xml:lang=\"fr\"><D:prop><x:b xmlns:x=\"urn:x\"/></D:prop></D:set>",
            "<D:set xml:lang=\"fr\"><D:prop xml:lang=\"de\">",
            "<x:c xmlns:x=\"urn:x\"/><x:d xmlns:x=\"urn:x\" xml:lang=\"it\"/>",
            "<x:e xmlns:x=\"urn:x\" xml:lang=\"\"/>",
            "</D:prop></D:set>",
            "</D:propertyupdate>"
        ))),
        vec![
            Some("en".to_string()),
            Some("fr".to_string()),
            Some("de".to_string()),
            Some("it".to_string()),
            None
        ]
    );

    let (name, value) = single(concat!(
        "<x:p xmlns:x=\"urn:x\" xml:lang=\"en-GB\">",
        "<x:q xml:lang=\"de\">Hallo</x:q>",
        "</x:p>"
    ));
    assert_eq!(value.lang.as_deref(), Some("en-GB"));
    assert!(value.attributes.is_empty());
    assert_eq!(
        value.children,
        vec![element(
            Some("urn:x"),
            "q",
            Some("x"),
            vec![attribute(Some(XML), "lang", "de")],
            vec![text("Hallo")]
        )]
    );
    let written = assert_round_trip(&name, &value);
    assert!(written.contains(" xml:lang=\"en-GB\""), "{written}");

    let mkcol = MkCol::parse(&mut Tokenizer::new(
        concat!(
            "<D:mkcol xmlns:D=\"DAV:\" xml:lang=\"es\"><D:set><D:prop>",
            "<x:a xmlns:x=\"urn:x\">hola</x:a>",
            "</D:prop></D:set></D:mkcol>"
        )
        .as_bytes(),
    ))
    .expect("valid");
    assert!(matches!(
        mkcol.props.as_slice(),
        [DavPropertyValue { value: DavValue::Dead(value), .. }] if value.lang.as_deref() == Some("es")
    ));
}

#[test]
fn significant_whitespace_and_merged_text() {
    let (name, value) = single(concat!(
        "<x:p xmlns:x=\"urn:x\">  a &amp; b <![CDATA[<c> & ]]>&#x41;&#66;<!-- gone -->d  ",
        "<x:q>\n\t</x:q>\r\n  </x:p>"
    ));
    assert_eq!(
        value.children,
        vec![
            text("  a & b <c> & ABd  "),
            element(Some("urn:x"), "q", Some("x"), vec![], vec![text("\n\t")]),
            text("\n  "),
        ]
    );
    assert_round_trip(&name, &value);

    let (_, blank) = single("<x:p xmlns:x=\"urn:x\">   </x:p>");
    assert_eq!(blank.children, vec![text("   ")]);

    let (_, empty) = single("<x:p xmlns:x=\"urn:x\"></x:p>");
    assert!(empty.children.is_empty());
    let (_, empty) = single("<x:p xmlns:x=\"urn:x\"/>");
    assert!(empty.is_empty());

    let (name, carriage) =
        single("<x:p xmlns:x=\"urn:x\" a=\"tab&#9;nl&#10;cr&#13;\">cr&#13;</x:p>");
    assert_eq!(carriage.children, vec![text("cr\r")]);
    assert_eq!(
        carriage.attributes,
        vec![attribute(None, "a", "tab\tnl\ncr\r")]
    );
    assert_round_trip(&name, &carriage);
}

#[test]
fn writer_output_is_well_formed_for_nested_values() {
    let (name, value) = single(concat!(
        "<C:source xmlns:C=\"http://calendarserver.org/ns/\">",
        "<D:href>https://example.com/a.ics</D:href>",
        "<C:outer><C:middle><C:inner x=\"1\">deep</C:inner></C:middle></C:outer>",
        "</C:source>"
    ));
    let written = assert_round_trip(&name, &value);
    assert_eq!(
        written,
        concat!(
            "<source xmlns=\"http://calendarserver.org/ns/\">",
            "<D:href xmlns:D=\"DAV:\">https://example.com/a.ics</D:href>",
            "<C:outer xmlns:C=\"http://calendarserver.org/ns/\"><C:middle><C:inner x=\"1\">",
            "deep</C:inner></C:middle></C:outer>",
            "</source>"
        )
    );

    let (name, value) =
        single("<p xmlns=\"urn:parent\"><child>x</child><other xmlns=\"\">y</other></p>");
    let written = assert_round_trip(&name, &value);
    assert_eq!(
        written,
        "<p xmlns=\"urn:parent\"><child>x</child><other xmlns=\"\">y</other></p>"
    );

    let (name, value) = single(concat!(
        "<x:p xmlns:x=\"urn:x\" xmlns:a=\"urn:a\" a:one=\"1\">",
        "<x:c xmlns:a0=\"urn:other\" a0:two=\"2\" a:three=\"3\"/>",
        "</x:p>"
    ));
    let written = assert_round_trip(&name, &value);
    assert_eq!(
        written,
        concat!(
            "<p xmlns=\"urn:x\" xmlns:a0=\"urn:a\" a0:one=\"1\">",
            "<x:c xmlns:x=\"urn:x\" xmlns:a1=\"urn:other\" a1:two=\"2\" a0:three=\"3\"/>",
            "</p>"
        )
    );
}

#[test]
fn known_non_live_names_become_dead_with_their_exact_namespace() {
    let update = parse_update(concat!(
        "<C:source xmlns:C=\"http://calendarserver.org/ns\"><D:href>u</D:href></C:source>",
        "<C:getctag xmlns:C=\"http://calendarserver.org/ns\">1</C:getctag>",
        "<D:displayname>n</D:displayname>",
        "<D:supported-live-property-set/>"
    ))
    .expect("valid");
    let properties = update
        .set
        .iter()
        .map(|property| &property.property)
        .collect::<Vec<_>>();
    assert_eq!(
        properties,
        [
            &DavProperty::Dead(XmlName::borrowed(
                Some("http://calendarserver.org/ns"),
                "source"
            )),
            &DavProperty::WebDav(WebDavProperty::GetCTag),
            &DavProperty::WebDav(WebDavProperty::DisplayName),
            &DavProperty::Dead(XmlName::borrowed(
                Some("DAV:"),
                "supported-live-property-set"
            )),
        ]
    );

    let propfind = PropFind::parse(&mut Tokenizer::new(
        concat!(
            "<D:propfind xmlns:D=\"DAV:\" xmlns:C=\"http://calendarserver.org/ns\" ",
            "xmlns:A=\"urn:ietf:params:xml:ns:caldav\"><D:prop>",
            "<C:source/><A:calendar-description/><unbound/>",
            "</D:prop></D:propfind>"
        )
        .as_bytes(),
    ))
    .expect("valid");
    assert_eq!(
        propfind,
        PropFind::Prop(vec![
            DavProperty::Dead(XmlName::borrowed(
                Some("http://calendarserver.org/ns"),
                "source"
            )),
            DavProperty::CalDav(CalDavProperty::CalendarDescription),
            DavProperty::Dead(XmlName::borrowed(None, "unbound")),
        ])
    );
}

#[test]
fn escaped_known_namespaces_resolve_like_plain_ones() {
    let update = parse_update(concat!(
        "<X:displayname xmlns:X=\"DAV&#58;\">n</X:displayname>",
        "<X:unknown-name xmlns:X=\"DAV&#x3A;\">v</X:unknown-name>",
        "<Y:p xmlns:Y=\"urn:a&amp;b\"/>"
    ))
    .expect("valid");
    let properties = update
        .set
        .iter()
        .map(|property| &property.property)
        .collect::<Vec<_>>();
    assert_eq!(
        properties,
        [
            &DavProperty::WebDav(WebDavProperty::DisplayName),
            &DavProperty::Dead(XmlName::borrowed(Some("DAV:"), "unknown-name")),
            &DavProperty::Dead(XmlName::borrowed(Some("urn:a&b"), "p")),
        ]
    );
}

#[test]
fn fuzz_oracle_over_fixtures() {
    let mut inputs = std::fs::read_dir("resources/requests")
        .expect("fixtures")
        .filter_map(|entry| {
            let path = entry.expect("fixture entry").path();
            (path.extension().is_some_and(|ext| ext == "xml"))
                .then(|| std::fs::read(path).expect("readable fixture"))
        })
        .collect::<Vec<_>>();
    inputs.extend(
        [
            concat!(
                "<D:propertyupdate xmlns:D=\"DAV:\" xml:lang=\"en\"><D:set><D:prop>",
                "<x:p xmlns:x=\"urn:x\" xmlns:y=\"urn:y\" y:a=\"1\" b='\"'>",
                " t <![CDATA[<c>]]> <x:q xml:lang=\"de\" y:c=\"&#9;\">&#13;</x:q>",
                "<a0:r xmlns:a0=\"urn:z\" y:d=\"2\"/><s xmlns=\"\"/></x:p>",
                "</D:prop></D:set></D:propertyupdate>"
            ),
            concat!(
                "<D:mkcol xmlns:D=\"DAV:\"><D:set><D:prop>",
                "<C:source xmlns:C=\"http://calendarserver.org/ns\"><D:href>u</D:href></C:source>",
                "</D:prop></D:set></D:mkcol>"
            ),
            concat!(
                "<D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:shared/></D:lockscope>",
                "<D:locktype><D:write/></D:locktype>",
                "<D:owner xml:lang=\"fr\" x:k=\"v\" xmlns:x=\"urn:x\">",
                "<D:href>mailto:a@b</D:href> text</D:owner></D:lockinfo>"
            ),
        ]
        .map(|input| input.as_bytes().to_vec()),
    );

    let mut checked = 0;
    for input in &inputs {
        if let Ok(update) = PropertyUpdate::parse(&mut Tokenizer::new(input)) {
            checked += update.set.into_iter().map(check_property).sum::<usize>();
        }
        if let Ok(mkcol) = MkCol::parse(&mut Tokenizer::new(input)) {
            checked += mkcol.props.into_iter().map(check_property).sum::<usize>();
        }
        if let Ok(LockInfo {
            owner: Some(owner), ..
        }) = LockInfo::parse(&mut Tokenizer::new(input))
        {
            check_owner(owner);
            checked += 1;
        }
    }
    assert!(checked >= 15, "{checked}");
}

fn check_property(property: DavPropertyValue) -> usize {
    let (DavProperty::Dead(name), DavValue::Dead(value)) = (property.property, property.value)
    else {
        return 0;
    };
    check_encoding(&value);

    let written = DavPropertyValue::new(
        DavProperty::Dead(name.clone()),
        value.to_encoded().expect("a parsed value encodes"),
    )
    .to_string();
    let request = format!(
        "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop>{written}</D:prop></D:set></D:propertyupdate>"
    );
    let reparsed = PropertyUpdate::parse(&mut Tokenizer::new(request.as_bytes()))
        .unwrap_or_else(|err| panic!("written value does not parse: {err} {written}"));
    match reparsed.set.as_slice() {
        [
            DavPropertyValue {
                property: DavProperty::Dead(reparsed_name),
                value: DavValue::Dead(reparsed_value),
            },
        ] => {
            assert_eq!(reparsed_name, &name, "{written}");
            assert_eq!(reparsed_value, &value, "{written}");
        }
        other => panic!("written value parses differently: {other:?} {written}"),
    }
    1
}

fn check_owner(owner: XmlValue<'static>) {
    check_encoding(&owner);

    let written = LockInfo {
        lock_scope: LockScope::Exclusive,
        lock_type: LockType::Write,
        owner: Some(owner.clone()),
    }
    .to_string()
    .replacen("<D:lockinfo>", "<D:lockinfo xmlns:D=\"DAV:\">", 1);
    let reparsed = LockInfo::parse(&mut Tokenizer::new(written.as_bytes()))
        .unwrap_or_else(|err| panic!("written owner does not parse: {err} {written}"));
    assert_eq!(reparsed.owner.as_ref(), Some(&owner), "{written}");
}

fn check_encoding(value: &XmlValue<'_>) {
    let encoded = value.encode().expect("a parsed value encodes");
    assert_eq!(Ok(encoded.len()), value.encoded_len());
    let view = DavValueView::parse(&encoded).expect("an encoded value validates");
    assert_eq!(view.to_value().as_ref(), Some(value));
    let mut out = String::new();
    view.write_property(&XmlName::borrowed(Some("urn:fuzz"), "p"), &mut out)
        .expect("an encoded value writes");
}

#[test]
fn invalid_values_are_rejected() {
    for props in [
        "<x:p xmlns:x=\"urn:x\">&unknown;</x:p>",
        "<x:p xmlns:x=\"urn:x\"><y:q/></x:p>",
        "<x:p xmlns:x=\"urn:x\" xmlns:a=\"urn:a\" xmlns:b=\"urn:a\" a:k=\"1\" b:k=\"2\"/>",
        "<x:p xmlns:x=\"urn:x\" k=\"1\" k=\"2\"/>",
        "<x:p xmlns:x=\"urn:x\" xml:lang=\"en\" xml:lang=\"de\"/>",
        "<x:p xmlns:x=\"urn:x\">&#1;</x:p>",
        "<x:p xmlns:x=\"urn:x\"><q xmlns=\"http://www.w3.org/XML/1998/namespace\"/></x:p>",
        "<x:p xmlns:x=\"urn:x\"><xmlns:q/></x:p>",
        "<x:p xmlns:x=\"urn:x\"><x:1q/></x:p>",
        "<x:p xmlns:x=\"urn:x\"><x:q>unterminated</x:p>",
        "<p xmlns=\"http://www.w3.org/XML/1998/namespace\"/>",
    ] {
        assert!(parse_update(props).is_err(), "{props}");
    }

    let mut deep = String::from("<x:p xmlns:x=\"urn:x\">");
    for _ in 0..XmlValue::MAX_DEPTH {
        deep.push_str("<x:n>");
    }
    for _ in 0..XmlValue::MAX_DEPTH {
        deep.push_str("</x:n>");
    }
    deep.push_str("</x:p>");
    let (name, value) = single(&deep);
    assert_round_trip(&name, &value);

    let too_deep = deep
        .replacen("<x:n>", "<x:n><x:n>", 1)
        .replacen("</x:n>", "</x:n></x:n>", 1);
    assert!(matches!(
        parse_update(&too_deep),
        Err(Error::Value(XmlError::NestingTooDeep))
    ));
}

#[test]
fn lock_owner_round_trip() {
    let info = LockInfo::parse(&mut Tokenizer::new(
        concat!(
            "<D:lockinfo xmlns:D=\"DAV:\" xml:lang=\"en\">",
            "<D:lockscope><D:exclusive/></D:lockscope>",
            "<D:locktype><D:write/></D:locktype>",
            "<D:owner><D:href>http://example.org/~ejw/contact.html</D:href></D:owner>",
            "</D:lockinfo>"
        )
        .as_bytes(),
    ))
    .expect("valid");
    let owner = info.owner.expect("owner");
    assert_eq!(owner.lang.as_deref(), Some("en"));
    assert_eq!(
        owner.children,
        vec![element(
            Some("DAV:"),
            "href",
            Some("D"),
            vec![],
            vec![text("http://example.org/~ejw/contact.html")]
        )]
    );

    let lock = ActiveLock::new("/dav/file/jane/doc", LockScope::Exclusive)
        .with_owner(owner.to_encoded().expect("encodable"))
        .to_string();
    assert!(
        lock.contains(concat!(
            "<D:owner xml:lang=\"en\">",
            "<D:href>http://example.org/~ejw/contact.html</D:href>",
            "</D:owner>"
        )),
        "{lock}"
    );
}

#[test]
fn random_values_round_trip() {
    let mut rng = Lcg(0x5eed_1234_abcd_ef01);
    for _ in 0..500 {
        let name = XmlName::owned(
            rng.pick(&[
                Some("urn:p"),
                None,
                Some("DAV:"),
                Some("http://calendarserver.org/ns"),
            ])
            .map(str::to_string),
            rng.pick(&["prop", "calendar-color", "x"]).to_string(),
        );
        let value = XmlValue {
            lang: rng
                .chance(4)
                .then(|| Cow::Owned(rng.pick(&["en", "de-CH"]).to_string())),
            attributes: rng.attributes(false),
            children: rng.children(0),
        };
        assert_round_trip(&name, &value);
    }
}

struct Lcg(u64);

const NAMESPACES: &[Option<&str>] = &[
    None,
    Some("urn:a"),
    Some("urn:b"),
    Some("DAV:"),
    Some("http://calendarserver.org/ns"),
    Some("urn:q&\"<>"),
];
const PREFIXES: &[&str] = &["a0", "a1", "D", "p", "q"];
const NAMES: &[&str] = &["n", "href", "value", "a0", "x-y.z"];
const TEXTS: &[&str] = &[
    "t",
    " ",
    "\n",
    "<&>",
    "\"'",
    "\u{e9}\u{65e5}",
    "]]>",
    "\r",
    "\t",
];

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, max: usize) -> usize {
        (self.next() % max as u64) as usize
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn text(&mut self) -> String {
        (0..1 + self.below(4)).map(|_| self.pick(TEXTS)).collect()
    }

    fn attributes(&mut self, allow_xml: bool) -> Vec<XmlAttribute<'static>> {
        let mut attributes: Vec<XmlAttribute<'static>> = Vec::new();
        for _ in 0..self.below(4) {
            let namespace = if allow_xml && self.chance(6) {
                Some(XML)
            } else {
                self.pick(NAMESPACES)
            };
            let candidate = attribute(namespace, self.pick(NAMES), &self.text());
            if !attributes
                .iter()
                .any(|existing| existing.name == candidate.name)
            {
                attributes.push(candidate);
            }
        }
        attributes
    }

    fn children(&mut self, depth: usize) -> Vec<XmlNode<'static>> {
        let mut children = Vec::new();
        let mut last_is_text = false;
        for _ in 0..self.below(if depth < 4 { 4 } else { 1 }) {
            if !last_is_text && self.chance(2) {
                children.push(text(&self.text()));
                last_is_text = true;
            } else {
                let namespace = self.pick(NAMESPACES);
                let prefix = namespace
                    .filter(|_| self.chance(2))
                    .map(|_| self.pick(PREFIXES));
                children.push(element(
                    namespace,
                    self.pick(NAMES),
                    prefix,
                    self.attributes(true),
                    self.children(depth + 1),
                ));
                last_is_text = false;
            }
        }
        children
    }
}
