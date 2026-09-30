/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::webdav::{DavResponse, DummyWebDavClient};
use hyper::StatusCode;
use quick_xml::{
    NsReader, XmlVersion,
    escape::resolve_predefined_entity,
    events::{BytesStart, Event},
    name::ResolveResult,
};
use std::fmt::{self, Display, Write};

pub const DAV_NS: &str = "DAV:";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct XmlAttribute {
    pub namespace: Option<String>,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlNode {
    Element(XmlElement),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlElement {
    pub namespace: Option<String>,
    pub name: String,
    pub attributes: Vec<XmlAttribute>,
    pub children: Vec<XmlNode>,
}

pub struct DavProp<'x> {
    pub status: StatusCode,
    pub element: &'x XmlElement,
}

impl XmlElement {
    pub fn parse(xml: &str) -> XmlElement {
        let mut reader = NsReader::from_str(xml);
        let mut buf = Vec::new();
        let mut stack: Vec<XmlElement> = Vec::new();

        loop {
            let (namespace, event) = reader
                .read_resolved_event_into(&mut buf)
                .unwrap_or_else(|err| panic!("Invalid XML ({err}): {xml}"));
            match event {
                Event::Start(ref e) => {
                    let namespace = resolved(&namespace);
                    let element = new_element(&reader, e, namespace);
                    stack.push(element);
                }
                Event::Empty(ref e) => {
                    let namespace = resolved(&namespace);
                    let element = new_element(&reader, e, namespace);
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(XmlNode::Element(element)),
                        None => return element,
                    }
                }
                Event::End(_) => {
                    let element = stack.pop().expect("balanced XML");
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(XmlNode::Element(element)),
                        None => return element,
                    }
                }
                Event::Text(e) => {
                    let text = e
                        .xml_content(XmlVersion::Implicit1_0)
                        .expect("valid text")
                        .into_owned();
                    append_text(&mut stack, &text);
                }
                Event::CData(e) => {
                    let text = e.decode().expect("valid CDATA").into_owned();
                    append_text(&mut stack, &text);
                }
                Event::GeneralRef(entity) => {
                    let text = match entity.resolve_char_ref() {
                        Ok(Some(ch)) => ch.to_string(),
                        _ => {
                            let name = entity.decode().expect("valid entity");
                            resolve_predefined_entity(&name)
                                .unwrap_or_else(|| panic!("Unknown entity {name:?}"))
                                .to_string()
                        }
                    };
                    append_text(&mut stack, &text);
                }
                Event::Eof => panic!("Unexpected end of XML: {xml}"),
                _ => {}
            }
            buf.clear();
        }
    }

    pub fn is(&self, namespace: &str, name: &str) -> bool {
        self.name == name && self.namespace.as_deref().unwrap_or_default() == namespace
    }

    pub fn child(&self, namespace: &str, name: &str) -> Option<&XmlElement> {
        self.elements().find(|element| element.is(namespace, name))
    }

    pub fn children_named<'x>(
        &'x self,
        namespace: &'x str,
        name: &'x str,
    ) -> impl Iterator<Item = &'x XmlElement> + 'x {
        self.elements()
            .filter(move |element| element.is(namespace, name))
    }

    pub fn elements(&self) -> impl Iterator<Item = &XmlElement> {
        self.children.iter().filter_map(|node| match node {
            XmlNode::Element(element) => Some(element),
            XmlNode::Text(_) => None,
        })
    }

    pub fn text(&self) -> String {
        let mut text = String::new();
        for node in &self.children {
            match node {
                XmlNode::Text(value) => text.push_str(value),
                XmlNode::Element(element) => text.push_str(&element.text()),
            }
        }
        text
    }

    pub fn attribute(&self, namespace: &str, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| {
                attribute.name == name
                    && attribute.namespace.as_deref().unwrap_or_default() == namespace
            })
            .map(|attribute| attribute.value.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }

    pub fn assert_equivalent(&self, expected: &XmlElement, context: &str) {
        if self != expected {
            panic!("{context}: XML values differ.\ngot:      {self}\nexpected: {expected}");
        }
    }

    pub fn response_hrefs(&self) -> Vec<String> {
        let mut hrefs = self
            .children_named(DAV_NS, "response")
            .filter_map(|response| response.child(DAV_NS, "href"))
            .map(|href| href.text())
            .collect::<Vec<_>>();
        hrefs.sort_unstable();
        hrefs
    }

    pub fn property<'x>(
        &'x self,
        href: &'x str,
        namespace: &str,
        name: &str,
    ) -> Option<DavProp<'x>> {
        self.props(href)
            .find(|prop| prop.element.is(namespace, name))
    }

    pub fn props<'x>(&'x self, href: &'x str) -> impl Iterator<Item = DavProp<'x>> + 'x {
        self.children_named(DAV_NS, "response")
            .filter(move |response| {
                response
                    .child(DAV_NS, "href")
                    .is_some_and(|value| value.text() == href)
            })
            .flat_map(|response| response.children_named(DAV_NS, "propstat"))
            .flat_map(|propstat| {
                let status = propstat
                    .child(DAV_NS, "status")
                    .map(|status| parse_status(&status.text()))
                    .unwrap_or(StatusCode::OK);
                propstat
                    .child(DAV_NS, "prop")
                    .into_iter()
                    .flat_map(|prop| prop.elements())
                    .map(move |element| DavProp { status, element })
            })
    }

    pub fn expect_property<'x>(
        &'x self,
        href: &'x str,
        namespace: &str,
        name: &str,
    ) -> DavProp<'x> {
        self.property(href, namespace, name).unwrap_or_else(|| {
            panic!("Property {{{namespace}}}{name} not found for {href} in {self}")
        })
    }

    pub fn assert_property_absent(&self, href: &str, namespace: &str, name: &str) {
        if let Some(prop) = self.property(href, namespace, name)
            && prop.status.is_success()
        {
            panic!(
                "Property {{{namespace}}}{name} unexpectedly present for {href}: {}",
                prop.element
            );
        }
    }
}

impl DavProp<'_> {
    pub fn with_status(&self, status: StatusCode) -> &Self {
        if self.status != status {
            panic!(
                "Expected status {status} for {} but got {}",
                self.element, self.status
            );
        }
        self
    }
}

impl DavResponse {
    pub fn xml_tree(&self) -> XmlElement {
        XmlElement::parse(self.expect_body())
    }
}

impl DummyWebDavClient {
    pub async fn proppatch_xml(&self, path: &str, updates: &str) -> DavResponse {
        self.request(
            "PROPPATCH",
            path,
            format!(
                concat!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                    "<D:propertyupdate xmlns:D=\"DAV:\">{}</D:propertyupdate>"
                ),
                updates
            ),
        )
        .await
    }

    pub async fn propfind_xml(&self, path: &str, depth: &str, body: &str) -> XmlElement {
        self.request_with_headers(
            "PROPFIND",
            path,
            [("depth", depth)],
            format!(
                concat!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                    "<D:propfind xmlns:D=\"DAV:\">{}</D:propfind>"
                ),
                body
            ),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree()
    }

    pub async fn propfind_allprop(&self, path: &str, depth: &str) -> XmlElement {
        self.propfind_xml(path, depth, "<D:allprop/>").await
    }

    pub async fn propfind_propname(&self, path: &str, depth: &str) -> XmlElement {
        self.propfind_xml(path, depth, "<D:propname/>").await
    }

    pub async fn propfind_named(&self, path: &str, depth: &str, props: &str) -> XmlElement {
        self.propfind_xml(path, depth, &format!("<D:prop>{props}</D:prop>"))
            .await
    }
}

impl Display for XmlElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('<')?;
        if let Some(namespace) = &self.namespace {
            write!(f, "{{{namespace}}}")?;
        }
        f.write_str(&self.name)?;
        for attribute in &self.attributes {
            f.write_char(' ')?;
            if let Some(namespace) = &attribute.namespace {
                write!(f, "{{{namespace}}}")?;
            }
            write!(f, "{}={:?}", attribute.name, attribute.value)?;
        }
        f.write_char('>')?;
        for node in &self.children {
            match node {
                XmlNode::Element(element) => element.fmt(f)?,
                XmlNode::Text(text) => write!(f, "{text:?}")?,
            }
        }
        f.write_str("</")?;
        f.write_str(&self.name)?;
        f.write_char('>')
    }
}

fn resolved(namespace: &ResolveResult<'_>) -> Option<String> {
    match namespace {
        ResolveResult::Bound(namespace) => {
            Some(String::from_utf8_lossy(namespace.as_ref()).into_owned())
        }
        ResolveResult::Unbound => None,
        ResolveResult::Unknown(prefix) => {
            panic!("Undeclared prefix {:?}", String::from_utf8_lossy(prefix))
        }
    }
}

fn new_element(
    reader: &NsReader<&[u8]>,
    start: &BytesStart<'_>,
    namespace: Option<String>,
) -> XmlElement {
    let mut attributes = Vec::new();
    for attribute in start.attributes() {
        let attribute = attribute.expect("valid attribute");
        if attribute.key.as_namespace_binding().is_some() {
            continue;
        }
        let (attribute_namespace, local_name) = reader.resolver().resolve_attribute(attribute.key);
        attributes.push(XmlAttribute {
            namespace: resolved(&attribute_namespace),
            name: String::from_utf8_lossy(local_name.as_ref()).into_owned(),
            value: attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .expect("valid attribute value")
                .into_owned(),
        });
    }
    attributes.sort_unstable();

    XmlElement {
        namespace,
        name: String::from_utf8_lossy(start.local_name().as_ref()).into_owned(),
        attributes,
        children: Vec::new(),
    }
}

fn append_text(stack: &mut [XmlElement], text: &str) {
    let Some(element) = stack.last_mut() else {
        return;
    };
    if let Some(XmlNode::Text(current)) = element.children.last_mut() {
        current.push_str(text);
    } else {
        element.children.push(XmlNode::Text(text.to_string()));
    }
}

fn parse_status(status: &str) -> StatusCode {
    status
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .unwrap_or_else(|| panic!("Invalid status line {status:?}"))
}
