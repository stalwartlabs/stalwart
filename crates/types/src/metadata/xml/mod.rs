/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod validate;
mod view;
mod writer;

#[cfg(test)]
mod tests;

pub(crate) use validate::check_property_name;
pub(crate) use view::{dav_value_span, validate_dav_value};

use super::{
    codec::{Reader, TrustedReader, bytes_len, varint_len, write_bytes, write_varint},
    registry::{known_xml_namespace, known_xml_namespace_id},
};
use std::{borrow::Cow, fmt};
use validate::{AttributeScope, check_attribute, check_element, check_text, has_duplicates};

const NS_NONE: u8 = 0x00;
const NS_INLINE: u8 = 0xFF;
const NODE_TEXT: u8 = 0x01;
const NODE_ELEMENT: u8 = 0x02;
const VALUE_HAS_LANG: u8 = 1;
const ELEMENT_HAS_PREFIX: u8 = 1;
const MAX_XML_NESTING: u32 = 64;
const XML_PREFIX: &str = "xml";
const XMLNS_PREFIX: &str = "xmlns";
const GENERATED_PREFIX: &str = "a";

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
pub struct XmlName<'x> {
    pub namespace: Option<Cow<'x, str>>,
    pub name: Cow<'x, str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
pub struct XmlValue<'x> {
    pub lang: Option<Cow<'x, str>>,
    pub attributes: Vec<XmlAttribute<'x>>,
    pub children: Vec<XmlNode<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
pub struct XmlElement<'x> {
    pub name: XmlName<'x>,
    pub prefix: Option<Cow<'x, str>>,
    pub attributes: Vec<XmlAttribute<'x>>,
    pub children: Vec<XmlNode<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
pub struct XmlAttribute<'x> {
    pub name: XmlName<'x>,
    pub value: Cow<'x, str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
pub enum XmlNode<'x> {
    Text(Cow<'x, str>),
    Element(XmlElement<'x>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XmlError {
    NestingTooDeep,
    InvalidName,
    InvalidPrefix,
    InvalidNamespace,
    InvalidCharacter,
    ReservedAttribute,
    DuplicateAttribute,
}

#[derive(Debug, Clone, Copy)]
pub struct DavValueView<'x> {
    reader: TrustedReader<'x>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedDavValue(Box<[u8]>);

impl<'x> XmlName<'x> {
    pub const fn borrowed(namespace: Option<&'x str>, name: &'x str) -> Self {
        XmlName {
            namespace: match namespace {
                Some(namespace) => Some(Cow::Borrowed(namespace)),
                None => None,
            },
            name: Cow::Borrowed(name),
        }
    }

    pub fn owned(namespace: Option<String>, name: String) -> XmlName<'static> {
        XmlName {
            namespace: namespace.map(Cow::Owned),
            name: Cow::Owned(name),
        }
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn matches(&self, namespace: Option<&str>, name: &str) -> bool {
        self.name() == name && self.namespace() == namespace
    }

    pub fn into_owned(self) -> XmlName<'static> {
        XmlName {
            namespace: self
                .namespace
                .map(|namespace| Cow::Owned(namespace.into_owned())),
            name: Cow::Owned(self.name.into_owned()),
        }
    }

    pub fn validate_property(&self) -> Result<(), XmlError> {
        check_property_name(self.namespace(), self.name())
    }

    pub fn write_empty(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        writer::write_empty_element(out, self.namespace(), self.name())
    }

    pub(crate) fn key_len(&self) -> usize {
        ns_ref_len(self.namespace()) + self.name.len()
    }

    pub(crate) fn write_key(&self, out: &mut Vec<u8>) {
        write_ns_ref(out, self.namespace());
        out.extend_from_slice(self.name.as_bytes());
    }
}

fn ns_ref_len(namespace: Option<&str>) -> usize {
    match namespace {
        None => 1,
        Some(uri) if known_xml_namespace_id(uri).is_some() => 1,
        Some(uri) => 1 + bytes_len(uri.len()),
    }
}

fn write_ns_ref(out: &mut Vec<u8>, namespace: Option<&str>) {
    match namespace {
        None => out.push(NS_NONE),
        Some(uri) => match known_xml_namespace_id(uri) {
            Some(id) => out.push(id),
            None => {
                out.push(NS_INLINE);
                write_bytes(out, uri.as_bytes());
            }
        },
    }
}

pub(crate) fn read_ns_ref<'x, const TRUSTED: bool>(
    reader: &mut Reader<'x, TRUSTED>,
) -> Option<Option<&'x str>> {
    match reader.u8()? {
        NS_NONE => Some(None),
        NS_INLINE => reader.str().map(Some),
        id => known_xml_namespace(id).map(Some),
    }
}

fn element_prefix<'y>(namespace: Option<&str>, prefix: Option<&'y str>) -> Option<&'y str> {
    namespace.and(prefix)
}

fn attributes_len(
    attributes: &[XmlAttribute<'_>],
    scope: AttributeScope,
) -> Result<usize, XmlError> {
    let mut len = varint_len(attributes.len() as u64);
    for attribute in attributes {
        check_attribute(
            attribute.name.namespace(),
            attribute.name.name(),
            &attribute.value,
            scope,
        )?;
        len += ns_ref_len(attribute.name.namespace())
            + bytes_len(attribute.name.name.len())
            + bytes_len(attribute.value.len());
    }
    if has_duplicates(attributes, |attribute| &attribute.name) {
        return Err(XmlError::DuplicateAttribute);
    }
    Ok(len)
}

fn children_len(children: &[XmlNode<'_>], nesting: u32) -> Result<usize, XmlError> {
    if nesting > MAX_XML_NESTING {
        return Err(XmlError::NestingTooDeep);
    }
    let mut len = varint_len(children.len() as u64);
    for child in children {
        len += 1 + match child {
            XmlNode::Text(text) => {
                check_text(text)?;
                bytes_len(text.len())
            }
            XmlNode::Element(element) => element.encoded_len(nesting)?,
        };
    }
    Ok(len)
}

fn write_attributes(out: &mut Vec<u8>, attributes: &[XmlAttribute<'_>]) {
    write_varint(out, attributes.len() as u64);
    for attribute in attributes {
        write_ns_ref(out, attribute.name.namespace());
        write_bytes(out, attribute.name.name.as_bytes());
        write_bytes(out, attribute.value.as_bytes());
    }
}

fn write_children(out: &mut Vec<u8>, children: &[XmlNode<'_>]) {
    write_varint(out, children.len() as u64);
    for child in children {
        match child {
            XmlNode::Text(text) => {
                out.push(NODE_TEXT);
                write_bytes(out, text.as_bytes());
            }
            XmlNode::Element(element) => {
                out.push(NODE_ELEMENT);
                element.write(out);
            }
        }
    }
}

impl XmlElement<'_> {
    fn stored_prefix(&self) -> Option<&str> {
        element_prefix(self.name.namespace(), self.prefix.as_deref())
    }

    fn encoded_len(&self, nesting: u32) -> Result<usize, XmlError> {
        check_element(
            self.name.namespace(),
            self.name.name(),
            self.prefix.as_deref(),
        )?;
        Ok(ns_ref_len(self.name.namespace())
            + bytes_len(self.name.name.len())
            + 1
            + self
                .stored_prefix()
                .map_or(0, |prefix| bytes_len(prefix.len()))
            + attributes_len(&self.attributes, AttributeScope::Element)?
            + children_len(&self.children, nesting + 1)?)
    }

    fn write(&self, out: &mut Vec<u8>) {
        write_ns_ref(out, self.name.namespace());
        write_bytes(out, self.name.name.as_bytes());
        match self.stored_prefix() {
            Some(prefix) => {
                out.push(ELEMENT_HAS_PREFIX);
                write_bytes(out, prefix.as_bytes());
            }
            None => out.push(0),
        }
        write_attributes(out, &self.attributes);
        write_children(out, &self.children);
    }
}

impl<'x> XmlValue<'x> {
    pub const MAX_DEPTH: usize = MAX_XML_NESTING as usize - 1;

    fn rest_len(&self) -> Result<usize, XmlError> {
        let lang_len = match &self.lang {
            Some(lang) => {
                check_text(lang)?;
                bytes_len(lang.len())
            }
            None => 0,
        };
        Ok(1 + lang_len
            + attributes_len(&self.attributes, AttributeScope::Property)?
            + children_len(&self.children, 1)?)
    }

    pub fn validate(&self) -> Result<(), XmlError> {
        self.rest_len().map(|_| ())
    }

    pub fn encoded_len(&self) -> Result<usize, XmlError> {
        self.rest_len().map(bytes_len)
    }

    pub fn encode(&self) -> Result<Vec<u8>, XmlError> {
        let rest_len = self.rest_len()?;
        let mut out = Vec::with_capacity(bytes_len(rest_len));
        write_varint(&mut out, rest_len as u64);
        match &self.lang {
            Some(lang) => {
                out.push(VALUE_HAS_LANG);
                write_bytes(&mut out, lang.as_bytes());
            }
            None => out.push(0),
        }
        write_attributes(&mut out, &self.attributes);
        write_children(&mut out, &self.children);
        debug_assert_eq!(out.len(), bytes_len(rest_len), "XML value length mismatch");
        Ok(out)
    }

    pub fn to_encoded(&self) -> Result<EncodedDavValue, XmlError> {
        self.encode()
            .map(|bytes| EncodedDavValue(bytes.into_boxed_slice()))
    }

    pub fn is_empty(&self) -> bool {
        self.lang.is_none() && self.attributes.is_empty() && self.children.is_empty()
    }

    pub fn into_owned(self) -> XmlValue<'static> {
        XmlValue {
            lang: self.lang.map(|lang| Cow::Owned(lang.into_owned())),
            attributes: self
                .attributes
                .into_iter()
                .map(XmlAttribute::into_owned)
                .collect(),
            children: self.children.into_iter().map(XmlNode::into_owned).collect(),
        }
    }
}

impl XmlAttribute<'_> {
    pub fn into_owned(self) -> XmlAttribute<'static> {
        XmlAttribute {
            name: self.name.into_owned(),
            value: Cow::Owned(self.value.into_owned()),
        }
    }
}

impl XmlNode<'_> {
    pub fn into_owned(self) -> XmlNode<'static> {
        match self {
            XmlNode::Text(text) => XmlNode::Text(Cow::Owned(text.into_owned())),
            XmlNode::Element(element) => XmlNode::Element(XmlElement {
                name: element.name.into_owned(),
                prefix: element.prefix.map(|prefix| Cow::Owned(prefix.into_owned())),
                attributes: element
                    .attributes
                    .into_iter()
                    .map(XmlAttribute::into_owned)
                    .collect(),
                children: element
                    .children
                    .into_iter()
                    .map(XmlNode::into_owned)
                    .collect(),
            }),
        }
    }
}

impl EncodedDavValue {
    pub fn view(&self) -> DavValueView<'_> {
        DavValueView::new(unsafe { Reader::trusted(&self.0) })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Box<[u8]> {
        self.0
    }

    pub fn encoded_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            XmlError::NestingTooDeep => "XML value is nested too deeply",
            XmlError::InvalidName => "invalid XML name",
            XmlError::InvalidPrefix => "invalid XML namespace prefix",
            XmlError::InvalidNamespace => "invalid XML namespace",
            XmlError::InvalidCharacter => "character not allowed in XML",
            XmlError::ReservedAttribute => "reserved XML attribute",
            XmlError::DuplicateAttribute => "duplicate XML attribute",
        })
    }
}
