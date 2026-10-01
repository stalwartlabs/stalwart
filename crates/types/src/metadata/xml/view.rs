/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    DavValueView, ELEMENT_HAS_PREFIX, EncodedDavValue, MAX_XML_NESTING, NODE_ELEMENT, NODE_TEXT,
    VALUE_HAS_LANG, XmlAttribute, XmlElement, XmlName, XmlNode, XmlValue, read_ns_ref,
    validate::{AttributeScope, check_attribute, check_element, has_duplicates, is_xml_text},
    writer::write_element,
};
use crate::metadata::codec::{CheckedReader, Reader, TrustedReader};
use std::{borrow::Cow, fmt};

pub(crate) fn dav_value_span<'x, const TRUSTED: bool>(
    reader: &mut Reader<'x, TRUSTED>,
) -> Option<Reader<'x, TRUSTED>> {
    let start = *reader;
    let len = reader.len()?;
    reader.skip(len)?;
    reader.consumed_since(&start)
}

fn validate_attributes(reader: &mut CheckedReader<'_>, scope: AttributeScope) -> Option<()> {
    let count = reader.len()?;
    let mut names = Vec::with_capacity(count.min(reader.remaining().len()));
    for _ in 0..count {
        let namespace = read_ns_ref(reader)?;
        let name = reader.str()?;
        check_attribute(namespace, name, reader.str()?, scope).ok()?;
        names.push((namespace, name));
    }
    (!has_duplicates(&names, |name| *name)).then_some(())
}

fn validate_children(reader: &mut CheckedReader<'_>, nesting: u32) -> Option<()> {
    if nesting > MAX_XML_NESTING {
        return None;
    }
    let count = reader.len()?;
    for _ in 0..count {
        match reader.u8()? {
            NODE_TEXT => {
                is_xml_text(reader.str()?).then_some(())?;
            }
            NODE_ELEMENT => {
                let namespace = read_ns_ref(reader)?;
                let name = reader.str()?;
                let prefix = match reader.u8()? {
                    0 => None,
                    ELEMENT_HAS_PREFIX => Some(reader.str()?),
                    _ => return None,
                };
                if prefix.is_some() && namespace.is_none() {
                    return None;
                }
                check_element(namespace, name, prefix).ok()?;
                validate_attributes(reader, AttributeScope::Element)?;
                validate_children(reader, nesting + 1)?;
            }
            _ => return None,
        }
    }
    Some(())
}

pub(crate) fn validate_dav_value(reader: &mut CheckedReader<'_>) -> Option<()> {
    let len = reader.len()?;
    let mut rest = reader.take_reader(len)?;
    match rest.u8()? {
        0 => {}
        VALUE_HAS_LANG => {
            is_xml_text(rest.str()?).then_some(())?;
        }
        _ => return None,
    }
    validate_attributes(&mut rest, AttributeScope::Property)?;
    validate_children(&mut rest, 1)?;
    rest.is_empty().then_some(())
}

struct ValueParts<'x> {
    lang: Option<&'x str>,
    body: TrustedReader<'x>,
}

impl<'x> DavValueView<'x> {
    pub(crate) const fn new(reader: TrustedReader<'x>) -> Self {
        DavValueView { reader }
    }

    pub fn parse(bytes: &'x [u8]) -> Option<Self> {
        let mut reader = Reader::checked(bytes);
        validate_dav_value(&mut reader)?;
        reader.is_empty().then_some(())?;
        Some(DavValueView {
            reader: unsafe { Reader::trusted(bytes) },
        })
    }

    pub fn as_bytes(&self) -> &'x [u8] {
        self.reader.remaining()
    }

    pub fn encoded_len(&self) -> usize {
        self.reader.remaining().len()
    }

    fn parts(&self) -> Option<ValueParts<'x>> {
        let mut reader = self.reader;
        let len = reader.len()?;
        let mut body = reader.take_reader(len)?;
        let lang = match body.u8()? {
            VALUE_HAS_LANG => Some(body.str()?),
            _ => None,
        };
        Some(ValueParts { lang, body })
    }

    pub fn lang(&self) -> Option<&'x str> {
        self.parts()?.lang
    }

    pub fn to_value(&self) -> Option<XmlValue<'x>> {
        let mut parts = self.parts()?;
        Some(XmlValue {
            lang: parts.lang.map(Cow::Borrowed),
            attributes: decode_attributes(&mut parts.body)?,
            children: decode_children(&mut parts.body, 1)?,
        })
    }

    pub fn text(&self) -> Option<Cow<'x, str>> {
        let mut body = self.parts()?.body;
        if body.len()? == 0 && body.len()? == 1 && body.u8()? == NODE_TEXT {
            return body.str().map(Cow::Borrowed);
        }
        let mut text = String::new();
        for child in self.to_value()?.children {
            if let XmlNode::Text(part) = child {
                text.push_str(&part);
            }
        }
        Some(Cow::Owned(text))
    }

    pub fn to_encoded(&self) -> EncodedDavValue {
        EncodedDavValue(self.as_bytes().into())
    }

    pub fn write_property(&self, name: &XmlName<'_>, out: &mut dyn fmt::Write) -> fmt::Result {
        let mut parts = self.parts().ok_or(fmt::Error)?;
        write_element(
            out,
            name.namespace(),
            name.name(),
            None,
            parts.lang,
            &mut parts.body,
        )
    }

    pub fn write_property_prefixed(
        &self,
        name: &XmlName<'_>,
        bound_prefix: &str,
        out: &mut dyn fmt::Write,
    ) -> fmt::Result {
        let mut parts = self.parts().ok_or(fmt::Error)?;
        write_element(
            out,
            name.namespace(),
            name.name(),
            Some(bound_prefix),
            parts.lang,
            &mut parts.body,
        )
    }
}

fn decode_attributes<'x>(reader: &mut TrustedReader<'x>) -> Option<Vec<XmlAttribute<'x>>> {
    let count = reader.len()?;
    let mut attributes = Vec::with_capacity(count.min(reader.remaining().len()));
    for _ in 0..count {
        let namespace = read_ns_ref(reader)?;
        let name = reader.str()?;
        let value = reader.str()?;
        attributes.push(XmlAttribute {
            name: XmlName::borrowed(namespace, name),
            value: Cow::Borrowed(value),
        });
    }
    Some(attributes)
}

fn decode_children<'x>(reader: &mut TrustedReader<'x>, nesting: u32) -> Option<Vec<XmlNode<'x>>> {
    if nesting > MAX_XML_NESTING {
        return None;
    }
    let count = reader.len()?;
    let mut children = Vec::with_capacity(count.min(reader.remaining().len()));
    for _ in 0..count {
        children.push(match reader.u8()? {
            NODE_TEXT => XmlNode::Text(Cow::Borrowed(reader.str()?)),
            NODE_ELEMENT => {
                let namespace = read_ns_ref(reader)?;
                let name = reader.str()?;
                let prefix = match reader.u8()? {
                    ELEMENT_HAS_PREFIX => Some(Cow::Borrowed(reader.str()?)),
                    _ => None,
                };
                XmlNode::Element(XmlElement {
                    name: XmlName::borrowed(namespace, name),
                    prefix,
                    attributes: decode_attributes(reader)?,
                    children: decode_children(reader, nesting + 1)?,
                })
            }
            _ => return None,
        });
    }
    Some(children)
}
