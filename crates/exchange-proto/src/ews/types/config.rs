/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ids::{ItemId, TargetFolderId},
    value::{EwsValue, Repeated, T, XBinary, XSI, enum_set, ews_struct},
};
use crate::{
    ews::{
        parser::{ParseErrorKind, Parser, Result},
        schema::{UserConfigurationDictionaryObjectType, UserConfigurationProperty},
    },
    xml::{Attrs, Ns, XmlWriter},
};
use std::borrow::Cow;

enum_set!(pub struct UserConfigurationProperties(UserConfigurationProperty) list "UserConfigurationProperties");

#[derive(Debug, Clone, PartialEq)]
pub struct UserConfigurationName<'a> {
    pub name: Cow<'a, str>,
    pub folder: TargetFolderId<'a>,
}

impl<'a> EwsValue<'a> for UserConfigurationName<'a> {
    fn parse(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        let name = p.attr_required(attrs, "Name")?;
        let folder = TargetFolderId::parse(p, attrs)?;
        Ok(UserConfigurationName { name, folder })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local).attr("Name", &self.name);
        self.folder.write_inner(w);
        w.end(T, local);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DictionaryObject<'a> {
    pub kind: UserConfigurationDictionaryObjectType,
    pub values: Vec<Cow<'a, str>>,
}

impl<'a> DictionaryObject<'a> {
    fn parse_optional(p: &mut Parser<'a>) -> Result<Option<Self>> {
        let mut kind = None;
        let mut values = Vec::new();
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "Type" => {
                    p.expect_types(&child)?;
                    kind = Some(p.text_enum("Type", UserConfigurationDictionaryObjectType::parse)?);
                },
                "Value" => {
                    p.expect_types(&child)?;
                    p.count_id()?;
                    values.push(p.text()?);
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        match kind {
            Some(kind) if !values.is_empty() => Ok(Some(DictionaryObject { kind, values })),
            Some(_) => Err(p.error(ParseErrorKind::MissingElement("Value"))),
            None if values.is_empty() => Ok(None),
            None => Err(p.error(ParseErrorKind::MissingElement("Type"))),
        }
    }

    fn write_inner(&self, w: &mut XmlWriter<'_>) {
        self.kind.write(w, "Type");
        for value in &self.values {
            w.leaf(T, "Value", value);
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DictionaryEntry<'a> {
    pub key: DictionaryObject<'a>,
    pub value: Option<DictionaryObject<'a>>,
}

impl<'a> EwsValue<'a> for DictionaryEntry<'a> {
    fn parse(p: &mut Parser<'a>, _: &Attrs<'a>) -> Result<Self> {
        let mut key = None;
        let mut value = None;
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "DictionaryKey" => {
                    p.expect_types(&child)?;
                    key = DictionaryObject::parse_optional(p)?;
                },
                "DictionaryValue" => {
                    p.expect_types(&child)?;
                    value = DictionaryObject::parse_optional(p)?;
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        let key = key.ok_or_else(|| p.error(ParseErrorKind::MissingElement("DictionaryKey")))?;
        Ok(DictionaryEntry { key, value })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        w.start(T, "DictionaryKey");
        self.key.write_inner(w);
        w.end(T, "DictionaryKey");
        match &self.value {
            Some(value) => {
                w.start(T, "DictionaryValue");
                value.write_inner(w);
                w.end(T, "DictionaryValue");
            }
            None => {
                w.start(T, "DictionaryValue")
                    .ns_decl(XSI, Ns::Xsi.uri())
                    .attr("xsi:nil", "true")
                    .empty();
            }
        }
        w.end(T, local);
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dictionary<'a>(pub Vec<DictionaryEntry<'a>>);

impl<'a> EwsValue<'a> for Dictionary<'a> {
    fn parse(p: &mut Parser<'a>, _: &Attrs<'a>) -> Result<Self> {
        let mut entries = None::<Repeated<DictionaryEntry<'a>>>;
        while let Some(child) = p.child()? {
            if child.local == "DictionaryEntry" {
                p.expect_types(&child)?;
                p.count_id()?;
                Repeated::merge(&mut entries, p, &child.attrs)?;
            } else {
                p.skip()?;
            }
        }
        Ok(Dictionary(
            entries.map(|entries| entries.0).unwrap_or_default(),
        ))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        for entry in &self.0 {
            entry.write(w, "DictionaryEntry");
        }
        w.end(T, local);
    }
}

ews_struct! {
    pub struct UserConfiguration<'x> {
        name: req "UserConfigurationName" => UserConfigurationName<'x>,
        item_id: opt "ItemId" => ItemId<'x>,
        dictionary: opt "Dictionary" => Dictionary<'x>,
        xml_data: opt "XmlData" => XBinary<'x>,
        binary_data: opt "BinaryData" => XBinary<'x>,
    }
}
