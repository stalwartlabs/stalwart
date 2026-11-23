/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::value::{DateTime, EwsValue, T, ews_fields, fields_value};
use crate::{
    common::{Braces, Guid, HexCase},
    ews::{
        parser::{ParseErrorKind, Parser, Result},
        schema::{BodyType, FlagStatus},
    },
    xml::{Attrs, Ns, XmlWriter},
};
use std::borrow::Cow;

ews_fields! {
    pub struct EffectiveRights {
        create_associated: "CreateAssociated" => bool,
        create_contents: "CreateContents" => bool,
        create_hierarchy: "CreateHierarchy" => bool,
        delete: "Delete" => bool,
        modify: "Modify" => bool,
        read: "Read" => bool,
        view_private_items: "ViewPrivateItems" => bool,
    }
}

fields_value!(EffectiveRights);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body<'x> {
    pub body_type: BodyType,
    pub is_truncated: Option<bool>,
    pub text: Cow<'x, str>,
}

impl<'x> EwsValue<'x> for Body<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let body_type = p
            .attr_enum(attrs, "BodyType", BodyType::parse)?
            .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("BodyType")))?;
        let is_truncated = p.attr_value(attrs, "IsTruncated")?;
        Ok(Body {
            body_type,
            is_truncated,
            text: p.text()?,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local).attr("BodyType", self.body_type.as_str());
        if let Some(truncated) = self.is_truncated {
            w.attr_bool("IsTruncated", truncated);
        }
        w.close_start();
        w.text(&self.text);
        w.end(T, local);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternetHeader<'x> {
    pub name: Cow<'x, str>,
    pub value: Cow<'x, str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InternetHeaders<'x>(pub Vec<InternetHeader<'x>>);

impl<'x> EwsValue<'x> for InternetHeaders<'x> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            if child.local == "InternetMessageHeader" {
                p.expect_types(&child)?;
                let name = p.attr(&child.attrs, "HeaderName")?.unwrap_or_default();
                list.push(InternetHeader {
                    name,
                    value: p.text()?,
                });
            } else {
                p.skip()?;
            }
        }
        Ok(InternetHeaders(list))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        let mut named = self.0.iter().filter(|header| !header.name.is_empty());
        let Some(first) = named.next() else {
            return;
        };
        w.start(T, local);
        for header in std::iter::once(first).chain(named) {
            w.start(T, "InternetMessageHeader")
                .attr("HeaderName", &header.name)
                .close_start();
            w.text(&header.value);
            w.end(T, "InternetMessageHeader");
        }
        w.end(T, local);
    }
}

ews_fields! {
    pub struct Flag {
        flag_status: "FlagStatus" => FlagStatus,
        start_date: "StartDate" => DateTime,
        due_date: "DueDate" => DateTime,
        complete_date: "CompleteDate" => DateTime,
    }
}

impl<'x> EwsValue<'x> for Flag {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut flag = Flag::default();
        while let Some(mut child) = p.child()? {
            child.ns = Ns::Types;
            if !flag.parse_child(p, &child)? {
                p.skip()?;
            }
        }
        Ok(flag)
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        self.write_fields(w);
        w.end(T, local);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionTag {
    pub guid: Guid,
    pub is_explicit: Option<bool>,
}

impl<'x> EwsValue<'x> for RetentionTag {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let is_explicit = p.attr_value(attrs, "IsExplicit")?;
        Ok(RetentionTag {
            guid: p.value("guid")?,
            is_explicit,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        if let Some(explicit) = self.is_explicit {
            w.attr_bool("IsExplicit", explicit);
        }
        w.close_start();
        self.guid
            .write_text(w.buffer(), HexCase::Lower, Braces::None);
        w.end(T, local);
    }
}
