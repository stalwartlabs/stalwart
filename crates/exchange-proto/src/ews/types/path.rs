/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    value::{EwsValue, T},
    xprop::ExtendedFieldUri,
};
use crate::{
    ews::{
        parser::{Child, ParseErrorKind, Parser, Result},
        schema::{DictionaryField, UnindexedField},
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Path<'a> {
    Field(UnindexedField),
    Indexed {
        field: DictionaryField,
        index: Cow<'a, str>,
    },
    Extended(ExtendedFieldUri<'a>),
}

impl<'a> Path<'a> {
    pub fn parse_child(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Option<Self>> {
        let path = hashify::fnc_map!(child.local.as_bytes(),
            "FieldURI" => {
                p.expect_types(child)?;
                p.count_path()?;
                Path::Field(
                    p.attr_enum(&child.attrs, "FieldURI", UnindexedField::parse)?
                        .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("FieldURI")))?,
                )
            },
            "IndexedFieldURI" => {
                p.expect_types(child)?;
                p.count_path()?;
                Path::Indexed {
                    field: p
                        .attr_enum(&child.attrs, "FieldURI", DictionaryField::parse)?
                        .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("FieldURI")))?,
                    index: p.attr_required(&child.attrs, "FieldIndex")?,
                }
            },
            "ExtendedFieldURI" => {
                p.expect_types(child)?;
                p.count_path()?;
                Path::Extended(ExtendedFieldUri::parse_attrs(p, &child.attrs)?)
            },
            _ => {
                return Ok(None);
            }
        );
        p.skip_rest()?;
        Ok(Some(path))
    }

    pub fn parse_one(p: &mut Parser<'a>) -> Result<Self> {
        let mut found = None;
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(path) if found.is_none() => found = Some(path),
                Some(_) => return Err(p.error(ParseErrorKind::InvalidValue("Path"))),
                None => p.skip()?,
            }
        }
        found.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Path")))
    }

    pub fn write(&self, w: &mut XmlWriter<'_>) {
        match self {
            Path::Field(field) => {
                w.start(T, "FieldURI")
                    .attr("FieldURI", field.as_str())
                    .empty();
            }
            Path::Indexed { field, index } => {
                w.start(T, "IndexedFieldURI")
                    .attr("FieldURI", field.as_str())
                    .attr("FieldIndex", index)
                    .empty();
            }
            Path::Extended(uri) => uri.write(w, "ExtendedFieldURI"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Paths<'a>(pub Vec<Path<'a>>);

impl<'a> EwsValue<'a> for Paths<'a> {
    fn parse(p: &mut Parser<'a>, _: &Attrs<'a>) -> Result<Self> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            match Path::parse_child(p, &child)? {
                Some(path) => list.push(path),
                None => p.skip()?,
            }
        }
        Ok(Paths(list))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        for path in &self.0 {
            path.write(w);
        }
        w.end(T, local);
    }
}
