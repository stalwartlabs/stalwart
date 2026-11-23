/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    path::Paths,
    value::{EwsValue, T, ews_struct},
};
use crate::{
    ews::{
        parser::{Parser, Result},
        schema::BaseShape,
    },
    xml::{Attrs, XmlWriter, writer::bool_str},
};
use std::borrow::Cow;

ews_struct! {
    pub struct PersonaShape<'x> {
        base: req "BaseShape" => BaseShape,
        additional: opt "AdditionalProperties" => Paths<'x>,
    }
}

ews_struct! {
    pub struct ContextProperty<'x> {
        key: req "Key" => Cow<'x, str>,
        value: req "Value" => Cow<'x, str>,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueryString<'a> {
    pub text: Cow<'a, str>,
    pub reset_cache: Option<bool>,
    pub return_highlight_terms: Option<bool>,
    pub return_deleted_items: Option<bool>,
}

impl<'a> EwsValue<'a> for QueryString<'a> {
    fn parse(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        Ok(QueryString {
            reset_cache: p.attr_value(attrs, "ResetCache")?,
            return_highlight_terms: p.attr_value(attrs, "ReturnHighlightTerms")?,
            return_deleted_items: p.attr_value(attrs, "ReturnDeletedItems")?,
            text: p.text()?,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        for (name, value) in [
            ("ResetCache", self.reset_cache),
            ("ReturnHighlightTerms", self.return_highlight_terms),
            ("ReturnDeletedItems", self.return_deleted_items),
        ] {
            if let Some(value) = value {
                w.attr(name, bool_str(value));
            }
        }
        w.close_start();
        w.text(&self.text);
        w.end(T, local);
    }
}
