/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    path::{Path, Paths},
    value::EwsValue,
};
use crate::{
    ews::{
        parser::{ParseErrorKind, Parser, Result},
        schema::{BaseShape, BodyTypeResponse},
    },
    xml::Attrs,
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemShape<'a> {
    pub base: BaseShape,
    pub include_mime: bool,
    pub body_type: Option<BodyTypeResponse>,
    pub unique_body_type: Option<BodyTypeResponse>,
    pub normalized_body_type: Option<BodyTypeResponse>,
    pub filter_html: bool,
    pub convert_html_to_utf8: bool,
    pub inline_image_url_template: Option<Cow<'a, str>>,
    pub block_external_images: bool,
    pub add_blank_target: bool,
    pub max_body_size: Option<u32>,
    pub additional: Vec<Path<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderShape<'a> {
    pub base: BaseShape,
    pub additional: Vec<Path<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttachmentShape<'a> {
    pub include_mime: bool,
    pub body_type: Option<BodyTypeResponse>,
    pub filter_html: bool,
    pub additional: Vec<Path<'a>>,
}

fn additional<'a>(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Vec<Path<'a>>> {
    Paths::parse(p, attrs).map(|paths| paths.0)
}

impl<'a> ItemShape<'a> {
    pub fn parse(p: &mut Parser<'a>) -> Result<Self> {
        let mut base = None;
        let mut shape = ItemShape {
            base: BaseShape::Default,
            include_mime: false,
            body_type: None,
            unique_body_type: None,
            normalized_body_type: None,
            filter_html: false,
            convert_html_to_utf8: false,
            inline_image_url_template: None,
            block_external_images: false,
            add_blank_target: false,
            max_body_size: None,
            additional: Vec::new(),
        };
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "BaseShape" => {
                    p.expect_types(&child)?;
                    base = Some(p.text_enum("BaseShape", BaseShape::parse)?);
                },
                "IncludeMimeContent" => {
                    p.expect_types(&child)?;
                    shape.include_mime = p.value("IncludeMimeContent")?;
                },
                "BodyType" => {
                    p.expect_types(&child)?;
                    shape.body_type = Some(p.text_enum("BodyType", BodyTypeResponse::parse)?);
                },
                "UniqueBodyType" => {
                    p.expect_types(&child)?;
                    shape.unique_body_type = Some(p.text_enum("UniqueBodyType", BodyTypeResponse::parse)?);
                },
                "NormalizedBodyType" => {
                    p.expect_types(&child)?;
                    shape.normalized_body_type = Some(p.text_enum("NormalizedBodyType", BodyTypeResponse::parse)?);
                },
                "FilterHtmlContent" => {
                    p.expect_types(&child)?;
                    shape.filter_html = p.value("FilterHtmlContent")?;
                },
                "ConvertHtmlCodePageToUTF8" => {
                    p.expect_types(&child)?;
                    shape.convert_html_to_utf8 = p.value("ConvertHtmlCodePageToUTF8")?;
                },
                "InlineImageUrlTemplate" => {
                    p.expect_types(&child)?;
                    shape.inline_image_url_template = Some(p.text()?);
                },
                "BlockExternalImages" => {
                    p.expect_types(&child)?;
                    shape.block_external_images = p.value("BlockExternalImages")?;
                },
                "AddBlankTargetToLinks" => {
                    p.expect_types(&child)?;
                    shape.add_blank_target = p.value("AddBlankTargetToLinks")?;
                },
                "MaximumBodySize" => {
                    p.expect_types(&child)?;
                    shape.max_body_size = Some(p.value("MaximumBodySize")?);
                },
                "AdditionalProperties" => {
                    p.expect_types(&child)?;
                    shape.additional = additional(p, &child.attrs)?;
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        shape.base = base.ok_or_else(|| p.error(ParseErrorKind::MissingElement("BaseShape")))?;
        Ok(shape)
    }
}

impl<'a> FolderShape<'a> {
    pub fn parse(p: &mut Parser<'a>) -> Result<Self> {
        let mut base = None;
        let mut paths = Vec::new();
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "BaseShape" => {
                    p.expect_types(&child)?;
                    base = Some(p.text_enum("BaseShape", BaseShape::parse)?);
                },
                "AdditionalProperties" => {
                    p.expect_types(&child)?;
                    paths = additional(p, &child.attrs)?;
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        Ok(FolderShape {
            base: base.ok_or_else(|| p.error(ParseErrorKind::MissingElement("BaseShape")))?,
            additional: paths,
        })
    }
}

impl<'a> AttachmentShape<'a> {
    pub fn parse(p: &mut Parser<'a>) -> Result<Self> {
        let mut shape = AttachmentShape::default();
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "IncludeMimeContent" => {
                    p.expect_types(&child)?;
                    shape.include_mime = p.value("IncludeMimeContent")?;
                },
                "BodyType" => {
                    p.expect_types(&child)?;
                    shape.body_type = Some(p.text_enum("BodyType", BodyTypeResponse::parse)?);
                },
                "FilterHtmlContent" => {
                    p.expect_types(&child)?;
                    shape.filter_html = p.value("FilterHtmlContent")?;
                },
                "AdditionalProperties" => {
                    p.expect_types(&child)?;
                    shape.additional = additional(p, &child.attrs)?;
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        Ok(shape)
    }
}
