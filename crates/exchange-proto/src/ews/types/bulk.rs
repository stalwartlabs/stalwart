/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ids::{FolderId, ItemId},
    value::{EwsValue, T, XBinary},
};
use crate::{
    ews::{
        parser::{ParseErrorKind, Parser, Result},
        schema::{CreateAction, NameEnum},
    },
    xml::{Attrs, XmlWriter, writer::bool_str},
};

#[derive(Debug, Clone, PartialEq)]
pub struct UploadItem<'x> {
    pub parent_folder_id: FolderId<'x>,
    pub item_id: Option<ItemId<'x>>,
    pub data: XBinary<'x>,
    pub create_action: CreateAction,
    pub is_associated: bool,
}

impl<'x> EwsValue<'x> for UploadItem<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let create_action = p
            .attr_enum(attrs, "CreateAction", CreateAction::parse_name)?
            .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("CreateAction")))?;
        let is_associated = p.attr_value(attrs, "IsAssociated")?.unwrap_or(false);
        let mut parent_folder_id = None;
        let mut item_id = None;
        let mut data = None;
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "ParentFolderId" => {
                    p.expect_types(&child)?;
                    parent_folder_id = Some(FolderId::parse(p, &child.attrs)?);
                },
                "ItemId" => {
                    p.expect_types(&child)?;
                    item_id = Some(ItemId::parse(p, &child.attrs)?);
                },
                "Data" => {
                    p.expect_types(&child)?;
                    data = Some(XBinary::parse(p, &child.attrs)?);
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        if item_id.is_none() && create_action != CreateAction::CreateNew {
            return Err(p.error(ParseErrorKind::MissingElement("ItemId")));
        }
        Ok(UploadItem {
            parent_folder_id: parent_folder_id
                .ok_or_else(|| p.error(ParseErrorKind::MissingElement("ParentFolderId")))?,
            item_id,
            data: data.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Data")))?,
            create_action,
            is_associated,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        w.attr("CreateAction", self.create_action.name());
        if self.is_associated {
            w.attr("IsAssociated", bool_str(true));
        }
        self.parent_folder_id.write(w, "ParentFolderId");
        if let Some(item_id) = &self.item_id {
            item_id.write(w, "ItemId");
        }
        self.data.write(w, "Data");
        w.end(T, local);
    }
}
