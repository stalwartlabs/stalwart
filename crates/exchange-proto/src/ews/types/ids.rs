/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    address::EmailAddress,
    value::{DateTime, EwsValue, ListItem, T, XSI},
};
use crate::{
    common::{TokenBuf, XsDateTime},
    ews::{
        parser::{Child, ParseErrorKind, Parser, Result},
        schema::{DistinguishedFolderName, IdFormat},
    },
    xml::{Attrs, Ns, XmlWriter, writer::bool_str},
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EwsIdStr<'a> {
    Parsed(Cow<'a, str>),
    Minted(TokenBuf),
}

impl<'a> EwsIdStr<'a> {
    pub fn as_str(&self) -> &str {
        match self {
            EwsIdStr::Parsed(text) => text,
            EwsIdStr::Minted(token) => token.as_str(),
        }
    }

    pub fn parse(p: &Parser<'a>, text: Cow<'a, str>) -> Result<Self> {
        p.check_id_len(&text)?;
        Ok(EwsIdStr::Parsed(text))
    }

    fn attr(p: &Parser<'a>, attrs: &Attrs<'a>, name: &'static str) -> Result<Option<Self>> {
        p.attr(attrs, name)?
            .map(|text| Self::parse(p, text))
            .transpose()
    }

    fn attr_required(p: &Parser<'a>, attrs: &Attrs<'a>, name: &'static str) -> Result<Self> {
        Self::parse(p, p.attr_required(attrs, name)?)
    }
}

impl<'a> From<TokenBuf> for EwsIdStr<'a> {
    fn from(token: TokenBuf) -> Self {
        EwsIdStr::Minted(token)
    }
}

fn change_key_attr(w: &mut XmlWriter<'_>, change_key: &Option<EwsIdStr<'_>>) {
    if let Some(change_key) = change_key {
        w.attr("ChangeKey", change_key.as_str());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemId<'a> {
    pub id: EwsIdStr<'a>,
    pub change_key: Option<EwsIdStr<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderId<'a> {
    pub id: EwsIdStr<'a>,
    pub change_key: Option<EwsIdStr<'a>>,
}

macro_rules! id_with_change_key {
    ($name:ident) => {
        impl<'a> EwsValue<'a> for $name<'a> {
            fn parse(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
                p.count_id()?;
                let id = EwsIdStr::attr_required(p, attrs, "Id")?;
                let change_key = EwsIdStr::attr(p, attrs, "ChangeKey")?;
                p.skip_rest()?;
                Ok($name { id, change_key })
            }

            fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
                w.start(T, local);
                self.write_attrs(w);
                w.empty();
            }
        }

        impl $name<'_> {
            pub fn write_attrs(&self, w: &mut XmlWriter<'_>) {
                w.attr("Id", self.id.as_str());
                change_key_attr(w, &self.change_key);
            }
        }
    };
}

id_with_change_key!(ItemId);
id_with_change_key!(FolderId);

impl<'a> ItemId<'a> {
    pub fn parse_list(p: &mut Parser<'a>) -> Result<Vec<Self>> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            match BaseItemId::parse_child(p, &child)? {
                Some(BaseItemId::Item(id)) => list.push(id),
                Some(_) => return Err(p.error(ParseErrorKind::InvalidValue("ItemId"))),
                None => p.skip()?,
            }
        }
        Ok(list)
    }
}

impl ListItem for FolderId<'_> {
    const ITEM: &'static str = "FolderId";
}

impl ListItem for ItemId<'_> {
    const ITEM: &'static str = "ItemId";
}

#[derive(Debug, Clone, PartialEq)]
pub struct DistinguishedFolderId<'a> {
    pub name: DistinguishedFolderName,
    pub change_key: Option<EwsIdStr<'a>>,
    pub mailbox: Option<EmailAddress<'a>>,
}

impl<'a> EwsValue<'a> for DistinguishedFolderId<'a> {
    fn parse(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        p.count_id()?;
        let name = p.attr_required(attrs, "Id")?;
        let name = DistinguishedFolderName::parse(name.trim_ascii().as_bytes())
            .unwrap_or(DistinguishedFolderName::Unknown);
        let change_key = EwsIdStr::attr(p, attrs, "ChangeKey")?;
        let mut mailbox = None;
        while let Some(child) = p.child()? {
            if child.local == "Mailbox" {
                p.expect_types(&child)?;
                mailbox = Some(EmailAddress::parse(p, &child.attrs)?);
            } else {
                p.skip()?;
            }
        }
        Ok(DistinguishedFolderId {
            name,
            change_key,
            mailbox,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local).attr("Id", self.name.as_str());
        change_key_attr(w, &self.change_key);
        if let Some(mailbox) = &self.mailbox {
            mailbox.write(w, "Mailbox");
        }
        w.end(T, local);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BaseFolderId<'a> {
    Folder(FolderId<'a>),
    Distinguished(DistinguishedFolderId<'a>),
}

impl<'a> BaseFolderId<'a> {
    pub fn parse_child(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Option<Self>> {
        let id = hashify::fnc_map!(child.local.as_bytes(),
            "FolderId" => {
                p.expect_types(child)?;
                BaseFolderId::Folder(FolderId::parse(p, &child.attrs)?)
            },
            "DistinguishedFolderId" => {
                p.expect_types(child)?;
                BaseFolderId::Distinguished(DistinguishedFolderId::parse(p, &child.attrs)?)
            },
            _ => {
                return Ok(None);
            }
        );
        Ok(Some(id))
    }

    pub fn parse_list(p: &mut Parser<'a>) -> Result<Vec<Self>> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(id) => list.push(id),
                None => p.skip()?,
            }
        }
        Ok(list)
    }

    pub fn parse_one(p: &mut Parser<'a>, name: &'static str) -> Result<Self> {
        let mut found = None;
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(id) if found.is_none() => found = Some(id),
                Some(_) => return Err(p.error(ParseErrorKind::InvalidValue(name))),
                None => p.skip()?,
            }
        }
        found.ok_or_else(|| p.error(ParseErrorKind::MissingElement(name)))
    }

    pub fn write(&self, w: &mut XmlWriter<'_>) {
        match self {
            BaseFolderId::Folder(id) => id.write(w, "FolderId"),
            BaseFolderId::Distinguished(id) => id.write(w, "DistinguishedFolderId"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TargetFolderId<'a> {
    Folder(FolderId<'a>),
    Distinguished(DistinguishedFolderId<'a>),
    AddressList(EwsIdStr<'a>),
}

impl<'a> EwsValue<'a> for TargetFolderId<'a> {
    fn parse(p: &mut Parser<'a>, _: &Attrs<'a>) -> Result<Self> {
        let mut found = None;
        while let Some(child) = p.child()? {
            let id = if child.local == "AddressListId" {
                p.expect_types(&child)?;
                p.count_id()?;
                let id = EwsIdStr::attr_required(p, &child.attrs, "Id")?;
                p.skip_rest()?;
                TargetFolderId::AddressList(id)
            } else {
                match BaseFolderId::parse_child(p, &child)? {
                    Some(BaseFolderId::Folder(id)) => TargetFolderId::Folder(id),
                    Some(BaseFolderId::Distinguished(id)) => TargetFolderId::Distinguished(id),
                    None => {
                        p.skip()?;
                        continue;
                    }
                }
            };
            if found.replace(id).is_some() {
                return Err(p.error(ParseErrorKind::InvalidValue("TargetFolderId")));
            }
        }
        found.ok_or_else(|| p.error(ParseErrorKind::MissingElement("TargetFolderId")))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        self.write_inner(w);
        w.end(T, local);
    }
}

impl TargetFolderId<'_> {
    pub fn write_inner(&self, w: &mut XmlWriter<'_>) {
        match self {
            TargetFolderId::Folder(id) => id.write(w, "FolderId"),
            TargetFolderId::Distinguished(id) => id.write(w, "DistinguishedFolderId"),
            TargetFolderId::AddressList(id) => {
                w.start(T, "AddressListId").attr("Id", id.as_str()).empty();
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccurrenceRange {
    pub start: Option<XsDateTime>,
    pub end: Option<XsDateTime>,
    pub count: Option<i32>,
    pub compare_original_start_time: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterRanges<'a> {
    pub id: ItemId<'a>,
    pub ranges: Vec<OccurrenceRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseItemId<'a> {
    Item(ItemId<'a>),
    Occurrence {
        master: EwsIdStr<'a>,
        change_key: Option<EwsIdStr<'a>>,
        index: i32,
    },
    RecurringMaster {
        occurrence: EwsIdStr<'a>,
        change_key: Option<EwsIdStr<'a>>,
    },
    MasterRanges(Box<MasterRanges<'a>>),
}

impl<'a> BaseItemId<'a> {
    pub fn parse_child(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Option<Self>> {
        let id = hashify::fnc_map!(child.local.as_bytes(),
            "ItemId" => {
                p.expect_types(child)?;
                BaseItemId::Item(ItemId::parse(p, &child.attrs)?)
            },
            "OccurrenceItemId" => {
                p.expect_types(child)?;
                p.count_id()?;
                let master = EwsIdStr::attr_required(p, &child.attrs, "RecurringMasterId")?;
                let change_key = EwsIdStr::attr(p, &child.attrs, "ChangeKey")?;
                let index = p
                    .attr_value(&child.attrs, "InstanceIndex")?
                    .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("InstanceIndex")))?;
                p.skip_rest()?;
                BaseItemId::Occurrence { master, change_key, index }
            },
            "RecurringMasterItemId" => {
                p.expect_types(child)?;
                p.count_id()?;
                let occurrence = EwsIdStr::attr_required(p, &child.attrs, "OccurrenceId")?;
                let change_key = EwsIdStr::attr(p, &child.attrs, "ChangeKey")?;
                p.skip_rest()?;
                BaseItemId::RecurringMaster { occurrence, change_key }
            },
            "RecurringMasterItemIdRanges" => {
                p.expect_types(child)?;
                BaseItemId::MasterRanges(Box::new(parse_master_ranges(p, &child.attrs)?))
            },
            _ => {
                return Ok(None);
            }
        );
        Ok(Some(id))
    }

    pub fn parse_list(p: &mut Parser<'a>) -> Result<Vec<Self>> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(id) => list.push(id),
                None => p.skip()?,
            }
        }
        Ok(list)
    }

    pub fn write(&self, w: &mut XmlWriter<'_>) {
        match self {
            BaseItemId::Item(id) => id.write(w, "ItemId"),
            BaseItemId::Occurrence {
                master,
                change_key,
                index,
            } => {
                w.start(T, "OccurrenceItemId")
                    .attr("RecurringMasterId", master.as_str());
                change_key_attr(w, change_key);
                w.attr_i64("InstanceIndex", i64::from(*index)).empty();
            }
            BaseItemId::RecurringMaster {
                occurrence,
                change_key,
            } => {
                w.start(T, "RecurringMasterItemId")
                    .attr("OccurrenceId", occurrence.as_str());
                change_key_attr(w, change_key);
                w.empty();
            }
            BaseItemId::MasterRanges(ranges) => ranges.write(w),
        }
    }
}

fn parse_master_ranges<'a>(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<MasterRanges<'a>> {
    p.count_id()?;
    let id = EwsIdStr::attr_required(p, attrs, "Id")?;
    let change_key = EwsIdStr::attr(p, attrs, "ChangeKey")?;
    let mut ranges = Vec::new();
    while let Some(child) = p.child()? {
        if child.local != "Ranges" {
            p.skip()?;
            continue;
        }
        p.expect_types(&child)?;
        while let Some(range) = p.child()? {
            if range.local != "Range" {
                p.skip()?;
                continue;
            }
            p.expect_types(&range)?;
            p.count_id()?;
            ranges.push(OccurrenceRange {
                start: p.attr_value(&range.attrs, "Start")?,
                end: p.attr_value(&range.attrs, "End")?,
                count: p.attr_value(&range.attrs, "Count")?,
                compare_original_start_time: p
                    .attr_value(&range.attrs, "CompareOriginalStartTime")?,
            });
            p.skip_rest()?;
        }
    }
    Ok(MasterRanges {
        id: ItemId { id, change_key },
        ranges,
    })
}

impl MasterRanges<'_> {
    fn write(&self, w: &mut XmlWriter<'_>) {
        w.start(T, "RecurringMasterItemIdRanges")
            .attr("Id", self.id.id.as_str());
        change_key_attr(w, &self.id.change_key);
        if !self.ranges.is_empty() {
            w.start(T, "Ranges");
            for range in &self.ranges {
                w.start(T, "Range");
                if let Some(start) = range.start {
                    DateTime::Parsed(start).write_attr(w, "Start");
                }
                if let Some(end) = range.end {
                    DateTime::Parsed(end).write_attr(w, "End");
                }
                if let Some(count) = range.count {
                    w.attr_i64("Count", i64::from(count));
                }
                if let Some(compare) = range.compare_original_start_time {
                    w.attr_bool("CompareOriginalStartTime", compare);
                }
                w.empty();
            }
            w.end(T, "Ranges");
        }
        w.end(T, "RecurringMasterItemIdRanges");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentId<'a> {
    pub id: EwsIdStr<'a>,
    pub root_item_id: Option<EwsIdStr<'a>>,
    pub root_item_change_key: Option<EwsIdStr<'a>>,
}

impl<'a> EwsValue<'a> for AttachmentId<'a> {
    fn parse(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        p.count_id()?;
        let id = EwsIdStr::attr_required(p, attrs, "Id")?;
        let root_item_id = EwsIdStr::attr(p, attrs, "RootItemId")?;
        let root_item_change_key = EwsIdStr::attr(p, attrs, "RootItemChangeKey")?;
        p.skip_rest()?;
        Ok(AttachmentId {
            id,
            root_item_id,
            root_item_change_key,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local).attr("Id", self.id.as_str());
        if let Some(root) = &self.root_item_id {
            w.attr("RootItemId", root.as_str());
        }
        if let Some(change_key) = &self.root_item_change_key {
            w.attr("RootItemChangeKey", change_key.as_str());
        }
        w.empty();
    }
}

impl<'a> AttachmentId<'a> {
    pub fn parse_request_list(p: &mut Parser<'a>) -> Result<Vec<Self>> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            if child.local == "AttachmentId" {
                p.expect_types(&child)?;
                list.push(Self::parse(p, &child.attrs)?);
            } else {
                p.skip()?;
            }
        }
        Ok(list)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlternateId<'a> {
    Mailbox {
        format: IdFormat,
        id: EwsIdStr<'a>,
        mailbox: Cow<'a, str>,
        is_archive: Option<bool>,
    },
    PublicFolder {
        format: IdFormat,
        folder_id: EwsIdStr<'a>,
    },
    PublicFolderItem {
        format: IdFormat,
        folder_id: EwsIdStr<'a>,
        item_id: EwsIdStr<'a>,
    },
}

#[derive(Clone, Copy)]
enum AlternateKind {
    Mailbox,
    PublicFolder,
    PublicFolderItem,
}

impl<'a> AlternateId<'a> {
    pub fn parse_list(p: &mut Parser<'a>) -> Result<Vec<Self>> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(id) => list.push(id),
                None => p.skip()?,
            }
        }
        Ok(list)
    }

    pub fn parse_child(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Option<Self>> {
        let Some(kind) = hashify::map!(child.local.as_bytes(), AlternateKind,
            "AlternateId" => AlternateKind::Mailbox,
            "AlternatePublicFolderId" => AlternateKind::PublicFolder,
            "AlternatePublicFolderItemId" => AlternateKind::PublicFolderItem,
        )
        .copied() else {
            return Ok(None);
        };
        p.expect_types(child)?;
        p.count_id()?;
        let attrs = &child.attrs;
        let format = p
            .attr_enum(attrs, "Format", IdFormat::parse)?
            .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("Format")))?;
        let id = match kind {
            AlternateKind::Mailbox => AlternateId::Mailbox {
                format,
                id: EwsIdStr::attr_required(p, attrs, "Id")?,
                mailbox: p.attr_required(attrs, "Mailbox")?,
                is_archive: p.attr_value(attrs, "IsArchive")?,
            },
            AlternateKind::PublicFolder => AlternateId::PublicFolder {
                format,
                folder_id: EwsIdStr::attr_required(p, attrs, "FolderId")?,
            },
            AlternateKind::PublicFolderItem => AlternateId::PublicFolderItem {
                format,
                folder_id: EwsIdStr::attr_required(p, attrs, "FolderId")?,
                item_id: EwsIdStr::attr_required(p, attrs, "ItemId")?,
            },
        };
        p.skip_rest()?;
        Ok(Some(id))
    }

    pub fn write_typed(&self, w: &mut XmlWriter<'_>, prefix: &str, local: &str) {
        w.start(prefix, local)
            .ns_decl(XSI, Ns::Xsi.uri())
            .attr("xsi:type", self.xsi_type());
        self.write_attrs(w);
        w.empty();
    }

    fn xsi_type(&self) -> &'static str {
        match self {
            AlternateId::Mailbox { .. } => "t:AlternateIdType",
            AlternateId::PublicFolder { .. } => "t:AlternatePublicFolderIdType",
            AlternateId::PublicFolderItem { .. } => "t:AlternatePublicFolderItemIdType",
        }
    }

    fn write_attrs(&self, w: &mut XmlWriter<'_>) {
        match self {
            AlternateId::Mailbox {
                format,
                id,
                mailbox,
                is_archive,
            } => {
                w.attr("Format", format.as_str())
                    .attr("Id", id.as_str())
                    .attr("Mailbox", mailbox);
                if let Some(is_archive) = is_archive {
                    w.attr("IsArchive", bool_str(*is_archive));
                }
            }
            AlternateId::PublicFolder { format, folder_id } => {
                w.attr("Format", format.as_str())
                    .attr("FolderId", folder_id.as_str());
            }
            AlternateId::PublicFolderItem {
                format,
                folder_id,
                item_id,
            } => {
                w.attr("Format", format.as_str())
                    .attr("FolderId", folder_id.as_str())
                    .attr("ItemId", item_id.as_str());
            }
        }
    }
}

macro_rules! text_token {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name<'a>(pub Cow<'a, str>);

        impl<'a> EwsValue<'a> for $name<'a> {
            fn parse(p: &mut Parser<'a>, _: &Attrs<'a>) -> Result<Self> {
                Ok($name(p.text()?))
            }

            fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
                w.leaf(T, local, &self.0);
            }
        }
    };
}

text_token!(SyncState);
text_token!(Watermark);
text_token!(SubscriptionId);
