/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Paging, ResponseMessage};
use crate::{
    ews::{
        bulk::BulkRecord,
        types::{
            generated::GroupSummary,
            ids::ItemId,
            item::Item,
            value::{EwsValue, M, T},
        },
    },
    xml::XmlWriter,
};
use std::borrow::Cow;

fn write_items(w: &mut XmlWriter<'_>, prefix: &str, items: &[Item<'_>]) {
    w.start(prefix, "Items");
    for item in items {
        item.write(w);
    }
    w.end(prefix, "Items");
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ItemInfoMessage<'x> {
    pub items: Vec<Item<'x>>,
}

impl ResponseMessage for ItemInfoMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        write_items(w, M, &self.items);
    }

    fn write_required(w: &mut XmlWriter<'_>) {
        write_items(w, M, &[]);
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct UpdateItemMessage<'x> {
    pub items: Vec<Item<'x>>,
    pub conflict_count: Option<i32>,
}

impl ResponseMessage for UpdateItemMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        write_items(w, M, &self.items);
        if let Some(count) = self.conflict_count {
            w.start(M, "ConflictResults");
            w.leaf_i64(T, "Count", i64::from(count));
            w.end(M, "ConflictResults");
        }
    }

    fn write_required(w: &mut XmlWriter<'_>) {
        write_items(w, M, &[]);
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MarkAsJunkMessage<'x> {
    pub moved_item_id: Option<ItemId<'x>>,
}

impl ResponseMessage for MarkAsJunkMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(id) = &self.moved_item_id {
            w.start(M, "MovedItemId");
            id.write_attrs(w);
            w.empty();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ExportItemsMessage<'x> {
    pub item_id: Option<ItemId<'x>>,
    pub data: Option<BulkRecord<'x>>,
}

impl ResponseMessage for ExportItemsMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(id) = &self.item_id {
            w.start(M, "ItemId");
            id.write_attrs(w);
            w.empty();
        }
        if let Some(data) = &self.data {
            w.start(M, "Data");
            let mut sink = w.base64_stream();
            data.encode(&mut sink);
            sink.finish();
            w.end(M, "Data");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct UploadItemsMessage<'x> {
    pub item_id: Option<ItemId<'x>>,
}

impl ResponseMessage for UploadItemsMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(id) = &self.item_id {
            w.start(M, "ItemId");
            id.write_attrs(w);
            w.empty();
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupedItems<'x> {
    pub group_index: Cow<'x, str>,
    pub items: Vec<Item<'x>>,
    pub group_summary: Option<GroupSummary<'x>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FindContent<'x> {
    Items(Vec<Item<'x>>),
    Groups(Vec<GroupedItems<'x>>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindRoot<'x> {
    pub paging: Paging,
    pub content: FindContent<'x>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FindItemMessage<'x> {
    pub root: Option<FindRoot<'x>>,
}

impl ResponseMessage for FindItemMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        let Some(root) = &self.root else {
            return;
        };
        w.start(M, "RootFolder");
        root.paging.write_attrs(w);
        match &root.content {
            FindContent::Items(items) => write_items(w, T, items),
            FindContent::Groups(groups) => {
                w.start(T, "Groups");
                for group in groups {
                    w.start(T, "GroupedItems");
                    w.leaf(T, "GroupIndex", &group.group_index);
                    write_items(w, T, &group.items);
                    if let Some(summary) = &group.group_summary {
                        summary.write(w, "GroupSummary");
                    }
                    w.end(T, "GroupedItems");
                }
                w.end(T, "Groups");
            }
        }
        w.end(M, "RootFolder");
    }
}
