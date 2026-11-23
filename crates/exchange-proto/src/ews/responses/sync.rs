/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMessage;
use crate::{
    ews::types::{
        folder::Folder,
        ids::{FolderId, ItemId},
        item::Item,
        value::{EwsValue, M, T},
    },
    xml::XmlWriter,
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq)]
pub enum FolderSyncChange<'x> {
    Create(Folder<'x>),
    Update(Folder<'x>),
    Delete(FolderId<'x>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyncChange<'x> {
    Create(Item<'x>),
    Update(Item<'x>),
    Delete(ItemId<'x>),
    ReadFlagChange { id: ItemId<'x>, is_read: bool },
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncFolderHierarchyMessage<'x> {
    pub state: Cow<'x, str>,
    pub includes_last_folder_in_range: bool,
    pub changes: Vec<FolderSyncChange<'x>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncFolderItemsMessage<'x> {
    pub state: Cow<'x, str>,
    pub includes_last_item_in_range: bool,
    pub changes: Vec<SyncChange<'x>>,
}

impl FolderSyncChange<'_> {
    pub fn write(&self, w: &mut XmlWriter<'_>) {
        match self {
            FolderSyncChange::Create(folder) | FolderSyncChange::Update(folder) => {
                let element = match self {
                    FolderSyncChange::Create(_) => "Create",
                    _ => "Update",
                };
                w.start(T, element);
                folder.write(w);
                w.end(T, element);
            }
            FolderSyncChange::Delete(id) => {
                w.start(T, "Delete");
                id.write(w, "FolderId");
                w.end(T, "Delete");
            }
        }
    }
}

impl SyncChange<'_> {
    pub fn write(&self, w: &mut XmlWriter<'_>) {
        match self {
            SyncChange::Create(item) => {
                w.start(T, "Create");
                item.write(w);
                w.end(T, "Create");
            }
            SyncChange::Update(item) => {
                w.start(T, "Update");
                item.write(w);
                w.end(T, "Update");
            }
            SyncChange::Delete(id) => {
                w.start(T, "Delete");
                id.write(w, "ItemId");
                w.end(T, "Delete");
            }
            SyncChange::ReadFlagChange { id, is_read } => {
                w.start(T, "ReadFlagChange");
                id.write(w, "ItemId");
                w.leaf_bool(T, "IsRead", *is_read);
                w.end(T, "ReadFlagChange");
            }
        }
    }
}

impl ResponseMessage for SyncFolderHierarchyMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.leaf(M, "SyncState", &self.state);
        w.leaf_bool(
            M,
            "IncludesLastFolderInRange",
            self.includes_last_folder_in_range,
        );
        w.start(M, "Changes");
        for change in &self.changes {
            change.write(w);
        }
        w.end(M, "Changes");
    }
}

impl ResponseMessage for SyncFolderItemsMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.leaf(M, "SyncState", &self.state);
        w.leaf_bool(
            M,
            "IncludesLastItemInRange",
            self.includes_last_item_in_range,
        );
        w.start(M, "Changes");
        for change in &self.changes {
            change.write(w);
        }
        w.end(M, "Changes");
    }
}
