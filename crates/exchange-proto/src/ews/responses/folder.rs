/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Paging, ResponseMessage};
use crate::{
    ews::types::{
        folder::Folder,
        value::{M, T},
    },
    xml::XmlWriter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmptyMessage;

impl ResponseMessage for EmptyMessage {
    fn write_body(&self, _: &mut XmlWriter<'_>) {}
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FolderInfoMessage<'x> {
    pub folders: Vec<Folder<'x>>,
}

impl ResponseMessage for FolderInfoMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "Folders");
        for folder in &self.folders {
            folder.write(w);
        }
        w.end(M, "Folders");
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindFolderRoot<'x> {
    pub paging: Paging,
    pub folders: Vec<Folder<'x>>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FindFolderMessage<'x> {
    pub root: Option<FindFolderRoot<'x>>,
}

impl ResponseMessage for FindFolderMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(root) = &self.root {
            w.start(M, "RootFolder");
            root.paging.write_attrs(w);
            w.start(T, "Folders");
            for folder in &root.folders {
                folder.write(w);
            }
            w.end(T, "Folders");
            w.end(M, "RootFolder");
        }
    }
}
