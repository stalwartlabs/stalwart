/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::prop::PropTag;
use crate::{
    common::LeWriter,
    ids::{Fid, Mid},
};

const NEW_MAIL: u16 = 0x0002;
const OBJECT_CREATED: u16 = 0x0004;
const OBJECT_DELETED: u16 = 0x0008;
const OBJECT_MODIFIED: u16 = 0x0010;
const OBJECT_MOVED: u16 = 0x0020;
const OBJECT_COPIED: u16 = 0x0040;
const SEARCH_COMPLETE: u16 = 0x0080;
const TABLE_MODIFIED: u16 = 0x0100;
const FLAG_TOTAL: u16 = 0x1000;
const FLAG_UNREAD: u16 = 0x2000;
const FLAG_SEARCH: u16 = 0x4000;
const FLAG_MESSAGE: u16 = 0x8000;
const ALL_TAGS: u16 = 0xFFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NotificationTypes(pub u16);

impl NotificationTypes {
    pub const NEW_MAIL: Self = Self(NEW_MAIL);
    pub const OBJECT_CREATED: Self = Self(OBJECT_CREATED);
    pub const OBJECT_DELETED: Self = Self(OBJECT_DELETED);
    pub const OBJECT_MODIFIED: Self = Self(OBJECT_MODIFIED);
    pub const OBJECT_MOVED: Self = Self(OBJECT_MOVED);
    pub const OBJECT_COPIED: Self = Self(OBJECT_COPIED);
    pub const SEARCH_COMPLETE: Self = Self(SEARCH_COMPLETE);
    pub const TABLE_MODIFIED: Self = Self(TABLE_MODIFIED);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationData<'x> {
    NewMail {
        fid: Fid,
        mid: Mid,
        flags: u32,
        unicode: bool,
        class: &'x str,
    },
    ObjectCreated(ObjectNotification<'x>),
    ObjectDeleted(ObjectNotification<'x>),
    ObjectModified(ObjectNotification<'x>),
    ObjectMoved(MoveNotification),
    ObjectCopied(MoveNotification),
    SearchComplete(Fid),
    Table(TableNotification<'x>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectNotification<'x> {
    pub fid: Fid,
    pub mid: Option<Mid>,
    pub parent: Option<Fid>,
    pub search_folder: bool,
    pub tags: Option<&'x [PropTag]>,
    pub total: Option<u32>,
    pub unread: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveNotification {
    pub fid: Fid,
    pub mid: Option<Mid>,
    pub parent: Option<Fid>,
    pub old_fid: Fid,
    pub old_mid: Option<Mid>,
    pub old_parent: Option<Fid>,
    pub search_folder: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableRowId {
    pub fid: Fid,
    pub mid: Mid,
    pub instance: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableRow<'x> {
    pub row: TableRowId,
    pub insert_after: TableRowId,
    pub data: &'x [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableNotification<'x> {
    pub message_rows: bool,
    pub event: TableChange<'x>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableChange<'x> {
    Changed,
    RowAdded(TableRow<'x>),
    RowDeleted(TableRowId),
    RowModified(TableRow<'x>),
    RestrictionChanged,
}

impl TableChange<'_> {
    const fn code(&self) -> u16 {
        match self {
            TableChange::Changed => 0x0001,
            TableChange::RowAdded(_) => 0x0003,
            TableChange::RowDeleted(_) => 0x0004,
            TableChange::RowModified(_) => 0x0005,
            TableChange::RestrictionChanged => 0x0007,
        }
    }
}

fn put_eid(out: &mut Vec<u8>, eid: Fid) {
    out.extend_from_slice(&eid.to_wire());
}

impl NotificationData<'_> {
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            NotificationData::NewMail {
                fid,
                mid,
                flags,
                unicode,
                class,
            } => {
                out.put_u16(NEW_MAIL | FLAG_MESSAGE);
                put_eid(out, *fid);
                put_eid(out, *mid);
                out.put_u32(*flags);
                out.put_u8(u8::from(*unicode));
                if *unicode {
                    out.put_utf16_z(class);
                } else {
                    out.put_ascii_z(class.as_bytes());
                }
            }
            NotificationData::ObjectCreated(n) => n.encode(out, OBJECT_CREATED),
            NotificationData::ObjectDeleted(n) => n.encode(out, OBJECT_DELETED),
            NotificationData::ObjectModified(n) => n.encode(out, OBJECT_MODIFIED),
            NotificationData::ObjectMoved(n) => n.encode(out, OBJECT_MOVED),
            NotificationData::ObjectCopied(n) => n.encode(out, OBJECT_COPIED),
            NotificationData::SearchComplete(fid) => {
                out.put_u16(SEARCH_COMPLETE);
                put_eid(out, *fid);
            }
            NotificationData::Table(n) => n.encode(out),
        }
    }
}

fn message_flags(mid: Option<Mid>, search_folder: bool) -> u16 {
    match (mid.is_some(), search_folder) {
        (true, true) => FLAG_MESSAGE | FLAG_SEARCH,
        (true, false) => FLAG_MESSAGE,
        (false, _) => 0,
    }
}

impl ObjectNotification<'_> {
    fn encode(&self, out: &mut Vec<u8>, kind: u16) {
        let mut flags = kind | message_flags(self.mid, self.search_folder);
        let counts = kind == OBJECT_MODIFIED;
        if counts && self.total.is_some() {
            flags |= FLAG_TOTAL;
        }
        if counts && self.unread.is_some() {
            flags |= FLAG_UNREAD;
        }
        out.put_u16(flags);
        put_eid(out, self.fid);
        if let Some(mid) = self.mid {
            put_eid(out, mid);
        }
        if kind != OBJECT_MODIFIED && has_parent(flags) {
            put_eid(out, self.parent.unwrap_or(self.fid));
        }
        if kind != OBJECT_DELETED {
            match self.tags {
                Some(tags) => {
                    let tags = tags.get(..usize::from(ALL_TAGS - 1)).unwrap_or(tags);
                    out.put_u16(u16::try_from(tags.len()).unwrap_or(0));
                    for tag in tags {
                        out.put_u32(tag.0);
                    }
                }
                None if kind == OBJECT_CREATED => out.put_u16(ALL_TAGS),
                None => out.put_u16(0),
            }
        }
        if counts {
            if let Some(total) = self.total {
                out.put_u32(total);
            }
            if let Some(unread) = self.unread {
                out.put_u32(unread);
            }
        }
    }
}

fn has_parent(flags: u16) -> bool {
    let message = flags & FLAG_MESSAGE != 0;
    let search = flags & FLAG_SEARCH != 0;
    message == search
}

impl MoveNotification {
    fn encode(&self, out: &mut Vec<u8>, kind: u16) {
        let flags = kind | message_flags(self.mid, self.search_folder);
        out.put_u16(flags);
        put_eid(out, self.fid);
        if let Some(mid) = self.mid {
            put_eid(out, mid);
        }
        if has_parent(flags) {
            put_eid(out, self.parent.unwrap_or(self.fid));
        }
        put_eid(out, self.old_fid);
        match self.mid {
            Some(_) => put_eid(out, self.old_mid.unwrap_or(Mid::from_le_u64(0))),
            None => put_eid(out, self.old_parent.unwrap_or(self.old_fid)),
        }
    }
}

impl TableNotification<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let message = self.message_rows;
        out.put_u16(TABLE_MODIFIED | if message { FLAG_MESSAGE } else { 0 });
        out.put_u16(self.event.code());
        let put_row = |out: &mut Vec<u8>, row: &TableRowId| {
            put_eid(out, row.fid);
            if message {
                put_eid(out, row.mid);
                out.put_u32(row.instance);
            }
        };
        match &self.event {
            TableChange::Changed | TableChange::RestrictionChanged => {}
            TableChange::RowDeleted(row) => put_row(out, row),
            TableChange::RowAdded(change) | TableChange::RowModified(change) => {
                put_row(out, &change.row);
                put_row(out, &change.insert_after);
                let data = change
                    .data
                    .get(..usize::from(u16::MAX))
                    .unwrap_or(change.data);
                out.put_u16(u16::try_from(data.len()).unwrap_or(0));
                out.extend_from_slice(data);
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/notify/tests.rs"]
mod tests;
