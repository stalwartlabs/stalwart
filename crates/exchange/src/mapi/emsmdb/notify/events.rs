/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    folders::{FolderNode, FolderTree, ScopeKinds},
    mapi::{
        emsmdb::state::{
            EmsmdbState, MAX_LOGON_MAILBOXES, ServerObject, Subscription, SubscriptionScope,
            TableKind, TableNotify,
        },
        ids::MapiId,
    },
    store::{FolderKind, FolderRef},
};
use common::cache::exchange::ExchangeAccountCache;
use exchange_proto::{
    ids::{Fid, Mid},
    mapi::{
        notify::{
            NotificationData, NotificationTypes, ObjectNotification, TableChange,
            TableNotification, TableRow, TableRowId,
        },
        rop::{Overflow, RopWriter},
    },
};
use smallvec::SmallVec;

const NEW_MAIL_CLASS: &str = "IPM.Note";
const NEW_MAIL_FLAGS: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectEvent {
    NewMail {
        folder: MapiId,
        message: MapiId,
    },
    Created {
        folder: MapiId,
        message: Option<MapiId>,
        parent: MapiId,
    },
    Deleted {
        folder: MapiId,
        parent: MapiId,
    },
    Modified {
        folder: MapiId,
        message: Option<MapiId>,
        counts: Option<(u32, u32)>,
    },
    SearchComplete {
        folder: MapiId,
    },
}

#[derive(Debug, Default)]
pub struct GroupEvents {
    pub objects: Vec<ObjectEvent>,
    pub contents: Vec<u64>,
    pub parents: Vec<u64>,
    pub ancestors: Vec<u64>,
    pub all_contents: bool,
    pub all_hierarchy: bool,
    pub rows: Vec<RowEvent>,
}

#[derive(Debug)]
pub struct RowEvent {
    pub handle: u32,
    pub logon_id: u8,
    pub row: Fid,
    pub after: Fid,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupWrite {
    Full,
    Degraded,
    Deferred,
    Split,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnOverflow {
    Degrade,
    Split,
}

#[derive(Debug, Clone, Copy)]
struct TableTarget {
    handle: u32,
    logon_id: u8,
    folder: u64,
    kind: TableKind,
    scope: Option<ScopeKinds>,
}

#[derive(Debug, Clone, Copy)]
struct SubscriptionTarget {
    handle: u32,
    logon_id: u8,
    subscription: Subscription,
}

#[derive(Debug, Default)]
pub struct Targets {
    subscriptions: Vec<SubscriptionTarget>,
    tables: Vec<TableTarget>,
}

impl ObjectEvent {
    fn kind(&self) -> NotificationTypes {
        match self {
            ObjectEvent::NewMail { .. } => NotificationTypes::NEW_MAIL,
            ObjectEvent::Created { .. } => NotificationTypes::OBJECT_CREATED,
            ObjectEvent::Deleted { .. } => NotificationTypes::OBJECT_DELETED,
            ObjectEvent::Modified { .. } => NotificationTypes::OBJECT_MODIFIED,
            ObjectEvent::SearchComplete { .. } => NotificationTypes::SEARCH_COMPLETE,
        }
    }

    fn matches(&self, subscription: &Subscription) -> bool {
        if !NotificationTypes(subscription.types).contains(self.kind()) {
            return false;
        }
        let (folder, message, parent) = match *self {
            ObjectEvent::NewMail { folder, message } => (folder, Some(message), None),
            ObjectEvent::Created {
                folder,
                message,
                parent,
            } => (folder, message, message.is_none().then_some(parent)),
            ObjectEvent::Deleted { folder, parent } => (folder, None, Some(parent)),
            ObjectEvent::Modified {
                folder, message, ..
            } => (folder, message, None),
            ObjectEvent::SearchComplete { folder } => (folder, None, None),
        };
        match subscription.scope {
            SubscriptionScope::Store => true,
            SubscriptionScope::Folder(scope) => {
                folder.counter() == scope || parent.is_some_and(|parent| parent.counter() == scope)
            }
            SubscriptionScope::Message {
                folder: scope_folder,
                message: scope_message,
            } => {
                folder.counter() == scope_folder
                    && message.is_some_and(|message| message.counter() == scope_message)
            }
        }
    }

    fn data(&self, exchange: &ExchangeAccountCache) -> NotificationData<'static> {
        let wire = |id: MapiId| id.to_client(exchange);
        match *self {
            ObjectEvent::NewMail { folder, message } => NotificationData::NewMail {
                fid: wire(folder).to_eid(),
                mid: message.to_eid(),
                flags: NEW_MAIL_FLAGS,
                unicode: false,
                class: NEW_MAIL_CLASS,
            },
            ObjectEvent::Created {
                folder,
                message,
                parent,
            } => NotificationData::ObjectCreated(object(
                wire(folder),
                message,
                Some(wire(parent)),
                None,
            )),
            ObjectEvent::Deleted { folder, parent } => NotificationData::ObjectDeleted(object(
                wire(folder),
                None,
                Some(wire(parent)),
                None,
            )),
            ObjectEvent::Modified {
                folder,
                message,
                counts,
            } => NotificationData::ObjectModified(object(wire(folder), message, None, counts)),
            ObjectEvent::SearchComplete { folder } => {
                NotificationData::SearchComplete(wire(folder).to_eid())
            }
        }
    }
}

fn object(
    folder: MapiId,
    message: Option<MapiId>,
    parent: Option<MapiId>,
    counts: Option<(u32, u32)>,
) -> ObjectNotification<'static> {
    ObjectNotification {
        fid: folder.to_eid(),
        mid: message.map(MapiId::to_eid),
        parent: parent.map(MapiId::to_eid),
        search_folder: false,
        tags: None,
        total: counts.map(|(total, _)| total),
        unread: counts.map(|(_, unread)| unread),
    }
}

impl GroupEvents {
    pub fn clear(&mut self) {
        self.objects.clear();
        self.contents.clear();
        self.parents.clear();
        self.ancestors.clear();
        self.rows.clear();
        self.all_contents = false;
        self.all_hierarchy = false;
    }

    pub fn degrade(&mut self) {
        self.clear();
        self.all_contents = true;
        self.all_hierarchy = true;
    }

    pub fn seal(&mut self) {
        for list in [&mut self.contents, &mut self.parents, &mut self.ancestors] {
            list.sort_unstable();
            list.dedup();
        }
    }

    fn table_changed(&self, target: &TableTarget, folders: FolderKind) -> bool {
        match target.kind {
            TableKind::Contents { associated: false } => {
                (self.all_contents && folder_kind(target.folder) == Some(folders))
                    || self.contents.binary_search(&target.folder).is_ok()
                    || target.scope.is_some_and(|scope| {
                        scope.contains(folders) && (self.all_contents || !self.contents.is_empty())
                    })
            }
            TableKind::Hierarchy { depth } => {
                self.all_hierarchy
                    || if depth {
                        self.ancestors.binary_search(&target.folder).is_ok()
                    } else {
                        self.parents.binary_search(&target.folder).is_ok()
                    }
            }
            TableKind::Contents { associated: true }
            | TableKind::Attachments
            | TableKind::Permissions { .. }
            | TableKind::Rules
            | TableKind::Empty => false,
        }
    }
}

fn folder_kind(counter: u64) -> Option<FolderKind> {
    match MapiId::from_counter(counter).and_then(MapiId::to_node) {
        Some(FolderNode::Stored(FolderRef { kind, .. })) => Some(kind),
        _ => None,
    }
}

fn search_scope(tree: &FolderTree, counter: u64, kind: TableKind) -> Option<ScopeKinds> {
    if !matches!(kind, TableKind::Contents { associated: false }) {
        return None;
    }
    let node = MapiId::from_counter(counter).and_then(MapiId::to_node)?;
    tree.get(node)
        .filter(|entry| entry.search)
        .map(|entry| entry.scope)
}

impl Targets {
    pub fn new(state: &EmsmdbState, mailbox_id: u32, tree: &FolderTree) -> Self {
        let logons: SmallVec<[u8; MAX_LOGON_MAILBOXES]> = state
            .logons()
            .filter(|(_, logon)| logon.mailbox_id == mailbox_id)
            .map(|(logon_id, _)| logon_id)
            .collect();
        let mut targets = Targets::default();
        for (handle, logon_id, object) in state.handles() {
            match object {
                ServerObject::Subscription(subscription) if logons.contains(&logon_id) => {
                    targets.subscriptions.push(SubscriptionTarget {
                        handle: handle.0,
                        logon_id,
                        subscription: *subscription,
                    })
                }
                ServerObject::Table(table)
                    if table.notify == TableNotify::Active
                        && table.folder.mailbox_id == mailbox_id =>
                {
                    targets.tables.push(TableTarget {
                        handle: handle.0,
                        logon_id,
                        folder: table.folder.counter,
                        kind: table.kind,
                        scope: search_scope(tree, table.folder.counter, table.kind),
                    })
                }
                _ => {}
            }
        }
        targets
    }

    pub fn hierarchy_tables(&self) -> impl Iterator<Item = (u32, u8)> + '_ {
        self.tables
            .iter()
            .filter(|target| matches!(target.kind, TableKind::Hierarchy { .. }))
            .map(|target| (target.handle, target.logon_id))
    }

    pub fn wants(&self, types: NotificationTypes) -> bool {
        self.subscriptions
            .iter()
            .any(|target| NotificationTypes(target.subscription.types).contains(types))
    }

    pub fn write_group(
        &self,
        writer: &mut RopWriter<'_>,
        folders: FolderKind,
        events: &mut GroupEvents,
        exchange: &ExchangeAccountCache,
        empty: usize,
        on_overflow: OnOverflow,
    ) -> GroupWrite {
        if self.write(writer, folders, events, exchange).is_ok() {
            return GroupWrite::Full;
        }
        if writer.remaining() != empty {
            return GroupWrite::Deferred;
        }
        if on_overflow == OnOverflow::Split {
            return GroupWrite::Split;
        }
        events.degrade();
        if self.write(writer, folders, events, exchange).is_ok() {
            GroupWrite::Degraded
        } else {
            GroupWrite::Deferred
        }
    }

    fn write(
        &self,
        writer: &mut RopWriter<'_>,
        folders: FolderKind,
        events: &GroupEvents,
        exchange: &ExchangeAccountCache,
    ) -> Result<(), Overflow> {
        let mark = writer.mark();
        let result = self.write_all(writer, folders, events, exchange);
        if result.is_err() {
            writer.rollback(mark);
        }
        result
    }

    fn write_all(
        &self,
        writer: &mut RopWriter<'_>,
        folders: FolderKind,
        events: &GroupEvents,
        exchange: &ExchangeAccountCache,
    ) -> Result<(), Overflow> {
        for event in &events.objects {
            let mut data = None;
            for target in &self.subscriptions {
                if event.matches(&target.subscription) {
                    let data = data.get_or_insert_with(|| event.data(exchange));
                    writer.notify(target.handle, target.logon_id, data)?;
                }
            }
        }
        for target in &self.tables {
            if events.table_changed(target, folders) {
                writer.notify(
                    target.handle,
                    target.logon_id,
                    &NotificationData::Table(TableNotification {
                        message_rows: matches!(target.kind, TableKind::Contents { .. }),
                        event: TableChange::Changed,
                    }),
                )?;
            }
        }
        for row in &events.rows {
            writer.notify(
                row.handle,
                row.logon_id,
                &NotificationData::Table(TableNotification {
                    message_rows: false,
                    event: TableChange::RowModified(TableRow {
                        row: TableRowId {
                            fid: row.row,
                            mid: Mid::from_le_u64(0),
                            instance: 0,
                        },
                        insert_after: TableRowId {
                            fid: row.after,
                            mid: Mid::from_le_u64(0),
                            instance: 0,
                        },
                        data: &row.data,
                    }),
                }),
            )?;
        }
        Ok(())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/notify/events/tests.rs"]
mod tests;
