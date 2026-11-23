/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    folders::FolderNode,
    mapi::{ids::MapiId, session::SessionState},
    store::{FolderKind, FolderRef},
};
use exchange_proto::mapi::{
    ErrorCode,
    rop::{LogonKind, LogonKinds},
};
use smallvec::SmallVec;
use store::{
    Serialize,
    write::{Archive, ArchiveBytes, ArchiveCompression, Archiver},
};

pub const MAX_OBJECTS: usize = 2048;
pub const MAX_OBJECTS_PER_LOGON: usize = 1024;
pub const MAX_TABLE_STATE_BYTES: usize = 256 * 1024;
pub const MAX_RECIPIENT_COLUMN_BYTES: usize = 64 * 1024;
const INDEX_BITS: u32 = 16;
pub const UNSAVED: u64 = 0;
pub const NOTIFY_GROUPS: usize = 3;
pub const MAX_LOGON_MAILBOXES: usize = 8;
const GENERATION_MAX: u16 = 0x7FFF;

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone)]
pub struct EmsmdbState {
    pub account_id: u32,
    pub code_page: u32,
    pub lcid_sort: u32,
    pub lcid_string: u32,
    pub sequence: u64,
    pub next_staged: u32,
    pub objects: Vec<ObjectSlot>,
    pub seen: Vec<MailboxCursor>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxCursor {
    pub mailbox_id: u32,
    pub heads: [u64; NOTIFY_GROUPS],
    pub exchange_change: u64,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone)]
pub struct ObjectSlot {
    pub generation: u16,
    pub logon_id: u8,
    pub object: Option<ServerObject>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone)]
pub enum ServerObject {
    Logon(LogonObject),
    Folder(FolderObject),
    Table(Box<TableObject>),
    Message(Box<MessageObject>),
    Attachment(Box<AttachmentObject>),
    Stream(Box<StreamObject>),
    Subscription(Subscription),
    Transfer(TransferObject),
}

impl ServerObject {
    pub fn staged_ids(&self) -> impl Iterator<Item = u32> {
        let (own, message) = match self {
            ServerObject::Message(message) => (None, Some(&**message)),
            ServerObject::Attachment(attachment) => (None, Some(&attachment.message)),
            ServerObject::Stream(stream) => (
                stream.staged,
                match &stream.owner {
                    StreamOwner::Folder(_) => None,
                    StreamOwner::Message(message) => Some(message),
                    StreamOwner::Attachment(attachment) => Some(&attachment.message),
                },
            ),
            ServerObject::Table(table) => (None, table.message.as_ref()),
            ServerObject::Transfer(transfer) => (Some(transfer.staged), None),
            ServerObject::Logon(_) | ServerObject::Folder(_) | ServerObject::Subscription(_) => {
                (None, None)
            }
        };
        own.into_iter()
            .chain(message.and_then(|message| message.staged))
    }
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    Contents,
    Hierarchy,
    StateStream,
    ContentsCollector,
    HierarchyCollector,
    Upload,
    Source,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy)]
pub struct TransferObject {
    pub folder: FolderObject,
    pub kind: TransferKind,
    pub staged: u32,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subscription {
    pub types: u16,
    pub scope: SubscriptionScope,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionScope {
    Store,
    Folder(u64),
    Message { folder: u64, message: u64 },
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableNotify {
    Disabled,
    Paused,
    Active,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct MessageObject {
    pub mailbox_id: u32,
    pub folder: u64,
    pub message: u64,
    pub code_page: u16,
    pub path: Vec<u32>,
    pub staged: Option<u32>,
    pub recipient_columns: RecipientColumns,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub enum RecipientColumns {
    #[default]
    Unannounced,
    Fixed,
    Client(Box<[u32]>),
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct AttachmentObject {
    pub message: MessageObject,
    pub number: u32,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum StreamOwner {
    Folder(FolderObject),
    Message(MessageObject),
    Attachment(AttachmentObject),
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamObject {
    pub owner: StreamOwner,
    pub tag: u32,
    pub size: u32,
    pub position: u32,
    pub staged: Option<u32>,
    pub dirty: bool,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy)]
pub struct LogonObject {
    pub mailbox_id: u32,
    pub private: bool,
    pub logon_flags: u8,
    pub open_flags: u32,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderObject {
    pub mailbox_id: u32,
    pub counter: u64,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone)]
pub struct TableObject {
    pub folder: FolderObject,
    pub kind: TableKind,
    pub message: Option<MessageObject>,
    pub unicode: bool,
    pub columns: Vec<u32>,
    pub sort: Vec<SortColumn>,
    pub categories: Option<Categories>,
    pub restriction: Vec<u8>,
    pub position: u32,
    pub bookmarks: Vec<TableBookmark>,
    pub next_bookmark: u32,
    pub notify: TableNotify,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    Hierarchy { depth: bool },
    Contents { associated: bool },
    Attachments,
    Permissions { free_busy: bool },
    Empty,
    Rules,
}

impl TableKind {
    pub fn has_bookmarks(self) -> bool {
        matches!(
            self,
            TableKind::Contents { .. } | TableKind::Hierarchy { .. } | TableKind::Empty
        )
    }

    pub fn has_restrictions(self) -> bool {
        self.has_bookmarks() || self == TableKind::Rules
    }

    pub fn require(self, supported: fn(Self) -> bool) -> Result<(), ErrorCode> {
        if supported(self) {
            Ok(())
        } else {
            Err(ErrorCode::NOT_SUPPORTED)
        }
    }
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortColumn {
    pub tag: u32,
    pub descending: bool,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Categories {
    pub depth: u16,
    pub expanded: u16,
    pub maximum: Option<SortColumn>,
    pub toggled: Vec<u64>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableBookmark {
    pub id: u32,
    pub row: u64,
    pub position: u32,
}

impl TableObject {
    pub fn new(folder: FolderObject, kind: TableKind, unicode: bool) -> Self {
        TableObject {
            folder,
            kind,
            message: None,
            unicode,
            columns: Vec::new(),
            sort: Vec::new(),
            categories: None,
            restriction: Vec::new(),
            position: 0,
            bookmarks: Vec::new(),
            next_bookmark: 1,
            notify: match kind {
                TableKind::Hierarchy { .. } | TableKind::Contents { associated: false } => {
                    TableNotify::Paused
                }
                TableKind::Contents { associated: true }
                | TableKind::Attachments
                | TableKind::Permissions { .. }
                | TableKind::Rules
                | TableKind::Empty => TableNotify::Disabled,
            },
        }
    }

    pub fn footprint(&self) -> usize {
        self.columns.len() * size_of::<u32>()
            + self.sort.len() * size_of::<SortColumn>()
            + self.restriction.len()
            + self.bookmarks.len() * size_of::<TableBookmark>()
            + self.categories.as_ref().map_or(0, Categories::footprint)
    }
}

impl MessageObject {
    pub fn id(&self) -> Option<MapiId> {
        MapiId::from_counter(self.message).filter(|_| self.message != UNSAVED)
    }

    pub fn same_root(&self, other: &MessageObject) -> bool {
        match (self.staged, other.staged) {
            (Some(staged), Some(other)) if staged == other => true,
            _ => {
                self.message != UNSAVED
                    && self.mailbox_id == other.mailbox_id
                    && self.message == other.message
            }
        }
    }

    pub fn folder(&self) -> FolderObject {
        FolderObject {
            mailbox_id: self.mailbox_id,
            counter: self.folder,
        }
    }

    pub fn container(&self) -> Option<u32> {
        mail_container(self.folder)
    }

    pub fn without_columns(&self) -> Self {
        MessageObject {
            path: self.path.clone(),
            recipient_columns: RecipientColumns::Unannounced,
            ..*self
        }
    }
}

impl RecipientColumns {
    pub fn footprint(&self) -> usize {
        match self {
            RecipientColumns::Client(tags) => size_of_val::<[u32]>(tags),
            RecipientColumns::Unannounced | RecipientColumns::Fixed => 0,
        }
    }
}

pub fn mail_container(folder: u64) -> Option<u32> {
    match MapiId::from_counter(folder).and_then(MapiId::to_node) {
        Some(FolderNode::Stored(FolderRef {
            kind: FolderKind::Mailbox,
            id,
        })) => Some(id),
        _ => None,
    }
}

impl FolderObject {
    pub fn new(mailbox_id: u32, id: MapiId) -> Self {
        FolderObject {
            mailbox_id,
            counter: id.counter(),
        }
    }

    pub fn id(&self) -> Option<MapiId> {
        MapiId::from_counter(self.counter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle(pub u32);

impl Handle {
    fn new(index: usize, generation: u16) -> Option<Self> {
        let index = u32::try_from(index)
            .ok()
            .filter(|index| *index < 1 << INDEX_BITS)?;
        let generation = generation.checked_sub(1)?;
        Some(Handle((u32::from(generation) << INDEX_BITS) | index))
    }

    fn index(self) -> usize {
        (self.0 & ((1 << INDEX_BITS) - 1)) as usize
    }

    fn generation(self) -> u16 {
        u16::try_from(self.0 >> INDEX_BITS)
            .ok()
            .and_then(|generation| generation.checked_add(1))
            .unwrap_or(u16::MAX)
    }
}

impl ArchiveCompression for EmsmdbState {}

impl SessionState for EmsmdbState {
    fn encode(self) -> trc::Result<Vec<u8>> {
        Archiver::new(self).untrusted().serialize()
    }

    fn decode(archive: &Archive<ArchiveBytes>) -> trc::Result<Self> {
        archive.deserialize_untrusted::<EmsmdbState>()
    }
}

impl EmsmdbState {
    pub fn new(account_id: u32, code_page: u32, lcid_sort: u32, lcid_string: u32) -> Self {
        EmsmdbState {
            account_id,
            code_page,
            lcid_sort,
            lcid_string,
            sequence: 0,
            next_staged: 0,
            objects: Vec::new(),
            seen: Vec::new(),
        }
    }

    pub fn insert(&mut self, logon_id: u8, object: ServerObject) -> Result<Handle, ErrorCode> {
        let mut free = None;
        let mut per_logon = 0usize;
        for (index, slot) in self.objects.iter().enumerate() {
            if slot.object.is_none() {
                free.get_or_insert(index);
            } else if slot.logon_id == logon_id {
                per_logon += 1;
            }
        }
        if per_logon >= MAX_OBJECTS_PER_LOGON {
            return Err(ErrorCode::TOO_MANY_OPEN_OBJECTS);
        }
        let index = match free {
            Some(index) => index,
            None if self.objects.len() < MAX_OBJECTS => {
                self.objects.push(ObjectSlot::default());
                self.objects.len() - 1
            }
            None => return Err(ErrorCode::TOO_MANY_OPEN_OBJECTS),
        };
        let slot = self
            .objects
            .get_mut(index)
            .ok_or(ErrorCode::TOO_MANY_OPEN_OBJECTS)?;
        slot.generation = if slot.generation >= GENERATION_MAX {
            1
        } else {
            slot.generation + 1
        };
        slot.logon_id = logon_id;
        slot.object = Some(object);
        Handle::new(index, slot.generation).ok_or(ErrorCode::TOO_MANY_OPEN_OBJECTS)
    }

    fn slot(&self, handle: Handle) -> Option<&ObjectSlot> {
        self.objects
            .get(handle.index())
            .filter(|slot| slot.generation == handle.generation() && slot.object.is_some())
    }

    pub fn get(&self, handle: Handle) -> Option<&ServerObject> {
        self.slot(handle).and_then(|slot| slot.object.as_ref())
    }

    pub fn get_mut(&mut self, handle: Handle) -> Option<&mut ServerObject> {
        self.objects
            .get_mut(handle.index())
            .filter(|slot| slot.generation == handle.generation())
            .and_then(|slot| slot.object.as_mut())
    }

    pub fn logon_id(&self, handle: Handle) -> Option<u8> {
        self.slot(handle).map(|slot| slot.logon_id)
    }

    pub fn logon_of(&self, handle: Handle) -> Option<(u8, &LogonObject)> {
        let logon_id = self.slot(handle)?.logon_id;
        self.logon(logon_id).map(|logon| (logon_id, logon))
    }

    pub fn logon(&self, logon_id: u8) -> Option<&LogonObject> {
        self.objects.iter().find_map(|slot| match &slot.object {
            Some(ServerObject::Logon(logon)) if slot.logon_id == logon_id => Some(logon),
            _ => None,
        })
    }

    pub fn logon_handle(&self, logon_id: u8) -> Option<Handle> {
        self.objects
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match &slot.object {
                Some(ServerObject::Logon(_)) if slot.logon_id == logon_id => {
                    Handle::new(index, slot.generation)
                }
                _ => None,
            })
    }

    pub fn handles(&self) -> impl Iterator<Item = (Handle, u8, &ServerObject)> {
        self.objects.iter().enumerate().filter_map(|(index, slot)| {
            Some((
                Handle::new(index, slot.generation)?,
                slot.logon_id,
                slot.object.as_ref()?,
            ))
        })
    }

    pub fn logons(&self) -> impl Iterator<Item = (u8, &LogonObject)> {
        self.objects.iter().filter_map(|slot| match &slot.object {
            Some(ServerObject::Logon(logon)) => Some((slot.logon_id, logon)),
            _ => None,
        })
    }

    pub fn logon_mailboxes(&self, except: Option<u8>) -> SmallVec<[u32; MAX_LOGON_MAILBOXES]> {
        let mut mailboxes = SmallVec::new();
        for (logon_id, logon) in self.logons() {
            if except != Some(logon_id) && !mailboxes.contains(&logon.mailbox_id) {
                mailboxes.push(logon.mailbox_id);
            }
        }
        mailboxes
    }

    pub fn notify_mailboxes(&self) -> SmallVec<[u32; MAX_LOGON_MAILBOXES]> {
        let logons: SmallVec<[(u8, u32); MAX_LOGON_MAILBOXES]> = self
            .logons()
            .map(|(logon_id, logon)| (logon_id, logon.mailbox_id))
            .collect();
        let mut mailboxes = SmallVec::new();
        for slot in &self.objects {
            let mailbox_id = match &slot.object {
                Some(ServerObject::Subscription(_)) => logons
                    .iter()
                    .find(|(logon_id, _)| *logon_id == slot.logon_id)
                    .map(|(_, mailbox_id)| *mailbox_id),
                Some(ServerObject::Table(table)) if table.notify == TableNotify::Active => {
                    Some(table.folder.mailbox_id)
                }
                _ => None,
            };
            if let Some(mailbox_id) = mailbox_id
                && !mailboxes.contains(&mailbox_id)
            {
                mailboxes.push(mailbox_id);
            }
        }
        mailboxes
    }

    pub fn cursor(&self, mailbox_id: u32) -> Option<MailboxCursor> {
        self.seen
            .iter()
            .find(|cursor| cursor.mailbox_id == mailbox_id)
            .copied()
    }

    pub fn set_cursor(&mut self, next: MailboxCursor) {
        match self
            .seen
            .iter_mut()
            .find(|cursor| cursor.mailbox_id == next.mailbox_id)
        {
            Some(cursor) => *cursor = next,
            None => self.seen.push(next),
        }
    }

    pub fn logon_kinds(&self) -> LogonKinds {
        let mut kinds = LogonKinds::default();
        for slot in &self.objects {
            if let Some(ServerObject::Logon(logon)) = &slot.object {
                kinds.set(
                    slot.logon_id,
                    Some(if logon.private {
                        LogonKind::Private
                    } else {
                        LogonKind::Public
                    }),
                );
            }
        }
        kinds
    }

    pub fn table_bytes_except(&self, handle: Handle) -> usize {
        self.objects
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != handle.index())
            .filter_map(|(_, slot)| match &slot.object {
                Some(ServerObject::Table(table)) => Some(table.footprint()),
                _ => None,
            })
            .sum()
    }

    pub fn check_recipient_columns(&self, handle: Handle, columns: usize) -> Result<(), ErrorCode> {
        let held: usize = self
            .objects
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != handle.index())
            .filter_map(|(_, slot)| match &slot.object {
                Some(ServerObject::Message(message)) => Some(message.recipient_columns.footprint()),
                _ => None,
            })
            .sum();
        if held.saturating_add(columns.saturating_mul(size_of::<u32>()))
            > MAX_RECIPIENT_COLUMN_BYTES
        {
            Err(ErrorCode::NOT_ENOUGH_MEMORY)
        } else {
            Ok(())
        }
    }

    pub fn release(&mut self, handle: Handle) -> bool {
        let Some(slot) = self
            .objects
            .get_mut(handle.index())
            .filter(|slot| slot.generation == handle.generation())
        else {
            return false;
        };
        match slot.object.take() {
            Some(ServerObject::Logon(_)) => {
                let logon_id = slot.logon_id;
                for slot in &mut self.objects {
                    if slot.logon_id == logon_id {
                        slot.object = None;
                    }
                }
                true
            }
            Some(_) => true,
            None => false,
        }
    }

    pub fn allocate_staged(&mut self) -> u32 {
        self.next_staged = self.next_staged.wrapping_add(1);
        self.next_staged
    }

    pub fn held_staged(&self) -> impl Iterator<Item = u32> + '_ {
        self.objects
            .iter()
            .filter_map(|slot| slot.object.as_ref())
            .flat_map(ServerObject::staged_ids)
    }

    pub fn shares_embedded(&self, staged: u32, path: &[u32]) -> bool {
        self.objects
            .iter()
            .filter(|slot| {
                matches!(&slot.object, Some(ServerObject::Message(message))
                    if message.staged == Some(staged) && message.path == path)
            })
            .nth(1)
            .is_some()
    }

    fn message_objects_mut(&mut self) -> impl Iterator<Item = &mut MessageObject> {
        self.objects
            .iter_mut()
            .filter_map(|slot| match slot.object.as_mut()? {
                ServerObject::Message(target) => Some(target.as_mut()),
                ServerObject::Attachment(attachment) => Some(&mut attachment.message),
                ServerObject::Stream(stream) => match &mut stream.owner {
                    StreamOwner::Folder(_) => None,
                    StreamOwner::Message(target) => Some(target),
                    StreamOwner::Attachment(attachment) => Some(&mut attachment.message),
                },
                ServerObject::Table(table) => table.message.as_mut(),
                ServerObject::Logon(_)
                | ServerObject::Folder(_)
                | ServerObject::Subscription(_)
                | ServerObject::Transfer(_) => None,
            })
    }

    pub fn attach_staged(&mut self, mailbox_id: u32, message: u64, id: u32) {
        for target in self.message_objects_mut() {
            if target.staged.is_none()
                && target.mailbox_id == mailbox_id
                && target.message == message
            {
                target.staged = Some(id);
            }
        }
    }

    pub fn assign_saved(&mut self, id: u32, folder: u64, message: u64) {
        for target in self.message_objects_mut() {
            if target.staged == Some(id) {
                target.folder = folder;
                target.message = message;
            }
        }
    }

    pub fn release_logon(&mut self, logon_id: u8) {
        if let Some(handle) = self.logon_handle(logon_id) {
            self.release(handle);
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/state/tests.rs"]
mod tests;
