/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    access::ViewRights,
    execute::{MailboxView, RopContext, RopError, RopResult},
    ics::stream::{Versions, folder_cn},
    props::{PropBag, PropDemand, PropOut},
    rules::is_rules_folder,
    state::{FolderObject, ServerObject},
    store::StoreGuids,
};
use crate::{
    ews::folder::props::CHANGE_TIME_BASE,
    folders::{FolderEntry, FolderNode, FolderTree, SpecialFolder},
    mapi::ids::MapiId,
    store::{FolderKind, FolderRef},
};
use ahash::AHashMap;
use bytes::Bytes;
use common::{MessageStoreCache, cache::exchange::ExchangeAccountCache};
use email::cache::email::{MailboxCounters, MessageCacheAccess};
use exchange_proto::{
    common::{FileTime, UtcSeconds},
    mapi::{
        ErrorCode,
        prop::{MvType, OwnedPropValue, PropTag, PropValue, tags},
        rop::{DecodedRop, requests::OpenFolder, responses::OpenFolderResponse},
    },
};
use store::{ValueKey, write::ValueClass};
use trc::AddContext;
use types::{collection::Collection, type_state::DataType};

const MAPI_FOLDER: i32 = 3;
const FOLDER_ROOT: i32 = 0;
const FOLDER_GENERIC: i32 = 1;
const FOLDER_SEARCH: i32 = 2;
const FOLDER_FLAG_IPM: i32 = 0x1;
const FOLDER_FLAG_SEARCH: i32 = 0x2;
const FOLDER_FLAG_NORMAL: i32 = 0x4;
const IPM_ARCHIVE_ENTRY_ID: PropTag = PropTag(0x36FF_0102);
const FOLDER_ENTRY_ID_CAPACITY: usize = 46;
pub(super) const REN_FOLDERS: [SpecialFolder; 5] = [
    SpecialFolder::Conflicts,
    SpecialFolder::SyncIssues,
    SpecialFolder::LocalFailures,
    SpecialFolder::ServerFailures,
    SpecialFolder::JunkEmail,
];

const SPECIAL_ENTRY_IDS: [(PropTag, SpecialFolder); 7] = [
    (IPM_ARCHIVE_ENTRY_ID, SpecialFolder::Archive),
    (tags::IPM_APPOINTMENT_ENTRY_ID, SpecialFolder::Calendar),
    (tags::IPM_CONTACT_ENTRY_ID, SpecialFolder::Contacts),
    (tags::IPM_JOURNAL_ENTRY_ID, SpecialFolder::Journal),
    (tags::IPM_NOTE_ENTRY_ID, SpecialFolder::Notes),
    (tags::IPM_TASK_ENTRY_ID, SpecialFolder::Tasks),
    (tags::IPM_DRAFTS_ENTRY_ID, SpecialFolder::Drafts),
];

impl RopContext<'_, '_> {
    pub async fn open_folder(&mut self, rop: &DecodedRop<'_>, request: &OpenFolder) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        match self.state.get(parent) {
            Some(ServerObject::Logon(_) | ServerObject::Folder(_)) => {}
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
        let (logon_id, logon) = self
            .state
            .logon_of(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let mailbox_id = logon.mailbox_id;
        let id = self.folder_id(mailbox_id, request.folder_id).await?;
        let node = id.to_node().ok_or(ErrorCode::NOT_FOUND)?;
        if self.folder_tree(mailbox_id).await?.get(node).is_none() {
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        }
        self.require_visible(mailbox_id, node).await?;
        let handle = self.state.insert(
            logon_id,
            ServerObject::Folder(FolderObject::new(mailbox_id, id)),
        )?;
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        self.respond(
            rop,
            index,
            &OpenFolderResponse {
                has_rules: false,
                ghosted: None,
            },
        )
    }

    pub async fn folder_props(
        &mut self,
        folder: &FolderObject,
        demand: PropDemand<'_>,
    ) -> Result<PropBag, RopError> {
        let mailbox_id = folder.mailbox_id;
        let node = folder
            .id()
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let rights = self.view_rights(mailbox_id).await?;
        let folder_rights = rights.of(node);
        if !folder_rights.is_visible() {
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        }
        let tree = self.folder_tree(mailbox_id).await?;
        let entry = tree.get(node).ok_or(ErrorCode::OBJECT_DELETED)?;
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let counters = self.folder_counters(mailbox_id).await?;
        let mut bag = folder_bag(
            &tree,
            entry,
            &guids,
            &mailbox.exchange,
            Some(&counters),
            &rights,
        );
        folder_rights.push_props(&mut bag);
        if rights.is_owner() && is_rules_folder(folder.counter) {
            let has_rules =
                demand.wants_value(tags::HAS_RULES) && self.has_rules(mailbox_id).await?;
            bag.push_bool(tags::HAS_RULES, has_rules);
        }
        if let FolderNode::Stored(stored) = node
            && stored.kind == FolderKind::Mailbox
            && folder_rights.reads_items()
            && demand.wants_value(tags::DELETED_COUNT_TOTAL)
            && let Some(messages) = &mailbox.messages
        {
            let deleted = self
                .deleted_count(mailbox_id, messages, &counters, stored.id)
                .await?;
            bag.push_i32(tags::DELETED_COUNT_TOTAL, deleted);
        }
        let wants_size = demand.wants_value(tags::MESSAGE_SIZE_EXTENDED);
        let wants_change_time = wants(demand, tags::LAST_MODIFICATION_TIME)
            || wants(demand, tags::LOCAL_COMMIT_TIME_MAX);
        let mut change_id = subtree_change(&tree, entry);
        match node {
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id,
            }) if folder_rights.reads_items() && (wants_size || wants_change_time) => {
                if let Some(messages) = &mailbox.messages {
                    let (size, highest) =
                        messages
                            .in_mailbox(id)
                            .fold((0u64, change_id), |(size, highest), item| {
                                (
                                    size.saturating_add(u64::from(item.size())),
                                    highest.max(item.change_id()),
                                )
                            });
                    change_id = highest;
                    if wants_size {
                        bag.push_i32(tags::MESSAGE_SIZE, i32::try_from(size).unwrap_or(i32::MAX));
                        bag.push_i64(
                            tags::MESSAGE_SIZE_EXTENDED,
                            i64::try_from(size).unwrap_or(i64::MAX),
                        );
                    }
                }
            }
            FolderNode::Stored(FolderRef { kind, .. })
                if wants_change_time && folder_rights.reads_items() =>
            {
                if let Some(highest) = self.highest_resource_change(mailbox_id, kind).await? {
                    change_id = change_id.max(highest);
                }
            }
            _ => {}
        }
        push_folder_state(&mut bag, &tree, entry);
        if wants(demand, tags::DELETED_COUNT_TOTAL) && !bag.contains(tags::DELETED_COUNT_TOTAL) {
            bag.push_i32(tags::DELETED_COUNT_TOTAL, 0);
        }
        if (wants(demand, tags::CHANGE_KEY) || wants(demand, tags::PREDECESSOR_CHANGE_LIST))
            && let Some(cn) = folder_cn(&tree, entry)
        {
            let versions = Versions::server(cn, guids.replica);
            bag.push_binary(tags::CHANGE_KEY, &versions.change_key);
            bag.push_binary(tags::PREDECESSOR_CHANGE_LIST, &versions.pcl);
        }
        if wants_change_time {
            push_change_time(&mut bag, &tree, entry, change_id);
        }
        let wants_row = match demand {
            PropDemand::All | PropDemand::Names => true,
            PropDemand::Tags(wanted) => wanted.iter().any(|tag| !bag.contains(*tag)),
        };
        if wants_row {
            self.push_folder_row(mailbox_id, node, &mut bag).await?;
        }
        if wants(demand, tags::ADDITIONAL_REN_ENTRY_IDS) {
            push_inbox_ren_entry_ids(&mut bag, &tree, entry, &guids, &mailbox.exchange, &rights);
        }
        if !bag.contains(tags::ATTRIBUTE_HIDDEN) {
            bag.push_bool(tags::ATTRIBUTE_HIDDEN, false);
        }
        Ok(bag)
    }

    pub(super) async fn deleted_count(
        &self,
        mailbox_id: u32,
        messages: &MessageStoreCache,
        counters: &FolderCounters,
        id: u32,
    ) -> Result<i32, RopError> {
        let uid_next = messages
            .refresh
            .uid_next
            .get_or_read(id, || async {
                self.request
                    .server
                    .core
                    .storage
                    .data
                    .get_counter(ValueKey {
                        account_id: mailbox_id,
                        collection: u8::from(Collection::Mailbox),
                        document_id: id,
                        class: ValueClass::MailboxUid,
                    })
                    .await
                    .caused_by(trc::location!())
                    .map(|counter| u32::try_from(counter.saturating_add(1)).unwrap_or(u32::MAX))
            })
            .await?;
        let total = counters.get(&id).map_or(0, |counters| counters.total);
        let deleted = usize::try_from(uid_next.saturating_sub(1))
            .unwrap_or(usize::MAX)
            .saturating_sub(total);
        Ok(i32::try_from(deleted).unwrap_or(i32::MAX))
    }

    pub(super) async fn highest_resource_change(
        &self,
        mailbox_id: u32,
        kind: FolderKind,
    ) -> trc::Result<Option<u64>> {
        let data_type = match kind {
            FolderKind::Calendar => DataType::CalendarEvent,
            FolderKind::AddressBook => DataType::ContactCard,
            FolderKind::Mailbox | FolderKind::Virtual | FolderKind::FileNode => return Ok(None),
        };
        Ok(self
            .container_resources(mailbox_id, data_type)
            .await?
            .map(|resources| resources.highest_change_id))
    }

    pub(super) async fn scan_folder_activity(
        &self,
        mailbox: &MailboxView,
        tree: &FolderTree,
    ) -> trc::Result<FolderActivity> {
        let mut mail = AHashMap::new();
        if let Some(messages) = &mailbox.messages {
            for item in messages.emails.iter() {
                let change_id = item.change_id();
                for uid in item.mailboxes() {
                    mail.entry(uid.mailbox_id)
                        .and_modify(|highest: &mut u64| *highest = (*highest).max(change_id))
                        .or_insert(change_id);
                }
            }
        }
        let has = |kind: FolderKind| {
            tree.iter().any(
                |entry| matches!(entry.node, FolderNode::Stored(folder) if folder.kind == kind),
            )
        };
        let calendar = if has(FolderKind::Calendar) {
            self.highest_resource_change(mailbox.id, FolderKind::Calendar)
                .await?
        } else {
            None
        };
        let address_book = if has(FolderKind::AddressBook) {
            self.highest_resource_change(mailbox.id, FolderKind::AddressBook)
                .await?
        } else {
            None
        };
        Ok(FolderActivity {
            mail,
            calendar,
            address_book,
        })
    }
}

pub struct FolderActivity {
    mail: AHashMap<u32, u64>,
    calendar: Option<u64>,
    address_book: Option<u64>,
}

impl FolderActivity {
    pub fn change_id(&self, node: FolderNode, base: u64) -> u64 {
        let highest = match node {
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id,
            }) => self.mail.get(&id).copied(),
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Calendar,
                ..
            }) => self.calendar,
            FolderNode::Stored(FolderRef {
                kind: FolderKind::AddressBook,
                ..
            }) => self.address_book,
            _ => None,
        };
        highest.map_or(base, |highest| highest.max(base))
    }
}

pub fn subtree_change(tree: &FolderTree, entry: &FolderEntry) -> u64 {
    tree.children(entry.node)
        .map(|child| child.change_id)
        .fold(entry.change_id, u64::max)
}

pub fn push_change_time(bag: &mut PropBag, tree: &FolderTree, entry: &FolderEntry, highest: u64) {
    let modified = tree.modified(entry.node).map_or_else(
        || change_time(entry.change_id),
        |seconds| FileTime::from_utc(UtcSeconds(i64::try_from(seconds).unwrap_or(i64::MAX)), 0),
    );
    bag.push_time(tags::LAST_MODIFICATION_TIME, modified);
    bag.push_time(tags::LOCAL_COMMIT_TIME_MAX, change_time(highest));
}

pub fn push_folder_state(bag: &mut PropBag, tree: &FolderTree, entry: &FolderEntry) {
    let version = tree.version();
    let hierarchy = [
        version.mail,
        version.calendar,
        version.address_book,
        version.virtual_change,
    ]
    .into_iter()
    .fold(0u64, u64::wrapping_add);
    let [low @ .., _, _, _, _] = hierarchy.to_le_bytes();
    bag.push_i32(tags::HIERARCHY_CHANGE_NUMBER, i32::from_le_bytes(low));
    bag.push_i32(tags::FOLDER_FLAGS, folder_flags(entry));
    bag.push_time(tags::HIER_REV, change_time(subtree_change(tree, entry)));
}

fn folder_flags(entry: &FolderEntry) -> i32 {
    let kind = if folder_type(entry) == FOLDER_SEARCH {
        FOLDER_FLAG_SEARCH
    } else {
        FOLDER_FLAG_NORMAL
    };
    if entry.ipm {
        FOLDER_FLAG_IPM | kind
    } else {
        kind
    }
}

pub fn folder_bag(
    tree: &FolderTree,
    entry: &FolderEntry,
    guids: &StoreGuids,
    exchange: &ExchangeAccountCache,
    counters: Option<&FolderCounters>,
    rights: &ViewRights,
) -> PropBag {
    let node = entry.node;
    let mut props = PropBag::with_capacity(256);
    props.push_i32(tags::OBJECT_TYPE, MAPI_FOLDER);
    push_folder_ids(&mut props, guids, exchange, node, FolderIds::SELF);
    if let Some(parent) = entry.parent {
        push_folder_ids(&mut props, guids, exchange, parent, FolderIds::PARENT);
    }
    props.push_text(tags::DISPLAY_NAME, &entry.name);
    let class = entry.class.as_str();
    if !class.is_empty() {
        props.push_text(tags::CONTAINER_CLASS, class);
    }
    props.push_i32(tags::FOLDER_TYPE, folder_type(entry));
    props.push_bool(
        tags::SUBFOLDERS,
        tree.children(node)
            .any(|child| rights.of(child.node).is_visible()),
    );
    if let Some(counters) = counters {
        let (total, unread) = match node {
            FolderNode::Stored(folder)
                if folder.kind == FolderKind::Mailbox && rights.of(node).reads_items() =>
            {
                counters
                    .get(&folder.id)
                    .map_or((0, 0), |counters| (counters.total, counters.unread))
            }
            _ => (0, 0),
        };
        props.push_i32(
            tags::CONTENT_COUNT,
            i32::try_from(total).unwrap_or(i32::MAX),
        );
        props.push_i32(
            tags::CONTENT_UNREAD_COUNT,
            i32::try_from(unread).unwrap_or(i32::MAX),
        );
    }
    props.push_i32(tags::ASSOC_CONTENT_COUNT, 0);
    if matches!(
        entry.special,
        Some(SpecialFolder::Root | SpecialFolder::Inbox)
    ) {
        for (tag, special) in SPECIAL_ENTRY_IDS {
            if let Some(target) = tree.special(special) {
                props.push_entry_id(
                    tag,
                    &guids.folder_entry_id(MapiId::from_folder(exchange, target.node)),
                );
            }
        }
    }
    props
}

pub fn change_time(change_id: u64) -> FileTime {
    let seconds =
        i64::try_from(change_id).map_or(i64::MAX, |id| id.saturating_add(CHANGE_TIME_BASE));
    FileTime::from_utc(UtcSeconds(seconds), 0)
}

fn wants(demand: PropDemand<'_>, tag: PropTag) -> bool {
    matches!(demand, PropDemand::Names) || demand.wants_value(tag)
}

pub(super) fn push_inbox_ren_entry_ids(
    bag: &mut PropBag,
    tree: &FolderTree,
    entry: &FolderEntry,
    guids: &StoreGuids,
    exchange: &ExchangeAccountCache,
    rights: &ViewRights,
) {
    if entry.special != Some(SpecialFolder::Inbox) {
        return;
    }
    let named = REN_FOLDERS.map(|special| {
        tree.special(special)
            .filter(|folder| rights.of(folder.node).is_visible())
            .and_then(|folder| {
                let mut entry_id = Vec::with_capacity(FOLDER_ENTRY_ID_CAPACITY);
                guids
                    .folder_entry_id(MapiId::from_folder(exchange, folder.node))
                    .encode(&mut entry_id)
                    .ok()
                    .map(|_| Bytes::from(entry_id))
            })
    });
    if named.iter().all(Option::is_none) {
        return;
    }
    let mut ids: Vec<Bytes> = match bag.get(tags::ADDITIONAL_REN_ENTRY_IDS) {
        Some(PropOut::Value(PropValue::Mv(view))) if view.mv_type() == MvType::Binary => view
            .iter()
            .map(|value| match value {
                PropValue::Binary(bytes) => Bytes::copy_from_slice(bytes),
                _ => Bytes::new(),
            })
            .collect(),
        _ => Vec::new(),
    };
    if ids.len() < REN_FOLDERS.len() {
        ids.resize(REN_FOLDERS.len(), Bytes::new());
    }
    for (slot, entry_id) in ids.iter_mut().zip(named) {
        if let Some(entry_id) = entry_id {
            *slot = entry_id;
        }
    }
    bag.remove(tags::ADDITIONAL_REN_ENTRY_IDS);
    bag.push_owned(
        tags::ADDITIONAL_REN_ENTRY_IDS,
        &OwnedPropValue::MvBinary(ids.into_boxed_slice()),
    );
}

pub type FolderCounters = AHashMap<u32, MailboxCounters>;

pub fn stored_mailbox(node: FolderNode) -> Option<u32> {
    match node {
        FolderNode::Stored(folder) if folder.kind == FolderKind::Mailbox => Some(folder.id),
        _ => None,
    }
}

pub fn folder_data_type(node: FolderNode) -> Option<DataType> {
    match node {
        FolderNode::Stored(FolderRef { kind, .. }) => match kind {
            FolderKind::Mailbox | FolderKind::Virtual => Some(DataType::Email),
            FolderKind::Calendar => Some(DataType::CalendarEvent),
            FolderKind::AddressBook => Some(DataType::ContactCard),
            FolderKind::FileNode => None,
        },
        FolderNode::Special(_) => None,
    }
}

struct FolderIds {
    folder_id: PropTag,
    entry_id: PropTag,
    source_key: PropTag,
}

impl FolderIds {
    const SELF: FolderIds = FolderIds {
        folder_id: tags::FOLDER_ID,
        entry_id: tags::ENTRY_ID,
        source_key: tags::SOURCE_KEY,
    };
    const PARENT: FolderIds = FolderIds {
        folder_id: tags::PARENT_FOLDER_ID,
        entry_id: tags::PARENT_ENTRY_ID,
        source_key: tags::PARENT_SOURCE_KEY,
    };
}

fn push_folder_ids(
    props: &mut PropBag,
    guids: &StoreGuids,
    exchange: &ExchangeAccountCache,
    node: FolderNode,
    ids: FolderIds,
) {
    let id = MapiId::from_folder(exchange, node);
    props.push_i64(ids.folder_id, i64::from_le_bytes(id.to_eid().to_wire()));
    props.push_entry_id(ids.entry_id, &guids.folder_entry_id(id));
    props.push_binary(ids.source_key, &guids.gid(id).to_wire());
}

fn folder_type(entry: &FolderEntry) -> i32 {
    match entry.special {
        Some(SpecialFolder::Root) => FOLDER_ROOT,
        _ if entry.search => FOLDER_SEARCH,
        _ => FOLDER_GENERIC,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/folder/tests.rs"]
mod tests;
