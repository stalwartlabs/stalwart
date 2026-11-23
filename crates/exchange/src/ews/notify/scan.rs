/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::groupware_log::{GROUPWARE_KINDS, GroupwareCursor, GroupwareInput, KINDS};
use crate::{
    folders::{FolderEntry, FolderNode, FolderTree, HierarchyVersion, SpecialFolder},
    store::{FolderKind, FolderRef},
};
use ahash::{AHashMap, AHashSet};
use common::{
    MessageStoreCache,
    cache::{
        email::MessageRef,
        exchange::{ExchangeAccountCache, Placement},
    },
};
use email::cache::email::MessageCacheAccess;
use exchange_proto::ews::{schema::NotificationEventType, types::subscription::EventTypes};
use smallvec::SmallVec;
use std::sync::Arc;
use store::roaring::RoaringBitmap;
use types::{
    keyword::{DRAFT, SEEN},
    type_state::DataType,
};
use utils::map::bitmap::Bitmap;

pub(crate) const MAX_EVENTS_PER_BATCH: usize = 50;
const NEW_MAIL_WINDOW: u64 = 60;
const NOT_NEW_MAIL: u32 = (1 << SEEN) | (1 << DRAFT);
const FOLDER_MARK_WEIGHT: u64 = 48;
const MAILBOX_WEIGHT: u64 = 64;
const ENTERED_WEIGHT: u64 = 24;
const ALIAS_WEIGHT: u64 = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scope {
    All,
    Folders(SmallVec<[FolderNode; 4]>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FolderMark {
    pub parent: Option<FolderNode>,
    pub change_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanObject {
    Item {
        mailbox: u32,
        identity: u32,
    },
    Groupware {
        kind: FolderKind,
        container: u32,
        document: u32,
    },
    Folder(FolderNode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Place {
    pub object: ScanObject,
    pub parent: FolderNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanEvent {
    Created(Place),
    NewMail(Place),
    Deleted(Place),
    Modified { place: Place, unread: Option<u32> },
    Moved { to: Place, from: Place },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffMode {
    Auto,
    Full,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ScanBatch {
    pub events: Vec<ScanEvent>,
    pub more: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Cursor {
    change_id: u64,
    modified_after: Option<(u64, u32, u32)>,
    complete: bool,
    version: HierarchyVersion,
    next_document_id: u32,
    scanned_at: u64,
    members: AHashMap<u32, RoaringBitmap>,
    entered: AHashMap<(u32, u32), u64>,
    folders: AHashMap<FolderNode, FolderMark>,
    aliases: Arc<AHashMap<u32, Placement>>,
    groupware: [GroupwareCursor; GROUPWARE_KINDS],
}

pub(crate) struct ScanInput<'x> {
    pub messages: &'x MessageStoreCache,
    pub exchange: &'x ExchangeAccountCache,
    pub tree: &'x FolderTree,
    pub scope: &'x Scope,
    pub mail: bool,
    pub now: u64,
    pub groupware: [Option<GroupwareInput<'x>>; GROUPWARE_KINDS],
}

pub(super) struct Emitter {
    pub(super) events: Vec<ScanEvent>,
    pub(super) filter: EventTypes,
    pub(super) budget: usize,
    pub(super) more: bool,
}

struct Entered {
    mailbox: u32,
    identity: u32,
    new_mail: bool,
}

impl Scope {
    pub fn folders(mut nodes: SmallVec<[FolderNode; 4]>) -> Self {
        nodes.sort_unstable_by_key(|node| node_key(*node));
        nodes.dedup();
        Scope::Folders(nodes)
    }

    pub(super) fn holds(&self, kind: FolderKind) -> bool {
        match self {
            Scope::All => true,
            Scope::Folders(nodes) => nodes.iter().any(|node| {
                matches!(node, FolderNode::Stored(FolderRef { kind: held, .. }) if *held == kind)
            }),
        }
    }

    pub(super) fn contains(&self, node: FolderNode) -> bool {
        match self {
            Scope::All => true,
            Scope::Folders(nodes) => nodes
                .binary_search_by_key(&node_key(node), |node| node_key(*node))
                .is_ok(),
        }
    }

    pub fn add_wake_types(&self, types: &mut Bitmap<DataType>) {
        const CONTAINERS: [DataType; 3] =
            [DataType::Mailbox, DataType::Calendar, DataType::AddressBook];
        let nodes = match self {
            Scope::All => {
                types.insert_many(CONTAINERS);
                types.insert_many([
                    DataType::Email,
                    DataType::CalendarEvent,
                    DataType::ContactCard,
                ]);
                return;
            }
            Scope::Folders(nodes) => nodes,
        };
        for node in nodes {
            match node {
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Mailbox,
                    ..
                }) => {
                    types.insert(DataType::Email);
                    types.insert(DataType::Mailbox);
                }
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Calendar,
                    ..
                }) => {
                    types.insert(DataType::CalendarEvent);
                    types.insert(DataType::Calendar);
                }
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::AddressBook,
                    ..
                }) => {
                    types.insert(DataType::ContactCard);
                    types.insert(DataType::AddressBook);
                }
                _ => types.insert_many(CONTAINERS),
            }
        }
    }

    fn folder(&self, entry: &FolderEntry) -> bool {
        self.contains(entry.node) || entry.parent.is_some_and(|parent| self.contains(parent))
    }

    fn mailbox(&self, entry: &FolderEntry) -> Option<u32> {
        match entry.node {
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id,
            }) if self.contains(entry.node) => Some(id),
            _ => None,
        }
    }
}

fn node_key(node: FolderNode) -> (u8, u32) {
    let folder = node.exchange_folder();
    (folder.kind, folder.id)
}

impl ScanEvent {
    fn kind(&self) -> NotificationEventType {
        match self {
            ScanEvent::Created(_) => NotificationEventType::CreatedEvent,
            ScanEvent::NewMail(_) => NotificationEventType::NewMailEvent,
            ScanEvent::Deleted(_) => NotificationEventType::DeletedEvent,
            ScanEvent::Modified { .. } => NotificationEventType::ModifiedEvent,
            ScanEvent::Moved { .. } => NotificationEventType::MovedEvent,
        }
    }
}

impl Emitter {
    fn admits(&self, events: &[ScanEvent]) -> bool {
        self.events.is_empty()
            || events
                .iter()
                .filter(|event| self.filter.contains(event.kind()))
                .count()
                <= self.budget
    }

    pub(super) fn emit(&mut self, events: &[ScanEvent]) -> bool {
        if self.more || !self.admits(events) {
            self.more = true;
            return false;
        }
        for event in events {
            if self.filter.contains(event.kind()) {
                self.events.push(*event);
                self.budget = self.budget.saturating_sub(1);
            }
        }
        true
    }
}

fn mailbox_node(id: u32) -> FolderNode {
    FolderNode::Stored(FolderRef {
        kind: FolderKind::Mailbox,
        id,
    })
}

fn item(mailbox: u32, identity: u32) -> Place {
    Place {
        object: ScanObject::Item { mailbox, identity },
        parent: mailbox_node(mailbox),
    }
}

fn folder(node: FolderNode, parent: Option<FolderNode>) -> Place {
    Place {
        object: ScanObject::Folder(node),
        parent: parent.unwrap_or(node),
    }
}

impl ScanInput<'_> {
    fn mailboxes(&self) -> Vec<u32> {
        if !self.mail {
            return Vec::new();
        }
        let mut mailboxes = self
            .tree
            .iter()
            .filter_map(|entry| self.scope.mailbox(entry))
            .collect::<Vec<_>>();
        mailboxes.sort_unstable();
        mailboxes.dedup();
        mailboxes
    }

    fn folder_marks(&self) -> impl Iterator<Item = (FolderNode, FolderMark)> + '_ {
        self.tree
            .iter()
            .filter(|entry| self.scope.folder(entry))
            .map(|entry| {
                (
                    entry.node,
                    FolderMark {
                        parent: entry.parent,
                        change_id: entry.change_id,
                    },
                )
            })
    }

    fn current_members(&self, mailboxes: &[u32]) -> (AHashMap<u32, RoaringBitmap>, u32) {
        let mut members = mailboxes
            .iter()
            .map(|&mailbox| (mailbox, RoaringBitmap::new()))
            .collect::<AHashMap<_, _>>();
        let mut next_document_id = 0;
        for message in self.messages.emails.iter() {
            let document_id = message.document_id();
            next_document_id = next_document_id.max(document_id.saturating_add(1));
            for uid in message.mailboxes() {
                if let Some(identities) = members.get_mut(&uid.mailbox_id) {
                    identities.insert(self.exchange.email_item(uid.mailbox_id, document_id));
                }
            }
        }
        (members, next_document_id)
    }

    fn filed(&self, mailbox: u32, identity: u32) -> Option<MessageRef<'_>> {
        self.messages
            .email_by_id(&self.exchange.email_document(mailbox, identity))
            .filter(|message| message.has_mailbox_id(mailbox))
    }

    fn excluded(&self) -> [Option<FolderNode>; 2] {
        [SpecialFolder::JunkEmail, SpecialFolder::DeletedItems]
            .map(|special| self.tree.special(special).map(|entry| entry.node))
    }
}

impl Cursor {
    pub fn baseline(input: &ScanInput<'_>) -> Self {
        let mailboxes = input.mailboxes();
        let (members, next_document_id) = input.current_members(&mailboxes);
        Cursor {
            change_id: input.messages.last_change_id,
            modified_after: None,
            entered: AHashMap::new(),
            complete: true,
            version: input.tree.version(),
            next_document_id,
            scanned_at: input.now,
            members,
            folders: input.folder_marks().collect(),
            aliases: Arc::clone(&input.exchange.aliases),
            groupware: input.groupware.each_ref().map(|groupware| {
                groupware
                    .as_ref()
                    .map(|groupware| GroupwareCursor::baseline(groupware, input.tree, input.scope))
                    .unwrap_or_default()
            }),
        }
    }

    pub fn groupware_window(&self, index: usize, scope: &Scope) -> (u64, u64) {
        self.groupware
            .get(index)
            .zip(KINDS.get(index))
            .filter(|(_, (kind, _, _))| scope.holds(*kind))
            .map_or((u64::MAX, 0), |(cursor, _)| cursor.window())
    }

    fn groupware_pending(&self, input: &ScanInput<'_>) -> bool {
        self.groupware
            .iter()
            .zip(&input.groupware)
            .any(|(cursor, groupware)| {
                groupware
                    .as_ref()
                    .is_some_and(|groupware| cursor.is_pending(groupware, input.scope))
            })
    }

    pub fn weight(&self) -> u64 {
        let members = self
            .members
            .values()
            .map(|identities| identities.serialized_size() as u64 + MAILBOX_WEIGHT)
            .sum::<u64>();
        members
            + self.folders.len() as u64 * FOLDER_MARK_WEIGHT
            + self.entered.len() as u64 * ENTERED_WEIGHT
            + self.aliases.len() as u64 * ALIAS_WEIGHT
            + self
                .groupware
                .iter()
                .map(GroupwareCursor::weight)
                .sum::<u64>()
    }

    pub fn scan(&mut self, input: &ScanInput<'_>, filter: EventTypes, budget: usize) -> ScanBatch {
        self.scan_with(input, filter, budget, DiffMode::Auto)
    }

    pub(crate) fn scan_with(
        &mut self,
        input: &ScanInput<'_>,
        filter: EventTypes,
        budget: usize,
        mode: DiffMode,
    ) -> ScanBatch {
        let last_change_id = input.messages.last_change_id;
        let version = input.tree.version();
        if mode == DiffMode::Auto
            && self.complete
            && self.change_id == last_change_id
            && self.version == version
            && !self.groupware_pending(input)
        {
            self.scanned_at = input.now;
            return ScanBatch::default();
        }
        let mut emitter = Emitter {
            events: Vec::new(),
            filter,
            budget,
            more: false,
        };
        for (cursor, groupware) in self.groupware.iter_mut().zip(&input.groupware) {
            if let Some(groupware) = groupware {
                cursor.prepare_truncated(groupware, &mut self.folders);
            }
        }
        self.scan_folders(input, &mut emitter);
        let mailboxes = input.mailboxes();
        self.members
            .retain(|mailbox, _| mailboxes.binary_search(mailbox).is_ok());
        let mut next_document_id = self.next_document_id;
        let mut changed = Vec::new();
        if !emitter.more && !mailboxes.is_empty() {
            let mode = if self.complete && self.members.len() == mailboxes.len() {
                mode
            } else {
                DiffMode::Full
            };
            let touched = match mode {
                DiffMode::Auto if self.change_id == last_change_id => {
                    Some((AHashMap::new(), next_document_id))
                }
                DiffMode::Auto => self.touched_since(input, &mailboxes),
                DiffMode::Full => None,
            };
            let (touched, high_water) =
                touched.unwrap_or_else(|| self.touched_full(input, &mailboxes));
            next_document_id = high_water;
            changed = self.scan_items(input, &mailboxes, touched, &mut emitter);
        }
        if !changed.is_empty() && filter.contains(NotificationEventType::ModifiedEvent) {
            let counters = input
                .messages
                .mailbox_counters(changed.iter().copied(), false);
            for mailbox in changed {
                let node = mailbox_node(mailbox);
                let count = counters
                    .get(&mailbox)
                    .map(|counter| u32::try_from(counter.unread).unwrap_or(u32::MAX));
                match emitter.events.iter_mut().find_map(|event| match event {
                    ScanEvent::Modified { place, unread }
                        if place.object == ScanObject::Folder(node) =>
                    {
                        Some(unread)
                    }
                    _ => None,
                }) {
                    Some(unread) => *unread = count,
                    None => {
                        let parent = input.tree.get(node).and_then(|entry| entry.parent);
                        emitter.events.push(ScanEvent::Modified {
                            place: folder(node, parent),
                            unread: count,
                        });
                    }
                }
            }
        }
        let mail_more = emitter.more;
        if !mail_more {
            for (cursor, groupware) in self.groupware.iter_mut().zip(&input.groupware) {
                if let Some(groupware) = groupware {
                    cursor.scan(groupware, input.tree, input.scope, &mut emitter);
                }
            }
        }
        if mail_more {
            self.complete = false;
        } else {
            self.complete = true;
            self.change_id = last_change_id;
            self.modified_after = None;
            self.entered.clear();
            self.version = version;
            self.next_document_id = self.next_document_id.max(next_document_id);
            self.scanned_at = input.now;
            self.aliases = Arc::clone(&input.exchange.aliases);
        }
        ScanBatch {
            more: emitter.more || self.groupware_pending(input),
            events: emitter.events,
        }
    }

    fn scan_folders(&mut self, input: &ScanInput<'_>, emitter: &mut Emitter) {
        let mut current = AHashSet::with_capacity(self.folders.len());
        for (node, mark) in input.folder_marks() {
            current.insert(node);
            let event = match self.folders.get(&node) {
                None => ScanEvent::Created(folder(node, mark.parent)),
                Some(old) if old.parent != mark.parent => ScanEvent::Moved {
                    to: folder(node, mark.parent),
                    from: folder(node, old.parent),
                },
                Some(old) if old.change_id != mark.change_id => ScanEvent::Modified {
                    place: folder(node, mark.parent),
                    unread: None,
                },
                Some(_) => continue,
            };
            if !emitter.emit(&[event]) {
                return;
            }
            self.folders.insert(node, mark);
        }
        let mut deleted = self
            .folders
            .iter()
            .filter(|(node, _)| !current.contains(*node))
            .map(|(node, mark)| (*node, mark.parent))
            .collect::<Vec<_>>();
        deleted.sort_unstable_by_key(|(node, _)| node_key(*node));
        for (node, parent) in deleted {
            if !emitter.emit(&[ScanEvent::Deleted(folder(node, parent))]) {
                return;
            }
            self.folders.remove(&node);
        }
    }

    fn touched_since(
        &self,
        input: &ScanInput<'_>,
        mailboxes: &[u32],
    ) -> Option<(AHashMap<u32, RoaringBitmap>, u32)> {
        let documents = input
            .messages
            .refresh
            .changed_items(self.change_id, input.messages.last_change_id)?;
        let mut touched = AHashMap::<u32, RoaringBitmap>::new();
        let mut next_document_id = self.next_document_id;
        let mut changed = RoaringBitmap::new();
        for &document_id in documents.iter() {
            changed.insert(document_id);
            for placement in [
                input.exchange.alias_of(document_id),
                self.aliases.get(&document_id).copied(),
            ]
            .into_iter()
            .flatten()
            .filter(|placement| mailboxes.binary_search(&placement.container).is_ok())
            {
                touched
                    .entry(placement.container)
                    .or_default()
                    .insert(placement.item);
            }
            if let Some(message) = input.messages.email_by_id(&document_id) {
                next_document_id = next_document_id.max(document_id.saturating_add(1));
                for mailbox in message
                    .mailboxes()
                    .iter()
                    .map(|uid| uid.mailbox_id)
                    .filter(|mailbox| mailboxes.binary_search(mailbox).is_ok())
                {
                    touched
                        .entry(mailbox)
                        .or_default()
                        .insert(input.exchange.email_item(mailbox, document_id));
                }
            }
        }
        for (mailbox, members) in &self.members {
            if !members.is_disjoint(&changed) {
                *touched.entry(*mailbox).or_default() |= members & &changed;
            }
        }
        Some((touched, next_document_id))
    }

    fn touched_full(
        &self,
        input: &ScanInput<'_>,
        mailboxes: &[u32],
    ) -> (AHashMap<u32, RoaringBitmap>, u32) {
        let (mut touched, next_document_id) = input.current_members(mailboxes);
        for (mailbox, identities) in &mut touched {
            if let Some(members) = self.members.get(mailbox) {
                *identities |= members;
            }
        }
        (touched, next_document_id)
    }

    fn scan_items(
        &mut self,
        input: &ScanInput<'_>,
        mailboxes: &[u32],
        touched: AHashMap<u32, RoaringBitmap>,
        emitter: &mut Emitter,
    ) -> Vec<u32> {
        let mut left = Vec::new();
        let mut entered = Vec::new();
        let mut modified = Vec::new();
        let excluded = input.excluded();
        for (mailbox, identities) in touched {
            let new_mail_allowed = !excluded.contains(&Some(mailbox_node(mailbox)));
            let members = self.members.entry(mailbox).or_default();
            for identity in &identities {
                let was = members.contains(identity);
                match (was, input.filed(mailbox, identity)) {
                    (true, None) => left.push((mailbox, identity)),
                    (false, Some(message)) => entered.push(Entered {
                        mailbox,
                        identity,
                        new_mail: new_mail_allowed
                            && message.document_id() >= self.next_document_id
                            && message.keywords() & NOT_NEW_MAIL == 0
                            && message.received_at().saturating_add(NEW_MAIL_WINDOW)
                                >= self.scanned_at,
                    }),
                    (true, Some(message)) => {
                        let key = (message.change_id(), mailbox, identity);
                        let since = self
                            .entered
                            .get(&(mailbox, identity))
                            .copied()
                            .unwrap_or(self.change_id);
                        if message.change_id() > since
                            && self.modified_after.is_none_or(|after| key > after)
                        {
                            modified.push(key);
                        }
                    }
                    (false, None) => {}
                }
            }
        }
        left.sort_unstable();
        entered.sort_unstable_by_key(|entry| (entry.mailbox, entry.identity));
        modified.sort_unstable();

        let mut changed = Vec::new();
        let mut consumed = AHashSet::new();
        let mut moved = Vec::new();
        let mut deleted = Vec::new();
        for &(mailbox, identity) in &left {
            let document_id = input.exchange.email_document(mailbox, identity);
            let target = input
                .messages
                .email_by_id(&document_id)
                .and_then(|message| {
                    let others = message
                        .mailboxes()
                        .iter()
                        .map(|uid| uid.mailbox_id)
                        .filter(|&other| other != mailbox);
                    others
                        .clone()
                        .filter(|other| mailboxes.binary_search(other).is_ok())
                        .map(|other| (other, input.exchange.email_item(other, document_id)))
                        .find(|&(other, other_identity)| {
                            !self
                                .members
                                .get(&other)
                                .is_some_and(|members| members.contains(other_identity))
                                && !consumed.contains(&(other, other_identity))
                        })
                        .or_else(|| {
                            others
                                .filter(|other| mailboxes.binary_search(other).is_err())
                                .map(|other| (other, input.exchange.email_item(other, document_id)))
                                .next()
                        })
                });
            match target {
                Some(to) => {
                    consumed.insert(to);
                    moved.push(((mailbox, identity), to));
                }
                None => deleted.push((mailbox, identity)),
            }
        }

        for (mailbox, identity) in deleted {
            if !emitter.emit(&[ScanEvent::Deleted(item(mailbox, identity))]) {
                return finish_changed(changed);
            }
            self.remove(mailbox, identity);
            changed.push(mailbox);
        }
        for ((mailbox, identity), (to_mailbox, to_identity)) in moved {
            let event = ScanEvent::Moved {
                to: item(to_mailbox, to_identity),
                from: item(mailbox, identity),
            };
            if !emitter.emit(&[event]) {
                return finish_changed(changed);
            }
            self.remove(mailbox, identity);
            changed.push(mailbox);
            if mailboxes.binary_search(&to_mailbox).is_ok() {
                self.members
                    .entry(to_mailbox)
                    .or_default()
                    .insert(to_identity);
                self.entered
                    .insert((to_mailbox, to_identity), input.messages.last_change_id);
                changed.push(to_mailbox);
            }
        }
        for key in modified {
            let (_, mailbox, identity) = key;
            let event = ScanEvent::Modified {
                place: item(mailbox, identity),
                unread: None,
            };
            if !emitter.emit(&[event]) {
                return finish_changed(changed);
            }
            self.modified_after = Some(key);
            changed.push(mailbox);
        }
        for entry in entered {
            if consumed.contains(&(entry.mailbox, entry.identity)) {
                continue;
            }
            let place = item(entry.mailbox, entry.identity);
            let pair = [ScanEvent::Created(place), ScanEvent::NewMail(place)];
            let events = if entry.new_mail {
                &pair[..]
            } else {
                &pair[..1]
            };
            if !emitter.emit(events) {
                return finish_changed(changed);
            }
            self.members
                .entry(entry.mailbox)
                .or_default()
                .insert(entry.identity);
            self.entered.insert(
                (entry.mailbox, entry.identity),
                input.messages.last_change_id,
            );
            changed.push(entry.mailbox);
        }
        finish_changed(changed)
    }

    fn remove(&mut self, mailbox: u32, identity: u32) {
        if let Some(members) = self.members.get_mut(&mailbox) {
            members.remove(identity);
        }
        self.entered.remove(&(mailbox, identity));
    }
}

fn finish_changed(mut changed: Vec<u32>) -> Vec<u32> {
    changed.sort_unstable();
    changed.dedup();
    changed
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/notify/scan/tests.rs"]
mod tests;
