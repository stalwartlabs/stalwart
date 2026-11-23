/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod events;
mod rows;

use super::{
    execute::{MailboxView, RopContext, RopError, RopResult},
    search::SearchFlags,
    state::{
        MailboxCursor, NOTIFY_GROUPS, ServerObject, Subscription, SubscriptionScope, TableNotify,
    },
};
use crate::{
    folders::{FolderNode, FolderTree, FolderWrites, SpecialFolder},
    mapi::ids::{IdSpace, MapiId, fixed},
    store::{FolderKind, FolderRef},
};
use common::cache::exchange::EXCHANGE_GROUPS;
use email::cache::email::MessageCacheAccess;
use events::{GroupEvents, GroupWrite, ObjectEvent, OnOverflow, Targets};
use exchange_proto::mapi::{
    ErrorCode,
    notify::NotificationTypes,
    rop::{DecodedRop, PENDING_LEN, RopId, RopRequest, requests::RegisterNotification},
};
use groupware::cache::GroupwareCache;
use store::query::log::{CappedChanges, Change, Query};
use trc::AddContext;
use types::{
    collection::SyncCollection,
    keyword::{DRAFT, SEEN},
    type_state::DataType,
};
use utils::map::bitmap::Bitmap;

pub const MAX_NOTIFY_IDS_PER_GROUP: usize = 256;
const SESSION_INDEX: u16 = 0;
const DOCUMENT_ID_MASK: u64 = u32::MAX as u64;

const NOTIFY_READ_CAP: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Span {
    First,
    Split(usize),
}

impl Span {
    fn limit(self) -> usize {
        match self {
            Span::First => NOTIFY_READ_CAP,
            Span::Split(limit) => limit,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Window {
    since: u64,
    head: u64,
    span: Span,
}

#[derive(Debug, Clone, Copy)]
struct Covered {
    upto: u64,
    split: Option<Span>,
}

#[derive(Debug, Clone, Copy)]
struct Group {
    collection: SyncCollection,
    folders: FolderKind,
    items: IdSpace,
    data_type: DataType,
}

const GROUPS: [Group; NOTIFY_GROUPS] = [
    Group {
        collection: SyncCollection::Email,
        folders: FolderKind::Mailbox,
        items: IdSpace::Email,
        data_type: DataType::Email,
    },
    Group {
        collection: SyncCollection::Calendar,
        folders: FolderKind::Calendar,
        items: IdSpace::Event,
        data_type: DataType::CalendarEvent,
    },
    Group {
        collection: SyncCollection::AddressBook,
        folders: FolderKind::AddressBook,
        items: IdSpace::Contact,
        data_type: DataType::ContactCard,
    },
];

pub fn activates_view(request: &RopRequest<'_>) -> bool {
    match request {
        RopRequest::FindRow(_)
        | RopRequest::QueryPosition
        | RopRequest::QueryRows(_)
        | RopRequest::SeekRow(_)
        | RopRequest::SeekRowBookmark(_)
        | RopRequest::SeekRowFractional(_)
        | RopRequest::SetCollapseState(_) => true,
        RopRequest::Stub(id, _) => *id == RopId::QUERY_COLUMNS_ALL,
        _ => false,
    }
}

pub fn behind(
    seen: &[u64; NOTIFY_GROUPS],
    heads: &[u64; EXCHANGE_GROUPS],
    types: Bitmap<DataType>,
) -> bool {
    GROUPS
        .iter()
        .zip(seen)
        .zip(heads)
        .any(|((group, seen), head)| types.contains(group.data_type) && head > seen)
}

fn group_heads(view: &MailboxView) -> [u64; NOTIFY_GROUPS] {
    let [email, calendar, address_book, ..] = view.exchange.change_ids;
    [
        view.messages
            .as_ref()
            .map_or(email, |messages| messages.last_change_id),
        calendar,
        address_book,
    ]
}

impl RopContext<'_, '_> {
    pub async fn register_notification(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &RegisterNotification,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let (logon_id, logon) = self
            .state
            .logon_of(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let mailbox_id = logon.mailbox_id;
        let scope = match (
            request.want_whole_store,
            request.folder_id,
            request.message_id,
        ) {
            (false, Some(folder), Some(message)) => {
                let folder = self.folder_id(mailbox_id, folder).await?;
                let node = folder.to_node().ok_or(ErrorCode::NOT_FOUND)?;
                if self.folder_tree(mailbox_id).await?.get(node).is_none() {
                    return Err(RopError::Code(ErrorCode::NOT_FOUND));
                }
                self.require_visible(mailbox_id, node).await?;
                if message.to_wire() == [0; 8] {
                    SubscriptionScope::Folder(folder.counter())
                } else {
                    SubscriptionScope::Message {
                        folder: folder.counter(),
                        message: MapiId::from_eid(message)
                            .filter(|id| !id.space.is_folder())
                            .ok_or(ErrorCode::NOT_FOUND)?
                            .counter(),
                    }
                }
            }
            _ => SubscriptionScope::Store,
        };
        let handle = self.state.insert(
            logon_id,
            ServerObject::Subscription(Subscription {
                types: request.notification_types,
                scope,
            }),
        )?;
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        self.respond_empty(rop, index)
    }

    pub fn activate_table(&mut self, rop: &DecodedRop<'_>) {
        if let Ok(handle) = self.input(rop.header.input_handle)
            && let Some(ServerObject::Table(table)) = self.state.get_mut(handle)
            && table.notify == TableNotify::Paused
        {
            table.notify = TableNotify::Active;
        }
    }

    pub async fn emit_notifications(&mut self, empty: usize) -> trc::Result<()> {
        let mailboxes = self.state.notify_mailboxes();
        self.state
            .seen
            .retain(|cursor| mailboxes.contains(&cursor.mailbox_id));
        if mailboxes.is_empty() {
            return Ok(());
        }
        self.invalidate_mailbox();
        self.writer.reserve_tail(PENDING_LEN);
        let empty = empty.saturating_sub(PENDING_LEN);
        let mut result = Ok(());
        for mailbox_id in mailboxes {
            match self.emit_mailbox(mailbox_id, empty).await {
                Ok(GroupWrite::Deferred) => {
                    self.writer.reserve_tail(0);
                    let _ = self.writer.pending(SESSION_INDEX);
                    return Ok(());
                }
                Ok(_) => {}
                Err(err) => {
                    result = Err(err);
                    break;
                }
            }
        }
        self.writer.reserve_tail(0);
        result
    }

    async fn emit_mailbox(&mut self, mailbox_id: u32, empty: usize) -> trc::Result<GroupWrite> {
        if self.logon_access(mailbox_id).is_none() {
            self.state
                .seen
                .retain(|cursor| cursor.mailbox_id != mailbox_id);
            return Ok(GroupWrite::Full);
        }
        let view = self.mailbox(mailbox_id).await?;
        let heads = group_heads(&view);
        let exchange_change = view.exchange.exchange_change;
        let completed = self
            .completed_searches
            .iter()
            .any(|(mailbox, _)| *mailbox == mailbox_id);
        let mut seen = match self.state.cursor(mailbox_id) {
            Some(seen) => seen,
            None => {
                let seen = MailboxCursor {
                    mailbox_id,
                    heads,
                    exchange_change,
                };
                self.state.set_cursor(seen);
                if !completed {
                    return Ok(GroupWrite::Full);
                }
                seen
            }
        };
        let scan = (exchange_change > seen.exchange_change).then_some(seen.exchange_change);
        let searched = completed || scan.is_some();
        if !searched
            && heads
                .iter()
                .zip(&seen.heads)
                .all(|(head, cursor)| head <= cursor)
        {
            return Ok(GroupWrite::Full);
        }
        let tree = self.folder_tree(mailbox_id).await?;
        let targets = Targets::new(self.state, mailbox_id, &tree);
        let mut events = GroupEvents::default();
        let mut result = Ok(GroupWrite::Full);
        'groups: for ((group, head), cursor) in GROUPS.iter().zip(heads).zip(seen.heads.iter_mut())
        {
            if head <= *cursor {
                continue;
            }
            if !self.types.contains(group.data_type) {
                *cursor = head;
                continue;
            }
            let mut span = Span::First;
            while *cursor < head {
                events.clear();
                let window = Window {
                    since: *cursor,
                    head,
                    span,
                };
                let covered = match self
                    .group_events(&view, group, window, &targets, &mut events)
                    .await
                {
                    Ok(covered) => covered,
                    Err(err) => {
                        result = Err(err);
                        break 'groups;
                    }
                };
                if let Err(err) = self
                    .hierarchy_row_events(mailbox_id, &targets, &mut events)
                    .await
                {
                    result = Err(err);
                    break 'groups;
                }
                let on_overflow = if covered.split.is_some() {
                    OnOverflow::Split
                } else {
                    OnOverflow::Degrade
                };
                match targets.write_group(
                    &mut self.writer,
                    group.folders,
                    &mut events,
                    &view.exchange,
                    empty,
                    on_overflow,
                ) {
                    GroupWrite::Full => *cursor = covered.upto,
                    GroupWrite::Degraded => *cursor = head,
                    GroupWrite::Split => match covered.split {
                        Some(split) => span = split,
                        None => *cursor = head,
                    },
                    GroupWrite::Deferred => {
                        result = Ok(GroupWrite::Deferred);
                        break 'groups;
                    }
                }
            }
        }
        if searched && matches!(result, Ok(GroupWrite::Full)) {
            events.clear();
            let collected = if targets.wants(NotificationTypes::SEARCH_COMPLETE)
                && self.types.contains(DataType::Email)
            {
                self.search_events(mailbox_id, scan, &mut events).await
            } else {
                Ok(0)
            };
            match collected {
                Err(err) => result = Err(err),
                Ok(_)
                    if !events.objects.is_empty()
                        && targets.write_group(
                            &mut self.writer,
                            FolderKind::Virtual,
                            &mut events,
                            &view.exchange,
                            empty,
                            OnOverflow::Degrade,
                        ) == GroupWrite::Deferred =>
                {
                    result = Ok(GroupWrite::Deferred);
                }
                Ok(highest) => {
                    seen.exchange_change = seen.exchange_change.max(exchange_change).max(highest)
                }
            }
        }
        self.state.set_cursor(seen);
        result
    }

    async fn search_events(
        &mut self,
        mailbox_id: u32,
        scan: Option<u64>,
        events: &mut GroupEvents,
    ) -> trc::Result<u64> {
        let mut highest = 0;
        if let Some(since) = scan {
            let tree = self.folder_tree(mailbox_id).await?;
            let request = self.request;
            let finder = tree.children(FolderNode::Special(SpecialFolder::Finder));
            let root = tree.children(FolderNode::Special(SpecialFolder::Root));
            for entry in finder.chain(root).filter(|entry| entry.search) {
                highest = highest.max(entry.change_id);
                if entry.change_id <= since {
                    continue;
                }
                if let Ok(search) = request
                    .server
                    .folder_search(request.access_token, mailbox_id, entry.node)
                    .await?
                    && search.started > since
                    && SearchFlags(search.flags).completes()
                {
                    events.objects.push(ObjectEvent::SearchComplete {
                        folder: MapiId::from_node(entry.node),
                    });
                }
            }
        }
        for (_, folder) in self
            .completed_searches
            .iter()
            .filter(|(mailbox, _)| *mailbox == mailbox_id)
        {
            let event = ObjectEvent::SearchComplete { folder: *folder };
            if !events.objects.contains(&event) {
                events.objects.push(event);
            }
        }
        Ok(highest)
    }

    async fn group_events(
        &mut self,
        view: &MailboxView,
        group: &Group,
        window: Window,
        targets: &Targets,
        events: &mut GroupEvents,
    ) -> trc::Result<Covered> {
        let Window { since, head, span } = window;
        let account_id = view.id;
        let server = self.request.server;
        let CappedChanges { changes, has_more } = server
            .store()
            .changes_capped(
                account_id,
                group.collection.into(),
                Query::Range(since, head),
                span.limit(),
            )
            .await
            .caused_by(trc::location!())?;
        if (has_more && span == Span::First) || changes.needs_full_rebuild(since) {
            events.degrade();
            return Ok(Covered {
                upto: head,
                split: None,
            });
        }
        let covered = Covered {
            upto: if has_more && changes.to_change_id > since {
                changes.to_change_id
            } else {
                head
            },
            split: match span.limit().min(changes.changes.len()) / 2 {
                0 => None,
                _ if changes.from_change_id == changes.to_change_id => None,
                limit => Some(Span::Split(limit)),
            },
        };
        let tree = self.folder_tree(account_id).await?;
        let rights = self.view_rights(account_id).await?;
        let items = changes
            .changes
            .iter()
            .filter(|change| {
                matches!(
                    change,
                    Change::InsertItem(_)
                        | Change::UpdateItem(_)
                        | Change::UpdateItemMetadata(_)
                        | Change::DeleteItem(_)
                )
            })
            .count();
        let exact = items <= MAX_NOTIFY_IDS_PER_GROUP;
        let counters = if group.folders == FolderKind::Mailbox
            && targets.wants(NotificationTypes::OBJECT_MODIFIED)
            && changes.changes.iter().any(|change| {
                matches!(change, Change::UpdateContainerPartial(_, partial) if partial.has_properties())
            }) {
            Some(self.folder_counters(account_id).await?)
        } else {
            None
        };
        let resources = if exact && items != 0 && group.folders != FolderKind::Mailbox {
            Some(
                server
                    .fetch_groupware_resources(account_id, account_id, group.collection)
                    .await
                    .caused_by(trc::location!())?,
            )
        } else {
            None
        };
        let folder_node = |id: u64| {
            u32::try_from(id).ok().map(|id| {
                FolderNode::Stored(FolderRef {
                    kind: group.folders,
                    id,
                })
            })
        };
        for change in &changes.changes {
            match *change {
                Change::InsertContainer(id) | Change::UpdateContainer(id) => {
                    let Some((node, Some(parent))) = folder_node(id)
                        .filter(|node| rights.of(*node).is_visible())
                        .and_then(|node| tree.get(node).map(|entry| (node, entry.parent)))
                    else {
                        events.all_hierarchy |= rights.is_delegate();
                        continue;
                    };
                    let folder = MapiId::from_node(node);
                    if matches!(change, Change::InsertContainer(_)) {
                        events.objects.push(ObjectEvent::Created {
                            folder,
                            message: None,
                            parent: MapiId::from_node(parent),
                        });
                        push_parent(&tree, parent, events);
                    } else {
                        events.objects.push(ObjectEvent::Modified {
                            folder,
                            message: None,
                            counts: None,
                        });
                        events.all_hierarchy = true;
                    }
                }
                Change::DeleteContainer(id) => {
                    events.all_hierarchy = true;
                    if let Some(node) = folder_node(id).filter(|node| rights.of(*node).is_visible())
                    {
                        events.objects.push(ObjectEvent::Deleted {
                            folder: MapiId::from_node(node),
                            parent: fixed::IPM_SUBTREE,
                        });
                    }
                }
                Change::UpdateContainerPartial(id, partial) if partial.has_properties() => {
                    let Some(node) = folder_node(id)
                        .filter(|node| tree.get(*node).is_some() && rights.of(*node).reads_items())
                    else {
                        continue;
                    };
                    let folder = MapiId::from_node(node);
                    let counts = counters.as_ref().map(|counters| {
                        u32::try_from(id)
                            .ok()
                            .and_then(|id| counters.get(&id))
                            .map_or((0, 0), |counter| {
                                (
                                    u32::try_from(counter.total).unwrap_or(u32::MAX),
                                    u32::try_from(counter.unread).unwrap_or(u32::MAX),
                                )
                            })
                    });
                    events.objects.push(ObjectEvent::Modified {
                        folder,
                        message: None,
                        counts,
                    });
                    events.contents.push(folder.counter());
                }
                Change::InsertItem(id)
                | Change::UpdateItem(id)
                | Change::UpdateItemMetadata(id)
                    if exact =>
                {
                    let id = (id & DOCUMENT_ID_MASK) as u32;
                    let created = matches!(change, Change::InsertItem(_));
                    match &resources {
                        None => {
                            let Some(item) = view
                                .messages
                                .as_ref()
                                .and_then(|messages| messages.email_by_id(&id))
                            else {
                                continue;
                            };
                            let keywords = item.keywords();
                            let new_mail = created && keywords & ((1 << SEEN) | (1 << DRAFT)) == 0;
                            for mailbox in item.mailboxes() {
                                let node = FolderNode::Stored(FolderRef {
                                    kind: FolderKind::Mailbox,
                                    id: mailbox.mailbox_id,
                                });
                                if tree.get(node).is_none() || !rights.of(node).reads_items() {
                                    continue;
                                }
                                let folder = MapiId::from_node(node);
                                let message = MapiId::new(
                                    group.items,
                                    view.email_item(mailbox.mailbox_id, id),
                                );
                                item_event(events, folder, message, created);
                                if new_mail {
                                    events
                                        .objects
                                        .push(ObjectEvent::NewMail { folder, message });
                                }
                            }
                        }
                        Some(resources) => {
                            let Some(node) = resources
                                .any_resource_path_by_id(id)
                                .and_then(|path| path.parent_id())
                                .and_then(|parent| folder_node(u64::from(parent)))
                                .filter(|node| {
                                    tree.get(*node).is_some() && rights.of(*node).reads_items()
                                })
                                .filter(|_| !rights.hides(resources, id))
                            else {
                                continue;
                            };
                            let message = match node {
                                FolderNode::Stored(folder) => view.client_item(folder, id),
                                FolderNode::Special(_) => MapiId::new(group.items, id),
                            };
                            item_event(events, MapiId::from_node(node), message, created);
                        }
                    }
                }
                Change::DeleteItem(_) if exact && group.folders != FolderKind::Mailbox => {
                    events.all_contents = true;
                }
                Change::InsertItem(_)
                | Change::UpdateItem(_)
                | Change::UpdateItemMetadata(_)
                | Change::DeleteItem(_)
                    if !exact =>
                {
                    events.all_contents = true;
                }
                _ => {}
            }
        }
        events.seal();
        Ok(covered)
    }
}

fn item_event(events: &mut GroupEvents, folder: MapiId, message: MapiId, created: bool) {
    events.objects.push(if created {
        ObjectEvent::Created {
            folder,
            message: Some(message),
            parent: folder,
        }
    } else {
        ObjectEvent::Modified {
            folder,
            message: Some(message),
            counts: None,
        }
    });
    events.contents.push(folder.counter());
}

fn push_parent(tree: &FolderTree, parent: FolderNode, events: &mut GroupEvents) {
    events.parents.push(MapiId::from_node(parent).counter());
    let mut node = Some(parent);
    for _ in 0..tree.len() {
        let Some(current) = node else {
            break;
        };
        events.ancestors.push(MapiId::from_node(current).counter());
        node = tree.get(current).and_then(|entry| entry.parent);
    }
}
