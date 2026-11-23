/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, ItemError, MailItem,
    fields::ShapeUse,
    mail_allowed,
    render::{DisplayNames, LoadedMail, MailShape, MailView, render},
};
use crate::{
    ews::{
        calendar::Events,
        contact::{
            Contacts,
            sync::{logged_changes, plan as groupware_plan},
        },
        context::EwsContext,
        folder::{FolderSelector, resolve_folder},
        groupware::{
            GroupwareFields,
            items::{GroupwareItems, GroupwareRef},
        },
        reply::{RESPONSE_CAPACITY, ews_response},
        task::Tasks,
    },
    folders::{ContainerClass, FolderEntry, FolderNode},
    store::{FolderKind, FolderRef},
};
use common::Server;
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use exchange_proto::{
    ews::{
        MessageResult, Operation, Status,
        requests::sync::SyncFolderItems,
        responses::sync::{SyncChange, SyncFolderItemsMessage},
        schema::ResponseCode,
        types::{shape::ItemShape, value::M},
    },
    ids::{
        ews::{EwsItemsState, EwsObjectId},
        token::ObjectKind,
    },
    xml::XmlWriter,
};
use http_proto::HttpResponse;
use store::roaring::RoaringBitmap;

const INVALID_STATE: &str = "Synchronization state data is corrupt or otherwise invalid.";
const NOT_SYNCABLE: &str = "Items in this folder cannot be synchronized.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncSource {
    Mailbox(u32),
    AddressBook(u32),
    TaskList(u32),
    Calendar(u32),
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncError {
    Item(ItemError),
    NotSyncable,
    InvalidState,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SyncWindow {
    pub deletes: Vec<u32>,
    pub updates: Vec<u32>,
    pub creates: Vec<u32>,
    pub last: bool,
}

pub(crate) async fn sync_folder_items(
    server: &Server,
    ctx: &EwsContext,
    request: &SyncFolderItems<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let tree = ctx.folder_tree(server).await?;
    let prepared = match resolve_folder(server, ctx, &tree, FolderSelector::from(&request.folder))
        .await?
    {
        Ok(entry) if !ctx.access.of(entry.node).reads_items() => Err(ItemError::Forbidden.status()),
        Ok(entry) => prepare(ctx, entry, request.state.as_deref()).map_err(SyncError::status),
        Err(status) => Err(status),
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::SyncFolderItems);
    let (source, mut state) = match prepared {
        Ok(prepared) => prepared,
        Err(status) => {
            messages.message(&MessageResult::<SyncFolderItemsMessage> { status, body: None });
            messages.finish();
            return Ok(ews_response(out));
        }
    };
    let contacts = match source {
        SyncSource::AddressBook(_) => match Contacts::load(server, ctx).await? {
            Ok(contacts) => Some(contacts),
            Err(err) => {
                messages.message(&MessageResult::<SyncFolderItemsMessage> {
                    status: err.status(),
                    body: None,
                });
                messages.finish();
                return Ok(ews_response(out));
            }
        },
        SyncSource::Mailbox(_)
        | SyncSource::TaskList(_)
        | SyncSource::Calendar(_)
        | SyncSource::Empty => None,
    };
    let tasks = match source {
        SyncSource::TaskList(_) => match Tasks::load(server, ctx).await? {
            Ok(tasks) => Some(tasks),
            Err(err) => {
                messages.message(&MessageResult::<SyncFolderItemsMessage> {
                    status: err.status(),
                    body: None,
                });
                messages.finish();
                return Ok(ews_response(out));
            }
        },
        SyncSource::Mailbox(_)
        | SyncSource::AddressBook(_)
        | SyncSource::Calendar(_)
        | SyncSource::Empty => None,
    };
    let events = match source {
        SyncSource::Calendar(_) => match Events::load(server, ctx).await? {
            Ok(events) => Some(events),
            Err(err) => {
                messages.message(&MessageResult::<SyncFolderItemsMessage> {
                    status: err.status(),
                    body: None,
                });
                messages.finish();
                return Ok(ews_response(out));
            }
        },
        SyncSource::Mailbox(_)
        | SyncSource::AddressBook(_)
        | SyncSource::TaskList(_)
        | SyncSource::Empty => None,
    };
    let cache = server.get_cached_messages(account_id).await?;
    let ids = EmailIds::load(server, ctx).await?;
    let window = match (source, &contacts, &tasks, &events) {
        (SyncSource::AddressBook(address_book), Some(contacts), ..) => {
            groupware_window(server, ctx, contacts, address_book, &mut state, request).await?
        }
        (SyncSource::TaskList(task_list), _, Some(tasks), _) => {
            groupware_window(server, ctx, tasks, task_list, &mut state, request).await?
        }
        (SyncSource::Calendar(calendar), .., Some(events)) => {
            groupware_window(server, ctx, events, calendar, &mut state, request).await?
        }
        (SyncSource::Mailbox(mailbox_id), ..) => {
            let ignored = ignored(ctx, ObjectKind::Email, mailbox_id, request);
            plan(
                cache.in_mailbox(mailbox_id).map(|message| {
                    (
                        ids.identity(MailItem {
                            mailbox_id,
                            document_id: message.document_id(),
                        }),
                        message.change_id(),
                    )
                }),
                &mut state,
                usize::from(request.max_changes),
                &ignored,
            )
        }
        (
            SyncSource::AddressBook(_)
            | SyncSource::TaskList(_)
            | SyncSource::Calendar(_)
            | SyncSource::Empty,
            ..,
        ) => SyncWindow {
            last: true,
            ..Default::default()
        },
    };
    state.held.optimize();
    let Some(encoded) = state.encode() else {
        messages.message(&MessageResult::<SyncFolderItemsMessage> {
            status: SyncError::InvalidState.status(),
            body: None,
        });
        messages.finish();
        return Ok(ews_response(out));
    };

    let mut shape = MailShape::new(&request.shape, ShapeUse::List);
    if matches!(source, SyncSource::Mailbox(_)) {
        shape.load_receiver(server, account_id).await?;
    }
    let mut body = messages.begin_message(&Status::SUCCESS);
    let w = body.writer();
    w.leaf(M, "SyncState", &encoded);
    w.leaf_bool(M, "IncludesLastItemInRange", window.last);
    w.start(M, "Changes");
    if let (SyncSource::AddressBook(address_book), Some(contacts)) = (source, &contacts) {
        write_groupware_changes(server, contacts, address_book, &window, &request.shape, w).await?;
    }
    if let (SyncSource::TaskList(task_list), Some(tasks)) = (source, &tasks) {
        write_groupware_changes(server, tasks, task_list, &window, &request.shape, w).await?;
    }
    if let (SyncSource::Calendar(calendar), Some(events)) = (source, &events) {
        write_groupware_changes(server, events, calendar, &window, &request.shape, w).await?;
    }
    if let SyncSource::Mailbox(mailbox_id) = source {
        for &identity in &window.deletes {
            SyncChange::Delete(ids.deleted_id(mailbox_id, identity)).write(w);
        }
        let mut flags = shape
            .stored_flags(
                server,
                account_id,
                ids.exchange(),
                window
                    .updates
                    .iter()
                    .chain(&window.creates)
                    .map(|&identity| ids.current(mailbox_id, identity).document_id),
            )
            .await?;
        for (identities, created) in [(&window.updates, false), (&window.creates, true)] {
            for &identity in identities {
                let item = ids.current(mailbox_id, identity);
                let Some(mut mail) =
                    LoadedMail::load(server, account_id, &cache, item, &shape).await?
                else {
                    continue;
                };
                mail.take_flags(&mut flags);
                let headers = mail.headers()?;
                let view = MailView::new(&mail, &headers, false)?;
                let item = render(&shape, &ids, &mail, &view, DisplayNames::Header);
                if created {
                    SyncChange::Create(item).write(w);
                } else {
                    SyncChange::Update(item).write(w);
                }
            }
        }
    }
    w.end(M, "Changes");
    body.finish();
    messages.finish();
    Ok(ews_response(out))
}

async fn groupware_window<F: GroupwareFields>(
    server: &Server,
    ctx: &EwsContext,
    items: &GroupwareItems<F>,
    container: u32,
    state: &mut EwsItemsState,
    request: &SyncFolderItems<'_>,
) -> trc::Result<SyncWindow> {
    let members = items.listed(server, container, &state.held).await?;
    let (changed, last) =
        logged_changes(server, items.account_id, state, F::KIND.sync_collection()).await?;
    Ok(groupware_plan(
        &members,
        changed,
        last,
        state,
        usize::from(request.max_changes),
        &ignored(ctx, F::KIND.object_kind(), container, request),
    ))
}

async fn write_groupware_changes<F: GroupwareFields>(
    server: &Server,
    items: &GroupwareItems<F>,
    container: u32,
    window: &SyncWindow,
    shape: &ItemShape<'_>,
    w: &mut XmlWriter<'_>,
) -> trc::Result<()> {
    let fields = F::from_shape(shape).for_list();
    let item = |document_id| GroupwareRef {
        container,
        document_id,
    };
    for &document_id in &window.deletes {
        SyncChange::Delete(items.unversioned_id(item(document_id))).write(w);
    }
    let mut refs = Vec::with_capacity(window.updates.len().max(window.creates.len()));
    for (documents, created) in [(&window.updates, false), (&window.creates, true)] {
        refs.clear();
        refs.extend(documents.iter().map(|&document_id| item(document_id)));
        let loaded = items.load_many(server, &refs, fields).await?;
        let mut pending = loaded.iter().peekable();
        for &item in &refs {
            match pending.next_if(|loaded| loaded.item == item) {
                Some(loaded) if created => {
                    SyncChange::Create(items.render(loaded, fields)).write(w)
                }
                Some(loaded) => SyncChange::Update(items.render(loaded, fields)).write(w),
                None if created => {}
                None => SyncChange::Delete(items.unversioned_id(item)).write(w),
            }
        }
    }
    Ok(())
}

fn prepare(
    ctx: &EwsContext,
    entry: &FolderEntry,
    state: Option<&str>,
) -> Result<(SyncSource, EwsItemsState), SyncError> {
    let node = entry.node;
    let source = match node {
        FolderNode::Stored(FolderRef {
            kind: FolderKind::Mailbox,
            id,
        }) => {
            mail_allowed(ctx).map_err(SyncError::Item)?;
            SyncSource::Mailbox(id)
        }
        FolderNode::Stored(FolderRef {
            kind: FolderKind::AddressBook,
            id,
        }) => SyncSource::AddressBook(id),
        FolderNode::Stored(FolderRef {
            kind: FolderKind::Calendar,
            id,
        }) if matches!(entry.class, ContainerClass::Task) => SyncSource::TaskList(id),
        FolderNode::Stored(FolderRef {
            kind: FolderKind::Calendar,
            id,
        }) if matches!(entry.class, ContainerClass::Appointment) => SyncSource::Calendar(id),
        _ => SyncSource::Empty,
    };
    let Some((kind, container)) = node.object_id() else {
        return Err(SyncError::NotSyncable);
    };
    let state = match state.filter(|state| !state.is_empty()) {
        None => EwsItemsState {
            container,
            kind,
            change_id: 0,
            after: u32::MAX,
            pinned: 0,
            held: RoaringBitmap::new(),
        },
        Some(text) => match EwsItemsState::decode(text) {
            Some(state) if state.container == container && state.kind == kind => state,
            _ => return Err(SyncError::InvalidState),
        },
    };
    Ok((source, state))
}

pub(crate) fn plan(
    current: impl Iterator<Item = (u32, u64)>,
    state: &mut EwsItemsState,
    max_changes: usize,
    ignored: &RoaringBitmap,
) -> SyncWindow {
    let mut members = RoaringBitmap::new();
    let mut updates = Vec::new();
    let mut newest = state.change_id;
    for (document_id, change_id) in current {
        members.insert(document_id);
        newest = newest.max(change_id);
        if (change_id, document_id) > (state.change_id, state.after)
            && state.held.contains(document_id)
        {
            updates.push((change_id, document_id));
        }
    }
    updates.sort_unstable();
    let deleted = &state.held - &members;
    let created = &members - &state.held;

    let mut window = SyncWindow::default();
    let mut budget = max_changes;
    for document_id in &deleted {
        if budget == 0 {
            return window;
        }
        state.held.remove(document_id);
        if !ignored.contains(document_id) {
            window.deletes.push(document_id);
            budget -= 1;
        }
    }
    for &(change_id, document_id) in &updates {
        if !ignored.contains(document_id) {
            if budget == 0 {
                return window;
            }
            window.updates.push(document_id);
            budget -= 1;
        }
        state.change_id = change_id;
        state.after = document_id;
    }
    state.change_id = newest;
    state.after = u32::MAX;
    for document_id in &created {
        if budget == 0 {
            return window;
        }
        state.held.insert(document_id);
        if !ignored.contains(document_id) {
            window.creates.push(document_id);
            budget -= 1;
        }
    }
    window.last = true;
    window
}

fn ignored(
    ctx: &EwsContext,
    kind: ObjectKind,
    folder: u32,
    request: &SyncFolderItems<'_>,
) -> RoaringBitmap {
    request
        .ignore
        .iter()
        .flatten()
        .filter_map(|id| match EwsObjectId::decode(id.id.as_str()) {
            Some(EwsObjectId::Item {
                account,
                kind: item_kind,
                container,
                id,
            }) if account == ctx.account.account_id && item_kind == kind && container == folder => {
                Some(id)
            }
            _ => None,
        })
        .collect()
}

impl SyncError {
    fn status(self) -> Status<'static> {
        match self {
            SyncError::Item(err) => err.status(),
            SyncError::NotSyncable => {
                Status::error(ResponseCode::ErrorInvalidOperation, NOT_SYNCABLE)
            }
            SyncError::InvalidState => {
                Status::error(ResponseCode::ErrorInvalidSyncStateData, INVALID_STATE)
            }
        }
    }
}
