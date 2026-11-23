/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, ItemError, MailItem, MailWrite,
    bulk::delete_associated,
    create::{SentFolder, ingest_error},
    edit::{Attempt, EditRound, Edited, commit_edits},
    find::mailbox_of,
    get::Target,
    id_only, mail_allowed, may_write_mailbox,
    send::default_folder,
    transfer::{Destination, transfer_mail},
    writable_mail,
};
use crate::{
    ews::{
        calendar::{
            Events, calendar_of,
            instance::indexed_instance,
            sent::MeetingSend,
            write::{EventScope, delete_send, event_id_only},
        },
        contact::{
            Contacts, address_book_of,
            write::{ContactWriter, contact_id_only},
        },
        context::{EwsCaller, EwsContext},
        folder::{FolderSelector, cross_mailbox_status, resolve_folder, saved_folder_status},
        groupware::{
            GroupwareFields, GroupwareKind,
            items::{GroupwareItems, GroupwareRef},
            write::{CalendarWriter, failure_error},
        },
        reply::{RESPONSE_CAPACITY, ews_response},
        task::{
            Tasks, task_list_of,
            write::{TaskWriter, task_id_only, virtual_task_list},
        },
    },
    folders::{FolderNode, SpecialFolder, access::ItemWrite},
    groupware_move::{GroupwareCopy, GroupwareMove, GroupwareMover, GroupwareRoute, Transfer},
    mail::{FlagEdit, keywords_fit},
    mail_copy::{Copied, CopyOrigin, MailCopier},
};
use ahash::AHashMap;
use common::Server;
use email::cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use exchange_proto::ews::{
    MessageResult, Operation, Status,
    requests::item::{ArchiveItem, DeleteItem, MarkAllItemsAsRead, MarkAsJunk, MoveCopyItem},
    responses::{
        folder::EmptyMessage,
        item::{ItemInfoMessage, MarkAsJunkMessage},
    },
    schema::{DisposalType, ResponseCode},
    types::{
        ids::{BaseItemId, TargetFolderId},
        item::Item,
    },
};
use groupware::calendar::write::ItipMode;
use http_proto::HttpResponse;
use smallvec::SmallVec;
use types::{keyword::Keyword, special_use::SpecialUse};

const NOT_A_MAIL_FOLDER: &str = "Mail items can only be placed in mail folders.";
const NO_ARCHIVE_MAILBOX: &str = "Archive mailboxes are not supported.";

pub(super) type Placed = Result<Option<Item<'static>>, Status<'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    Move,
    Copy,
}

pub(crate) async fn delete_item(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &DeleteItem<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let to_trash = request.delete_type == DisposalType::MoveToDeletedItems;
    let decoded = request
        .item_ids
        .iter()
        .map(|id| (id, Target::with_associated(id)))
        .collect::<Vec<_>>();
    let mut outcomes = vec![Ok(()); decoded.len()];
    for (slot, (_, target)) in outcomes.iter_mut().zip(&decoded) {
        if let Target::Associated(target) = *target {
            *slot = match target {
                Ok(target) => delete_associated(server, ctx, caller, target).await?,
                Err(err) => Err(err),
            };
        }
    }
    if decoded
        .iter()
        .any(|(_, target)| matches!(target, Target::Mail))
    {
        let ids = EmailIds::load(server, ctx).await?;
        let passes = placement_passes(&decoded, |id| ids.decode(ctx, id).ok());
        let last_pass = passes.iter().flatten().copied().max().unwrap_or_default();
        let planned = decoded.iter().zip(&passes).collect::<Vec<_>>();
        for pass in 0..=last_pass {
            let committed = commit_edits(
                server,
                caller,
                account_id,
                &planned,
                |round, ((id, _), item_pass)| {
                    if **item_pass != Some(pass) {
                        return Ok(Ok(Edited::Done));
                    }
                    let item = match ids
                        .decode(ctx, id)
                        .and_then(|item| writable_mail(ctx, round.cache, item, MailWrite::Delete))
                    {
                        Ok(item) => item,
                        Err(err) => return Ok(Err(err)),
                    };
                    let trash_id =
                        match to_trash.then(|| round.cache.mailbox_by_role(&SpecialUse::Trash)) {
                            Some(None) => return Ok(Err(ItemError::NoDeletedItems)),
                            trash => trash
                                .flatten()
                                .map(|mailbox| mailbox.document_id)
                                .filter(|trash_id| *trash_id != item.mailbox_id),
                        };
                    if trash_id.is_some_and(|trash_id| {
                        !may_write_mailbox(ctx, trash_id, ItemWrite::Create)
                    }) {
                        return Ok(Err(ItemError::CannotDelete));
                    }
                    place_or_remove(round, item, trash_id)
                },
            )
            .await?;
            for ((slot, outcome), _) in outcomes
                .iter_mut()
                .zip(committed.outcomes)
                .zip(&passes)
                .filter(|(_, item_pass)| **item_pass == Some(pass))
            {
                *slot = outcome.map(|_| ());
            }
        }
    }
    if decoded
        .iter()
        .any(|(_, target)| matches!(target, Target::Contact(..)))
    {
        let contacts = Contacts::load(server, ctx).await?;
        let writer = match &contacts {
            Ok(contacts) => Ok((contacts, ContactWriter::new(server, caller, contacts))),
            Err(err) => Err(*err),
        };
        for (slot, (account, contact)) in
            outcomes
                .iter_mut()
                .zip(&decoded)
                .filter_map(|(slot, (_, target))| match target {
                    Target::Contact(account, contact) => Some((slot, (*account, *contact))),
                    _ => None,
                })
        {
            *slot = match &writer {
                Ok((contacts, writer)) => match contacts.check(account, contact) {
                    Ok(contact) => writer.delete(contact).await?,
                    Err(err) => Err(err),
                },
                Err(err) => Err(*err),
            };
        }
    }
    if decoded
        .iter()
        .any(|(_, target)| matches!(target, Target::Task(..)))
    {
        let tasks = Tasks::load(server, ctx).await?;
        let writer = match &tasks {
            Ok(tasks) => Ok((tasks, TaskWriter::new(server, caller, tasks))),
            Err(err) => Err(*err),
        };
        for (slot, (account, task)) in
            outcomes
                .iter_mut()
                .zip(&decoded)
                .filter_map(|(slot, (_, target))| match target {
                    Target::Task(account, task) => Some((slot, (*account, *task))),
                    _ => None,
                })
        {
            *slot = match &writer {
                Ok((tasks, writer)) => match tasks.check(account, task) {
                    Ok(task) => writer.delete(task, ItipMode::Suppress).await?,
                    Err(err) => Err(err),
                },
                Err(err) => Err(*err),
            };
        }
    }
    if decoded.iter().any(|(_, target)| {
        matches!(
            target,
            Target::Event(..) | Target::Occurrence(..) | Target::Indexed(..)
        )
    }) {
        let events = Events::load(server, ctx).await?;
        let send = delete_send(request.send_meeting_cancellations);
        let writer = match (&events, send) {
            (_, Err(err)) => Err(err),
            (Err(err), _) => Err(*err),
            (Ok(events), Ok(send)) => {
                Ok((events, CalendarWriter::new(server, caller, events), send))
            }
        };
        let mut sent = SentFolder::new(None);
        for (slot, (_, target)) in outcomes.iter_mut().zip(&decoded) {
            let (account, event, scope) = match *target {
                Target::Event(account, event) => (account, event, EventScope::Master),
                Target::Occurrence(account, event, instance) => {
                    (account, event, EventScope::Instance(instance))
                }
                Target::Indexed(account, event, index) => {
                    (account, event, EventScope::Indexed(index))
                }
                _ => continue,
            };
            *slot = match &writer {
                Ok((events, writer, send)) => match events.check(account, event) {
                    Ok(event) => match writer.delete_event(event, scope, *send).await? {
                        Ok(copies) => {
                            sent.save(server, ctx, caller, copies).await;
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    Err(err) => Err(err),
                },
                Err(err) => Err(*err),
            };
        }
    }

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::DeleteItem);
    for outcome in &outcomes {
        messages.message(&MessageResult::<EmptyMessage> {
            status: match outcome {
                Ok(_) => Status::SUCCESS,
                Err(err) => err.status(),
            },
            body: None,
        });
    }
    messages.finish();
    Ok(ews_response(out))
}

fn placement_passes(
    decoded: &[(&BaseItemId<'_>, Target)],
    decode: impl Fn(&BaseItemId<'_>) -> Option<MailItem>,
) -> Vec<Option<usize>> {
    let mut placements: AHashMap<u32, SmallVec<[u32; 2]>> = AHashMap::new();
    decoded
        .iter()
        .map(|(id, target)| {
            if !matches!(target, Target::Mail) {
                return None;
            }
            let Some(item) = decode(id) else {
                return Some(0);
            };
            let seen = placements.entry(item.document_id).or_default();
            Some(
                match seen.iter().position(|mailbox| *mailbox == item.mailbox_id) {
                    Some(pass) => pass,
                    None => {
                        seen.push(item.mailbox_id);
                        seen.len() - 1
                    }
                },
            )
        })
        .collect()
}

pub(super) async fn file_answered_request(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    item: MailItem,
    send: MeetingSend,
) {
    let answered = FlagEdit {
        answered: Some(true),
        ..Default::default()
    };
    if let Err(err) = commit_edits(
        server,
        caller,
        ctx.account.account_id,
        &[item],
        |round, item| {
            let item = match writable_mail(ctx, round.cache, *item, MailWrite::Read) {
                Ok(item) => item,
                Err(err) => return Ok(Err(err)),
            };
            let marks = writable_mail(ctx, round.cache, item, MailWrite::Edit).is_ok();
            let trash_id = match send {
                MeetingSend::Suppress => None,
                _ => writable_mail(ctx, round.cache, item, MailWrite::Delete)
                    .ok()
                    .and(round.cache.mailbox_by_role(&SpecialUse::Trash))
                    .map(|mailbox| mailbox.document_id)
                    .filter(|trash_id| {
                        *trash_id != item.mailbox_id
                            && may_write_mailbox(ctx, *trash_id, ItemWrite::Create)
                    }),
            };
            let Some(data) = round
                .cache
                .message_data(item.document_id)
                .filter(|data| data.has_mailbox_id(item.mailbox_id))
            else {
                return Ok(Err(ItemError::NotFound));
            };
            if let Err(err) = round.claim(item.document_id) {
                return Ok(Err(err));
            }
            match trash_id {
                Some(trash_id) => {
                    let (added, removed) = answered.diff(data.keywords);
                    let keywords = if marks
                        && keywords_fit(&server.core.email.limits, &data, added, removed)
                    {
                        (added, removed)
                    } else {
                        (0, 0)
                    };
                    round.edits.move_with_keywords(
                        item.document_id,
                        data,
                        (item.mailbox_id, trash_id),
                        keywords,
                        None,
                    )?;
                }
                None if marks => {
                    round.edits.set_flags(
                        &server.core.email.limits,
                        item.document_id,
                        &data,
                        answered,
                    )?;
                }
                None => {}
            }
            Ok(Ok(Edited::Done))
        },
    )
    .await
    {
        trc::error!(err.caused_by(trc::location!()));
    }
}

pub(super) fn place_or_remove(
    round: &mut EditRound<'_>,
    item: MailItem,
    trash_id: Option<u32>,
) -> trc::Result<Result<Edited, ItemError>> {
    let Some(data) = round
        .cache
        .message_data(item.document_id)
        .filter(|data| data.has_mailbox_id(item.mailbox_id))
    else {
        return Ok(
            if round.planned_before(item.document_id)
                && trash_id.is_none_or(|trash_id| {
                    round
                        .cache
                        .email_by_id(&item.document_id)
                        .is_some_and(|message| message.has_mailbox_id(trash_id))
                })
            {
                Ok(Edited::Done)
            } else {
                Err(ItemError::NotFound)
            },
        );
    };
    if let Err(err) = round.claim(item.document_id) {
        return Ok(Err(err));
    }
    let written = match trash_id {
        Some(trash_id) => round
            .edits
            .move_to(item.document_id, data, item.mailbox_id, trash_id)?,
        None => round
            .edits
            .remove_from(item.document_id, data, item.mailbox_id)?,
    };
    Ok(if written {
        Ok(Edited::Done)
    } else {
        Err(ItemError::NotFound)
    })
}

pub(crate) async fn move_copy_item(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &MoveCopyItem<'_>,
    placement: Placement,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let operation = match placement {
        Placement::Move => Operation::MoveItem,
        Placement::Copy => Operation::CopyItem,
    };
    let tree = match Destination::of(server, ctx, &request.to_folder_id).await? {
        Destination::Other(destination) => {
            let placed = Box::pin(transfer_mail(
                server,
                ctx,
                caller,
                &destination,
                &request.to_folder_id,
                &request.item_ids,
                placement,
            ))
            .await?;
            return Ok(placed_response(ctx, operation, placed, false));
        }
        Destination::Refused => None,
        Destination::Same => Some(ctx.folder_tree(server).await?),
    };
    let resolved = match &tree {
        Some(tree) => {
            resolve_folder(
                server,
                ctx,
                tree,
                FolderSelector::from(&request.to_folder_id),
            )
            .await?
        }
        None => Err(cross_mailbox_status()),
    };
    let entry = match resolved {
        Ok(entry) => entry,
        Err(status) => {
            let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
            let mut messages = ctx.envelope(&mut out).shape_a(operation);
            for _ in &request.item_ids {
                messages.message(&MessageResult::<ItemInfoMessage> {
                    status: status.clone(),
                    body: None,
                });
            }
            messages.finish();
            return Ok(ews_response(out));
        }
    };
    let decoded = request
        .item_ids
        .iter()
        .map(|id| (id, Target::of(id)))
        .collect::<Vec<_>>();
    let mut placed: Vec<Placed> = vec![Ok(None); decoded.len()];
    if decoded
        .iter()
        .any(|(_, target)| matches!(target, Target::Mail))
    {
        match mailbox_of(entry.node) {
            Some(to) if placement == Placement::Copy => {
                if may_write_mailbox(ctx, to, ItemWrite::Create) {
                    copy_mail(server, ctx, caller, &decoded, &mut placed, to).await?;
                } else {
                    for (slot, _) in placed
                        .iter_mut()
                        .zip(&decoded)
                        .filter(|(_, (_, target))| matches!(target, Target::Mail))
                    {
                        *slot = Err(ItemError::Forbidden.status());
                    }
                }
            }
            Some(to) => {
                let ids = EmailIds::load(server, ctx).await?;
                let committed = commit_edits(
                    server,
                    caller,
                    account_id,
                    &decoded,
                    |round, (id, target)| {
                        if !matches!(target, Target::Mail) {
                            return Ok(Ok(Edited::Done));
                        }
                        move_mail(round, ctx, &ids, id, to)
                    },
                )
                .await?;
                for ((slot, (_, target)), outcome) in
                    placed.iter_mut().zip(&decoded).zip(&committed.outcomes)
                {
                    if matches!(target, Target::Mail) {
                        *slot = outcome
                            .map(|edited| {
                                committed
                                    .change_id_of(edited)
                                    .map(|(item, change_id)| id_only(ids.item_id(item, change_id)))
                            })
                            .map_err(ItemError::status);
                    }
                }
            }
            None => {
                for (slot, _) in placed
                    .iter_mut()
                    .zip(&decoded)
                    .filter(|(_, (_, target))| matches!(target, Target::Mail))
                {
                    *slot = Err(not_a_mail_folder());
                }
            }
        }
    }
    if decoded
        .iter()
        .any(|(_, target)| matches!(target, Target::Contact(..)))
    {
        let contacts = Contacts::load(server, ctx).await?;
        let to = address_book_of(entry.node).ok_or_else(|| ItemError::GroupwareFolder.status());
        place_groupware(
            server,
            caller,
            &contacts,
            to,
            placement,
            placed
                .iter_mut()
                .zip(&decoded)
                .filter_map(|(slot, (_, target))| match target {
                    Target::Contact(account, contact) => Some((slot, *account, *contact)),
                    _ => None,
                }),
        )
        .await?;
    }
    if decoded
        .iter()
        .any(|(_, target)| matches!(target, Target::Task(..)))
    {
        let tasks = Tasks::load(server, ctx).await?;
        let to = match task_list_of(entry) {
            Some(to) => Ok(to),
            None if entry.node == FolderNode::Special(SpecialFolder::Tasks) => {
                virtual_task_list(server, ctx, caller).await?
            }
            None => Err(ItemError::GroupwareFolder.status()),
        };
        place_groupware(
            server,
            caller,
            &tasks,
            to,
            placement,
            placed
                .iter_mut()
                .zip(&decoded)
                .filter_map(|(slot, (_, target))| match target {
                    Target::Task(account, task) => Some((slot, *account, *task)),
                    _ => None,
                }),
        )
        .await?;
    }
    if decoded.iter().any(|(_, target)| {
        matches!(
            target,
            Target::Event(..) | Target::Occurrence(..) | Target::Indexed(..)
        )
    }) {
        let events = Events::load(server, ctx).await?;
        for (slot, (_, target)) in placed.iter_mut().zip(&decoded) {
            let refused = match (target, &events) {
                (Target::Indexed(account, event, index), Ok(events)) => {
                    match events.check(*account, *event) {
                        Ok(event) => match events.load_ical(server, event).await? {
                            Ok((ical, _))
                                if matches!(
                                    indexed_instance(&ical, *index),
                                    Err(ItemError::NotRecurringMaster)
                                ) =>
                            {
                                ItemError::NotRecurringMaster
                            }
                            _ => ItemError::OccurrenceMoveCopy,
                        },
                        Err(_) => ItemError::OccurrenceMoveCopy,
                    }
                }
                (Target::Occurrence(..) | Target::Indexed(..), _) => ItemError::OccurrenceMoveCopy,
                _ => continue,
            };
            *slot = Err(refused.status());
        }
        let to = calendar_of(entry).ok_or_else(|| ItemError::GroupwareFolder.status());
        place_groupware(
            server,
            caller,
            &events,
            to,
            placement,
            placed
                .iter_mut()
                .zip(&decoded)
                .filter_map(|(slot, (_, target))| match target {
                    Target::Event(account, event) => Some((slot, *account, *event)),
                    _ => None,
                }),
        )
        .await?;
    }

    Ok(placed_response(
        ctx,
        operation,
        placed,
        request.return_new_item_ids != Some(false),
    ))
}

fn placed_response(
    ctx: &EwsContext,
    operation: Operation,
    placed: Vec<Placed>,
    return_ids: bool,
) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(operation);
    for outcome in placed {
        match outcome {
            Ok(item) => messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(ItemInfoMessage {
                    items: item.filter(|_| return_ids).into_iter().collect(),
                }),
            }),
            Err(status) => {
                messages.message(&MessageResult::<ItemInfoMessage> { status, body: None })
            }
        }
    }
    messages.finish();
    ews_response(out)
}

async fn copy_mail(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    decoded: &[(&BaseItemId<'_>, Target)],
    placed: &mut [Placed],
    to: u32,
) -> trc::Result<()> {
    let account_id = ctx.account.account_id;
    let ids = EmailIds::load(server, ctx).await?;
    let cache = server.get_cached_messages(account_id).await?;
    let mut copier = MailCopier::new(
        server,
        caller.access_token,
        account_id,
        caller.session.session_id,
    )
    .await?;
    let session_id = caller.session.session_id;
    for (slot, (id, target)) in decoded.iter().enumerate() {
        if !matches!(target, Target::Mail) {
            continue;
        }
        match ids
            .decode(ctx, id)
            .and_then(|item| writable_mail(ctx, &cache, item, MailWrite::Read))
        {
            Ok(item) => {
                let origin = CopyOrigin {
                    document_id: item.document_id,
                    from: item.mailbox_id,
                };
                copier.copy(&cache, origin, to, slot).await;
            }
            Err(err) => {
                if let Some(placed) = placed.get_mut(slot) {
                    *placed = Err(err.status());
                }
            }
        }
        place_copies(placed, &ids, to, session_id, copier.settled());
    }
    copier.finish(&cache).await;
    place_copies(placed, &ids, to, session_id, copier.settled());
    Ok(())
}

fn place_copies(
    placed: &mut [Placed],
    ids: &EmailIds,
    to: u32,
    session_id: u64,
    copies: impl Iterator<Item = (usize, Copied)>,
) {
    for (slot, copied) in copies {
        let Some(placed) = placed.get_mut(slot) else {
            continue;
        };
        *placed = match copied {
            Copied::Created {
                document_id,
                change_id,
            } => Ok(Some(id_only(ids.item_id(
                MailItem {
                    mailbox_id: to,
                    document_id,
                },
                change_id,
            )))),
            Copied::NotFound => Err(ItemError::NotFound.status()),
            Copied::OverQuota => Err(ItemError::Quota.status()),
            Copied::CommitFailed => Err(ItemError::MoveCopyFailed.status()),
            Copied::Rejected(err) | Copied::Failed(err) => Err(ingest_error(err)
                .unwrap_or_else(|err| {
                    trc::error!(err.caused_by(trc::location!()).span_id(session_id));
                    ItemError::MoveCopyFailed
                })
                .status()),
        };
    }
}

async fn place_groupware<'p, F: GroupwareFields>(
    server: &Server,
    caller: EwsCaller<'_>,
    items: &Result<GroupwareItems<F>, ItemError>,
    to: Result<u32, Status<'static>>,
    placement: Placement,
    targets: impl Iterator<Item = (&'p mut Placed, u32, GroupwareRef)>,
) -> trc::Result<()> {
    let (items, to) = match (items, to) {
        (Ok(items), Ok(to)) => (items, to),
        (Err(err), _) => {
            for (slot, ..) in targets {
                *slot = Err(err.status());
            }
            return Ok(());
        }
        (Ok(_), Err(status)) => {
            for (slot, ..) in targets {
                *slot = Err(status.clone());
            }
            return Ok(());
        }
    };
    let mut checked = targets
        .filter_map(|(slot, account, item)| match items.check(account, item) {
            Ok(item) => Some((slot, item)),
            Err(err) => {
                *slot = Err(err.status());
                None
            }
        })
        .collect::<Vec<_>>();
    checked.sort_unstable_by_key(|(_, item)| item.container);
    let transfer = match placement {
        Placement::Move => Transfer::Move,
        Placement::Copy => Transfer::Copy,
    };
    let placed_id = |document_id, change_id: Option<u64>| {
        let item = GroupwareRef {
            container: to,
            document_id,
        };
        let id = match change_id {
            Some(change_id) => items.item_id(item, change_id),
            None => items.unversioned_id(item),
        };
        match F::KIND {
            GroupwareKind::Contact => contact_id_only(id),
            GroupwareKind::Task => task_id_only(id),
            GroupwareKind::Event => event_id_only(id),
        }
    };
    let mut mover: Option<(u32, Option<GroupwareMover<'_>>)> = None;
    for (slot, item) in checked {
        if placement == Placement::Move && item.container == to {
            *slot = Ok(Some(placed_id(item.document_id, None)));
            continue;
        }
        if mover
            .as_ref()
            .is_none_or(|(from, _)| *from != item.container)
        {
            mover = Some((
                item.container,
                GroupwareMover::open(
                    server,
                    caller.access_token,
                    items.account_id,
                    match F::KIND {
                        GroupwareKind::Contact => GroupwareRoute::Cards {
                            from: item.container,
                            to,
                        },
                        GroupwareKind::Task | GroupwareKind::Event => GroupwareRoute::Events {
                            from: item.container,
                            to,
                        },
                    },
                    transfer,
                )
                .await?,
            ));
        }
        let Some((_, Some(mover))) = &mut mover else {
            *slot = Err(ItemError::AccessDenied.status());
            continue;
        };
        *slot = match placement {
            Placement::Move => match mover.move_item(item.document_id).await? {
                GroupwareMove::Moved { change_id } => {
                    Ok(Some(placed_id(item.document_id, change_id)))
                }
                GroupwareMove::Refused(failure) => Err(failure_error(failure).status()),
            },
            Placement::Copy => match mover.copy_item(item.document_id).await? {
                GroupwareCopy::Copied {
                    document_id,
                    change_id,
                } => Ok(Some(placed_id(document_id, change_id))),
                GroupwareCopy::Refused(failure) => Err(failure_error(failure).status()),
            },
        };
    }
    Ok(())
}

fn move_mail(
    round: &mut EditRound<'_>,
    ctx: &EwsContext,
    ids: &EmailIds,
    id: &BaseItemId<'_>,
    to: u32,
) -> trc::Result<Result<Edited, ItemError>> {
    let item = match ids
        .decode(ctx, id)
        .and_then(|item| writable_mail(ctx, round.cache, item, MailWrite::Move))
    {
        Ok(item) => item,
        Err(err) => return Ok(Err(err)),
    };
    if !may_write_mailbox(ctx, to, ItemWrite::Create) {
        return Ok(Err(ItemError::Forbidden));
    }
    let placed = MailItem {
        mailbox_id: to,
        document_id: item.document_id,
    };
    let Some(data) = round.cache.message_data(item.document_id).filter(|data| {
        data.has_mailbox_id(item.mailbox_id) || round.planned_before(item.document_id)
    }) else {
        return Ok(Err(ItemError::NotFound));
    };
    if let Err(err) = round.claim(item.document_id) {
        return Ok(Err(err));
    }
    let change_id = data.change_id;
    if item.mailbox_id == to {
        return Ok(Ok(Edited::Unchanged(placed, change_id)));
    }
    let in_destination = data.has_mailbox_id(to);
    Ok(
        if round
            .edits
            .move_to(item.document_id, data, item.mailbox_id, to)?
        {
            Ok(Edited::Written(placed))
        } else if round.attempt == Attempt::Retry && in_destination {
            Ok(Edited::Unchanged(placed, change_id))
        } else {
            Err(ItemError::NotFound)
        },
    )
}

pub(crate) async fn mark_as_junk(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &MarkAsJunk<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    if !ctx.targets_caller() {
        let mut messages = ctx.envelope(&mut out).shape_a(Operation::MarkAsJunk);
        for _ in &request.item_ids {
            messages.message(&MessageResult::<MarkAsJunkMessage> {
                status: ItemError::Forbidden.status(),
                body: None,
            });
        }
        messages.finish();
        return Ok(ews_response(out));
    }
    let destination = if request.move_item {
        let role = if request.is_junk {
            SpecialUse::Junk
        } else {
            SpecialUse::Inbox
        };
        match default_folder(server, account_id, role).await? {
            Ok(to) => Some(to),
            Err(status) => {
                let mut messages = ctx.envelope(&mut out).shape_a(Operation::MarkAsJunk);
                for _ in &request.item_ids {
                    messages.message(&MessageResult::<MarkAsJunkMessage> {
                        status: status.clone(),
                        body: None,
                    });
                }
                messages.finish();
                return Ok(ews_response(out));
            }
        }
    } else {
        None
    };
    let ids = EmailIds::load(server, ctx).await?;
    let committed = commit_edits(
        server,
        caller,
        account_id,
        &request.item_ids,
        |round, id| match destination {
            Some(to) => move_mail(round, ctx, &ids, id, to),
            None => Ok(ids.resolve(ctx, round.cache, id).map(|_| Edited::Done)),
        },
    )
    .await?;

    let mut messages = ctx.envelope(&mut out).shape_a(Operation::MarkAsJunk);
    for outcome in &committed.outcomes {
        match outcome.map(|edited| committed.change_id_of(edited)) {
            Ok(placed) => messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(MarkAsJunkMessage {
                    moved_item_id: placed.map(|(item, change_id)| ids.item_id(item, change_id)),
                }),
            }),
            Err(err) => messages.message(&MessageResult::<MarkAsJunkMessage> {
                status: err.status(),
                body: None,
            }),
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

pub(crate) fn archive_item(ctx: &EwsContext, request: &ArchiveItem<'_>) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let status = Status::error(
        ResponseCode::ErrorArchiveMailboxNotEnabled,
        NO_ARCHIVE_MAILBOX,
    );
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::ArchiveItem);
    for _ in &request.item_ids {
        messages.message(&MessageResult::<ItemInfoMessage> {
            status: status.clone(),
            body: None,
        });
    }
    messages.finish();
    ews_response(out)
}

pub(crate) async fn mark_all_items_as_read(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &MarkAllItemsAsRead<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let tree = ctx.folder_tree(server).await?;
    let mut folders = Vec::with_capacity(request.folder_ids.len());
    for id in &request.folder_ids {
        folders.push(
            match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
                Ok(entry) => match (mailbox_of(entry.node), mail_allowed(ctx)) {
                    (Some(mailbox_id), Ok(())) => Ok(Some(mailbox_id)),
                    (Some(_), Err(err)) => Err(err.status()),
                    (None, _) => Ok(None),
                },
                Err(status) => Err(status),
            },
        );
    }
    let edit = FlagEdit {
        read: Some(request.read_flag),
        ..Default::default()
    };
    let limits = &server.core.email.limits;
    let committed = commit_edits(server, caller, account_id, &folders, |round, folder| {
        let Ok(Some(mailbox_id)) = folder else {
            return Ok(Ok(Edited::Done));
        };
        if !may_write_mailbox(ctx, *mailbox_id, ItemWrite::ReadState) {
            return Ok(Err(ItemError::Forbidden));
        }
        let cache = round.cache;
        for message in cache
            .in_mailbox(*mailbox_id)
            .filter(|message| cache.has_keyword(*message, &Keyword::Seen) != request.read_flag)
        {
            let document_id = message.document_id();
            let item = MailItem {
                mailbox_id: *mailbox_id,
                document_id,
            };
            if writable_mail(ctx, cache, item, MailWrite::ReadState).is_err()
                || round.claim(document_id).is_err()
            {
                continue;
            }
            if let Some(data) = cache.message_data(document_id) {
                round.edits.set_flags(limits, document_id, &data, edit)?;
            }
        }
        Ok(Ok(Edited::Done))
    })
    .await?;

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx
        .envelope(&mut out)
        .shape_a(Operation::MarkAllItemsAsRead);
    for (folder, outcome) in folders.iter().zip(&committed.outcomes) {
        let status = match (folder, outcome) {
            (Err(status), _) => status.clone(),
            (Ok(_), Err(err)) => err.status(),
            (Ok(_), Ok(_)) => Status::SUCCESS,
        };
        messages.message(&MessageResult::<EmptyMessage> { status, body: None });
    }
    messages.finish();
    Ok(ews_response(out))
}

pub(super) async fn saved_destination(
    server: &Server,
    ctx: &EwsContext,
    id: &TargetFolderId<'_>,
) -> trc::Result<Result<u32, Status<'static>>> {
    Ok(match destination(server, ctx, id).await? {
        Ok(mailbox_id) if may_write_mailbox(ctx, mailbox_id, ItemWrite::Create) => Ok(mailbox_id),
        Ok(_) => Err(ItemError::Forbidden.status()),
        Err(status) => Err(saved_folder_status(ctx, status)),
    })
}

pub(super) async fn destination(
    server: &Server,
    ctx: &EwsContext,
    id: &TargetFolderId<'_>,
) -> trc::Result<Result<u32, Status<'static>>> {
    let tree = ctx.folder_tree(server).await?;
    Ok(
        match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => mailbox_of(entry.node).ok_or_else(not_a_mail_folder),
            Err(status) => Err(status),
        },
    )
}

fn not_a_mail_folder() -> Status<'static> {
    Status::error(ResponseCode::ErrorMoveCopyFailed, NOT_A_MAIL_FOLDER)
}
