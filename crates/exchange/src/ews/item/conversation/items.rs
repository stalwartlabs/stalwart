/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    eas::convert::flag::StoredFlags,
    ews::{
        context::EwsContext,
        folder::{FolderSelector, resolve_folder},
        item::{
            EmailIds, ItemError, MailItem,
            fields::ShapeUse,
            find::mailbox_of,
            get::{MailRender, render_mail},
            reads_mailbox,
            render::{LoadedMail, MailShape, MailView},
        },
        reply::{RESPONSE_CAPACITY, ews_response},
    },
};
use ahash::AHashMap;
use common::{Server, cache::email::MessageRef};
use email::cache::MessageCacheFetch;
use exchange_proto::ews::{
    MessageResult, Operation, Status,
    envelope::MessagesWriter,
    requests::conversation::GetConversationItems,
    responses::folder::EmptyMessage,
    schema::{ConversationNodeSortOrder, MailboxSearchLocation, ResponseCode},
    types::value::{EwsValue, M, T},
};
use http_proto::HttpResponse;
use smallvec::SmallVec;
use std::cmp::Reverse;

const MAX_ITEMS: usize = 1000;
const BUDGET_EXCEEDED: &str = "The request reads more than 1000 conversation items.";

struct NodeKey {
    message_id: Option<Box<str>>,
    parent_id: Option<Box<str>>,
    received: u64,
}

type Member<'k> = (Option<&'k str>, u64, usize);

struct Node<'k> {
    members: &'k [Member<'k>],
    message_id: Option<&'k str>,
    in_reply_to: Option<&'k str>,
    parent: Option<usize>,
    received: u64,
}

pub(crate) async fn get_conversation_items(
    server: &Server,
    ctx: &EwsContext,
    request: &GetConversationItems<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let ids = EmailIds::load(server, ctx).await?;
    let cache = server.get_cached_messages(account_id).await?;
    let ignored = ignored_mailboxes(server, ctx, request).await?;
    let mut shape = MailShape::new(&request.shape, ShapeUse::Get);
    shape.load_receiver(server, account_id).await?;
    let probe = MailShape::metadata_only();
    let limit = request
        .max_items_to_return
        .and_then(|max| usize::try_from(max).ok())
        .filter(|max| *max > 0)
        .map_or(MAX_ITEMS, |max| max.min(MAX_ITEMS));
    let order = request
        .sort_order
        .unwrap_or(ConversationNodeSortOrder::TreeOrderDescending);
    let archive_only = request.mailbox_scope == Some(MailboxSearchLocation::ArchiveOnly);
    let mut state = MailRender::default();
    let mut loads = MAX_ITEMS;
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx
        .envelope(&mut out)
        .shape_a(Operation::GetConversationItems);
    let decoded = request
        .conversations
        .iter()
        .map(|conversation| ids.decode_conversation(ctx, &conversation.conversation_id))
        .collect::<Vec<_>>();
    let mut threads = AHashMap::<u32, Vec<MessageRef<'_>>>::new();
    if !archive_only && ignored.is_ok() {
        threads.extend(decoded.iter().flatten().map(|thread| (*thread, Vec::new())));
    }
    if !threads.is_empty() {
        for message in cache.emails.iter() {
            if let Some(bucket) = threads.get_mut(&message.thread_id()) {
                bucket.push(message);
            }
        }
    }
    for thread in decoded {
        let (thread, ignored) = match (thread, &ignored) {
            (_, Err(status)) => {
                messages.message(&MessageResult::<EmptyMessage> {
                    status: status.clone(),
                    body: None,
                });
                continue;
            }
            (Err(err), _) => {
                messages.message(&MessageResult::<EmptyMessage> {
                    status: err.status(),
                    body: None,
                });
                continue;
            }
            (Ok(_), _) if loads == 0 => {
                messages.message(&MessageResult::<EmptyMessage> {
                    status: Status::error(
                        ResponseCode::ErrorExceededFindCountLimit,
                        BUDGET_EXCEEDED,
                    ),
                    body: None,
                });
                continue;
            }
            (Ok(thread), Ok(ignored)) if !archive_only => (thread, ignored),
            (Ok(_), Ok(_)) => {
                not_found(&mut messages);
                continue;
            }
        };
        let mut candidates = threads
            .get(&thread)
            .into_iter()
            .flatten()
            .flat_map(|message| {
                message
                    .mailboxes()
                    .iter()
                    .filter(move |mailbox| {
                        !ignored.contains(&mailbox.mailbox_id)
                            && reads_mailbox(&ctx.access, mailbox.mailbox_id)
                    })
                    .map(move |mailbox| {
                        (
                            message.received_at(),
                            MailItem {
                                mailbox_id: mailbox.mailbox_id,
                                document_id: message.document_id(),
                            },
                        )
                    })
            })
            .collect::<Vec<_>>();
        let newest = |(received, item): &(u64, MailItem)| {
            Reverse((*received, item.document_id, item.mailbox_id))
        };
        if candidates.len() > loads {
            candidates.select_nth_unstable_by_key(loads, newest);
            candidates.truncate(loads);
        }
        candidates.sort_unstable_by_key(newest);
        loads -= candidates.len();
        let mut mails = Vec::with_capacity(candidates.len());
        let mut keys = Vec::with_capacity(candidates.len());
        for (received, item) in candidates {
            let Some(mail) = LoadedMail::load(server, account_id, &cache, item, &probe).await?
            else {
                continue;
            };
            keys.push(node_key(&mail, received)?);
            mails.push(Some(mail));
        }
        if mails.is_empty() {
            not_found(&mut messages);
            continue;
        }
        let mut flags = if shape.reads_carried() {
            StoredFlags::default()
        } else {
            shape
                .stored_flags(
                    server,
                    account_id,
                    ids.exchange(),
                    mails.iter().flatten().map(|mail| mail.item.document_id),
                )
                .await?
        };
        let grouped = grouped(&keys);
        let nodes = nodes(&keys, &grouped);
        let mut body = messages.begin_message(&Status::SUCCESS);
        let w = body.writer();
        w.start(M, "Conversation");
        ids.conversation_id(thread).write(w, "ConversationId");
        w.start(T, "ConversationNodes");
        let mut budget = limit;
        for node in node_order(&nodes, order)
            .into_iter()
            .filter_map(|index| nodes.get(index))
        {
            if budget == 0 {
                break;
            }
            w.start(T, "ConversationNode");
            if let Some(message_id) = node.message_id {
                w.leaf(T, "InternetMessageId", message_id);
            }
            if let Some(parent_id) = node.in_reply_to {
                w.leaf(T, "ParentInternetMessageId", parent_id);
            }
            w.start(T, "Items");
            for (_, _, member) in node.members.iter().take(budget) {
                let Some(mut mail) = mails.get_mut(*member).and_then(Option::take) else {
                    continue;
                };
                mail.load_row(server, account_id, ids.exchange(), &shape, &mut flags)
                    .await?;
                mail.complete(server, &shape).await?;
                let headers = mail.headers()?;
                let view = MailView::new(&mail, &headers, false)?;
                render_mail(server, ctx, &mut state, &ids, &shape, &mail, &view)
                    .await?
                    .write(w);
                budget -= 1;
            }
            w.end(T, "Items");
            w.end(T, "ConversationNode");
        }
        w.end(T, "ConversationNodes");
        w.end(M, "Conversation");
        body.finish();
    }
    messages.finish();
    Ok(ews_response(out))
}

fn not_found(messages: &mut MessagesWriter<'_>) {
    messages.message(&MessageResult::<EmptyMessage> {
        status: ItemError::NotFound.status(),
        body: None,
    });
}

async fn ignored_mailboxes(
    server: &Server,
    ctx: &EwsContext,
    request: &GetConversationItems<'_>,
) -> trc::Result<Result<SmallVec<[u32; 4]>, Status<'static>>> {
    let mut ignored = SmallVec::new();
    let Some(folders) = &request.folders_to_ignore else {
        return Ok(Ok(ignored));
    };
    let tree = ctx.folder_tree(server).await?;
    for id in folders {
        match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => ignored.extend(mailbox_of(entry.node)),
            Err(status) => return Ok(Err(status)),
        }
    }
    Ok(Ok(ignored))
}

fn node_key(mail: &LoadedMail<'_>, received: u64) -> trc::Result<NodeKey> {
    let headers = mail.headers()?;
    let view = MailView::new(mail, &headers, false)?;
    Ok(NodeKey {
        message_id: view.message_id().map(Box::from),
        parent_id: view.in_reply_to().map(Box::from),
        received,
    })
}

fn grouped(keys: &[NodeKey]) -> Vec<Member<'_>> {
    let mut grouped = keys
        .iter()
        .enumerate()
        .map(|(index, key)| (key.message_id.as_deref(), key.received, index))
        .collect::<Vec<_>>();
    grouped.sort_unstable();
    grouped
}

fn nodes<'k>(keys: &'k [NodeKey], grouped: &'k [Member<'k>]) -> Vec<Node<'k>> {
    let mut nodes = grouped
        .chunk_by(|(a, _, _), (b, _, _)| a.is_some() && a == b)
        .filter_map(|members| {
            let (message_id, received, member) = members.first()?;
            Some(Node {
                members,
                message_id: *message_id,
                in_reply_to: keys
                    .get(*member)
                    .and_then(|key| key.parent_id.as_deref())
                    .filter(|parent_id| Some(*parent_id) != *message_id),
                parent: None,
                received: *received,
            })
        })
        .collect::<Vec<_>>();
    let parents = nodes
        .iter()
        .map(|node| {
            let parent_id = node.in_reply_to?;
            nodes
                .binary_search_by(|candidate| candidate.message_id.cmp(&Some(parent_id)))
                .ok()
        })
        .collect::<Vec<_>>();
    for (node, parent) in nodes.iter_mut().zip(parents) {
        node.parent = parent;
    }
    nodes
}

fn node_order(nodes: &[Node<'_>], order: ConversationNodeSortOrder) -> Vec<usize> {
    let mut by_date = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.received, index))
        .collect::<Vec<_>>();
    by_date.sort_unstable();
    let by_date = by_date
        .into_iter()
        .map(|(_, index)| index)
        .collect::<Vec<_>>();
    let mut ordered = match order {
        ConversationNodeSortOrder::DateOrderAscending
        | ConversationNodeSortOrder::DateOrderDescending => by_date,
        ConversationNodeSortOrder::TreeOrderAscending
        | ConversationNodeSortOrder::TreeOrderDescending => tree_order(nodes, &by_date),
    };
    if matches!(
        order,
        ConversationNodeSortOrder::DateOrderDescending
            | ConversationNodeSortOrder::TreeOrderDescending
    ) {
        ordered.reverse();
    }
    ordered
}

fn tree_order(nodes: &[Node<'_>], by_date: &[usize]) -> Vec<usize> {
    let mut children = vec![SmallVec::<[usize; 2]>::new(); nodes.len()];
    let mut roots = Vec::new();
    for index in by_date {
        match nodes
            .get(*index)
            .and_then(|node| node.parent)
            .and_then(|parent| children.get_mut(parent))
        {
            Some(siblings) => siblings.push(*index),
            None => roots.push(*index),
        }
    }
    let mut visited = vec![false; nodes.len()];
    let mut ordered = Vec::with_capacity(nodes.len());
    let mut stack = Vec::new();
    for start in roots.iter().chain(by_date) {
        stack.push(*start);
        while let Some(index) = stack.pop() {
            let Some(seen) = visited.get_mut(index) else {
                continue;
            };
            if std::mem::replace(seen, true) {
                continue;
            }
            ordered.push(index);
            if let Some(next) = children.get(index) {
                stack.extend(next.iter().rev());
            }
        }
    }
    ordered
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/ews/item/conversation/items/tests.rs"]
mod tests;
