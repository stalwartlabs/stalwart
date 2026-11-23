/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, ItemError, MailItem,
    bulk::find_associated,
    fields::ShapeUse,
    mail_allowed,
    props::ItemProp,
    render::{DisplayNames, LoadedMail, MailShape, MailView, render},
};
use crate::{
    eas::convert::flag::StoredFlags,
    ews::{
        calendar::{
            Events, calendar_of,
            invitation::meeting_location,
            view::{CalendarView, find_view},
        },
        contact::{Contacts, address_book_of},
        context::EwsContext,
        filter::{Filter, FilterProp, PropValue},
        folder::{FolderSelector, get::Window, resolve_folder},
        groupware::find::find_items,
        reply::{RESPONSE_CAPACITY, ews_response},
        task::{Tasks, task_list_of},
    },
    folders::FolderNode,
    store::{FolderKind, FolderRef},
};
use common::{MessageStoreCache, Server, cache::exchange::ExchangeAccountCache};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::sortkeys::{EmailSortKeys, MessageSortField},
};
use exchange_proto::{
    convert::ical::REPLY_CLASSES,
    ews::{
        MessageResult, Operation, Status,
        requests::find::FindItem,
        responses::item::FindItemMessage,
        schema::{IndexBasePoint, ItemQueryTraversal, ResponseCode, SortDirection},
        types::{
            value::{M, T},
            view::{FolderView, IndexedView, ItemView},
        },
    },
};
use http_proto::HttpResponse;
use smallvec::SmallVec;
use std::cmp::Ordering;
use store::roaring::RoaringBitmap;

const GROUP_BY_UNSUPPORTED: &str = "GroupBy is not supported.";
const SORT_UNSUPPORTED: &str = "The property cannot be used for sorting.";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SortKey {
    Missing,
    Int(i64),
    Text(String),
}

#[derive(Debug, Clone, Copy)]
enum SortSource {
    Ranked(MessageSortField),
    Value(ItemProp),
}

impl SortSource {
    fn of(prop: ItemProp) -> Self {
        match prop {
            ItemProp::Subject => SortSource::Ranked(MessageSortField::Subject),
            ItemProp::From => SortSource::Ranked(MessageSortField::From),
            ItemProp::To => SortSource::Ranked(MessageSortField::To),
            prop => SortSource::Value(prop),
        }
    }

    fn needs_metadata(self) -> bool {
        matches!(self, SortSource::Value(prop) if prop.needs_metadata())
    }
}

struct Candidate {
    document_id: u32,
    keys: SmallVec<[SortKey; 2]>,
}

pub(crate) async fn find_item(
    server: &Server,
    ctx: &EwsContext,
    request: &FindItem<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let tree = ctx.folder_tree(server).await?;
    let cache = server.get_cached_messages(account_id).await?;
    let ids = EmailIds::load(server, ctx).await?;
    let mut shape = MailShape::new(&request.shape, ShapeUse::List);
    let mut receiver_loaded = false;
    let view = request.view.as_ref().map(page_view);
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::FindItem);
    let mut contacts = None;
    let mut tasks = None;
    let mut events = None;
    for id in &request.parent_folder_ids {
        let parent = match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => entry,
            Err(status) => {
                messages.message(&MessageResult::<FindItemMessage> { status, body: None });
                continue;
            }
        };
        if !ctx.access.of(parent.node).reads_items() {
            messages.message(&MessageResult::<FindItemMessage> {
                status: ItemError::Forbidden.status(),
                body: None,
            });
            continue;
        }
        if request.traversal == ItemQueryTraversal::Associated {
            let filter = match request
                .restriction
                .as_ref()
                .map(Filter::<ItemProp>::new)
                .transpose()
            {
                Ok(filter) => filter,
                Err(unsupported) => {
                    messages.message(&MessageResult::<FindItemMessage> {
                        status: unsupported.status(),
                        body: None,
                    });
                    continue;
                }
            };
            let items = match find_associated(server, ctx, parent.node, filter.as_ref()).await? {
                Ok(items) => items,
                Err(err) => {
                    messages.message(&MessageResult::<FindItemMessage> {
                        status: err.status(),
                        body: None,
                    });
                    continue;
                }
            };
            let window = Window::new(view.as_ref(), items.len());
            let mut body = messages.begin_message(&Status::SUCCESS);
            let w = body.writer();
            w.start(M, "RootFolder");
            window.paging.write_attrs(w);
            w.start(T, "Items");
            for item in window.slice(&items) {
                item.write(w);
            }
            w.end(T, "Items");
            w.end(M, "RootFolder");
            body.finish();
            continue;
        }
        if let Some(address_book) = address_book_of(parent.node) {
            if contacts.is_none() {
                contacts = Some(Contacts::load(server, ctx).await?);
            }
            if let Some(contacts) = &contacts {
                find_items(
                    server,
                    contacts,
                    request,
                    address_book,
                    view.as_ref(),
                    &mut messages,
                )
                .await?;
            }
            continue;
        }
        if let Some(task_list) = task_list_of(parent) {
            if tasks.is_none() {
                tasks = Some(Tasks::load(server, ctx).await?);
            }
            if let Some(tasks) = &tasks {
                find_items(
                    server,
                    tasks,
                    request,
                    task_list,
                    view.as_ref(),
                    &mut messages,
                )
                .await?;
            }
            continue;
        }
        if let Some(calendar) = calendar_of(parent) {
            if events.is_none() {
                events = Some(Events::load(server, ctx).await?);
            }
            if let Some(events) = &events {
                match &request.view {
                    Some(ItemView::Calendar {
                        max_entries,
                        start,
                        end,
                    }) => {
                        let view = CalendarView {
                            max_entries: *max_entries,
                            start: *start,
                            end: *end,
                        };
                        find_view(server, events, request, calendar, view, &mut messages).await?
                    }
                    _ => {
                        find_items(
                            server,
                            events,
                            request,
                            calendar,
                            view.as_ref(),
                            &mut messages,
                        )
                        .await?
                    }
                }
            }
            continue;
        }
        let candidates =
            match select(server, ctx, &cache, ids.exchange(), request, parent.node).await? {
                Ok(candidates) => candidates,
                Err(status) => {
                    messages.message(&MessageResult::<FindItemMessage> { status, body: None });
                    continue;
                }
            };
        if !receiver_loaded && !candidates.is_empty() {
            shape.load_receiver(server, account_id).await?;
            receiver_loaded = true;
        }
        let window = Window::new(view.as_ref(), candidates.len());
        let mut body = messages.begin_message(&Status::SUCCESS);
        let w = body.writer();
        w.start(M, "RootFolder");
        window.paging.write_attrs(w);
        w.start(T, "Items");
        let mailbox_id = mailbox_of(parent.node).unwrap_or_default();
        let page = window.slice(&candidates);
        let mut flags = shape
            .stored_flags(
                server,
                account_id,
                ids.exchange(),
                page.iter().map(|candidate| candidate.document_id),
            )
            .await?;
        for candidate in page {
            let item = MailItem {
                mailbox_id,
                document_id: candidate.document_id,
            };
            let Some(mut mail) = LoadedMail::load(server, account_id, &cache, item, &shape).await?
            else {
                continue;
            };
            mail.take_flags(&mut flags);
            let headers = mail.headers()?;
            let view = MailView::new(&mail, &headers, false)?;
            render(&shape, &ids, &mail, &view, DisplayNames::Header).write(w);
        }
        w.end(T, "Items");
        w.end(M, "RootFolder");
        body.finish();
    }
    messages.finish();
    Ok(ews_response(out))
}

async fn select(
    server: &Server,
    ctx: &EwsContext,
    cache: &MessageStoreCache,
    exchange: &ExchangeAccountCache,
    request: &FindItem<'_>,
    node: FolderNode,
) -> trc::Result<Result<Vec<Candidate>, Status<'static>>> {
    if let Err(err) = mail_allowed(ctx) {
        return Ok(Err(err.status()));
    }
    if request.group_by.is_some() {
        return Ok(Err(Status::error(
            ResponseCode::ErrorInvalidOperation,
            GROUP_BY_UNSUPPORTED,
        )));
    }
    let Some(mailbox_id) = mailbox_of(node) else {
        return Ok(Ok(Vec::new()));
    };
    if request.traversal != ItemQueryTraversal::Shallow {
        return Ok(Ok(Vec::new()));
    }
    let filter = match request
        .restriction
        .as_ref()
        .map(Filter::<ItemProp>::new)
        .transpose()
    {
        Ok(filter) => filter,
        Err(unsupported) => return Ok(Err(unsupported.status())),
    };
    let mut order = Vec::new();
    for field in request.sort_order.iter().flatten() {
        match ItemProp::of_path(&field.path) {
            Some(ItemProp::ConversationIndex) | None => {
                return Ok(Err(Status::error(
                    ResponseCode::ErrorUnsupportedPathForSortGroup,
                    SORT_UNSUPPORTED,
                )));
            }
            Some(prop) => order.push((SortSource::of(prop), field.order)),
        }
    }
    if order.is_empty() {
        order.push((
            SortSource::Value(ItemProp::Received),
            SortDirection::Descending,
        ));
    }
    let filter_props = || filter.iter().flat_map(|filter| filter.props());
    let needs_metadata = filter_props().any(ItemProp::needs_metadata)
        || order.iter().any(|(source, _)| source.needs_metadata());
    let joined = filter_props().any(|prop| matches!(prop, ItemProp::To | ItemProp::Cc));
    let filters_class = filter_props().any(|prop| prop == ItemProp::ItemClass);
    let reads_location = filter_props().any(|prop| prop == ItemProp::Location)
        || order
            .iter()
            .any(|(source, _)| matches!(source, SortSource::Value(ItemProp::Location)));
    let sorts_class = order
        .iter()
        .any(|(source, _)| matches!(source, SortSource::Value(ItemProp::ItemClass)));
    let probe = if needs_metadata {
        MailShape::metadata_only()
    } else {
        MailShape::id_only()
    };
    let account_id = ctx.account.account_id;
    let reads_flags = filter_props()
        .chain(order.iter().filter_map(|(source, _)| match source {
            SortSource::Value(prop) => Some(*prop),
            SortSource::Ranked(_) => None,
        }))
        .any(|prop| {
            matches!(
                prop,
                ItemProp::FlagStatus | ItemProp::LastVerb | ItemProp::ItemClass
            )
        });
    let mut flags = if reads_flags {
        StoredFlags::load(
            server,
            exchange,
            account_id,
            &cache
                .in_mailbox(mailbox_id)
                .map(|message| message.document_id())
                .collect::<RoaringBitmap>(),
        )
        .await?
    } else {
        StoredFlags::default()
    };
    let mut candidates = Vec::new();
    for message in cache.in_mailbox(mailbox_id) {
        let item = MailItem {
            mailbox_id,
            document_id: message.document_id(),
        };
        let Some(mut mail) = LoadedMail::load(server, account_id, cache, item, &probe).await?
        else {
            continue;
        };
        mail.take_flags(&mut flags);
        let mut headers = mail.headers()?;
        let location = if reads_location {
            meeting_location(server, &mail, &headers).await?
        } else {
            None
        };
        let mut view = MailView::new(&mail, &headers, joined)?;
        if (filters_class || sorts_class) && view.has_unresolved_class() {
            let ambiguous = sorts_class
                || filter.as_ref().is_some_and(|filter| {
                    let mut outcomes = REPLY_CLASSES.into_iter().map(|class| {
                        view.assume_reply_class(class);
                        filter.matches(&|prop| item_value(&mail, &view, location.as_deref(), prop))
                    });
                    let first = outcomes.next();
                    outcomes.any(|outcome| Some(outcome) != first)
                });
            if ambiguous {
                drop(view);
                drop(headers);
                mail.resolve_reply(server).await?;
                headers = mail.headers()?;
                view = MailView::new(&mail, &headers, joined)?;
            }
        }
        let value = |prop| item_value(&mail, &view, location.as_deref(), prop);
        if filter
            .as_ref()
            .is_some_and(|filter| !filter.matches(&value))
        {
            continue;
        }
        candidates.push(Candidate {
            document_id: item.document_id,
            keys: order
                .iter()
                .map(|(source, _)| match source {
                    SortSource::Value(prop) => sort_key(value(*prop)),
                    SortSource::Ranked(_) => SortKey::Missing,
                })
                .collect(),
        });
    }
    rank(server, account_id, &order, &mut candidates).await?;
    candidates.sort_unstable_by(|a, b| {
        a.keys
            .iter()
            .zip(&b.keys)
            .zip(&order)
            .map(|((a, b), (_, direction))| match direction {
                SortDirection::Ascending => a.cmp(b),
                SortDirection::Descending => b.cmp(a),
            })
            .find(|ordering| ordering.is_ne())
            .unwrap_or(Ordering::Equal)
            .then(a.document_id.cmp(&b.document_id))
    });
    Ok(Ok(candidates))
}

async fn rank(
    server: &Server,
    account_id: u32,
    order: &[(SortSource, SortDirection)],
    candidates: &mut [Candidate],
) -> trc::Result<()> {
    let mut fields = SmallVec::<[MessageSortField; 3]>::new();
    for (source, _) in order {
        if let SortSource::Ranked(field) = source
            && !fields.contains(field)
        {
            fields.push(*field);
        }
    }
    if fields.is_empty() || candidates.len() < 2 {
        return Ok(());
    }
    let documents = candidates
        .iter()
        .map(|candidate| candidate.document_id)
        .collect::<RoaringBitmap>();
    let ranks = server
        .message_sort_ranks(account_id, &documents, &fields)
        .await?;
    for candidate in candidates {
        for (key, (source, _)) in candidate.keys.iter_mut().zip(order) {
            if let SortSource::Ranked(field) = source
                && let Some(rank) = ranks
                    .get(field.index())
                    .and_then(Option::as_ref)
                    .and_then(|ranks| ranks.get(&candidate.document_id))
            {
                *key = SortKey::Int(i64::from(*rank));
            }
        }
    }
    Ok(())
}

fn item_value<'x>(
    mail: &'x LoadedMail<'_>,
    view: &'x MailView<'x>,
    location: Option<&'x str>,
    prop: ItemProp,
) -> Option<PropValue<'x>> {
    match prop {
        ItemProp::Location => location.map(PropValue::Text),
        prop => mail.value(view, prop),
    }
}

pub(crate) fn sort_key(value: Option<PropValue<'_>>) -> SortKey {
    match value {
        None => SortKey::Missing,
        Some(PropValue::Int(value)) => SortKey::Int(value),
        Some(PropValue::Name(value)) => SortKey::Int(value.ordinal()),
        Some(PropValue::Bool(value)) => SortKey::Int(i64::from(value)),
        Some(PropValue::Time(time)) => SortKey::Int(time.as_second()),
        Some(PropValue::Text(text)) => SortKey::Text(text.to_lowercase()),
    }
}

pub(crate) fn mailbox_of(node: FolderNode) -> Option<u32> {
    match node {
        FolderNode::Stored(FolderRef {
            kind: FolderKind::Mailbox,
            id,
        }) => Some(id),
        _ => None,
    }
}

pub(super) fn page_view(view: &ItemView<'_>) -> FolderView {
    match view {
        ItemView::Indexed(view) => FolderView::Indexed(*view),
        ItemView::Fractional(view) => FolderView::Fractional(*view),
        ItemView::SeekToCondition { max_entries, .. }
        | ItemView::Calendar { max_entries, .. }
        | ItemView::Contacts { max_entries, .. } => FolderView::Indexed(IndexedView {
            max_entries: *max_entries,
            offset: 0,
            base_point: IndexBasePoint::Beginning,
        }),
    }
}
