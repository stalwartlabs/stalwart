/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ews::{
        context::EwsContext,
        folder::{FolderSelector, get::Window, resolve_folder},
        item::{
            EmailIds, ItemError, MailItem,
            find::mailbox_of,
            mail_allowed, reads_mailbox,
            render::{LoadedMail, MailShape, MailView, date_time, seconds},
        },
        reply::{RESPONSE_CAPACITY, ews_response},
    },
    folders::access::ViewRights,
};
use ahash::AHashMap;
use common::{MessageStoreCache, Server, cache::email::MessageRef};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use exchange_proto::{
    common::time::UtcSeconds,
    ews::{
        Operation, Status,
        requests::conversation::FindConversation,
        responses::{ShapeB, conversation::FindConversationBody},
        schema::{
            ConversationQueryTraversal, Importance, ResponseCode, SortDirection, UnindexedField,
            ViewFilter,
        },
        types::{
            conversation::Conversation,
            path::Path,
            value::{DateTime, ItemClasses, List, Strings},
            view::{FolderView, ItemView},
        },
    },
};
use http_proto::HttpResponse;
use smallvec::SmallVec;
use std::{borrow::Cow, cmp::Ordering};
use types::keyword::SEEN;

const MAX_DIGESTS: usize = 100;
const MAX_DIGEST_ROWS: usize = 5000;
const MAX_NAMES: usize = 100;
const UNSUPPORTED_VIEW: &str = "Only IndexedPageItemView is supported.";
const UNSUPPORTED_SEARCH: &str =
    "QueryString, deep traversal and view filters are not supported for conversations.";
const SCOPE_WITHOUT_QUERY: &str = "MailboxScope requires a QueryString.";
const SORT_UNSUPPORTED: &str = "The property cannot be used for sorting.";

#[derive(Debug, Clone, Copy, Default)]
struct Totals {
    messages: u32,
    unread: u32,
    size: u64,
    last_delivery: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct ThreadTotals {
    folder: Totals,
    global: Totals,
}

#[derive(Debug, Clone, Copy)]
enum Scope {
    Folder,
    Global,
}

#[derive(Debug, Clone, Copy)]
enum SortField {
    LastDelivery,
    Messages,
    Unread,
    Size,
}

#[derive(Default)]
struct Digest {
    senders: Vec<String>,
    unread_senders: Vec<String>,
    recipients: Vec<String>,
    classes: SmallVec<[&'static str; 4]>,
    importance: Option<Importance>,
    has_attachments: bool,
}

struct Summarizer<'a> {
    server: &'a Server,
    cache: &'a MessageStoreCache,
    ids: &'a EmailIds,
    access: &'a ViewRights,
    mailbox_id: u32,
    digests: usize,
    probe: MailShape<'static>,
}

pub(crate) async fn find_conversation(
    server: &Server,
    ctx: &EwsContext,
    request: &FindConversation<'_>,
) -> trc::Result<HttpResponse> {
    let (status, body) = match conversations(server, ctx, request).await? {
        Ok(body) => (Status::SUCCESS, Some(body)),
        Err(status) => (status, None),
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::FindConversation,
        status,
        body,
    });
    Ok(ews_response(out))
}

async fn conversations(
    server: &Server,
    ctx: &EwsContext,
    request: &FindConversation<'_>,
) -> trc::Result<Result<FindConversationBody<'static>, Status<'static>>> {
    if let Err(err) = mail_allowed(ctx) {
        return Ok(Err(err.status()));
    }
    if request.query_string.is_some()
        || request.traversal == Some(ConversationQueryTraversal::Deep)
        || request
            .view_filter
            .is_some_and(|filter| filter != ViewFilter::All)
    {
        return Ok(Err(Status::error(
            ResponseCode::ErrorInvalidOperation,
            UNSUPPORTED_SEARCH,
        )));
    }
    if request.mailbox_scope.is_some() {
        return Ok(Err(Status::error(
            ResponseCode::ErrorMailboxScopeNotAllowedWithoutQueryString,
            SCOPE_WITHOUT_QUERY,
        )));
    }
    let view = match &request.view {
        None => None,
        Some(ItemView::Indexed(view)) => Some(FolderView::Indexed(*view)),
        Some(_) => {
            return Ok(Err(Status::error(
                ResponseCode::ErrorInvalidOperation,
                UNSUPPORTED_VIEW,
            )));
        }
    };
    let mut order = SmallVec::<[(Scope, SortField, SortDirection); 2]>::new();
    for field in request.sort_order.iter().flatten() {
        let Some((scope, sort)) = sort_field(&field.path) else {
            return Ok(Err(Status::error(
                ResponseCode::ErrorUnsupportedPathForSortGroup,
                SORT_UNSUPPORTED,
            )));
        };
        order.push((scope, sort, field.order));
    }
    if order.is_empty() {
        order.push((
            Scope::Folder,
            SortField::LastDelivery,
            SortDirection::Descending,
        ));
    }
    let account_id = ctx.account.account_id;
    let tree = ctx.folder_tree(server).await?;
    let selector = FolderSelector::from(&request.parent_folder_id);
    let parent = match resolve_folder(server, ctx, &tree, selector).await? {
        Ok(entry) => entry,
        Err(status) => return Ok(Err(status)),
    };
    if !ctx.access.of(parent.node).reads_items() {
        return Ok(Err(ItemError::Forbidden.status()));
    }
    let Some(mailbox_id) = mailbox_of(parent.node) else {
        return Ok(Ok(FindConversationBody::default()));
    };
    let cache = server.get_cached_messages(account_id).await?;
    let mut threads = AHashMap::<u32, ThreadTotals>::new();
    for message in cache.in_mailbox(mailbox_id) {
        threads
            .entry(message.thread_id())
            .or_default()
            .folder
            .add(message, 1);
    }
    for message in cache.emails.iter() {
        if let Some(thread) = threads.get_mut(&message.thread_id()) {
            let readable = copies(message, &ctx.access);
            if readable > 0 {
                thread.global.add(message, readable);
            }
        }
    }
    let mut ranked = threads.into_iter().collect::<Vec<_>>();
    ranked.sort_unstable_by(|(a_id, a), (b_id, b)| {
        order
            .iter()
            .map(|(scope, field, direction)| {
                let ordering = a.key(*scope, *field).cmp(&b.key(*scope, *field));
                match direction {
                    SortDirection::Ascending => ordering,
                    SortDirection::Descending => ordering.reverse(),
                }
            })
            .find(|ordering| ordering.is_ne())
            .unwrap_or(Ordering::Equal)
            .then(b_id.cmp(a_id))
    });
    let window = Window::new(view.as_ref(), ranked.len());
    let page = window.slice(&ranked);
    let positions = page
        .iter()
        .enumerate()
        .map(|(position, (thread_id, _))| (*thread_id, position))
        .collect::<AHashMap<_, _>>();
    let mut members = vec![Vec::new(); page.len()];
    for message in cache.emails.iter() {
        if let Some(list) = positions
            .get(&message.thread_id())
            .and_then(|position| members.get_mut(*position))
            && readable(message, &ctx.access).next().is_some()
        {
            list.push(message);
        }
    }
    let ids = EmailIds::load(server, ctx).await?;
    let summarizer = Summarizer {
        server,
        cache: &cache,
        ids: &ids,
        access: &ctx.access,
        mailbox_id,
        digests: (MAX_DIGEST_ROWS / page.len().max(1) / 2).clamp(1, MAX_DIGESTS),
        probe: MailShape::classified(),
    };
    let mut conversations = Vec::with_capacity(page.len());
    for ((thread_id, totals), messages) in page.iter().zip(&mut members) {
        messages.sort_unstable_by_key(|message| (message.received_at(), message.document_id()));
        conversations.push(summarizer.summarize(*thread_id, totals, messages).await?);
    }
    Ok(Ok(FindConversationBody {
        conversations,
        total_conversations_in_view: window.paging.total_items_in_view,
        indexed_offset: window.paging.indexed_paging_offset.unwrap_or_default(),
    }))
}

impl Summarizer<'_> {
    async fn summarize(
        &self,
        thread_id: u32,
        totals: &ThreadTotals,
        messages: &[MessageRef<'_>],
    ) -> trc::Result<Conversation<'static>> {
        let mut folder = Digest::default();
        let mut global = Digest::default();
        let mut topic = None;
        let mut folder_left = self.digests;
        let mut global_left = self.digests;
        for message in messages.iter().rev() {
            if folder_left == 0 && global_left == 0 {
                break;
            }
            let in_folder = folder_left > 0 && message.has_mailbox_id(self.mailbox_id);
            let in_global = global_left > 0;
            if !in_folder && !in_global {
                continue;
            }
            folder_left -= usize::from(in_folder);
            global_left -= usize::from(in_global);
            let Some(first) = readable(*message, self.access).next() else {
                continue;
            };
            let item = MailItem {
                mailbox_id: first,
                document_id: message.document_id(),
            };
            let Some(mail) = LoadedMail::load(
                self.server,
                self.ids.account_id(),
                self.cache,
                item,
                &self.probe,
            )
            .await?
            else {
                continue;
            };
            let headers = mail.headers()?;
            let view = MailView::new(&mail, &headers, false)?;
            let unread = message.keywords() & (1 << SEEN) == 0;
            if in_folder {
                folder.add(&view, unread);
            }
            if in_global {
                global.add(&view, unread);
            }
            if topic.is_none() {
                topic = view.topic().map(String::from);
            }
        }
        let folder_ids = messages
            .iter()
            .rev()
            .filter(|message| message.has_mailbox_id(self.mailbox_id))
            .map(|message| {
                let item = MailItem {
                    mailbox_id: self.mailbox_id,
                    document_id: message.document_id(),
                };
                self.ids.item_id(item, message.change_id())
            })
            .collect();
        let global_ids = messages
            .iter()
            .rev()
            .flat_map(|message| {
                readable(*message, self.access).map(move |mailbox_id| {
                    let item = MailItem {
                        mailbox_id,
                        document_id: message.document_id(),
                    };
                    self.ids.item_id(item, message.change_id())
                })
            })
            .collect();
        let folder = folder.finish();
        let global = global.finish();
        Ok(Conversation {
            conversation_id: self.ids.conversation_id(thread_id),
            conversation_topic: topic.map_or(Cow::Borrowed(""), Cow::Owned),
            unique_recipients: folder.recipients,
            global_unique_recipients: global.recipients,
            unique_unread_senders: folder.unread_senders,
            global_unique_unread_senders: global.unread_senders,
            unique_senders: folder.senders,
            global_unique_senders: global.senders,
            last_delivery_time: delivery_time(totals.folder.last_delivery),
            global_last_delivery_time: delivery_time(totals.global.last_delivery),
            has_attachments: folder.has_attachments,
            global_has_attachments: global.has_attachments,
            message_count: count(totals.folder.messages),
            global_message_count: count(totals.global.messages),
            unread_count: count(totals.folder.unread),
            global_unread_count: count(totals.global.unread),
            size: size(totals.folder.size),
            global_size: size(totals.global.size),
            item_classes: folder.classes,
            global_item_classes: global.classes,
            importance: folder.importance,
            global_importance: global.importance,
            item_ids: List(folder_ids),
            global_item_ids: List(global_ids),
        })
    }
}

struct DigestSummary {
    senders: Strings<'static>,
    unread_senders: Strings<'static>,
    recipients: Strings<'static>,
    classes: ItemClasses<'static>,
    importance: Importance,
    has_attachments: bool,
}

impl Digest {
    fn add(&mut self, view: &MailView<'_>, unread: bool) {
        if let Some(name) = view.sender_name() {
            if unread {
                insert_name(&mut self.unread_senders, name);
            }
            insert_name(&mut self.senders, name);
        }
        for name in view.recipient_names() {
            insert_name(&mut self.recipients, name);
        }
        if let Some(class) = view.class()
            && !self.classes.contains(&class)
        {
            self.classes.push(class);
        }
        let importance = view.importance();
        self.importance = Some(
            self.importance
                .map_or(importance, |current| current.max(importance)),
        );
        self.has_attachments |= view.has_attachments();
    }

    fn finish(self) -> DigestSummary {
        DigestSummary {
            senders: strings(self.senders),
            unread_senders: strings(self.unread_senders),
            recipients: strings(self.recipients),
            classes: ItemClasses(self.classes.into_iter().map(Cow::Borrowed).collect()),
            importance: self.importance.unwrap_or(Importance::Normal),
            has_attachments: self.has_attachments,
        }
    }
}

impl Totals {
    fn add(&mut self, message: MessageRef<'_>, copies: u32) {
        self.messages = self.messages.saturating_add(copies);
        if message.keywords() & (1 << SEEN) == 0 {
            self.unread = self.unread.saturating_add(copies);
        }
        self.size = self
            .size
            .saturating_add(u64::from(message.size()).saturating_mul(u64::from(copies)));
        self.last_delivery = self.last_delivery.max(message.received_at());
    }
}

impl ThreadTotals {
    fn key(&self, scope: Scope, field: SortField) -> u64 {
        let totals = match scope {
            Scope::Folder => &self.folder,
            Scope::Global => &self.global,
        };
        match field {
            SortField::LastDelivery => totals.last_delivery,
            SortField::Messages => u64::from(totals.messages),
            SortField::Unread => u64::from(totals.unread),
            SortField::Size => totals.size,
        }
    }
}

fn sort_field(path: &Path<'_>) -> Option<(Scope, SortField)> {
    let Path::Field(field) = path else {
        return None;
    };
    Some(match field {
        UnindexedField::ConversationLastDeliveryTime => (Scope::Folder, SortField::LastDelivery),
        UnindexedField::ConversationGlobalLastDeliveryTime => {
            (Scope::Global, SortField::LastDelivery)
        }
        UnindexedField::ConversationMessageCount => (Scope::Folder, SortField::Messages),
        UnindexedField::ConversationGlobalMessageCount => (Scope::Global, SortField::Messages),
        UnindexedField::ConversationUnreadCount => (Scope::Folder, SortField::Unread),
        UnindexedField::ConversationGlobalUnreadCount => (Scope::Global, SortField::Unread),
        UnindexedField::ConversationSize => (Scope::Folder, SortField::Size),
        UnindexedField::ConversationGlobalSize => (Scope::Global, SortField::Size),
        _ => return None,
    })
}

fn insert_name(names: &mut Vec<String>, name: &str) {
    if names.len() < MAX_NAMES
        && let Err(position) = names.binary_search_by(|known| known.as_str().cmp(name))
    {
        names.insert(position, name.into());
    }
}

fn strings(names: Vec<String>) -> Strings<'static> {
    Strings(names.into_iter().map(Cow::Owned).collect())
}

fn copies(message: MessageRef<'_>, access: &ViewRights) -> u32 {
    u32::try_from(readable(message, access).count()).unwrap_or(u32::MAX)
}

fn readable<'m>(message: MessageRef<'m>, access: &'m ViewRights) -> impl Iterator<Item = u32> + 'm {
    message
        .mailboxes()
        .iter()
        .map(|mailbox| mailbox.mailbox_id)
        .filter(move |mailbox_id| reads_mailbox(access, *mailbox_id))
}

fn count(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn size(value: u64) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn delivery_time(received_at: u64) -> DateTime {
    date_time(seconds(received_at)).unwrap_or(DateTime::utc(UtcSeconds(0)))
}
