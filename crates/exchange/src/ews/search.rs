/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EwsCaller,
    context::EwsContext,
    folder::{FolderSelector, resolve_folder},
    item::{
        EmailIds, MailItem,
        find::mailbox_of,
        mail_allowed,
        render::{DisplayNames, LoadedMail, MailShape, MailView, render},
    },
    people::directory_page,
    reply::{RESPONSE_CAPACITY, ews_response},
};
use crate::{
    eas::{
        directory::GalQuery,
        mail_search::{MAX_TEXT_TOKENS, MailHits, MailSearch, mailbox_tree, search_terms},
    },
    folders::{FolderNode, FolderTree, SpecialFolder, access::ViewRights},
    mapi::{
        emsmdb::store::StoreGuids,
        ids::{IdSpace, MapiId},
        nspi::{
            book::{Book, BookError},
            scan::ScanScope,
        },
    },
    store::{FolderKind, FolderRef},
};
use common::{MessageStoreCache, Server, cache::exchange::ExchangeAccountCache};
use email::cache::{MessageCacheFetch, mailbox::MailboxCacheAccess};
use exchange_proto::{
    common::guid::{decode_hex_into, push_hex_upper},
    ews::{
        Operation, Status,
        requests::search::{ExecuteSearch, GetSearchSuggestions},
        responses::{ShapeB, folder::EmptyMessage},
        schema::{IdFormat, IndexBasePoint},
        types::{
            ids::{BaseFolderId, EwsIdStr, FolderId, ItemId},
            item::Item,
            search::{PeopleSuggestion, SearchResultsSummary, SearchSuggestions},
            value::XBinary,
            view::IndexedView,
        },
    },
    ids::entryid::EntryId,
};
use http_proto::HttpResponse;
use smallvec::SmallVec;
use std::{
    borrow::Cow,
    ops::Range,
    time::{SystemTime, UNIX_EPOCH},
};
use store::roaring::RoaringBitmap;
use types::{special_use::SpecialUse, type_state::DataType};

const DEFAULT_RESULT_ROWS: usize = 25;
const MAX_RESULT_ROWS: usize = 250;
const MAX_SUGGESTIONS: usize = 10;
const ENTRY_ID_CAPACITY: usize = 70;
const MAX_ENTRY_ID_HEX: usize = 2 * ENTRY_ID_CAPACITY;
const CONVERSATION_GUID: Range<usize> = 6..22;

pub(crate) fn start_search_session(ctx: &EwsContext) -> HttpResponse {
    session_reply(ctx, Operation::StartSearchSession)
}

pub(crate) fn end_search_session(ctx: &EwsContext) -> HttpResponse {
    session_reply(ctx, Operation::EndSearchSession)
}

fn session_reply(ctx: &EwsContext, op: Operation) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op,
        status: Status::SUCCESS,
        body: Some(EmptyMessage),
    });
    ews_response(out)
}

pub(crate) async fn get_search_suggestions(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &GetSearchSuggestions<'_>,
) -> trc::Result<HttpResponse> {
    let trigger = request.query.as_deref().unwrap_or_default();
    let limit = request
        .max_suggestions
        .and_then(|max| usize::try_from(max).ok())
        .unwrap_or(MAX_SUGGESTIONS)
        .min(MAX_SUGGESTIONS);
    let mut entries = Vec::new();
    if let (Some(query), true, true) = (
        GalQuery::new(trigger),
        request.suggestion_types.is_some_and(|kinds| kinds.people),
        ctx.account.data_types.contains(DataType::Principal) && limit > 0,
    ) {
        let mut book = Book::new(server, caller.access_token).with_scope(ScanScope::Accounts);
        let view = IndexedView {
            max_entries: Some(u32::try_from(limit).unwrap_or(u32::MAX)),
            offset: 0,
            base_point: IndexBasePoint::Beginning,
        };
        match directory_page(&mut book, &query, view).await {
            Ok(page) => entries = page.entries,
            Err(BookError::OutOfMemory) => {}
            Err(BookError::Store(err)) => return Err(err),
        }
    }
    let people = entries
        .iter()
        .filter_map(|entry| {
            Some(PeopleSuggestion {
                display_name: Cow::Borrowed(&*entry.display_name),
                address: Cow::Borrowed(entry.view().addresses().next()?),
            })
        })
        .collect();
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::GetSearchSuggestions,
        status: Status::SUCCESS,
        body: Some(SearchSuggestions {
            batch_id: batch_id(),
            instance_id: Cow::Borrowed(session_guid(&request.search_session_id)),
            trigger: Cow::Borrowed(trigger),
            people,
        }),
    });
    Ok(ews_response(out))
}

pub(crate) async fn execute_search(
    server: &Server,
    ctx: &EwsContext,
    request: &ExecuteSearch<'_>,
) -> trc::Result<HttpResponse> {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    if let Err(err) = mail_allowed(ctx) {
        ctx.envelope(&mut out)
            .shape_b(Operation::ExecuteSearch, &err.status())
            .finish();
        return Ok(ews_response(out));
    }
    let account_id = ctx.account.account_id;
    let cache = server.get_cached_messages(account_id).await?;
    let ids = EmailIds::load(server, ctx).await?;
    let offset = request
        .result_row_offset
        .and_then(|offset| usize::try_from(offset.saturating_sub(1)).ok())
        .unwrap_or_default();
    let rows = request
        .result_row_count
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count > 0)
        .unwrap_or(DEFAULT_RESULT_ROWS)
        .min(MAX_RESULT_ROWS);
    let hits = match search_scope(server, ctx, &cache, ids.exchange(), request).await? {
        Ok(Some(mut search)) => {
            search.push_text(&request.query, server.core.email.default_language);
            if search.text.is_empty() {
                MailHits::default()
            } else {
                search
                    .run_top(server, account_id, &cache, offset.saturating_add(rows))
                    .await?
            }
        }
        Ok(None) => MailHits::default(),
        Err(status) => {
            ctx.envelope(&mut out)
                .shape_b(Operation::ExecuteSearch, &status)
                .finish();
            return Ok(ews_response(out));
        }
    };
    let page = hits.top.get(offset..).unwrap_or_default();
    let page = page.get(..rows).unwrap_or(page);
    let shape = MailShape::search_results();
    let guids = (request.id_format == Some(IdFormat::HexEntryId))
        .then(|| StoreGuids::new(ids.exchange().store_instance, account_id));
    let mut body = ctx
        .envelope(&mut out)
        .shape_b(Operation::ExecuteSearch, &Status::SUCCESS);
    let w = body.writer();
    SearchResultsSummary::start(w);
    let mut written = 0;
    let mut scratch = Vec::with_capacity(ENTRY_ID_CAPACITY);
    for hit in page {
        let item = MailItem {
            mailbox_id: hit.mailbox_id,
            document_id: hit.document_id,
        };
        let Some(mail) = LoadedMail::load(server, account_id, &cache, item, &shape).await? else {
            continue;
        };
        let headers = mail.headers()?;
        let view = MailView::new(&mail, &headers, false)?;
        let mut rendered = render(&shape, &ids, &mail, &view, DisplayNames::Header);
        if let Some(guids) = &guids {
            hex_ids(&mut rendered, guids, &ids, item, &mut scratch);
        }
        rendered.write_untyped(w);
        written += 1;
    }
    let terms = search_terms(&request.query).collect::<SmallVec<[&str; MAX_TEXT_TOKENS]>>();
    SearchResultsSummary {
        more_results: offset.saturating_add(page.len()) < hits.total,
        count: written,
        total: hits.total,
        terms: &terms,
    }
    .finish(w);
    body.finish();
    Ok(ews_response(out))
}

async fn search_scope(
    server: &Server,
    ctx: &EwsContext,
    cache: &MessageStoreCache,
    exchange: &ExchangeAccountCache,
    request: &ExecuteSearch<'_>,
) -> trc::Result<Result<Option<MailSearch>, Status<'static>>> {
    let Some(scope) = request
        .search_scope
        .mailbox
        .as_ref()
        .filter(|_| request.item_types.mail)
    else {
        return Ok(Ok(None));
    };
    let root = match &scope.folder {
        Some(folder) => match scope_node(server, ctx, exchange, folder).await? {
            Ok(node) => match mailbox_of(node) {
                Some(mailbox_id) => Some(mailbox_id),
                None if matches!(
                    node,
                    FolderNode::Special(SpecialFolder::Root | SpecialFolder::IpmSubtree)
                ) =>
                {
                    None
                }
                None => return Ok(Ok(None)),
            },
            Err(status) => return Ok(Err(status)),
        },
        None => None,
    };
    let mut search = MailSearch::default();
    match root {
        Some(mailbox_id) => search.add_mailbox(cache, mailbox_id, scope.deep),
        None => {
            let all = search.scope.get_or_insert_default();
            all.extend(
                cache
                    .mailboxes
                    .items
                    .iter()
                    .map(|mailbox| mailbox.document_id),
            );
            if !request.include_deleted.unwrap_or(false)
                && let Some(trash) = cache.mailboxes.mailbox_by_role(&SpecialUse::Trash)
            {
                *all -= mailbox_tree(cache, trash.document_id);
            }
        }
    }
    if !matches!(ctx.access, ViewRights::Owner | ViewRights::Member)
        && let Some(scope) = search.scope.as_mut()
    {
        *scope = scope
            .iter()
            .filter(|mailbox_id| {
                ctx.access
                    .of(FolderNode::Stored(FolderRef {
                        kind: FolderKind::Mailbox,
                        id: *mailbox_id,
                    }))
                    .reads_items()
            })
            .collect::<RoaringBitmap>();
    }
    Ok(Ok(Some(search)))
}

async fn scope_node(
    server: &Server,
    ctx: &EwsContext,
    exchange: &ExchangeAccountCache,
    folder: &BaseFolderId<'_>,
) -> trc::Result<Result<FolderNode, Status<'static>>> {
    let tree = ctx.folder_tree(server).await?;
    if let BaseFolderId::Folder(id) = folder
        && let Some(node) = hex_folder_node(ctx, &tree, exchange, id)
    {
        return Ok(Ok(node));
    }
    Ok(
        resolve_folder(server, ctx, &tree, FolderSelector::from(folder))
            .await?
            .map(|entry| entry.node),
    )
}

fn hex_folder_node(
    ctx: &EwsContext,
    tree: &FolderTree,
    exchange: &ExchangeAccountCache,
    id: &FolderId<'_>,
) -> Option<FolderNode> {
    let hex = id.id.as_str().as_bytes();
    if hex.len() > MAX_ENTRY_ID_HEX {
        return None;
    }
    let mut buf = [0u8; ENTRY_ID_CAPACITY];
    let EntryId::Folder(entry) = EntryId::decode(decode_hex_into(hex, &mut buf)?).ok()? else {
        return None;
    };
    let guids = StoreGuids::new(exchange.store_instance, ctx.account.account_id);
    if entry.provider != guids.mailbox || entry.gid.guid != guids.replica {
        return None;
    }
    let node = MapiId::from_counter(entry.gid.counter.get())?.to_folder(exchange)?;
    match node {
        FolderNode::Special(special) => tree.special(special),
        node => tree.get(node),
    }
    .map(|entry| entry.node)
}

fn hex_ids(
    rendered: &mut Item<'_>,
    guids: &StoreGuids,
    ids: &EmailIds,
    item: MailItem,
    scratch: &mut Vec<u8>,
) {
    let conversation = match rendered {
        Item::Message(message) => match &message.message.conversation_index {
            Some(XBinary::Bytes(index)) => index.get(CONVERSATION_GUID).and_then(upper_hex),
            _ => None,
        },
        _ => None,
    };
    let folder = MapiId::from_folder(
        ids.exchange(),
        FolderNode::Stored(FolderRef {
            kind: FolderKind::Mailbox,
            id: item.mailbox_id,
        }),
    );
    let message = MapiId::new(IdSpace::Email, ids.identity(item));
    let fields = rendered.fields_mut();
    fields.item_id =
        hex_entry_id(&guids.message_entry_id(folder, message), scratch).map(|id| ItemId {
            id,
            change_key: None,
        });
    fields.parent_folder_id =
        hex_entry_id(&guids.folder_entry_id(folder), scratch).map(|id| FolderId {
            id,
            change_key: None,
        });
    if let Some(id) = conversation {
        fields.conversation_id = Some(ItemId {
            id,
            change_key: None,
        });
    }
}

fn hex_entry_id(entry: &EntryId<'_>, scratch: &mut Vec<u8>) -> Option<EwsIdStr<'static>> {
    scratch.clear();
    entry.encode(scratch).ok()?;
    upper_hex(scratch)
}

fn upper_hex(bytes: &[u8]) -> Option<EwsIdStr<'static>> {
    let mut hex = Vec::with_capacity(bytes.len() * 2);
    push_hex_upper(bytes, &mut hex);
    String::from_utf8(hex)
        .ok()
        .map(|hex| EwsIdStr::Parsed(Cow::Owned(hex)))
}

fn session_guid(id: &str) -> &str {
    let id = id.trim();
    id.strip_prefix('{')
        .and_then(|id| id.strip_suffix('}'))
        .unwrap_or(id)
}

fn batch_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
