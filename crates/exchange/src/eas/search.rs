/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{EasContext, EasDataKind},
    convert::flag::StoredFlags,
    directory::{GalQuery, gal_entry, open_directory, page_range, returned_range},
    groupware_search::{GroupwareScope, groupware_search},
    mail_search::{MailHit, MailSearch, ScopeError, TextFields, TextFit},
    response::{EasResponse, MAX_RESPONSE_BYTES},
    sync::{
        email::{LoadedMail, load_mail, mail_class, mail_flags},
        estimate::mail_folder,
        groupware::{GroupwareKind, GroupwareTarget},
        meetings::resolve_meetings,
    },
};
use crate::{
    cache::ExchangeCacheFetch,
    folders::{ExchangeFolders, FolderNode, FolderTree},
    mapi::nspi::book::BookError,
    store::{FolderKind, FolderRef},
};
use ::email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use common::{MessageStoreCache, Server, cache::exchange::ExchangeAccountCache};
use exchange_proto::{
    common::token::TokenBuf,
    eas::{
        commands::{
            ItemRange,
            appdata::ApplicationData,
            search::{
                QueryNode, SearchOptions, SearchProperties, SearchQuery, SearchRequest,
                SearchResponse, SearchResult, SearchStore, SearchStoreResult,
            },
            sync::SyncOptions,
        },
        http::Command,
        status::{CommonStatus, SearchStatus},
        tokens::{ProtocolVersion, Tag, tag::email},
        types::{Class, EasDateTime},
        wbxml::Decoder,
    },
    ids::eas::EasServerId,
};
use nlp::language::Language;
use smallvec::SmallVec;
use store::{roaring::RoaringBitmap, search::SearchFilter};

pub const MAX_MAIL_RESULTS: u32 = 100;
const CONVERSATION_THREAD_LEN: usize = 4;

pub trait EasSearch: Sync + Send {
    fn eas_search(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

pub struct MailRow {
    pub mail: LoadedMail,
    pub mailbox_id: u32,
    pub server_id: TokenBuf,
    pub collection_id: TokenBuf,
}

impl EasSearch for Server {
    async fn eas_search(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(EasResponse::status(
                Command::Search,
                CommonStatus::INVALID_XML.into(),
            ));
        };
        let request = match SearchRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::Search,
                    err.status(Command::Search),
                ));
            }
        };
        match request.store {
            SearchStore::Gal => gal_search(self, ctx, &request).await,
            SearchStore::Mailbox => mailbox_search(self, ctx, &request).await,
            SearchStore::DocumentLibrary => Ok(store_status(ctx, SearchStatus::NOT_FOUND)),
        }
    }
}

fn store_status(ctx: &EasContext<'_>, status: SearchStatus) -> EasResponse {
    respond(
        ctx,
        SearchStoreResult {
            status,
            results: Vec::new(),
            range: None,
            total: None,
        },
    )
}

pub(super) fn respond(ctx: &EasContext<'_>, store: SearchStoreResult<'_>) -> EasResponse {
    let response = SearchResponse {
        status: Some(SearchStatus::SUCCESS),
        store: Some(store),
    };
    EasResponse::encode(ctx.version, |encoder| response.encode(encoder))
}

async fn gal_search(
    server: &Server,
    ctx: &EasContext<'_>,
    request: &SearchRequest<'_>,
) -> trc::Result<EasResponse> {
    let Some(QueryNode::Text(text)) = request.query.root() else {
        return Ok(store_status(ctx, SearchStatus::INVALID_REQUEST));
    };
    let Some(query) = GalQuery::new(text) else {
        return Ok(store_status(ctx, SearchStatus::INVALID_REQUEST));
    };
    let Some(mut book) = open_directory(server, ctx) else {
        return Ok(store_status(ctx, SearchStatus::ACCESS_DENIED));
    };
    let page = match query.page(&mut book, request.options.range).await {
        Ok(page) => page,
        Err(BookError::OutOfMemory) => return Ok(store_status(ctx, SearchStatus::SERVER_ERROR)),
        Err(BookError::Store(err)) => return Err(err),
    };
    let picture = request.options.picture.as_ref();
    Ok(respond(
        ctx,
        SearchStoreResult {
            status: SearchStatus::SUCCESS,
            results: page
                .entries
                .iter()
                .map(|entry| SearchResult {
                    class: None,
                    long_id: None,
                    collection_id: None,
                    properties: Some(SearchProperties::Gal(gal_entry(entry, picture))),
                })
                .collect(),
            range: page.range,
            total: Some(page.total),
        },
    ))
}

pub(super) fn range_len(range: ItemRange) -> usize {
    usize::try_from(range.end.saturating_sub(range.start))
        .unwrap_or(usize::MAX)
        .saturating_add(1)
}

async fn mailbox_search(
    server: &Server,
    ctx: &EasContext<'_>,
    request: &SearchRequest<'_>,
) -> trc::Result<EasResponse> {
    if request.query.has_and_with_siblings() {
        return Ok(store_status(ctx, SearchStatus::TOO_COMPLEX));
    }
    let groupware = match groupware_scope(server, ctx, &request.query).await? {
        Ok(groupware) => groupware,
        Err(status) => return Ok(store_status(ctx, status)),
    };
    if let Some(groupware) = groupware {
        let kind = groupware.target.kind;
        let mut search = MailSearch {
            fields: match kind {
                GroupwareKind::Calendar | GroupwareKind::Tasks => TextFields::Calendar,
                GroupwareKind::Contacts => TextFields::Contacts,
            },
            ..Default::default()
        };
        let mut builder = QueryBuilder {
            scope: QueryScope::Groupware(kind),
            query: &request.query,
            language: server.core.email.default_language,
            search: &mut search,
            conversation: false,
        };
        if let Err(status) = builder.node(request.query.root, false) {
            return Ok(store_status(ctx, status));
        }
        return groupware_search(server, ctx, request, groupware, search).await;
    }
    if !ctx.allows(EasDataKind::Mail) {
        return Ok(store_status(ctx, SearchStatus::ACCESS_DENIED));
    }
    let options = mail_options(&request.options);
    if options.has_unsupported_body_part() {
        return Ok(store_status(
            ctx,
            CommonStatus::BODY_PART_PREFERENCE_TYPE_NOT_SUPPORTED.into(),
        ));
    }
    let cache = server.get_cached_messages(ctx.account_id).await?;
    let mut search = MailSearch::default();
    let mut builder = QueryBuilder {
        scope: QueryScope::Mail {
            ctx,
            cache: &cache,
            deep: request.options.deep_traversal,
        },
        query: &request.query,
        language: server.core.email.default_language,
        search: &mut search,
        conversation: false,
    };
    if let Err(status) = builder.node(request.query.root, false) {
        return Ok(store_status(ctx, status));
    }
    let hits = search.run(server, ctx.account_id, &cache).await?;
    let total = u32::try_from(hits.len()).unwrap_or(u32::MAX);
    let range = page_range(request.options.range, total, MAX_MAIL_RESULTS);
    let mut rows = load_page(
        server,
        ctx,
        &cache,
        &hits,
        range,
        &options,
        MAX_RESPONSE_BYTES,
    )
    .await?;
    let exchange = server.get_cached_exchange(ctx.account_id).await?;
    let stored = StoredFlags::load(
        server,
        &exchange,
        ctx.account_id,
        &rows
            .iter()
            .map(|row| row.mail.document_id)
            .collect::<RoaringBitmap>(),
    )
    .await?;
    let owner = resolve_meetings(
        server,
        &ctx.access_token,
        ctx.account_id,
        ctx.version,
        &exchange,
        &stored,
        rows.iter_mut().map(|row| &mut row.mail),
    )
    .await?;
    let mut classes: SmallVec<[(u32, Class); 4]> = SmallVec::new();
    let mut results = Vec::with_capacity(rows.len());
    for row in &rows {
        let class = match classes.iter().find(|(id, _)| *id == row.mailbox_id) {
            Some((_, class)) => *class,
            None => {
                let class =
                    mail_class(server, ctx.account_id, &cache, &exchange, row.mailbox_id).await?;
                classes.push((row.mailbox_id, class));
                class
            }
        };
        if let Some(data) = render(&cache, &exchange, &stored, row, class, &owner, ctx.version)? {
            results.push(SearchResult {
                class: Some(class),
                long_id: Some(row.server_id.as_str()),
                collection_id: Some(row.collection_id.as_str()),
                properties: Some(SearchProperties::Item(data)),
            });
        }
    }
    Ok(respond(
        ctx,
        SearchStoreResult {
            status: SearchStatus::SUCCESS,
            range: returned_range(range, results.len()),
            results,
            total: Some(total),
        },
    ))
}

pub async fn load_page(
    server: &Server,
    ctx: &EasContext<'_>,
    cache: &MessageStoreCache,
    hits: &[MailHit],
    range: Option<ItemRange>,
    options: &SyncOptions,
    mut budget: usize,
) -> trc::Result<Vec<MailRow>> {
    let Some(range) = range else {
        return Ok(Vec::new());
    };
    let charge = truncation_limit(options);
    let mut rows = Vec::with_capacity(range_len(range).min(hits.len()));
    for hit in hits
        .iter()
        .skip(range.start as usize)
        .take(range_len(range))
    {
        let Some(size) = cache
            .email_by_id(&hit.document_id)
            .map(|message| message.size() as usize)
        else {
            continue;
        };
        if budget == 0 {
            break;
        }
        budget = budget.saturating_sub(charge.map_or(size, |limit| size.min(limit)));
        if let Some(row) =
            load_row(server, ctx, cache, hit.document_id, hit.mailbox_id, options).await?
        {
            rows.push(row);
        }
    }
    Ok(rows)
}

pub(super) fn truncation_limit(options: &SyncOptions) -> Option<usize> {
    options
        .body_preferences
        .iter()
        .map(|preference| preference.truncation_size)
        .try_fold(0usize, |limit, truncation| {
            truncation.map(|truncation| limit.max(truncation as usize))
        })
        .filter(|_| !options.body_preferences.is_empty())
}

pub async fn load_row(
    server: &Server,
    ctx: &EasContext<'_>,
    cache: &MessageStoreCache,
    document_id: u32,
    mailbox_id: u32,
    options: &SyncOptions,
) -> trc::Result<Option<MailRow>> {
    Ok(
        load_mail(server, ctx.account_id, cache, document_id, Some(options))
            .await?
            .map(|mail| MailRow {
                mail,
                mailbox_id,
                server_id: EasServerId {
                    container: mailbox_id,
                    id: document_id,
                }
                .encode(),
                collection_id: FolderNode::Stored(FolderRef {
                    kind: FolderKind::Mailbox,
                    id: mailbox_id,
                })
                .eas_collection_id(),
            }),
    )
}

fn render<'a>(
    cache: &'a MessageStoreCache,
    exchange: &'a ExchangeAccountCache,
    stored: &'a StoredFlags,
    row: &'a MailRow,
    class: Class,
    owner: &[String],
    version: ProtocolVersion,
) -> trc::Result<Option<ApplicationData<'a>>> {
    let Some(flags) = mail_flags(cache, exchange, stored, row.mail.document_id) else {
        return Ok(None);
    };
    Ok(Some(match class {
        Class::Notes => ApplicationData::Note(Box::new(row.mail.note(flags)?)),
        _ => ApplicationData::Email(Box::new(row.mail.email(flags, owner, version)?)),
    }))
}

pub(super) fn mail_options(options: &SearchOptions<'_>) -> SyncOptions {
    SyncOptions {
        class: Some(Class::Email),
        body_preferences: options.body_preferences.clone(),
        body_part_preferences: options.body_part_preferences.clone(),
        mime_support: options.mime_support,
        rights_management_support: options.rights_management_support,
        ..Default::default()
    }
}

async fn groupware_scope(
    server: &Server,
    ctx: &EasContext<'_>,
    query: &SearchQuery<'_>,
) -> trc::Result<Result<Option<GroupwareScope>, SearchStatus>> {
    let mut ids = SmallVec::<[&str; 2]>::new();
    collection_ids(query, query.root, &mut ids);
    let mut tree: Option<FolderTree> = None;
    let mut scope: Option<GroupwareScope> = None;
    for id in ids {
        let Some(node) = FolderNode::from_eas_collection_id(id) else {
            continue;
        };
        if mail_folder(ctx, node).is_some() {
            return Ok(Ok(None));
        }
        if tree.is_none() {
            tree = Some(
                server
                    .exchange_folder_tree(ctx.account_id, ctx.data_types)
                    .await?,
            );
        }
        let Some(target) = tree
            .as_ref()
            .and_then(|tree| GroupwareTarget::resolve(ctx, tree, node))
        else {
            continue;
        };
        match &scope {
            Some(current) if current.target == target => {}
            Some(_) => return Ok(Err(SearchStatus::TOO_COMPLEX)),
            None => scope = Some(GroupwareScope { target, node }),
        }
    }
    Ok(Ok(scope))
}

fn collection_ids<'q>(query: &'q SearchQuery<'q>, index: u16, ids: &mut SmallVec<[&'q str; 2]>) {
    match query.node(index) {
        Some(QueryNode::And(children)) => {
            for child in children {
                collection_ids(query, *child, ids);
            }
        }
        Some(QueryNode::CollectionId(id)) => ids.push(id),
        _ => {}
    }
}

enum QueryScope<'q, 'x> {
    Mail {
        ctx: &'q EasContext<'x>,
        cache: &'q MessageStoreCache,
        deep: bool,
    },
    Groupware(GroupwareKind),
}

struct QueryBuilder<'q, 'x> {
    scope: QueryScope<'q, 'x>,
    query: &'q SearchQuery<'q>,
    language: Language,
    search: &'q mut MailSearch,
    conversation: bool,
}

impl QueryBuilder<'_, '_> {
    fn node(&mut self, index: u16, in_or: bool) -> Result<(), SearchStatus> {
        let Some(node) = self.query.node(index) else {
            return Err(SearchStatus::INVALID_REQUEST);
        };
        match node {
            QueryNode::And(children) if !in_or => {
                for child in children {
                    self.node(*child, false)?;
                }
            }
            QueryNode::Or(children) if !in_or => {
                self.search.text.push(SearchFilter::Or);
                for child in children {
                    self.node(*child, true)?;
                }
                self.search.text.push(SearchFilter::End);
            }
            QueryNode::FreeText(text) | QueryNode::Text(text) => {
                match self.search.push_text(text, self.language) {
                    TextFit::Truncated => return Err(SearchStatus::TOO_COMPLEX),
                    TextFit::Unconstrained if in_or => return Err(SearchStatus::TOO_COMPLEX),
                    TextFit::Complete | TextFit::Unconstrained => {}
                }
            }
            QueryNode::Class(class) if !in_or => {
                let expected = match self.scope {
                    QueryScope::Mail { .. } => Class::Email,
                    QueryScope::Groupware(kind) => kind.class(),
                };
                if *class != expected {
                    self.search.empty = true;
                }
            }
            QueryNode::CollectionId(collection_id) if !in_or => {
                let QueryScope::Mail { ctx, cache, deep } = self.scope else {
                    return Ok(());
                };
                match self.search.add_folder(ctx, cache, collection_id, deep) {
                    Ok(()) => {}
                    Err(ScopeError::UnknownFolder) => {
                        return Err(SearchStatus::FOLDER_SYNC_REQUIRED);
                    }
                    Err(ScopeError::NotMail) => {}
                }
            }
            QueryNode::ConversationId(_)
            | QueryNode::GreaterThan { .. }
            | QueryNode::LessThan { .. }
                if matches!(self.scope, QueryScope::Groupware(_)) =>
            {
                return Err(SearchStatus::INVALID_REQUEST);
            }
            QueryNode::ConversationId(_) if !in_or && self.conversation => {
                return Err(SearchStatus::NOT_FOUND);
            }
            QueryNode::ConversationId(id) if !in_or => {
                self.conversation = true;
                match id.first_chunk::<CONVERSATION_THREAD_LEN>() {
                    Some(prefix) => self.search.thread_id = Some(u32::from_be_bytes(*prefix)),
                    None => self.search.empty = true,
                }
            }
            QueryNode::GreaterThan { property, value } if !in_or => {
                self.search.after = Some(received_bound(*property, value)?);
            }
            QueryNode::LessThan { property, value } if !in_or => {
                self.search.before = Some(received_bound(*property, value)?);
            }
            QueryNode::EqualTo { .. } | QueryNode::Unsupported(_) => {
                return Err(SearchStatus::INVALID_REQUEST);
            }
            _ => return Err(SearchStatus::TOO_COMPLEX),
        }
        Ok(())
    }
}

fn received_bound(property: Tag, value: &str) -> Result<u64, SearchStatus> {
    if property != email::DATE_RECEIVED {
        return Err(SearchStatus::INVALID_REQUEST);
    }
    EasDateTime::parse(value.as_bytes())
        .map(|date| u64::try_from(date.0.0).unwrap_or(0))
        .ok_or(SearchStatus::INVALID_REQUEST)
}
