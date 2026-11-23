/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{EasContext, EasDataKind},
    convert::flag::StoredFlags,
    directory::{GalQuery, gal_entry, open_directory, page_range, returned_range},
    mail_search::{MailSearch, ScopeError},
    response::EasResponse,
    search::{MAX_MAIL_RESULTS, load_page},
    sync::email::mail_flags,
};
use crate::cache::ExchangeCacheFetch;
use crate::mapi::nspi::book::BookError;
use ::email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use common::Server;
use exchange_proto::eas::{
    commands::{
        ItemRange,
        find::{
            FindCriterion, FindOptions, FindProperties, FindRequest, FindResponse, FindResult,
            FindStoreResult,
        },
        sync::SyncOptions,
    },
    http::Command,
    status::{CommonStatus, FindStatus},
    types::{BodyPreference, BodyType, Class},
    wbxml::Decoder,
};
use smallvec::smallvec;
use types::keyword::DRAFT;

const MAX_FIND_RESULTS: u32 = 1000;
const DRAFT_BIT: u32 = 1 << DRAFT;
const DEFAULT_MAIL_RANGE: ItemRange = ItemRange {
    start: 0,
    end: MAX_MAIL_RESULTS - 1,
};
const STORE_MAILBOX: &str = "Mailbox";
const STORE_GAL: &str = "GAL";

pub trait EasFind: Sync + Send {
    fn eas_find(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

impl EasFind for Server {
    async fn eas_find(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(EasResponse::status(
                Command::Find,
                CommonStatus::INVALID_XML.into(),
            ));
        };
        let request = match FindRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::Find,
                    err.status(Command::Find),
                ));
            }
        };
        match &request.criterion {
            FindCriterion::Mailbox {
                free_text,
                class,
                collection_id,
                options,
            } => {
                if let Some(status) = check_range(options) {
                    return Ok(respond(ctx, empty_store(STORE_MAILBOX, status)));
                }
                find_mail(
                    self,
                    ctx,
                    free_text,
                    *class,
                    collection_id.as_deref(),
                    options,
                )
                .await
            }
            FindCriterion::Gal { query, options } => {
                if let Some(status) = check_range(options) {
                    return Ok(respond(ctx, empty_store(STORE_GAL, status)));
                }
                find_gal(self, ctx, query, options).await
            }
        }
    }
}

fn check_range(options: &FindOptions) -> Option<FindStatus> {
    match options.range {
        Some(range) if range.end >= MAX_FIND_RESULTS => Some(FindStatus::INVALID_REQUEST),
        _ => None,
    }
}

fn empty_store(store: &'static str, status: FindStatus) -> FindStoreResult<'static> {
    FindStoreResult {
        store,
        status,
        results: Vec::new(),
        range: None,
        total: 0,
    }
}

fn respond(ctx: &EasContext<'_>, store: FindStoreResult<'_>) -> EasResponse {
    let response = FindResponse {
        status: FindStatus::SUCCESS,
        response: Some(store),
    };
    EasResponse::encode(ctx.version, |encoder| response.encode(encoder))
}

fn find_status(ctx: &EasContext<'_>, status: FindStatus) -> EasResponse {
    let response = FindResponse {
        status,
        response: None,
    };
    EasResponse::encode(ctx.version, |encoder| response.encode(encoder))
}

async fn find_gal(
    server: &Server,
    ctx: &EasContext<'_>,
    query: &str,
    options: &FindOptions,
) -> trc::Result<EasResponse> {
    let Some(query) = GalQuery::new(query) else {
        return Ok(find_status(ctx, FindStatus::INVALID_REQUEST));
    };
    let Some(mut book) = open_directory(server, ctx) else {
        return Ok(respond(ctx, empty_store(STORE_GAL, FindStatus::SUCCESS)));
    };
    let page = match query.page(&mut book, options.range).await {
        Ok(page) => page,
        Err(BookError::OutOfMemory) => {
            return Ok(respond(ctx, empty_store(STORE_GAL, FindStatus::SUCCESS)));
        }
        Err(BookError::Store(err)) => return Err(err),
    };
    let picture = options.picture.as_ref();
    Ok(respond(
        ctx,
        FindStoreResult {
            store: STORE_GAL,
            status: FindStatus::SUCCESS,
            results: page
                .entries
                .iter()
                .map(|entry| FindResult {
                    class: None,
                    server_id: None,
                    collection_id: None,
                    properties: FindProperties::Gal(gal_entry(entry, picture)),
                })
                .collect(),
            range: page.range,
            total: page.total,
        },
    ))
}

async fn find_mail(
    server: &Server,
    ctx: &EasContext<'_>,
    free_text: &str,
    class: Option<Class>,
    collection_id: Option<&str>,
    options: &FindOptions,
) -> trc::Result<EasResponse> {
    if !ctx.allows(EasDataKind::Mail) {
        return Ok(respond(
            ctx,
            empty_store(STORE_MAILBOX, FindStatus::SUCCESS),
        ));
    }
    let cache = server.get_cached_messages(ctx.account_id).await?;
    let mut search = MailSearch::default();
    search.push_text(free_text, server.core.email.default_language);
    if class.is_some_and(|class| class != Class::Email) {
        search.empty = true;
    }
    if let Some(collection_id) = collection_id {
        match search.add_folder(ctx, &cache, collection_id, options.deep_traversal) {
            Ok(()) => {}
            Err(ScopeError::UnknownFolder) => {
                return Ok(find_status(ctx, FindStatus::FOLDER_SYNC_REQUIRED));
            }
            Err(ScopeError::NotMail) => {}
        }
    }
    let hits = search.run(server, ctx.account_id, &cache).await?;
    let total = u32::try_from(hits.len()).unwrap_or(u32::MAX);
    let range = page_range(
        Some(options.range.unwrap_or(DEFAULT_MAIL_RANGE)),
        total,
        MAX_FIND_RESULTS,
    );
    let sync_options = SyncOptions {
        class: Some(Class::Email),
        body_preferences: smallvec![BodyPreference {
            body_type: BodyType::Plain,
            truncation_size: Some(0),
            all_or_none: false,
            preview: None,
        }],
        ..Default::default()
    };
    let rows = load_page(server, ctx, &cache, &hits, range, &sync_options, usize::MAX).await?;
    let exchange = if rows.is_empty() {
        None
    } else {
        Some(server.get_cached_exchange(ctx.account_id).await?)
    };
    let stored = StoredFlags::default();
    let mut results = Vec::with_capacity(rows.len());
    for row in &rows {
        let Some(flags) = exchange
            .as_deref()
            .and_then(|exchange| mail_flags(&cache, exchange, &stored, row.mail.document_id))
        else {
            continue;
        };
        let draft = cache
            .email_by_id(&row.mail.document_id)
            .is_some_and(|message| message.keywords() & DRAFT_BIT != 0);
        results.push(FindResult {
            class: Some(Class::Email),
            server_id: Some(row.server_id.as_str()),
            collection_id: Some(row.collection_id.as_str()),
            properties: FindProperties::Mail(row.mail.find_properties(flags, draft)?),
        });
    }
    Ok(respond(
        ctx,
        FindStoreResult {
            store: STORE_MAILBOX,
            status: FindStatus::SUCCESS,
            range: returned_range(range, results.len()),
            results,
            total,
        },
    ))
}
