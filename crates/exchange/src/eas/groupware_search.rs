/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EasContext,
    convert::body::BodyChoice,
    directory::{page_range, returned_range},
    mail_search::MailSearch,
    response::{EasResponse, MAX_RESPONSE_BYTES},
    search::{MAX_MAIL_RESULTS, mail_options, range_len, respond, truncation_limit},
    sync::groupware::{GroupwareTarget, load_item, render_context},
};
use crate::folders::FolderNode;
use common::Server;
use exchange_proto::{
    eas::{
        commands::search::{SearchProperties, SearchRequest, SearchResult, SearchStoreResult},
        status::SearchStatus,
    },
    ids::eas::EasServerId,
};
use groupware::cache::GroupwareCache;
use std::cmp::Reverse;
use store::search::SearchQuery;
use trc::AddContext;

pub struct GroupwareScope {
    pub target: GroupwareTarget,
    pub node: FolderNode,
}

struct Hit {
    document_id: u32,
    size: u32,
}

pub async fn groupware_search(
    server: &Server,
    ctx: &EasContext<'_>,
    request: &SearchRequest<'_>,
    scope: GroupwareScope,
    search: MailSearch,
) -> trc::Result<EasResponse> {
    let kind = scope.target.kind;
    let hits = if search.empty {
        Vec::new()
    } else {
        let resources = server
            .fetch_groupware_resources(ctx.account_id, ctx.account_id, kind.collection())
            .await?;
        let mut hits: Vec<Hit> = resources
            .children(scope.target.container_id)
            .filter(|path| !path.is_container())
            .map(|path| Hit {
                document_id: path.document_id(),
                size: path.size(),
            })
            .collect();
        if !search.text.is_empty() && !hits.is_empty() {
            let matches = server
                .search_store()
                .filter_account(
                    SearchQuery::new(search.fields.index())
                        .with_filters(search.text)
                        .with_account_id(ctx.account_id)
                        .with_mask(hits.iter().map(|hit| hit.document_id).collect()),
                )
                .await
                .caused_by(trc::location!())?;
            hits.retain(|hit| matches.contains(hit.document_id));
        }
        hits.sort_unstable_by_key(|hit| Reverse(hit.document_id));
        hits
    };
    let total = u32::try_from(hits.len()).unwrap_or(u32::MAX);
    let range = page_range(request.options.range, total, MAX_MAIL_RESULTS);
    let mut items = Vec::new();
    if let Some(range) = range {
        let options = mail_options(&request.options);
        let body = BodyChoice::select(Some(&options), false);
        let charge = truncation_limit(&options);
        let mut budget = MAX_RESPONSE_BYTES;
        items.reserve(range_len(range).min(hits.len()));
        for hit in hits
            .iter()
            .skip(range.start as usize)
            .take(range_len(range))
        {
            if budget == 0 {
                break;
            }
            let size = hit.size as usize;
            budget = budget.saturating_sub(charge.map_or(size, |limit| size.min(limit)));
            if let Some(item) =
                load_item(server, ctx.account_id, kind, hit.document_id, body).await?
            {
                let server_id = EasServerId {
                    container: scope.target.container_id,
                    id: hit.document_id,
                }
                .encode();
                items.push((server_id, item));
            }
        }
    }
    let context = if items.is_empty() {
        None
    } else {
        Some(render_context(server, ctx.account_id, ctx.version).await?)
    };
    let collection_id = scope.node.eas_collection_id();
    let results: Vec<SearchResult<'_>> = context
        .as_ref()
        .map(|context| {
            items
                .iter()
                .filter_map(|(server_id, item)| {
                    Some(SearchResult {
                        class: Some(kind.class()),
                        long_id: Some(server_id.as_str()),
                        collection_id: Some(collection_id.as_str()),
                        properties: Some(SearchProperties::Item(item.render(context)?)),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
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
