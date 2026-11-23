/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod filter;
mod window;

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/jmap/src/email/query/tests.rs"]
mod tests;

use crate::{
    api::{
        metadata::{MetadataType, ObjectMetadata},
        query::QueryResponseBuilder,
    },
    changes::state::JmapCacheState,
};
use common::{
    MessageStoreCache, MessagesCache, Server, auth::AccessToken, cache::email::MessageRef,
};
use compact_str::ToCompactString;
use email::{
    cache::{
        MessageCacheFetch,
        email::{MessageAccess, MessageCacheAccess, thread_keywords},
        mailbox::MailboxCacheAccess,
    },
    message::{
        query::{QueryFilter, RowFilter},
        sortkeys::{
            CacheSorter, EmailSortKeys, MessageCacheField, MessageComparator, MessageSortField,
        },
    },
};
use filter::parse_filter;
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse},
    object::email::{Email, EmailComparator, EmailQueryFilter},
    request::capability::CapabilityIds,
    types::state::State,
};
use std::future::Future;
use store::{
    roaring::RoaringBitmap,
    search::{SearchComparator, SearchQuery},
    write::SearchIndex,
};
use trc::AddContext;
use types::acl::Acl;
use window::{TextSource, TextWindow, WindowedWalk};

const SPARSE_RESIDUAL_RATIO: u64 = 8;

pub trait EmailQuery: Sync + Send {
    fn email_query(
        &self,
        request: QueryRequest<Email>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkOrder {
    Ascending,
    Descending,
}

enum Plan {
    Walk(WalkOrder),
    TopK(CacheSorter),
    Sorted(Vec<MessageComparator>),
}

enum Candidates {
    All,
    Positions(Vec<u32>),
}

enum Pending {
    Ready(Page),
    Sort {
        page: Page,
        matches: RoaringBitmap,
        comparators: Vec<MessageComparator>,
    },
    Window {
        page: Page,
        candidates: Candidates,
        order: WalkOrder,
        text: TextWindow,
    },
}

struct Page {
    builder: QueryResponseBuilder,
    threads: Option<RoaringBitmap>,
    total: usize,
}

impl EmailQuery for Server {
    async fn email_query(
        &self,
        mut request: QueryRequest<Email>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let object_metadata = ObjectMetadata::new(self, access_token, using, MetadataType::Email);
        let sampled = object_metadata.viewer_change_id(self, account_id).await?;
        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        let access = if access_token.is_shared(account_id) {
            MessageAccess::Mailboxes(cache.shared_mailboxes(access_token, Acl::ReadItems))
        } else {
            MessageAccess::All
        };
        let metadata =
            object_metadata.query(request.filter.iter().filter_map(|filter| match filter {
                Filter::Property(EmailQueryFilter::Metadata(filter)) => Some(filter),
                _ => None,
            }))?;
        let metadata_matches = object_metadata
            .evaluate(self, account_id, &metadata, || {
                cache
                    .with_metadata()
                    .filter(|message| access.allows(*message))
                    .map(|message| message.document_id())
                    .collect::<RoaringBitmap>()
            })
            .await?;
        let filter = parse_filter(
            std::mem::take(&mut request.filter),
            &cache,
            access,
            metadata_matches.into_iter(),
            self.core.email.default_language,
        )?;
        let mut comparators = sort_comparators(request.sort.take())?;
        let query_state = sampled.state(cache.get_state(false));
        let max_results = self.core.jmap.query_max_results;

        let Some(mut filter) = filter.filter(|query| !query.row.access.is_empty()) else {
            return Page::new(&request, max_results, query_state).finish();
        };

        restrict_thread_keywords(&mut comparators, &cache, &mut filter);
        let windowed = if self.search_store().supports_windowed_walk() {
            let resolve_rows = self
                .search_store()
                .account_query_rows(cache.emails.len() as u64);
            WindowedWalk::of(
                &request,
                &comparators,
                &mut filter,
                account_id,
                resolve_rows,
            )
        } else {
            None
        };
        let residual_filters = filter.residual_filters();
        if !residual_filters.is_empty() {
            let residual = self
                .search_store()
                .filter_account(
                    SearchQuery::new(SearchIndex::Email)
                        .with_filters(residual_filters)
                        .with_account_id(account_id)
                        .with_mask(filter.readable(&cache)),
                )
                .await
                .caused_by(trc::location!())?;
            if residual.is_empty() {
                return Page::new(&request, max_results, query_state).finish();
            }
            filter.row.residual = Some(residual);
        }

        let mut row = filter.into_row();
        match Pending::new(
            &cache,
            &mut row,
            comparators,
            request,
            max_results,
            query_state,
            windowed,
        ) {
            Pending::Ready(page) => page.finish(),
            Pending::Window {
                mut page,
                candidates,
                order,
                text,
            } => {
                page.walk_windowed(
                    TextSource::Store(self),
                    &cache,
                    &mut row,
                    &candidates,
                    order,
                    text,
                )
                .await?;
                page.finish()
            }
            Pending::Sort {
                mut page,
                matches,
                comparators,
            } => {
                let results = self
                    .query_emails(
                        account_id,
                        &cache,
                        SearchQuery::new(SearchIndex::Email)
                            .with_account_id(account_id)
                            .with_mask(matches),
                        comparators,
                    )
                    .await?;
                page.feed(&cache, results);
                page.finish()
            }
        }
    }
}

impl Pending {
    fn new(
        cache: &MessageStoreCache,
        filter: &mut RowFilter,
        comparators: Vec<MessageComparator>,
        mut request: QueryRequest<Email>,
        max_results: usize,
        query_state: State,
        windowed: Option<WindowedWalk>,
    ) -> Self {
        let candidates = Candidates::new(&cache.emails, filter);
        if let Some(WindowedWalk {
            order,
            query,
            resolve_rows,
        }) = windowed
        {
            let page = Page::new(&request, max_results, query_state);
            let wanted = usize::try_from(request.position.unwrap_or(0))
                .unwrap_or(0)
                .saturating_add(page.builder.limit);
            if wanted == 0 {
                return Pending::Ready(page);
            }
            let count = match (&candidates, &filter.residual) {
                (Candidates::All, Some(residual)) => {
                    usize::try_from(residual.len()).unwrap_or(usize::MAX)
                }
                (candidates, _) => candidates.len(&cache.emails),
            };
            return Pending::Window {
                text: TextWindow::new(query, wanted, count, resolve_rows),
                page,
                candidates,
                order,
            };
        }
        let plan = Plan::new(&request, cache, comparators);
        if request.anchor.is_none()
            && let Some(position) = request.position.filter(|position| *position < 0)
            && !matches!(plan, Plan::Sorted(_))
        {
            let total = candidates.count(&cache.emails, filter, collapse_threads(&request));
            let start = i64::try_from(total)
                .unwrap_or(i64::MAX)
                .saturating_add(i64::from(position))
                .max(0);
            request.position = Some(i32::try_from(start).unwrap_or(i32::MAX));
        }

        let mut page = Page::new(&request, max_results, query_state);
        match plan {
            Plan::Walk(order) => {
                page.walk(&cache.emails, filter, &candidates, order);
                Pending::Ready(page)
            }
            Plan::TopK(sorter) => {
                let start = usize::try_from(request.position.unwrap_or(0)).unwrap_or(0);
                page.top(cache, filter, &candidates, &sorter, start);
                Pending::Ready(page)
            }
            Plan::Sorted(comparators) => Pending::Sort {
                page,
                matches: candidates.matches(&cache.emails, filter),
                comparators,
            },
        }
    }
}

fn restrict_thread_keywords(
    comparators: &mut [MessageComparator],
    cache: &MessageStoreCache,
    filter: &mut QueryFilter,
) {
    for comparator in comparators {
        if let MessageComparator::Cache {
            field: MessageCacheField::ThreadKeyword { keyword, match_all },
            ascending,
        } = comparator
            && let Some(visible) = filter.visible(cache)
        {
            let documents = thread_keywords(cache, keyword, *match_all, None, Some(visible));
            *comparator = MessageComparator::Search(SearchComparator::set(documents, *ascending));
        }
    }
}

fn collapse_threads(request: &QueryRequest<Email>) -> bool {
    request.arguments.collapse_threads.unwrap_or(false)
}

impl Plan {
    fn walk_order(comparators: &[MessageComparator]) -> Option<WalkOrder> {
        match comparators {
            [] => Some(WalkOrder::Ascending),
            [
                MessageComparator::Cache {
                    field: MessageCacheField::ReceivedAt,
                    ascending,
                },
            ] => Some(if *ascending {
                WalkOrder::Ascending
            } else {
                WalkOrder::Descending
            }),
            _ => None,
        }
    }

    fn new(
        request: &QueryRequest<Email>,
        cache: &MessageStoreCache,
        comparators: Vec<MessageComparator>,
    ) -> Self {
        if let Some(order) = Plan::walk_order(&comparators) {
            return Plan::Walk(order);
        }
        match comparators.as_slice() {
            _ if !collapse_threads(request) && request.anchor.is_none() => {
                match CacheSorter::new(cache, comparators) {
                    Ok(sorter) => Plan::TopK(sorter),
                    Err(comparators) => Plan::Sorted(comparators),
                }
            }
            _ => Plan::Sorted(comparators),
        }
    }
}

impl WindowedWalk {
    fn of(
        request: &QueryRequest<Email>,
        comparators: &[MessageComparator],
        filter: &mut QueryFilter,
        account_id: u32,
        resolve_rows: Option<f64>,
    ) -> Option<Self> {
        let order = Plan::walk_order(comparators)?;
        if request.anchor.is_some()
            || request.calculate_total.unwrap_or(false)
            || request.position.is_some_and(|position| position < 0)
        {
            return None;
        }
        filter.take_text().map(|filters| WindowedWalk {
            order,
            query: SearchQuery::new(SearchIndex::Email)
                .with_filters(filters)
                .with_account_id(account_id),
            resolve_rows,
        })
    }
}

impl Candidates {
    fn new(cache: &MessagesCache, filter: &mut RowFilter) -> Self {
        match filter.residual.take() {
            Some(residual)
                if residual.len().saturating_mul(SPARSE_RESIDUAL_RATIO) < cache.len() as u64 =>
            {
                let mut positions = residual
                    .iter()
                    .filter_map(|document_id| cache.position(document_id))
                    .collect::<Vec<_>>();
                positions.sort_unstable();
                Candidates::Positions(positions)
            }
            residual => {
                filter.residual = residual;
                Candidates::All
            }
        }
    }

    fn len(&self, cache: &MessagesCache) -> usize {
        match self {
            Candidates::All => cache.len(),
            Candidates::Positions(positions) => positions.len(),
        }
    }

    fn count(&self, cache: &MessagesCache, filter: &RowFilter, collapse_threads: bool) -> usize {
        match self {
            Candidates::All => count_matches(cache.iter(), filter, collapse_threads),
            Candidates::Positions(positions) => count_matches(
                positions.iter().filter_map(|position| cache.at(*position)),
                filter,
                collapse_threads,
            ),
        }
    }

    fn matches(&self, cache: &MessagesCache, filter: &RowFilter) -> RoaringBitmap {
        match self {
            Candidates::All => matching_ids(cache.iter(), filter),
            Candidates::Positions(positions) => matching_ids(
                positions.iter().filter_map(|position| cache.at(*position)),
                filter,
            ),
        }
    }
}

fn count_matches<'x>(
    messages: impl Iterator<Item = MessageRef<'x>>,
    filter: &RowFilter,
    collapse_threads: bool,
) -> usize {
    if collapse_threads {
        let mut threads = RoaringBitmap::new();
        messages
            .filter(|message| filter.matches(*message) && threads.insert(message.thread_id()))
            .count()
    } else {
        messages.filter(|message| filter.matches(*message)).count()
    }
}

fn matching_ids<'x>(
    messages: impl Iterator<Item = MessageRef<'x>>,
    filter: &RowFilter,
) -> RoaringBitmap {
    messages
        .filter(|message| filter.matches(*message))
        .map(|message| message.document_id())
        .collect()
}

impl Page {
    fn new(request: &QueryRequest<Email>, max_results: usize, query_state: State) -> Self {
        Page {
            builder: QueryResponseBuilder::new_streaming(max_results, query_state, request),
            threads: collapse_threads(request).then(RoaringBitmap::new),
            total: 0,
        }
    }

    fn emit(&mut self, message: MessageRef<'_>) -> bool {
        if self
            .threads
            .as_mut()
            .is_some_and(|threads| !threads.insert(message.thread_id()))
        {
            return true;
        }
        self.total += 1;
        self.builder.add(message.thread_id(), message.document_id())
    }

    fn count(&mut self, message: MessageRef<'_>) {
        if self
            .threads
            .as_mut()
            .is_none_or(|threads| threads.insert(message.thread_id()))
        {
            self.total += 1;
        }
    }

    fn fill<'x>(
        &mut self,
        filter: &RowFilter,
        messages: &mut impl Iterator<Item = MessageRef<'x>>,
    ) -> bool {
        for message in messages {
            if filter.matches(message) && !self.emit(message) {
                return true;
            }
        }
        false
    }

    fn count_rest<'x>(
        &mut self,
        filter: &RowFilter,
        messages: impl Iterator<Item = MessageRef<'x>>,
    ) {
        for message in messages {
            if filter.matches(message) {
                self.count(message);
            }
        }
    }

    fn walk(
        &mut self,
        cache: &MessagesCache,
        filter: &RowFilter,
        candidates: &Candidates,
        order: WalkOrder,
    ) {
        let counts = self.builder.wants_total();
        match (candidates, order) {
            (Candidates::All, WalkOrder::Ascending) => {
                let mut messages = cache.iter();
                if self.fill(filter, &mut messages) && counts {
                    self.count_rest(filter, messages);
                }
            }
            (Candidates::All, WalkOrder::Descending) => {
                let mut messages = cache.iter().rev();
                if self.fill(filter, &mut messages) && counts {
                    self.count_rest(filter, messages);
                }
            }
            (Candidates::Positions(positions), WalkOrder::Ascending) => {
                let mut messages = positions.iter().filter_map(|position| cache.at(*position));
                if self.fill(filter, &mut messages) && counts {
                    self.count_rest(filter, messages);
                }
            }
            (Candidates::Positions(positions), WalkOrder::Descending) => {
                let mut messages = positions
                    .iter()
                    .rev()
                    .filter_map(|position| cache.at(*position));
                if self.fill(filter, &mut messages) && counts {
                    self.count_rest(filter, messages);
                }
            }
        }
    }

    fn top(
        &mut self,
        cache: &MessageStoreCache,
        filter: &RowFilter,
        candidates: &Candidates,
        sorter: &CacheSorter,
        start: usize,
    ) {
        let count = start.saturating_add(self.builder.limit);
        let (messages, total) = match candidates {
            Candidates::All => sorter.top(
                cache,
                cache
                    .emails
                    .iter()
                    .filter(|message| filter.matches(*message)),
                count,
            ),
            Candidates::Positions(positions) => sorter.top(
                cache,
                positions
                    .iter()
                    .filter_map(|position| cache.emails.at(*position))
                    .filter(|message| filter.matches(*message)),
                count,
            ),
        };
        self.total = total;
        for (document_id, thread_id) in messages {
            if !self.builder.add(thread_id, document_id) {
                break;
            }
        }
    }

    fn feed(&mut self, cache: &MessageStoreCache, results: Vec<u32>) {
        let counts = self.builder.wants_total();
        let mut results = results
            .into_iter()
            .filter_map(|document_id| cache.email_by_id(&document_id));
        for message in results.by_ref() {
            if !self.emit(message) {
                break;
            }
        }
        if counts {
            for message in results {
                self.count(message);
            }
        }
    }

    fn finish(self) -> trc::Result<QueryResponse> {
        let total = self.builder.wants_total().then_some(self.total);
        self.builder.finish(total)
    }
}

fn sort_comparators(
    sort: Option<Vec<Comparator<EmailComparator>>>,
) -> trc::Result<Vec<MessageComparator>> {
    let sort = sort.filter(|sort| !sort.is_empty()).unwrap_or_default();
    let mut comparators = Vec::with_capacity(sort.len());
    for comparator in sort {
        let ascending = comparator.is_ascending;
        comparators.push(match comparator.property {
            EmailComparator::ReceivedAt => MessageComparator::Cache {
                field: MessageCacheField::ReceivedAt,
                ascending,
            },
            EmailComparator::Size => MessageComparator::Cache {
                field: MessageCacheField::Size,
                ascending,
            },
            EmailComparator::From => MessageComparator::SortKey {
                field: MessageSortField::From,
                ascending,
            },
            EmailComparator::To => MessageComparator::SortKey {
                field: MessageSortField::To,
                ascending,
            },
            EmailComparator::Subject => MessageComparator::SortKey {
                field: MessageSortField::Subject,
                ascending,
            },
            EmailComparator::SentAt => MessageComparator::Cache {
                field: MessageCacheField::SentAt,
                ascending,
            },
            EmailComparator::HasKeyword(keyword) => MessageComparator::Cache {
                field: MessageCacheField::Keyword(keyword),
                ascending,
            },
            EmailComparator::AllInThreadHaveKeyword(keyword) => MessageComparator::Cache {
                field: MessageCacheField::ThreadKeyword {
                    keyword,
                    match_all: true,
                },
                ascending,
            },
            EmailComparator::SomeInThreadHaveKeyword(keyword) => MessageComparator::Cache {
                field: MessageCacheField::ThreadKeyword {
                    keyword,
                    match_all: false,
                },
                ascending,
            },
            other => {
                return Err(trc::JmapEvent::UnsupportedSort
                    .into_err()
                    .details(other.to_compact_string()));
            }
        });
    }
    Ok(comparators)
}
