/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use common::{MessageStoreCache, Server, auth::AccessToken};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::email::{Email, EmailComparator, EmailFilter},
};
use mail_parser::HeaderName;
use nlp::language::Language;
use std::future::Future;
use store::{
    ahash::{AHashMap, AHashSet},
    roaring::RoaringBitmap,
    search::{
        EmailSearchField, SearchComparator, SearchFilter, SearchOperator, SearchQuery, SearchValue,
    },
    write::SearchIndex,
};
use trc::AddContext;
use types::{acl::Acl, keyword::Keyword};
use utils::map::vec_map::VecMap;

pub trait EmailQuery: Sync + Send {
    fn email_query(
        &self,
        request: QueryRequest<Email>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl EmailQuery for Server {
    async fn email_query(
        &self,
        mut request: QueryRequest<Email>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());
        let cached_messages = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;

        for filter in std::mem::take(&mut request.filter) {
            match filter {
                Filter::Property(cond) => match cond {
                    EmailFilter::Text(text) => {
                        let (text, language) =
                            Language::detect(text, self.core.jmap.default_language);

                        filters.push(SearchFilter::Or);
                        filters.push(SearchFilter::has_text(
                            EmailSearchField::From,
                            &text,
                            Language::None,
                        ));
                        filters.push(SearchFilter::has_text(
                            EmailSearchField::To,
                            &text,
                            Language::None,
                        ));
                        filters.push(SearchFilter::has_text(
                            EmailSearchField::Cc,
                            &text,
                            Language::None,
                        ));
                        filters.push(SearchFilter::has_text(
                            EmailSearchField::Bcc,
                            &text,
                            Language::None,
                        ));
                        filters.push(SearchFilter::has_text(
                            EmailSearchField::Subject,
                            &text,
                            language,
                        ));
                        filters.push(SearchFilter::has_text(
                            EmailSearchField::Body,
                            &text,
                            language,
                        ));
                        filters.push(SearchFilter::has_text(
                            EmailSearchField::Attachment,
                            text,
                            language,
                        ));
                        filters.push(SearchFilter::End);
                    }
                    EmailFilter::From(text) => filters.push(SearchFilter::has_text(
                        EmailSearchField::From,
                        text,
                        Language::None,
                    )),
                    EmailFilter::To(text) => filters.push(SearchFilter::has_text(
                        EmailSearchField::To,
                        text,
                        Language::None,
                    )),
                    EmailFilter::Cc(text) => filters.push(SearchFilter::has_text(
                        EmailSearchField::Cc,
                        text,
                        Language::None,
                    )),
                    EmailFilter::Bcc(text) => filters.push(SearchFilter::has_text(
                        EmailSearchField::Bcc,
                        text,
                        Language::None,
                    )),
                    EmailFilter::Subject(text) => filters.push(SearchFilter::has_text_detect(
                        EmailSearchField::Subject,
                        text,
                        self.core.jmap.default_language,
                    )),
                    EmailFilter::Body(text) => filters.push(SearchFilter::has_text_detect(
                        EmailSearchField::Body,
                        text,
                        self.core.jmap.default_language,
                    )),
                    EmailFilter::Header(header) => {
                        let mut header = header.into_iter();
                        let header_name = header.next().ok_or_else(|| {
                            trc::JmapEvent::InvalidArguments
                                .into_err()
                                .details("Header name is missing.".to_string())
                        })?;

                        if let Some(header_name) = HeaderName::parse(header_name) {
                            let value = header.next();
                            let op = if matches!(
                                header_name,
                                HeaderName::MessageId
                                    | HeaderName::InReplyTo
                                    | HeaderName::References
                                    | HeaderName::ResentMessageId
                            ) || value.is_none()
                            {
                                SearchOperator::Equal
                            } else {
                                SearchOperator::Contains
                            };

                            filters.push(SearchFilter::cond(
                                EmailSearchField::Headers,
                                op,
                                SearchValue::KeyValues(VecMap::with_capacity(1).with_append(
                                    header_name.as_str().to_lowercase(),
                                    value.unwrap_or_default(),
                                )),
                            ));
                        }
                    }
                    EmailFilter::InMailbox(mailbox) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cached_messages
                                .in_mailbox(mailbox.document_id())
                                .map(|item| item.document_id),
                        )))
                    }
                    EmailFilter::InMailboxOtherThan(mailboxes) => {
                        let mailboxes = mailboxes
                            .into_iter()
                            .map(|m| m.document_id())
                            .collect::<AHashSet<_>>();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cached_messages.emails.items.iter().filter_map(|item| {
                                if item
                                    .mailboxes
                                    .iter()
                                    .any(|mb| mailboxes.contains(&mb.mailbox_id))
                                {
                                    None
                                } else {
                                    Some(item.document_id)
                                }
                            }),
                        )));
                    }
                    EmailFilter::Before(date) => filters.push(SearchFilter::lt(
                        EmailSearchField::ReceivedAt,
                        date.timestamp(),
                    )),
                    EmailFilter::After(date) => filters.push(SearchFilter::gt(
                        EmailSearchField::ReceivedAt,
                        date.timestamp(),
                    )),
                    EmailFilter::MinSize(size) => {
                        filters.push(SearchFilter::ge(EmailSearchField::Size, size))
                    }
                    EmailFilter::MaxSize(size) => {
                        filters.push(SearchFilter::lt(EmailSearchField::Size, size))
                    }
                    EmailFilter::AllInThreadHaveKeyword(keyword) => filters.push(
                        SearchFilter::is_in_set(thread_keywords(&cached_messages, keyword, true)),
                    ),
                    EmailFilter::SomeInThreadHaveKeyword(keyword) => filters.push(
                        SearchFilter::is_in_set(thread_keywords(&cached_messages, keyword, false)),
                    ),
                    EmailFilter::NoneInThreadHaveKeyword(keyword) => {
                        filters.push(SearchFilter::Not);
                        filters.push(SearchFilter::is_in_set(thread_keywords(
                            &cached_messages,
                            keyword,
                            false,
                        )));
                        filters.push(SearchFilter::End);
                    }
                    EmailFilter::HasKeyword(keyword) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cached_messages
                                .with_keyword(&keyword)
                                .map(|item| item.document_id),
                        )));
                    }
                    EmailFilter::NotKeyword(keyword) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cached_messages
                                .without_keyword(&keyword)
                                .map(|item| item.document_id),
                        )));
                    }
                    EmailFilter::HasAttachment(has_attach) => {
                        filters.push(SearchFilter::eq(
                            EmailSearchField::HasAttachment,
                            has_attach,
                        ));
                    }

                    // Non-standard
                    EmailFilter::Id(ids) => {
                        let mut set = RoaringBitmap::new();
                        for id in ids {
                            set.insert(id.document_id());
                        }
                        filters.push(SearchFilter::is_in_set(set));
                    }
                    EmailFilter::SentBefore(date) => {
                        filters.push(SearchFilter::lt(EmailSearchField::SentAt, date.timestamp()))
                    }
                    EmailFilter::SentAfter(date) => {
                        filters.push(SearchFilter::gt(EmailSearchField::SentAt, date.timestamp()))
                    }
                    EmailFilter::InThread(id) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cached_messages
                                .in_thread(id.document_id())
                                .map(|item| item.document_id),
                        )))
                    }
                    other => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(other.to_string()));
                    }
                },
                Filter::And => {
                    filters.push(SearchFilter::And);
                }
                Filter::Or => {
                    filters.push(SearchFilter::Or);
                }
                Filter::Not => {
                    filters.push(SearchFilter::Not);
                }
                Filter::Close => {
                    filters.push(SearchFilter::End);
                }
            }
        }

        // Parse sort criteria
        let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
        for comparator in request
            .sort
            .take()
            .filter(|s| !s.is_empty())
            .unwrap_or_default()
        {
            comparators.push(match comparator.property {
                EmailComparator::ReceivedAt => {
                    SearchComparator::field(EmailSearchField::ReceivedAt, comparator.is_ascending)
                }
                EmailComparator::Size => {
                    SearchComparator::field(EmailSearchField::Size, comparator.is_ascending)
                }
                EmailComparator::From => {
                    SearchComparator::field(EmailSearchField::From, comparator.is_ascending)
                }
                EmailComparator::To => {
                    SearchComparator::field(EmailSearchField::To, comparator.is_ascending)
                }
                EmailComparator::Subject => {
                    SearchComparator::field(EmailSearchField::Subject, comparator.is_ascending)
                }
                EmailComparator::SentAt => {
                    SearchComparator::field(EmailSearchField::SentAt, comparator.is_ascending)
                }
                EmailComparator::HasKeyword(keyword) => SearchComparator::set(
                    RoaringBitmap::from_iter(
                        cached_messages
                            .with_keyword(&keyword)
                            .map(|item| item.document_id),
                    ),
                    comparator.is_ascending,
                ),
                EmailComparator::AllInThreadHaveKeyword(keyword) => SearchComparator::set(
                    thread_keywords(&cached_messages, keyword, true),
                    comparator.is_ascending,
                ),
                EmailComparator::SomeInThreadHaveKeyword(keyword) => SearchComparator::set(
                    thread_keywords(&cached_messages, keyword, false),
                    comparator.is_ascending,
                ),
                // Non-standard
                EmailComparator::Cc => {
                    SearchComparator::field(EmailSearchField::Cc, comparator.is_ascending)
                }

                other => {
                    return Err(trc::JmapEvent::UnsupportedSort
                        .into_err()
                        .details(other.to_string()));
                }
            });
        }

        let results = self
            .search_store()
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(filters)
                    .with_comparators(comparators)
                    .with_account_id(account_id)
                    .with_mask(if access_token.is_shared(account_id) {
                        cached_messages.shared_messages(access_token, Acl::ReadItems)
                    } else {
                        cached_messages
                            .emails
                            .items
                            .iter()
                            .map(|item| item.document_id)
                            .collect()
                    }),
            )
            .await?;

        let mut response = QueryResponseBuilder::new(
            results.len(),
            self.core.jmap.query_max_results,
            cached_messages.get_state(false),
            &request,
        );

        if !results.is_empty() {
            let collapse_threads = request.arguments.collapse_threads.unwrap_or(false);
            let mut seen_thread_ids = AHashSet::new();

            for document_id in results {
                let Some(thread_id) = cached_messages
                    .email_by_id(&document_id)
                    .map(|email| email.thread_id)
                else {
                    continue;
                };
                if collapse_threads && !seen_thread_ids.insert(thread_id) {
                    continue;
                }

                if !response.add(thread_id, document_id) {
                    break;
                }
            }
        }

        response.build()
    }
}

fn thread_keywords(cache: &MessageStoreCache, keyword: Keyword, match_all: bool) -> RoaringBitmap {
    let keyword_doc_ids =
        RoaringBitmap::from_iter(cache.with_keyword(&keyword).map(|item| item.document_id));
    if keyword_doc_ids.is_empty() {
        return keyword_doc_ids;
    }
    let mut not_matched_ids = RoaringBitmap::new();
    let mut matched_ids = RoaringBitmap::new();

    let mut thread_map: AHashMap<u32, RoaringBitmap> = AHashMap::new();

    for item in &cache.emails.items {
        thread_map
            .entry(item.thread_id)
            .or_default()
            .insert(item.document_id);
    }

    for item in &cache.emails.items {
        let keyword_doc_id = item.document_id;
        if !keyword_doc_ids.contains(keyword_doc_id)
            || matched_ids.contains(keyword_doc_id)
            || not_matched_ids.contains(keyword_doc_id)
        {
            continue;
        }

        if let Some(thread_doc_ids) = thread_map.get(&item.thread_id) {
            let mut thread_tag_intersection = thread_doc_ids.clone();
            thread_tag_intersection &= &keyword_doc_ids;

            if (match_all && &thread_tag_intersection == thread_doc_ids)
                || (!match_all && !thread_tag_intersection.is_empty())
            {
                matched_ids |= thread_doc_ids;
            } else if !thread_tag_intersection.is_empty() {
                not_matched_ids |= &thread_tag_intersection;
            }
        }
    }

    matched_ids
}
