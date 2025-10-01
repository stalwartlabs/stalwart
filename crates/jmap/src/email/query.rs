/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{JmapMethods, changes::state::MessageCacheState};
use common::{MessageStoreCache, Server, auth::AccessToken};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse},
    object::email::{Email, EmailComparator, EmailFilter},
};
use mail_parser::HeaderName;
use nlp::language::Language;
use std::future::Future;
use store::{
    SerializeInfallible,
    ahash::AHashMap,
    fts::{Field, FilterGroup, FtsFilter, IntoFilterGroup},
    query::{self},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::{acl::Acl, collection::Collection, field::EmailField, keyword::Keyword};

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

        for cond_group in std::mem::take(&mut request.filter).into_filter_group() {
            match cond_group {
                FilterGroup::Fts(conds) => {
                    let mut fts_filters = Vec::with_capacity(filters.len());
                    for cond in conds {
                        match cond {
                            Filter::Property(cond) => match cond {
                                EmailFilter::Text(text) => {
                                    fts_filters.push(FtsFilter::Or);
                                    fts_filters.push(FtsFilter::has_text(
                                        Field::Header(HeaderName::From),
                                        &text,
                                        Language::None,
                                    ));
                                    fts_filters.push(FtsFilter::has_text(
                                        Field::Header(HeaderName::To),
                                        &text,
                                        Language::None,
                                    ));
                                    fts_filters.push(FtsFilter::has_text(
                                        Field::Header(HeaderName::Cc),
                                        &text,
                                        Language::None,
                                    ));
                                    fts_filters.push(FtsFilter::has_text(
                                        Field::Header(HeaderName::Bcc),
                                        &text,
                                        Language::None,
                                    ));
                                    fts_filters.push(FtsFilter::has_text_detect(
                                        Field::Header(HeaderName::Subject),
                                        &text,
                                        self.core.jmap.default_language,
                                    ));
                                    fts_filters.push(FtsFilter::has_text_detect(
                                        Field::Body,
                                        &text,
                                        self.core.jmap.default_language,
                                    ));
                                    fts_filters.push(FtsFilter::has_text_detect(
                                        Field::Attachment,
                                        text,
                                        self.core.jmap.default_language,
                                    ));
                                    fts_filters.push(FtsFilter::End);
                                }
                                EmailFilter::From(text) => fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::From),
                                    text,
                                    Language::None,
                                )),
                                EmailFilter::To(text) => fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::To),
                                    text,
                                    Language::None,
                                )),
                                EmailFilter::Cc(text) => fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::Cc),
                                    text,
                                    Language::None,
                                )),
                                EmailFilter::Bcc(text) => fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::Bcc),
                                    text,
                                    Language::None,
                                )),
                                EmailFilter::Subject(text) => {
                                    fts_filters.push(FtsFilter::has_text_detect(
                                        Field::Header(HeaderName::Subject),
                                        text,
                                        self.core.jmap.default_language,
                                    ))
                                }
                                EmailFilter::Body(text) => {
                                    fts_filters.push(FtsFilter::has_text_detect(
                                        Field::Body,
                                        text,
                                        self.core.jmap.default_language,
                                    ))
                                }
                                EmailFilter::Header(header) => {
                                    let mut header = header.into_iter();
                                    let header_name = header.next().ok_or_else(|| {
                                        trc::JmapEvent::InvalidArguments
                                            .into_err()
                                            .details("Header name is missing.".to_string())
                                    })?;

                                    match HeaderName::parse(header_name) {
                                        Some(HeaderName::Other(header_name)) => {
                                            return Err(trc::JmapEvent::InvalidArguments
                                            .into_err()
                                            .details(format!(
                                                "Querying header '{header_name}' is not supported.",
                                            )));
                                        }
                                        Some(header_name) => {
                                            if let Some(header_value) = header.next() {
                                                if matches!(
                                                    header_name,
                                                    HeaderName::MessageId
                                                        | HeaderName::InReplyTo
                                                        | HeaderName::References
                                                        | HeaderName::ResentMessageId
                                                ) {
                                                    fts_filters.push(FtsFilter::has_keyword(
                                                        Field::Header(header_name),
                                                        header_value,
                                                    ));
                                                } else {
                                                    fts_filters.push(FtsFilter::has_text(
                                                        Field::Header(header_name),
                                                        header_value,
                                                        Language::None,
                                                    ));
                                                }
                                            } else {
                                                fts_filters.push(FtsFilter::has_keyword(
                                                    Field::Keyword,
                                                    header_name.as_str().to_lowercase(),
                                                ));
                                            }
                                        }
                                        None => (),
                                    }
                                }
                                other => {
                                    return Err(trc::JmapEvent::UnsupportedFilter
                                        .into_err()
                                        .details(other.to_string()));
                                }
                            },
                            Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                                fts_filters.push(cond.into());
                            }
                        }
                    }
                    filters.push(query::Filter::is_in_set(
                        self.fts_filter(account_id, Collection::Email, fts_filters)
                            .await?,
                    ));
                }
                FilterGroup::Store(cond) => {
                    match cond {
                        Filter::Property(cond) => {
                            match cond {
                                EmailFilter::InMailbox(mailbox) => filters.push(
                                    query::Filter::is_in_set(RoaringBitmap::from_iter(
                                        cached_messages
                                            .in_mailbox(mailbox.document_id())
                                            .map(|item| item.document_id),
                                    )),
                                ),
                                EmailFilter::InMailboxOtherThan(mailboxes) => {
                                    filters.push(query::Filter::Not);
                                    filters.push(query::Filter::Or);
                                    for mailbox in mailboxes {
                                        filters.push(query::Filter::is_in_set(
                                            RoaringBitmap::from_iter(
                                                cached_messages
                                                    .in_mailbox(mailbox.document_id())
                                                    .map(|item| item.document_id),
                                            ),
                                        ));
                                    }
                                    filters.push(query::Filter::End);
                                    filters.push(query::Filter::End);
                                }
                                EmailFilter::Before(date) => filters.push(query::Filter::lt(
                                    EmailField::ReceivedAt,
                                    date.timestamp().serialize(),
                                )),
                                EmailFilter::After(date) => filters.push(query::Filter::gt(
                                    EmailField::ReceivedAt,
                                    date.timestamp().serialize(),
                                )),
                                EmailFilter::MinSize(size) => filters
                                    .push(query::Filter::ge(EmailField::Size, size.serialize())),
                                EmailFilter::MaxSize(size) => filters
                                    .push(query::Filter::lt(EmailField::Size, size.serialize())),
                                EmailFilter::AllInThreadHaveKeyword(keyword) => {
                                    filters.push(query::Filter::is_in_set(thread_keywords(
                                        &cached_messages,
                                        keyword,
                                        true,
                                    )))
                                }
                                EmailFilter::SomeInThreadHaveKeyword(keyword) => {
                                    filters.push(query::Filter::is_in_set(thread_keywords(
                                        &cached_messages,
                                        keyword,
                                        false,
                                    )))
                                }
                                EmailFilter::NoneInThreadHaveKeyword(keyword) => {
                                    filters.push(query::Filter::Not);
                                    filters.push(query::Filter::is_in_set(thread_keywords(
                                        &cached_messages,
                                        keyword,
                                        false,
                                    )));
                                    filters.push(query::Filter::End);
                                }
                                EmailFilter::HasKeyword(keyword) => {
                                    filters.push(query::Filter::is_in_set(
                                        RoaringBitmap::from_iter(
                                            cached_messages
                                                .with_keyword(&keyword)
                                                .map(|item| item.document_id),
                                        ),
                                    ));
                                }
                                EmailFilter::NotKeyword(keyword) => {
                                    filters.push(query::Filter::Not);
                                    filters.push(query::Filter::is_in_set(
                                        RoaringBitmap::from_iter(
                                            cached_messages
                                                .with_keyword(&keyword)
                                                .map(|item| item.document_id),
                                        ),
                                    ));
                                    filters.push(query::Filter::End);
                                }
                                EmailFilter::HasAttachment(has_attach) => {
                                    if !has_attach {
                                        filters.push(query::Filter::Not);
                                    }
                                    filters.push(query::Filter::is_in_bitmap(
                                        EmailField::HasAttachment,
                                        (),
                                    ));
                                    if !has_attach {
                                        filters.push(query::Filter::End);
                                    }
                                }

                                // Non-standard
                                EmailFilter::Id(ids) => {
                                    let mut set = RoaringBitmap::new();
                                    for id in ids {
                                        set.insert(id.document_id());
                                    }
                                    filters.push(query::Filter::is_in_set(set));
                                }
                                EmailFilter::SentBefore(date) => filters.push(query::Filter::lt(
                                    EmailField::SentAt,
                                    date.timestamp().serialize(),
                                )),
                                EmailFilter::SentAfter(date) => filters.push(query::Filter::gt(
                                    EmailField::SentAt,
                                    date.timestamp().serialize(),
                                )),
                                EmailFilter::InThread(id) => filters.push(
                                    query::Filter::is_in_set(RoaringBitmap::from_iter(
                                        cached_messages
                                            .in_thread(id.document_id())
                                            .map(|item| item.document_id),
                                    )),
                                ),
                                other => {
                                    return Err(trc::JmapEvent::UnsupportedFilter
                                        .into_err()
                                        .details(other.to_string()));
                                }
                            }
                        }

                        Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                            filters.push(cond.into());
                        }
                    }
                }
            }
        }

        let mut result_set = self.filter(account_id, Collection::Email, filters).await?;
        if access_token.is_shared(account_id) {
            result_set.apply_mask(cached_messages.shared_messages(access_token, Acl::ReadItems));
        }
        let (response, paginate) = self
            .build_query_response(&result_set, cached_messages.get_state(false), &request)
            .await?;

        if let Some(paginate) = paginate {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .and_then(|s| if !s.is_empty() { s.into() } else { None })
                .unwrap_or_else(|| vec![Comparator::descending(EmailComparator::ReceivedAt)])
            {
                comparators.push(match comparator.property {
                    EmailComparator::ReceivedAt => {
                        query::Comparator::field(EmailField::ReceivedAt, comparator.is_ascending)
                    }
                    EmailComparator::Size => {
                        query::Comparator::field(EmailField::Size, comparator.is_ascending)
                    }
                    EmailComparator::From => {
                        query::Comparator::field(EmailField::From, comparator.is_ascending)
                    }
                    EmailComparator::To => {
                        query::Comparator::field(EmailField::To, comparator.is_ascending)
                    }
                    EmailComparator::Subject => {
                        query::Comparator::field(EmailField::Subject, comparator.is_ascending)
                    }
                    EmailComparator::SentAt => {
                        query::Comparator::field(EmailField::SentAt, comparator.is_ascending)
                    }
                    EmailComparator::HasKeyword(keyword) => query::Comparator::set(
                        RoaringBitmap::from_iter(
                            cached_messages
                                .with_keyword(&keyword)
                                .map(|item| item.document_id),
                        ),
                        comparator.is_ascending,
                    ),
                    EmailComparator::AllInThreadHaveKeyword(keyword) => query::Comparator::set(
                        thread_keywords(&cached_messages, keyword, true),
                        comparator.is_ascending,
                    ),
                    EmailComparator::SomeInThreadHaveKeyword(keyword) => query::Comparator::set(
                        thread_keywords(&cached_messages, keyword, false),
                        comparator.is_ascending,
                    ),
                    // Non-standard
                    EmailComparator::Cc => {
                        query::Comparator::field(EmailField::Cc, comparator.is_ascending)
                    }

                    other => {
                        return Err(trc::JmapEvent::UnsupportedSort
                            .into_err()
                            .details(other.to_string()));
                    }
                });
            }

            // Sort results
            self.sort(
                result_set,
                comparators,
                paginate
                    .with_prefix_map(
                        &cached_messages
                            .emails
                            .items
                            .iter()
                            .map(|item| (item.document_id, item.thread_id))
                            .collect(),
                    )
                    .with_prefix_unique(request.arguments.collapse_threads.unwrap_or(false)),
                response,
            )
            .await
        } else {
            Ok(response)
        }
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
