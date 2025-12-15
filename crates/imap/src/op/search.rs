/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FromModSeq, ToModSeq};
use crate::{
    core::{ImapId, SavedSearch, SelectedMailbox, Session, SessionData},
    spawn_op,
};
use common::listener::SessionStream;
use directory::Permission;
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use imap_proto::{
    Command, StatusResponse,
    protocol::{
        Sequence,
        search::{self, Arguments, Comparator, Filter, Response, ResultOption},
    },
    receiver::Request,
};
use mail_parser::HeaderName;
use nlp::language::Language;
use std::{str::FromStr, sync::Arc, time::Instant};
use store::{
    query::log::Query,
    roaring::RoaringBitmap,
    search::{
        EmailSearchField, SearchComparator, SearchFilter, SearchOperator, SearchQuery, SearchValue,
    },
    write::{SearchIndex, now},
};
use tokio::sync::watch;
use trc::AddContext;
use types::{collection::SyncCollection, id::Id, keyword::Keyword};
use utils::map::vec_map::VecMap;

impl<T: SessionStream> Session<T> {
    pub async fn handle_search(
        &mut self,
        request: Request<Command>,
        is_sort: bool,
        is_uid: bool,
    ) -> trc::Result<()> {
        let op_start = Instant::now();
        let mut arguments = if !is_sort {
            // Validate access
            self.assert_has_permission(Permission::ImapSearch)?;

            request.parse_search(self.version)
        } else {
            // Validate access
            self.assert_has_permission(Permission::ImapSort)?;

            request.parse_sort()
        }?;

        let (data, mailbox) = self.state.mailbox_state();

        // Create channel for results
        let (results_tx, prev_saved_search) =
            if arguments.result_options.contains(&ResultOption::Save) {
                let prev_saved_search = Some(mailbox.get_saved_search().await);
                let (tx, rx) = watch::channel(Arc::new(Vec::new()));
                *mailbox.saved_search.lock() = SavedSearch::InFlight { rx };
                (tx.into(), prev_saved_search)
            } else {
                (None, None)
            };

        spawn_op!(data, {
            let tag = std::mem::take(&mut arguments.tag);
            let bytes = match data
                .search(
                    arguments,
                    mailbox.clone(),
                    results_tx,
                    prev_saved_search.clone(),
                    is_uid,
                    op_start,
                )
                .await
            {
                Ok(response) => {
                    let response = response.serialize(&tag);
                    StatusResponse::completed(if !is_sort {
                        Command::Search(is_uid)
                    } else {
                        Command::Sort(is_uid)
                    })
                    .with_tag(tag)
                    .serialize(response)
                }
                Err(err) => {
                    if let Some(prev_saved_search) = prev_saved_search {
                        *mailbox.saved_search.lock() = prev_saved_search
                            .map_or(SavedSearch::None, |s| SavedSearch::Results { items: s });
                    }
                    return Err(err.id(tag));
                }
            };
            data.write_bytes(bytes).await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn search(
        &self,
        arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        results_tx: Option<watch::Sender<Arc<Vec<ImapId>>>>,
        prev_saved_search: Option<Option<Arc<Vec<ImapId>>>>,
        is_uid: bool,
        op_start: Instant,
    ) -> trc::Result<search::Response> {
        // Run query
        let is_sort = arguments.sort.is_some();
        let (result_set, include_highest_modseq) = self
            .query(
                arguments.filter,
                arguments.sort.unwrap_or_default(),
                &mailbox,
                &prev_saved_search,
            )
            .await?;

        // Obtain modseq
        let highest_modseq = if include_highest_modseq {
            self.synchronize_messages(&mailbox)
                .await?
                .to_modseq()
                .into()
        } else {
            None
        };

        // Sort and map ids
        let mut min: Option<(u32, ImapId)> = None;
        let mut max: Option<(u32, ImapId)> = None;
        let mut total = 0;
        let results_len = result_set.len();
        let mut saved_results = if results_tx.is_some() {
            Some(Vec::with_capacity(results_len))
        } else {
            None
        };
        let mut imap_ids = Vec::with_capacity(results_len);
        mailbox.map_search_results(
            result_set.into_iter(),
            is_uid,
            arguments.result_options.contains(&ResultOption::Min),
            arguments.result_options.contains(&ResultOption::Max),
            &mut min,
            &mut max,
            &mut total,
            &mut imap_ids,
            &mut saved_results,
        );
        if !is_sort {
            imap_ids.sort_unstable();
        }

        // Save results
        if let (Some(results_tx), Some(saved_results)) = (results_tx, saved_results) {
            let saved_results = Arc::new(saved_results);
            *mailbox.saved_search.lock() = SavedSearch::Results {
                items: saved_results.clone(),
            };
            results_tx.send(saved_results).ok();
        }

        trc::event!(
            Imap(if !is_sort {
                trc::ImapEvent::Search
            } else {
                trc::ImapEvent::Sort
            }),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
            Total = total,
            Elapsed = op_start.elapsed()
        );

        // Build response
        Ok(Response {
            is_uid,
            min: min.map(|(id, _)| id),
            max: max.map(|(id, _)| id),
            count: if arguments.result_options.contains(&ResultOption::Count) {
                Some(total)
            } else {
                None
            },
            ids: if arguments.result_options.is_empty()
                || arguments.result_options.contains(&ResultOption::All)
            {
                imap_ids
            } else {
                vec![]
            },
            is_sort,
            is_esearch: arguments.is_esearch,
            highest_modseq,
        })
    }

    pub async fn query(
        &self,
        imap_filter: Vec<Filter>,
        imap_comparator: Vec<Comparator>,
        mailbox: &SelectedMailbox,
        prev_saved_search: &Option<Option<Arc<Vec<ImapId>>>>,
    ) -> trc::Result<(Vec<u32>, bool)> {
        // Obtain message ids
        let mut filters = Vec::with_capacity(imap_filter.len() + 1);
        let cache = self
            .server
            .get_cached_messages(mailbox.id.account_id)
            .await
            .caused_by(trc::location!())?;
        let message_ids = RoaringBitmap::from_iter(
            cache
                .in_mailbox(mailbox.id.mailbox_id)
                .map(|m| m.document_id),
        );

        // Convert query
        let mut include_highest_modseq = false;
        for filter in imap_filter {
            match filter {
                Filter::Sequence(sequence, uid_filter) => {
                    let mut set = RoaringBitmap::new();
                    if let (Sequence::SavedSearch, Some(prev_saved_search)) =
                        (&sequence, &prev_saved_search)
                    {
                        if let Some(prev_saved_search) = prev_saved_search {
                            let state = mailbox.state.lock();
                            for imap_id in prev_saved_search.iter() {
                                if let Some(id) = state.uid_to_id.get(&imap_id.uid) {
                                    set.insert(*id);
                                }
                            }
                        } else {
                            return Err(trc::ImapEvent::Error
                                .into_err()
                                .details("No saved search found."));
                        }
                    } else {
                        for id in mailbox.sequence_to_ids(&sequence, uid_filter).await?.keys() {
                            set.insert(*id);
                        }
                    }
                    filters.push(SearchFilter::is_in_set(set));
                }
                Filter::All => {
                    filters.push(SearchFilter::is_in_set(message_ids.clone()));
                }
                Filter::Answered => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .with_keyword(&Keyword::Answered)
                            .map(|m| m.document_id),
                    )));
                }
                Filter::Before(date) => {
                    filters.push(SearchFilter::lt(EmailSearchField::ReceivedAt, date));
                }
                Filter::Deleted => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache.with_keyword(&Keyword::Deleted).map(|m| m.document_id),
                    )));
                }
                Filter::Draft => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache.with_keyword(&Keyword::Draft).map(|m| m.document_id),
                    )));
                }
                Filter::Flagged => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache.with_keyword(&Keyword::Flagged).map(|m| m.document_id),
                    )));
                }
                Filter::Keyword(keyword) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .with_keyword(&Keyword::from(keyword))
                            .map(|m| m.document_id),
                    )));
                }
                Filter::Larger(size) => {
                    filters.push(SearchFilter::gt(EmailSearchField::Size, size));
                }
                Filter::On(date) => {
                    filters.push(SearchFilter::And);
                    filters.push(SearchFilter::ge(EmailSearchField::ReceivedAt, date));
                    filters.push(SearchFilter::lt(EmailSearchField::ReceivedAt, date + 86400));
                    filters.push(SearchFilter::End);
                }
                Filter::Seen => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache.with_keyword(&Keyword::Seen).map(|m| m.document_id),
                    )));
                }
                Filter::SentBefore(date) => {
                    filters.push(SearchFilter::lt(EmailSearchField::SentAt, date));
                }
                Filter::SentOn(date) => {
                    filters.push(SearchFilter::And);
                    filters.push(SearchFilter::ge(EmailSearchField::SentAt, date));
                    filters.push(SearchFilter::lt(EmailSearchField::SentAt, date + 86400));
                    filters.push(SearchFilter::End);
                }
                Filter::SentSince(date) => {
                    filters.push(SearchFilter::ge(EmailSearchField::SentAt, date));
                }
                Filter::Since(date) => {
                    filters.push(SearchFilter::ge(EmailSearchField::ReceivedAt, date));
                }
                Filter::Smaller(size) => {
                    filters.push(SearchFilter::lt(EmailSearchField::Size, size));
                }
                Filter::Unanswered => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::Answered)
                            .map(|m| m.document_id),
                    )));
                }
                Filter::Undeleted => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::Deleted)
                            .map(|m| m.document_id),
                    )));
                }
                Filter::Undraft => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::Draft)
                            .map(|m| m.document_id),
                    )));
                }
                Filter::Unflagged => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::Flagged)
                            .map(|m| m.document_id),
                    )));
                }
                Filter::Unkeyword(keyword) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::from(keyword))
                            .map(|m| m.document_id),
                    )));
                }
                Filter::Unseen => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache.without_keyword(&Keyword::Seen).map(|m| m.document_id),
                    )));
                }
                Filter::Recent => {
                    //filters.push(SearchFilter::is_in_set(self.get_recent(&mailbox.id)));
                }
                Filter::New => {
                    /*filters.push(SearchFilter::And);
                    filters.push(SearchFilter::is_in_set(self.get_recent(&mailbox.id)));
                    filters.push(SearchFilter::Not);
                    filters.push(SearchFilter::is_in_bitmap(
                        EmailSearchField::Keywords,
                        Keyword::Seen,
                    ));
                    filters.push(SearchFilter::End);
                    filters.push(SearchFilter::End);*/
                }
                Filter::Old => {
                    /*filters.push(SearchFilter::Not);
                    filters.push(SearchFilter::is_in_set(self.get_recent(&mailbox.id)));
                    filters.push(SearchFilter::End);*/
                }
                Filter::Older(secs) => {
                    filters.push(SearchFilter::le(
                        EmailSearchField::ReceivedAt,
                        now().saturating_sub(secs as u64),
                    ));
                }
                Filter::Younger(secs) => {
                    filters.push(SearchFilter::ge(
                        EmailSearchField::ReceivedAt,
                        now().saturating_sub(secs as u64),
                    ));
                }
                Filter::ModSeq((modseq, _)) => {
                    let mut set = RoaringBitmap::new();
                    for id in self
                        .server
                        .store()
                        .changes(
                            mailbox.id.account_id,
                            SyncCollection::Email.into(),
                            Query::from_modseq(modseq),
                        )
                        .await?
                        .changes
                        .into_iter()
                        .filter_map(|change| change.try_unwrap_item_id())
                    {
                        let id = (id & u32::MAX as u64) as u32;
                        if message_ids.contains(id) {
                            set.insert(id);
                        }
                    }
                    filters.push(SearchFilter::is_in_set(set));
                    include_highest_modseq = true;
                }
                Filter::EmailId(id) => {
                    if let Ok(id) = Id::from_str(&id) {
                        filters.push(SearchFilter::is_in_set(
                            RoaringBitmap::from_sorted_iter([id.document_id()]).unwrap(),
                        ));
                    } else {
                        return Err(trc::ImapEvent::Error
                            .into_err()
                            .details(format!("Failed to parse email id '{id}'.",)));
                    }
                }
                Filter::ThreadId(id) => {
                    if let Ok(id) = Id::from_str(&id) {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.in_thread(id.document_id()).map(|m| m.document_id),
                        )));
                    } else {
                        return Err(trc::ImapEvent::Error
                            .into_err()
                            .details(format!("Failed to parse thread id '{id}'.",)));
                    }
                }
                Filter::Bcc(text) => {
                    filters.push(SearchFilter::has_text(
                        EmailSearchField::Bcc,
                        text,
                        Language::None,
                    ));
                }
                Filter::Body(text) => {
                    filters.push(SearchFilter::has_text_detect(
                        EmailSearchField::Body,
                        text,
                        self.server.core.jmap.default_language,
                    ));
                }
                Filter::Cc(text) => {
                    filters.push(SearchFilter::has_text(
                        EmailSearchField::Cc,
                        text,
                        Language::None,
                    ));
                }
                Filter::From(text) => {
                    filters.push(SearchFilter::has_text(
                        EmailSearchField::From,
                        text,
                        Language::None,
                    ));
                }
                Filter::Header(header, value) => {
                    if let Some(header) = HeaderName::parse(header) {
                        let op = if matches!(
                            header,
                            HeaderName::MessageId
                                | HeaderName::InReplyTo
                                | HeaderName::References
                                | HeaderName::ResentMessageId
                        ) || value.is_empty()
                        {
                            SearchOperator::Equal
                        } else {
                            SearchOperator::Contains
                        };

                        filters.push(SearchFilter::cond(
                            EmailSearchField::Headers,
                            op,
                            SearchValue::KeyValues(
                                VecMap::with_capacity(1)
                                    .with_append(header.as_str().to_lowercase(), value),
                            ),
                        ));
                    }
                }
                Filter::Subject(text) => {
                    filters.push(SearchFilter::has_text_detect(
                        EmailSearchField::Subject,
                        text,
                        self.server.core.jmap.default_language,
                    ));
                }
                Filter::Text(text) => {
                    let (text, language) =
                        Language::detect(text, self.server.core.jmap.default_language);

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
                Filter::To(text) => {
                    filters.push(SearchFilter::has_text(
                        EmailSearchField::To,
                        text,
                        Language::None,
                    ));
                }
                Filter::And => {
                    filters.push(SearchFilter::And);
                }
                Filter::Or => {
                    filters.push(SearchFilter::Or);
                }
                Filter::Not => {
                    filters.push(SearchFilter::Not);
                }
                Filter::End => {
                    filters.push(SearchFilter::End);
                }
            }
        }

        // Convert comparators
        let mut comparators = Vec::with_capacity(imap_comparator.len());
        for comparator in imap_comparator {
            comparators.push(match comparator.sort {
                search::Sort::Arrival => {
                    SearchComparator::field(EmailSearchField::ReceivedAt, comparator.ascending)
                }
                search::Sort::Cc => {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("Sorting by CC is not supported."));
                }
                search::Sort::Date => {
                    SearchComparator::field(EmailSearchField::SentAt, comparator.ascending)
                }
                search::Sort::From | search::Sort::DisplayFrom => {
                    SearchComparator::field(EmailSearchField::From, comparator.ascending)
                }
                search::Sort::Size => {
                    SearchComparator::field(EmailSearchField::Size, comparator.ascending)
                }
                search::Sort::Subject => {
                    SearchComparator::field(EmailSearchField::Subject, comparator.ascending)
                }
                search::Sort::To | search::Sort::DisplayTo => {
                    SearchComparator::field(EmailSearchField::To, comparator.ascending)
                }
            });
        }

        // Run query
        self.server
            .search_store()
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(filters)
                    .with_comparators(comparators)
                    .with_account_id(mailbox.id.account_id)
                    .with_mask(message_ids),
            )
            .await
            .map(|res| (res, include_highest_modseq))
            .caused_by(trc::location!())
    }
}

impl SelectedMailbox {
    pub async fn get_saved_search(&self) -> Option<Arc<Vec<ImapId>>> {
        let mut rx = match &*self.saved_search.lock() {
            SavedSearch::InFlight { rx } => rx.clone(),
            SavedSearch::Results { items } => {
                return Some(items.clone());
            }
            SavedSearch::None => {
                return None;
            }
        };
        rx.changed().await.ok();
        let v = rx.borrow();
        Some(v.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn map_search_results(
        &self,
        ids: impl Iterator<Item = u32>,
        is_uid: bool,
        find_min: bool,
        find_max: bool,
        min: &mut Option<(u32, ImapId)>,
        max: &mut Option<(u32, ImapId)>,
        total: &mut u32,
        imap_ids: &mut Vec<u32>,
        saved_results: &mut Option<Vec<ImapId>>,
    ) {
        let state = self.state.lock();
        let find_min_or_max = find_min || find_max;
        for document_id in ids {
            if let Some((id, imap_id)) = state.map_result_id(document_id, is_uid) {
                if find_min_or_max {
                    if find_min {
                        if let Some((prev_min, _)) = min {
                            if id < *prev_min {
                                *min = Some((id, imap_id));
                            }
                        } else {
                            *min = Some((id, imap_id));
                        }
                    }
                    if find_max {
                        if let Some((prev_max, _)) = max {
                            if id > *prev_max {
                                *max = Some((id, imap_id));
                            }
                        } else {
                            *max = Some((id, imap_id));
                        }
                    }
                } else {
                    imap_ids.push(id);
                    if let Some(r) = saved_results.as_mut() {
                        r.push(imap_id)
                    }
                }
                *total += 1;
            }
        }
        if find_min || find_max {
            for (id, imap_id) in [min, max].into_iter().flatten() {
                imap_ids.push(*id);
                if let Some(r) = saved_results.as_mut() {
                    r.push(*imap_id)
                }
            }
        }
    }
}

impl SavedSearch {
    pub async fn unwrap(&self) -> Option<Arc<Vec<ImapId>>> {
        match self {
            SavedSearch::InFlight { rx } => {
                let mut rx = rx.clone();
                rx.changed().await.ok();
                let v = rx.borrow();
                Some(v.clone())
            }
            SavedSearch::Results { items } => Some(items.clone()),
            SavedSearch::None => None,
        }
    }
}
