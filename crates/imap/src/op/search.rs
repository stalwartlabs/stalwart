/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::{Resolved, Row, SavedSearch, SelectedMailbox, Session, SessionData},
    spawn_op,
};
use common::{MessageStoreCache, network::SessionStream};
use email::{
    cache::{
        MessageCacheFetch,
        email::{MessageCacheAccess, SearchOperator},
    },
    message::sortkeys::{EmailSortKeys, MessageCacheField, MessageComparator, MessageSortField},
};
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    protocol::{
        Sequence,
        search::{self, Arguments, Comparator, Filter, Response, ResultOption},
    },
    receiver::Request,
};
use mail_parser::HeaderName;
use nlp::language::Language;
use registry::schema::enums::Permission;
use std::{str::FromStr, sync::Arc, time::Instant};
use store::{
    roaring::RoaringBitmap,
    search::{EmailSearchField, KeyValueMatch, SearchFilter, SearchQuery},
    write::{SearchIndex, now},
};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::watch;
use trc::AddContext;
use types::{id::Id, keyword::Keyword};

impl<T: SessionStream> Session<T> {
    pub async fn handle_search(
        &mut self,
        request: Request<Command>,
        is_sort: bool,
        is_uid: bool,
        permit: Option<OwnedSemaphorePermit>,
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

        // RFC 9586 forbids the sequence set criterion once UIDONLY is enabled
        if self.is_uidonly
            && arguments.filter.iter().any(|filter| {
                matches!(filter, Filter::Sequence(sequence, false) if !sequence.is_saved_search())
            })
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details("The sequence set search criterion is not allowed once UIDONLY is enabled.")
                .code(ResponseCode::UidRequired)
                .ctx(trc::Key::Type, ResponseType::Bad)
                .id(arguments.tag));
        }

        let (data, mailbox) = self.state.mailbox_state();
        let message_limit = self.server.core.imap.max_messages_per_command;

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

        spawn_op!(permit, data, {
            let tag = std::mem::take(&mut arguments.tag);
            let bytes = match data
                .search(
                    arguments,
                    mailbox.clone(),
                    results_tx,
                    prev_saved_search.clone(),
                    is_uid,
                    message_limit,
                    op_start,
                )
                .await
            {
                Ok((response, limited_uid)) => {
                    let response = response.serialize(&tag);
                    let status = StatusResponse::completed(if !is_sort {
                        Command::Search(is_uid)
                    } else {
                        Command::Sort(is_uid)
                    })
                    .with_tag(tag);

                    match limited_uid {
                        Some(uid) => status.with_code(ResponseCode::MessageLimit {
                            limit: message_limit,
                            uid: uid.into(),
                        }),
                        None => status,
                    }
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
    #[allow(clippy::too_many_arguments)]
    pub async fn search(
        &self,
        arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        results_tx: Option<watch::Sender<Arc<Vec<Row>>>>,
        prev_saved_search: Option<Option<Arc<Vec<Row>>>>,
        is_uid: bool,
        message_limit: u32,
        op_start: Instant,
    ) -> trc::Result<(search::Response, Option<u32>)> {
        let cache = self
            .server
            .get_cached_messages(mailbox.id.account_id)
            .await
            .caused_by(trc::location!())?;
        self.sync_view(&mailbox, &cache, None)
            .await
            .caused_by(trc::location!())?;

        // Run query
        let is_sort = arguments.sort.is_some();
        let (result_set, include_highest_modseq) = self
            .query(
                arguments.filter,
                arguments.sort.unwrap_or_default(),
                &mailbox,
                &cache,
                &prev_saved_search,
            )
            .await?;
        // Sort and map ids
        let find_min = arguments.result_options.contains(&ResultOption::Min);
        let find_max = arguments.result_options.contains(&ResultOption::Max);
        let mut results = SearchResults {
            is_uid,
            find_min,
            find_max,
            min: None,
            max: None,
            total: 0,
            imap_ids: Vec::with_capacity(result_set.len()),
            modseq_cache: include_highest_modseq.then_some(&cache),
            highest_modseq: None,
            saved_results: results_tx
                .is_some()
                .then(|| Vec::with_capacity(result_set.len())),
        };
        {
            let view = mailbox.view.lock();
            if !is_sort && result_set.len() > view.len() / 8 {
                let set = RoaringBitmap::from_iter(result_set);
                view.map_result_set(&set, |resolved| results.push(resolved));
            } else {
                for document_id in result_set {
                    if let Some(resolved) = view.map_result(document_id) {
                        results.push(resolved);
                    }
                }
            }
        }
        results.finish();
        let SearchResults {
            min,
            max,
            total,
            mut imap_ids,
            mut saved_results,
            highest_modseq,
            ..
        } = results;

        // RFC 9738 exempts SORT, whose ordering is meaningless once truncated
        let mut limited_uid = None;
        if !is_sort {
            imap_ids.sort_unstable();

            let message_limit = message_limit as usize;
            if imap_ids.len() > message_limit {
                let cutoff = imap_ids.len() - message_limit;
                let threshold = imap_ids.get(cutoff).copied().unwrap_or_default();
                imap_ids.drain(..cutoff);
                let threshold_uid = if is_uid {
                    Some(threshold)
                } else {
                    mailbox.view.lock().seqnum_to_uid(threshold)
                };
                limited_uid = threshold_uid;

                // RFC 9738 requires the saved search to be truncated to match
                if let (Some(saved_results), Some(threshold_uid)) =
                    (saved_results.as_mut(), threshold_uid)
                {
                    saved_results.retain(|row| row.uid >= threshold_uid);
                }
            }
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
        Ok((
            Response {
                is_uid,
                min: min.map(|resolved| resolved.imap_id(is_uid)),
                max: max.map(|resolved| resolved.imap_id(is_uid)),
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
            },
            limited_uid,
        ))
    }

    pub async fn query(
        &self,
        imap_filter: Vec<Filter>,
        imap_comparator: Vec<Comparator>,
        mailbox: &SelectedMailbox,
        cache: &MessageStoreCache,
        prev_saved_search: &Option<Option<Arc<Vec<Row>>>>,
    ) -> trc::Result<(Vec<u32>, bool)> {
        // Obtain message ids
        let mut filters = Vec::with_capacity(imap_filter.len() + 1);
        let message_ids = mailbox.view.lock().document_ids();

        // Convert query
        let mut include_highest_modseq = false;
        for filter in imap_filter {
            match filter {
                Filter::Sequence(sequence, uid_filter) => {
                    let resolved = if let (Sequence::SavedSearch, Some(prev_saved_search)) =
                        (&sequence, &prev_saved_search)
                    {
                        if let Some(prev_saved_search) = prev_saved_search {
                            mailbox.view.lock().resolve(
                                &sequence,
                                true,
                                Some(prev_saved_search.as_slice()),
                            )
                        } else {
                            return Err(trc::ImapEvent::Error
                                .into_err()
                                .details("No saved search found."));
                        }
                    } else {
                        mailbox.resolve(&sequence, uid_filter).await?
                    };
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        resolved.iter().map(|resolved| resolved.id),
                    )));
                }
                Filter::UidAfter(uid) => {
                    filters.push(SearchFilter::is_in_set(match uid.checked_add(1) {
                        Some(min) => mailbox.view.lock().uids_in_range(Some(min), None),
                        None => RoaringBitmap::new(),
                    }));
                }
                Filter::UidBefore(uid) => {
                    filters.push(SearchFilter::is_in_set(if uid > 1 {
                        mailbox.view.lock().uids_in_range(None, Some(uid - 1))
                    } else {
                        RoaringBitmap::new()
                    }));
                }
                Filter::All => {
                    filters.push(SearchFilter::is_in_set(message_ids.clone()));
                }
                Filter::Answered => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .with_keyword(&Keyword::Answered)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Before(date) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .received(date, SearchOperator::LowerThan)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Deleted => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .with_keyword(&Keyword::Deleted)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Draft => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache.with_keyword(&Keyword::Draft).map(|m| m.document_id()),
                    )));
                }
                Filter::Flagged => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .with_keyword(&Keyword::Flagged)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Keyword(keyword) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .with_keyword(&Keyword::from(keyword))
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Larger(size) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .size(size, SearchOperator::GreaterThan)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::On(date) => {
                    let date_from = date as u64;
                    let date_to = date_from + 86400;
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .emails
                            .iter()
                            .filter(|m| m.received_at() >= date_from && m.received_at() < date_to)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Seen => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache.with_keyword(&Keyword::Seen).map(|m| m.document_id()),
                    )));
                }
                Filter::SentBefore(date) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .sent(date, SearchOperator::LowerThan)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::SentOn(date) => {
                    let date_from = date;
                    let date_to = date_from + 86400;
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .emails
                            .iter()
                            .filter(|m| {
                                let sent_at = m.received_at() as i64 + m.sent_at() as i64;
                                sent_at >= date_from && sent_at < date_to
                            })
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::SentSince(date) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .sent(date, SearchOperator::GreaterEqualThan)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Since(date) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .received(date, SearchOperator::GreaterEqualThan)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Smaller(size) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .size(size, SearchOperator::LowerThan)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Unanswered => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::Answered)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Undeleted => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::Deleted)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Undraft => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::Draft)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Unflagged => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::Flagged)
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Unkeyword(keyword) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::from(keyword))
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Unseen => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .without_keyword(&Keyword::Seen)
                            .map(|m| m.document_id()),
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
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .received(
                                now().saturating_sub(secs as u64) as i64,
                                SearchOperator::LowerThan,
                            )
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::Younger(secs) => {
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .received(
                                now().saturating_sub(secs as u64) as i64,
                                SearchOperator::GreaterEqualThan,
                            )
                            .map(|m| m.document_id()),
                    )));
                }
                Filter::ModSeq((modseq, _)) => {
                    let mailbox_id = mailbox.id.mailbox_id;
                    filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                        cache
                            .emails
                            .iter()
                            .filter(|m| m.change_id() + 1 >= modseq && m.has_mailbox_id(mailbox_id))
                            .map(|m| m.document_id()),
                    )));
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
                            cache.in_thread(id.document_id()).map(|m| m.document_id()),
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
                        self.server.core.email.default_language,
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
                        match header {
                            HeaderName::Subject => {
                                filters.push(SearchFilter::has_text_detect(
                                    EmailSearchField::Subject,
                                    value,
                                    self.server.core.email.default_language,
                                ));
                            }
                            header @ (HeaderName::From
                            | HeaderName::To
                            | HeaderName::Cc
                            | HeaderName::Bcc) => {
                                filters.push(SearchFilter::has_text(
                                    match header {
                                        HeaderName::From => EmailSearchField::From,
                                        HeaderName::To => EmailSearchField::To,
                                        HeaderName::Cc => EmailSearchField::Cc,
                                        HeaderName::Bcc => EmailSearchField::Bcc,
                                        _ => unreachable!(),
                                    },
                                    value,
                                    Language::None,
                                ));
                            }
                            header => {
                                let op = if value.is_empty() {
                                    KeyValueMatch::Exists
                                } else if matches!(
                                    header,
                                    HeaderName::MessageId
                                        | HeaderName::InReplyTo
                                        | HeaderName::References
                                        | HeaderName::ResentMessageId
                                ) {
                                    KeyValueMatch::Equals(value)
                                } else {
                                    KeyValueMatch::Contains(value)
                                };

                                filters.push(SearchFilter::KeyValue {
                                    field: EmailSearchField::Headers.into(),
                                    key: header.as_str().to_lowercase(),
                                    op,
                                });
                            }
                        }
                    }
                }
                Filter::Subject(text) => {
                    filters.push(SearchFilter::has_text_detect(
                        EmailSearchField::Subject,
                        text,
                        self.server.core.email.default_language,
                    ));
                }
                Filter::Text(text) => {
                    let (text, language) =
                        Language::detect(text, self.server.core.email.default_language);

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
                search::Sort::Arrival => MessageComparator::Cache {
                    field: MessageCacheField::ReceivedAt,
                    ascending: comparator.ascending,
                },
                search::Sort::Cc => {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("Sorting by CC is not supported."));
                }
                search::Sort::Date => MessageComparator::Cache {
                    field: MessageCacheField::SentAt,
                    ascending: comparator.ascending,
                },
                search::Sort::From | search::Sort::DisplayFrom => MessageComparator::SortKey {
                    field: MessageSortField::From,
                    ascending: comparator.ascending,
                },
                search::Sort::Size => MessageComparator::Cache {
                    field: MessageCacheField::Size,
                    ascending: comparator.ascending,
                },
                search::Sort::Subject => MessageComparator::SortKey {
                    field: MessageSortField::Subject,
                    ascending: comparator.ascending,
                },
                search::Sort::To | search::Sort::DisplayTo => MessageComparator::SortKey {
                    field: MessageSortField::To,
                    ascending: comparator.ascending,
                },
            });
        }

        // Run query
        self.server
            .query_emails(
                mailbox.id.account_id,
                cache,
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(filters)
                    .with_account_id(mailbox.id.account_id)
                    .with_mask(message_ids),
                comparators,
            )
            .await
            .map(|res| (res, include_highest_modseq))
            .caused_by(trc::location!())
    }
}

struct SearchResults<'x> {
    is_uid: bool,
    find_min: bool,
    find_max: bool,
    min: Option<Resolved>,
    max: Option<Resolved>,
    total: u32,
    imap_ids: Vec<u32>,
    saved_results: Option<Vec<Row>>,
    modseq_cache: Option<&'x MessageStoreCache>,
    highest_modseq: Option<u64>,
}

impl SearchResults<'_> {
    fn push(&mut self, resolved: Resolved) {
        let id = resolved.imap_id(self.is_uid);
        if self.find_min || self.find_max {
            if self.find_min && self.min.is_none_or(|min| id < min.imap_id(self.is_uid)) {
                self.min = Some(resolved);
            }
            if self.find_max && self.max.is_none_or(|max| id > max.imap_id(self.is_uid)) {
                self.max = Some(resolved);
            }
        } else {
            self.imap_ids.push(id);
            self.track_modseq(&resolved);
            if let Some(saved) = self.saved_results.as_mut() {
                saved.push(resolved.row());
            }
        }
        self.total += 1;
    }

    fn finish(&mut self) {
        if self.find_min || self.find_max {
            for resolved in [self.min, self.max].into_iter().flatten() {
                self.imap_ids.push(resolved.imap_id(self.is_uid));
                self.track_modseq(&resolved);
                if let Some(saved) = self.saved_results.as_mut() {
                    saved.push(resolved.row());
                }
            }
        }
    }

    fn track_modseq(&mut self, resolved: &Resolved) {
        if let Some(cache) = self.modseq_cache
            && let Some(item) = cache.email_by_id(&resolved.id)
        {
            let modseq = item.change_id() + 1;
            if self.highest_modseq.is_none_or(|highest| modseq > highest) {
                self.highest_modseq = Some(modseq);
            }
        }
    }
}

impl SelectedMailbox {
    pub async fn get_saved_search(&self) -> Option<Arc<Vec<Row>>> {
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
}

impl SavedSearch {
    pub async fn unwrap(&self) -> Option<Arc<Vec<Row>>> {
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
