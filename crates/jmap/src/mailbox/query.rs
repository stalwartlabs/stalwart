/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use common::{Server, auth::AccessToken};
use email::cache::{MessageCacheFetch, mailbox::MailboxCacheAccess};
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse},
    object::mailbox::{Mailbox, MailboxComparator, MailboxFilter},
};
use std::{collections::BTreeMap, future::Future};
use store::{
    ahash::AHashMap,
    roaring::RoaringBitmap,
    search::{SearchComparator, SearchFilter, SearchQuery},
    write::SearchIndex,
};
use types::{acl::Acl, special_use::SpecialUse};

pub trait MailboxQuery: Sync + Send {
    fn mailbox_query(
        &self,
        request: QueryRequest<Mailbox>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl MailboxQuery for Server {
    async fn mailbox_query(
        &self,
        mut request: QueryRequest<Mailbox>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let sort_as_tree = request.arguments.sort_as_tree.unwrap_or(false);
        let filter_as_tree = request.arguments.filter_as_tree.unwrap_or(false);
        let mut filters = Vec::with_capacity(request.filter.len());
        let mailboxes = self.get_cached_messages(account_id).await?;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => {
                    match cond {
                        MailboxFilter::ParentId(parent_id) => {
                            let parent_id = parent_id
                                .and_then(|id| id.try_unwrap().map(|id| id.document_id()))
                                .unwrap_or(u32::MAX);
                            filters.push(SearchFilter::is_in_set(
                                mailboxes
                                    .mailboxes
                                    .items
                                    .iter()
                                    .filter(|mailbox| mailbox.parent_id == parent_id)
                                    .map(|m| m.document_id)
                                    .collect::<RoaringBitmap>(),
                            ));
                        }
                        MailboxFilter::Name(name) => {
                            #[cfg(feature = "test_mode")]
                            {
                                // Used for concurrent requests tests
                                if name == "__sleep" {
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                }
                            }
                            let name = name.to_lowercase();
                            filters.push(SearchFilter::is_in_set(
                                mailboxes
                                    .mailboxes
                                    .items
                                    .iter()
                                    .filter(|mailbox| mailbox.name.to_lowercase().contains(&name))
                                    .map(|m| m.document_id)
                                    .collect::<RoaringBitmap>(),
                            ));
                        }
                        MailboxFilter::Role(role) => {
                            if let Some(role) = role {
                                filters.push(SearchFilter::is_in_set(
                                    mailboxes
                                        .mailboxes
                                        .items
                                        .iter()
                                        .filter(|mailbox| mailbox.role == role)
                                        .map(|m| m.document_id)
                                        .collect::<RoaringBitmap>(),
                                ));
                            } else {
                                filters.push(SearchFilter::is_in_set(
                                    mailboxes
                                        .mailboxes
                                        .items
                                        .iter()
                                        .filter(|mailbox| matches!(mailbox.role, SpecialUse::None))
                                        .map(|m| m.document_id)
                                        .collect::<RoaringBitmap>(),
                                ));
                            }
                        }
                        MailboxFilter::HasAnyRole(has_role) => {
                            filters.push(SearchFilter::is_in_set(
                                mailboxes
                                    .mailboxes
                                    .items
                                    .iter()
                                    .filter(|mailbox| {
                                        matches!(mailbox.role, SpecialUse::None) != has_role
                                    })
                                    .map(|m| m.document_id)
                                    .collect::<RoaringBitmap>(),
                            ));
                        }
                        MailboxFilter::IsSubscribed(is_subscribed) => {
                            filters.push(SearchFilter::is_in_set(
                                mailboxes
                                    .mailboxes
                                    .items
                                    .iter()
                                    .filter(|mailbox| {
                                        mailbox.subscribers.contains(&access_token.primary_id)
                                            == is_subscribed
                                    })
                                    .map(|m| m.document_id)
                                    .collect::<RoaringBitmap>(),
                            ));
                        }
                        MailboxFilter::_T(other) => {
                            return Err(trc::JmapEvent::UnsupportedFilter
                                .into_err()
                                .details(other));
                        }
                    }
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
                Filter::Close => {
                    filters.push(SearchFilter::End);
                }
            }
        }

        let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));

        // Sort as tree
        if sort_as_tree {
            let sorted_set = mailboxes
                .mailboxes
                .items
                .iter()
                .map(|mailbox| (mailbox.path.as_str(), mailbox.document_id))
                .collect::<BTreeMap<_, _>>();
            comparators.push(SearchComparator::sorted_set(
                sorted_set
                    .into_iter()
                    .enumerate()
                    .map(|(i, (_, v))| (v, i as u32))
                    .collect(),
                true,
            ));
        }

        // Parse sort criteria
        for comparator in request
            .sort
            .take()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| vec![Comparator::ascending(MailboxComparator::ParentId)])
        {
            comparators.push(match comparator.property {
                MailboxComparator::Name => {
                    let sorted_set = mailboxes
                        .mailboxes
                        .items
                        .iter()
                        .map(|mailbox| (mailbox.name.as_str(), mailbox.document_id))
                        .collect::<BTreeMap<_, _>>();

                    SearchComparator::sorted_set(
                        sorted_set
                            .into_iter()
                            .enumerate()
                            .map(|(i, (_, v))| (v, i as u32))
                            .collect(),
                        comparator.is_ascending,
                    )
                }
                MailboxComparator::SortOrder => {
                    let sorted_set = mailboxes
                        .mailboxes
                        .items
                        .iter()
                        .map(|mailbox| (mailbox.document_id, mailbox.sort_order))
                        .collect::<AHashMap<_, _>>();

                    SearchComparator::sorted_set(sorted_set, comparator.is_ascending)
                }
                MailboxComparator::ParentId => {
                    let sorted_set = mailboxes
                        .mailboxes
                        .items
                        .iter()
                        .map(|mailbox| {
                            (
                                mailbox.document_id,
                                mailbox.parent_id().map(|id| id + 1).unwrap_or_default(),
                            )
                        })
                        .collect::<AHashMap<_, _>>();

                    SearchComparator::sorted_set(sorted_set, comparator.is_ascending)
                }

                MailboxComparator::_T(other) => {
                    return Err(trc::JmapEvent::UnsupportedSort.into_err().details(other));
                }
            });
        }

        let mut results = SearchQuery::new(SearchIndex::InMemory)
            .with_filters(filters)
            .with_comparators(comparators)
            .with_mask(if access_token.is_shared(account_id) {
                mailboxes.shared_mailboxes(access_token, Acl::Read)
            } else {
                mailboxes
                    .mailboxes
                    .items
                    .iter()
                    .map(|m| m.document_id)
                    .collect()
            })
            .filter();

        // Filter as tree
        if filter_as_tree {
            let mut new_results = RoaringBitmap::new();

            for document_id in results.results() {
                let mut check_id = document_id;
                for _ in 0..self.core.jmap.mailbox_max_depth {
                    if let Some(mailbox) = mailboxes.mailbox_by_id(&check_id) {
                        if let Some(parent_id) = mailbox.parent_id() {
                            if results.results().contains(parent_id) {
                                check_id = parent_id;
                            } else {
                                break;
                            }
                        } else {
                            new_results.insert(document_id);
                        }
                    }
                }
            }

            results.update_results(new_results);
        }

        let mut response = QueryResponseBuilder::new(
            results.results().len() as usize,
            self.core.jmap.query_max_results,
            mailboxes.get_state(true),
            &request,
        );

        for document_id in results.into_sorted() {
            if !response.add(0, document_id) {
                break;
            }
        }

        response.build()
    }
}
