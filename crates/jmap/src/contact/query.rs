/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::{
        metadata::{
            MetadataType, ObjectMetadata, ResourceScope, filter_containers, flagged_documents,
        },
        query::QueryResponseBuilder,
    },
    calendar_event::query::{matched_items, rank_comparator},
    changes::state::JmapCacheState,
};
use common::{Server, auth::AccessToken};
use groupware::cache::GroupwareCache;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::{
        addressbook::{AddressBook, AddressBookFilter},
        contact::{ContactCard, ContactCardComparator, ContactCardFilter},
    },
    request::{MaybeInvalid, capability::CapabilityIds},
};
use store::{
    roaring::RoaringBitmap,
    search::{ContactSearchField, QueryResults, SearchFilter, SearchQuery},
    write::SearchIndex,
};
use types::{acl::Acl, collection::SyncCollection};
use utils::sanitize_email;

pub trait ContactCardQuery: Sync + Send {
    fn contact_card_query(
        &self,
        request: QueryRequest<ContactCard>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;

    fn address_book_query(
        &self,
        request: QueryRequest<AddressBook>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl ContactCardQuery for Server {
    async fn contact_card_query(
        &self,
        mut request: QueryRequest<ContactCard>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::ContactCard);
        let sampled = metadata.viewer_change_id(self, account_id).await?;
        let metadata_query =
            metadata.query(request.filter.iter().filter_map(|filter| match filter {
                Filter::Property(ContactCardFilter::Metadata(filter)) => Some(filter),
                _ => None,
            }))?;
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::AddressBook,
            )
            .await?;
        let is_shared = access_token.is_shared(account_id);
        let mask = if is_shared {
            cache.shared_items(access_token, [Acl::ReadItems], true)
        } else {
            cache.document_ids(false).collect()
        };
        let mut metadata_leaves = metadata
            .evaluate(self, account_id, &metadata_query, || {
                flagged_documents(&cache, ResourceScope::Items, is_shared.then_some(&mask))
            })
            .await?
            .into_iter();

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    ContactCardFilter::InAddressBook(MaybeInvalid::Value(id)) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.children_ids(id.document_id()),
                        )))
                    }
                    ContactCardFilter::Name(value)
                    | ContactCardFilter::NameGiven(value)
                    | ContactCardFilter::NameSurname(value)
                    | ContactCardFilter::NameSurname2(value) => {
                        filters.push(SearchFilter::has_keyword(ContactSearchField::Name, value));
                    }
                    ContactCardFilter::Nickname(value) => {
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::Nickname,
                            value,
                        ));
                    }
                    ContactCardFilter::Organization(value) => {
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::Organization,
                            value,
                        ));
                    }
                    ContactCardFilter::Phone(value) => {
                        filters.push(SearchFilter::has_keyword(ContactSearchField::Phone, value));
                    }
                    ContactCardFilter::OnlineService(value) => {
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::OnlineService,
                            value,
                        ));
                    }
                    ContactCardFilter::Address(value) => {
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::Address,
                            value,
                        ));
                    }
                    ContactCardFilter::Note(value) => {
                        filters.push(SearchFilter::has_text_detect(
                            ContactSearchField::Note,
                            value,
                            self.core.email.default_language,
                        ));
                    }
                    ContactCardFilter::HasMember(value) => {
                        filters.push(SearchFilter::has_keyword(ContactSearchField::Member, value));
                    }
                    ContactCardFilter::Kind(value) => {
                        filters.push(SearchFilter::text_eq(ContactSearchField::Kind, value));
                    }
                    ContactCardFilter::Uid(uid) => {
                        filters.push(SearchFilter::is_in_set(cache.uid_matches(&uid)));
                    }
                    ContactCardFilter::Email(email) => filters.push(SearchFilter::has_keyword(
                        ContactSearchField::Email,
                        sanitize_email(&email).unwrap_or(email),
                    )),
                    ContactCardFilter::Text(value) => {
                        filters.push(SearchFilter::Or);
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::Name,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::Nickname,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::Organization,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::Email,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::Phone,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::OnlineService,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_keyword(
                            ContactSearchField::Address,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_text_detect(
                            ContactSearchField::Note,
                            value,
                            self.core.email.default_language,
                        ));
                        filters.push(SearchFilter::End);
                    }
                    ContactCardFilter::CreatedBefore(before) => {
                        let before = before.timestamp();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                r.created_at()
                                    .filter(|created_at| *created_at < before)
                                    .map(|_| r.document_id())
                            }),
                        )));
                    }
                    ContactCardFilter::CreatedAfter(after) => {
                        let after = after.timestamp();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                r.created_at()
                                    .filter(|created_at| *created_at > after)
                                    .map(|_| r.document_id())
                            }),
                        )));
                    }
                    ContactCardFilter::UpdatedBefore(before) => {
                        let before = before.timestamp();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                r.modified_at()
                                    .filter(|modified_at| *modified_at < before)
                                    .map(|_| r.document_id())
                            }),
                        )));
                    }
                    ContactCardFilter::UpdatedAfter(after) => {
                        let after = after.timestamp();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                r.modified_at()
                                    .filter(|modified_at| *modified_at > after)
                                    .map(|_| r.document_id())
                            }),
                        )));
                    }
                    ContactCardFilter::Metadata(_) => {
                        filters.push(SearchFilter::is_in_set(
                            metadata_leaves.next().unwrap_or_default(),
                        ));
                    }
                    unsupported => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(unsupported.into_string()));
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

        let sort = request
            .sort
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|comparator| match comparator.property {
                ContactCardComparator::Created => {
                    Ok((ContactSortKey::Created, comparator.is_ascending))
                }
                ContactCardComparator::Updated => {
                    Ok((ContactSortKey::Updated, comparator.is_ascending))
                }
                other => Err(trc::JmapEvent::UnsupportedSort
                    .into_err()
                    .details(other.into_string())),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let results = self
            .search_store()
            .filter_account(
                SearchQuery::new(SearchIndex::Contacts)
                    .with_filters(filters)
                    .with_account_id(account_id)
                    .with_mask(mask),
            )
            .await?;
        let results = if results.len() > 1 && !sort.is_empty() {
            let items = matched_items(&cache, &results);
            let comparators = sort
                .into_iter()
                .map(|(key, is_ascending)| match key {
                    ContactSortKey::Created => {
                        rank_comparator(&items, |item| item.created_at(), is_ascending)
                    }
                    ContactSortKey::Updated => {
                        rank_comparator(&items, |item| item.modified_at(), is_ascending)
                    }
                })
                .collect();
            QueryResults::new(results, comparators).into_sorted()
        } else {
            results.into_iter().collect()
        };

        let mut response = QueryResponseBuilder::new(
            results.len(),
            self.core.jmap.query_max_results,
            sampled.state(cache.get_state(false)),
            &request,
        );

        for document_id in results {
            if !response.add(0, document_id) {
                break;
            }
        }

        response.build()
    }

    async fn address_book_query(
        &self,
        request: QueryRequest<AddressBook>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<QueryResponse> {
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::AddressBook);
        let mut metadata_filters = Vec::new();
        for filter in &request.filter {
            match filter {
                Filter::Property(AddressBookFilter::Metadata(filter)) => {
                    metadata_filters.push(filter);
                }
                Filter::Property(AddressBookFilter::_T(other)) => {
                    return Err(trc::JmapEvent::UnsupportedFilter
                        .into_err()
                        .details(other.clone()));
                }
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {}
            }
        }
        let metadata_query = metadata.query(metadata_filters)?;

        let account_id = request.account_id.document_id();
        let sampled = metadata.viewer_change_id(self, account_id).await?;
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::AddressBook,
            )
            .await?;

        let is_member = access_token.is_member(account_id);
        let readable = if is_member {
            cache.document_ids(true).collect::<RoaringBitmap>()
        } else {
            cache.shared_containers(access_token, [Acl::Read, Acl::ReadItems], true)
        };
        let leaves = metadata
            .evaluate(self, account_id, &metadata_query, || {
                flagged_documents(
                    &cache,
                    ResourceScope::Containers,
                    (!is_member).then_some(&readable),
                )
            })
            .await?;
        let results = filter_containers(&request.filter, leaves, readable);

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            sampled.state(cache.get_state(true)),
            &request,
        );

        for document_id in results {
            if !response.add(0, document_id) {
                break;
            }
        }

        response.build()
    }
}

#[derive(Debug, Clone, Copy)]
enum ContactSortKey {
    Created,
    Updated,
}
