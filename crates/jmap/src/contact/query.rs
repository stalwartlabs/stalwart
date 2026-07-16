/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use common::{DavResourceMetadata, Server, auth::AccessToken};
use groupware::cache::GroupwareCache;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::{
        addressbook::AddressBook,
        contact::{ContactCard, ContactCardComparator, ContactCardFilter},
    },
    request::MaybeInvalid,
    types::state::State,
};
use store::{
    roaring::RoaringBitmap,
    search::{ContactSearchField, SearchComparator, SearchFilter, SearchQuery},
    write::SearchIndex,
};
use types::{acl::Acl, collection::SyncCollection};
use utils::sanitize_email;

pub trait ContactCardQuery: Sync + Send {
    fn contact_card_query(
        &self,
        request: QueryRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;

    fn address_book_query(
        &self,
        request: QueryRequest<AddressBook>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl ContactCardQuery for Server {
    async fn contact_card_query(
        &self,
        mut request: QueryRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());
        let cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::AddressBook,
            )
            .await?;

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
                    ContactCardFilter::Uid(value) => {
                        filters.push(SearchFilter::text_eq(ContactSearchField::Uid, value))
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
                                if let DavResourceMetadata::ContactCard { created_at, .. } = &r.data
                                {
                                    (*created_at < before).then_some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
                    }
                    ContactCardFilter::CreatedAfter(after) => {
                        let after = after.timestamp();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if let DavResourceMetadata::ContactCard { created_at, .. } = &r.data
                                {
                                    (*created_at > after).then_some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
                    }
                    ContactCardFilter::UpdatedBefore(before) => {
                        let before = before.timestamp();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if let DavResourceMetadata::ContactCard {
                                    modified_at,
                                    created_at,
                                    ..
                                } = &r.data
                                {
                                    ((*modified_at as i64 + *created_at) < before)
                                        .then_some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
                    }
                    ContactCardFilter::UpdatedAfter(after) => {
                        let after = after.timestamp();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if let DavResourceMetadata::ContactCard {
                                    modified_at,
                                    created_at,
                                    ..
                                } = &r.data
                                {
                                    ((*modified_at as i64 + *created_at) > after)
                                        .then_some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
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

        let comparators = request
            .sort
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|comparator| match comparator.property {
                ContactCardComparator::Created => {
                    let mut items = cache
                        .resources
                        .iter()
                        .filter_map(|r| {
                            if let DavResourceMetadata::ContactCard { created_at, .. } = &r.data {
                                Some((r.document_id, *created_at))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                    items.sort_by_key(|(document_id, created_at)| (*created_at, *document_id));

                    Ok(SearchComparator::sorted_set(
                        items
                            .iter()
                            .enumerate()
                            .map(|(idx, (u, _))| (*u, idx as u32))
                            .collect(),
                        comparator.is_ascending,
                    ))
                }
                ContactCardComparator::Updated => {
                    let mut items = cache
                        .resources
                        .iter()
                        .filter_map(|r| {
                            if let DavResourceMetadata::ContactCard {
                                modified_at,
                                created_at,
                                ..
                            } = &r.data
                            {
                                Some((r.document_id, *modified_at as i64 + *created_at))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                    items.sort_by_key(|(document_id, modified_at)| (*modified_at, *document_id));

                    Ok(SearchComparator::sorted_set(
                        items
                            .iter()
                            .enumerate()
                            .map(|(idx, (u, _))| (*u, idx as u32))
                            .collect(),
                        comparator.is_ascending,
                    ))
                }
                other => Err(trc::JmapEvent::UnsupportedSort
                    .into_err()
                    .details(other.into_string())),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let results = self
            .search_store()
            .query_account(
                SearchQuery::new(SearchIndex::Contacts)
                    .with_filters(filters)
                    .with_comparators(comparators)
                    .with_account_id(account_id)
                    .with_mask(if access_token.is_shared(account_id) {
                        cache.shared_items(access_token, [Acl::ReadItems], true)
                    } else {
                        cache.document_ids(false).collect()
                    }),
            )
            .await?;

        let mut response = QueryResponseBuilder::new(
            results.len(),
            self.core.jmap.query_max_results,
            cache.get_state(false),
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
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::AddressBook,
            )
            .await?;

        let results = cache.document_ids(true).collect::<Vec<_>>();

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            State::Initial,
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
