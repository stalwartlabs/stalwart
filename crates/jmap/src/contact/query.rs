/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use common::{Server, auth::AccessToken};
use groupware::cache::GroupwareCache;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::contact::{ContactCard, ContactCardComparator, ContactCardFilter},
    request::MaybeInvalid,
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
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
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
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Name,
                            value,
                        ));
                    }
                    ContactCardFilter::Nickname(value) => {
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Nickname,
                            value,
                        ));
                    }
                    ContactCardFilter::Organization(value) => {
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Organization,
                            value,
                        ));
                    }
                    ContactCardFilter::Phone(value) => {
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Phone,
                            value,
                        ));
                    }
                    ContactCardFilter::OnlineService(value) => {
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::OnlineService,
                            value,
                        ));
                    }
                    ContactCardFilter::Address(value) => {
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Address,
                            value,
                        ));
                    }
                    ContactCardFilter::Note(value) => {
                        filters.push(SearchFilter::has_text_detect(
                            ContactSearchField::Note,
                            value,
                            self.core.jmap.default_language,
                        ));
                    }
                    ContactCardFilter::HasMember(value) => {
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Member,
                            value,
                        ));
                    }
                    ContactCardFilter::Kind(value) => {
                        filters.push(SearchFilter::eq(ContactSearchField::Kind, value));
                    }
                    ContactCardFilter::Uid(value) => {
                        filters.push(SearchFilter::eq(ContactSearchField::Uid, value))
                    }
                    ContactCardFilter::Email(email) => {
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Email,
                            sanitize_email(&email).unwrap_or(email),
                        ))
                    }
                    ContactCardFilter::Text(value) => {
                        filters.push(SearchFilter::Or);
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Name,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Nickname,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Organization,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Email,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Phone,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::OnlineService,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_unknown_text(
                            ContactSearchField::Address,
                            value.clone(),
                        ));
                        filters.push(SearchFilter::has_text_detect(
                            ContactSearchField::Note,
                            value,
                            self.core.jmap.default_language,
                        ));
                        filters.push(SearchFilter::End);
                    }
                    ContactCardFilter::CreatedBefore(before) => filters.push(SearchFilter::lt(
                        ContactSearchField::Created,
                        before.timestamp(),
                    )),
                    ContactCardFilter::CreatedAfter(after) => filters.push(SearchFilter::gt(
                        ContactSearchField::Created,
                        after.timestamp(),
                    )),
                    /*ContactCardFilter::UpdatedBefore(before) => filters.push(SearchFilter::lt(
                        ContactSearchField::Updated,
                        before.timestamp(),
                    )),
                    ContactCardFilter::UpdatedAfter(after) => filters.push(SearchFilter::gt(
                        ContactSearchField::Updated,
                        after.timestamp(),
                    )),*/
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
                ContactCardComparator::Created => Ok(SearchComparator::field(
                    ContactSearchField::Created,
                    comparator.is_ascending,
                )),
                /*ContactCardComparator::Updated => Ok(SearchComparator::field(
                    ContactSearchField::Updated,
                    comparator.is_ascending,
                )),*/
                other => Err(trc::JmapEvent::UnsupportedSort
                    .into_err()
                    .details(other.into_string())),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let results = self
            .search_store()
            .query(
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
}
