/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use groupware::cache::GroupwareCache;
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse},
    object::contact::{ContactCard, ContactCardComparator, ContactCardFilter},
    request::MaybeInvalid,
};
use nlp::tokenizers::word::WordTokenizer;
use store::{SerializeInfallible, backend::MAX_TOKEN_LENGTH, query, roaring::RoaringBitmap};
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::ContactField,
};
use utils::sanitize_email;

use crate::{JmapMethods, changes::state::JmapCacheState};

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
        let filter_mask = (access_token.is_shared(account_id))
            .then(|| cache.shared_items(access_token, [Acl::ReadItems], true));

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    ContactCardFilter::InAddressBook(MaybeInvalid::Value(id)) => {
                        filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
                            cache.children_ids(id.document_id()),
                        )))
                    }
                    ContactCardFilter::Uid(uid) => {
                        filters.push(query::Filter::eq(ContactField::Uid, uid.into_bytes()))
                    }
                    ContactCardFilter::Email(email) => filters.push(query::Filter::eq(
                        ContactField::Email,
                        sanitize_email(&email).unwrap_or(email).into_bytes(),
                    )),
                    ContactCardFilter::Text(value) => {
                        for token in WordTokenizer::new(&value, MAX_TOKEN_LENGTH) {
                            filters.push(query::Filter::eq(
                                ContactField::Text,
                                token.word.into_owned().into_bytes(),
                            ));
                        }
                    }
                    ContactCardFilter::CreatedBefore(before) => filters.push(query::Filter::lt(
                        ContactField::Created,
                        (before.timestamp() as u64).serialize(),
                    )),
                    ContactCardFilter::CreatedAfter(after) => filters.push(query::Filter::gt(
                        ContactField::Created,
                        (after.timestamp() as u64).serialize(),
                    )),
                    ContactCardFilter::UpdatedBefore(before) => filters.push(query::Filter::lt(
                        ContactField::Updated,
                        (before.timestamp() as u64).serialize(),
                    )),
                    ContactCardFilter::UpdatedAfter(after) => filters.push(query::Filter::gt(
                        ContactField::Updated,
                        (after.timestamp() as u64).serialize(),
                    )),
                    unsupported => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(unsupported.into_string()));
                    }
                },

                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }
            }
        }

        let mut result_set = self
            .filter(account_id, Collection::ContactCard, filters)
            .await?;

        if let Some(filter_mask) = filter_mask {
            result_set.apply_mask(filter_mask);
        }

        let (response, paginate) = self
            .build_query_response(result_set.results.len() as usize, cache.get_state(false), &request)
            .await?;

        if let Some(paginate) = paginate {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| vec![Comparator::descending(ContactCardComparator::Updated)])
            {
                comparators.push(match comparator.property {
                    ContactCardComparator::Created => {
                        query::Comparator::field(ContactField::Created, comparator.is_ascending)
                    }
                    ContactCardComparator::Updated => {
                        query::Comparator::field(ContactField::Updated, comparator.is_ascending)
                    }
                    unsupported => {
                        return Err(trc::JmapEvent::UnsupportedSort
                            .into_err()
                            .details(unsupported.into_string()));
                    }
                });
            }

            // Sort results
            self.sort(result_set, comparators, paginate, response).await
        } else {
            Ok(response)
        }
    }
}
