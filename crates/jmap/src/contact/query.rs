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
    IterateParams, U32_LEN, U64_LEN, ValueKey,
    roaring::RoaringBitmap,
    search::{ContactSearchField, SearchComparator, SearchFilter, SearchQuery},
    write::{IndexPropertyClass, SearchIndex, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::ContactField,
};
use utils::sanitize_email;

pub trait ContactCardQuery: Sync + Send {
    fn contact_card_query(
        &self,
        request: QueryRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

#[derive(Clone)]
struct CreatedUpdated {
    document_id: u32,
    created: u64,
    updated: u64,
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
        let mut created_to_updated = Vec::new();

        if request.filter.iter().any(|cond| {
            matches!(
                cond,
                Filter::Property(
                    ContactCardFilter::CreatedBefore(_)
                        | ContactCardFilter::CreatedAfter(_)
                        | ContactCardFilter::UpdatedBefore(_)
                        | ContactCardFilter::UpdatedAfter(_)
                )
            )
        }) || request.sort.as_ref().is_some_and(|v| {
            v.iter().any(|sort| {
                matches!(
                    sort.property,
                    ContactCardComparator::Created | ContactCardComparator::Updated
                )
            })
        }) {
            self.store()
                .iterate(
                    IterateParams::new(
                        ValueKey {
                            account_id,
                            collection: Collection::ContactCard.into(),
                            document_id: 0,
                            class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                                property: ContactField::CreatedToUpdated.into(),
                                value: 0,
                            }),
                        },
                        ValueKey {
                            account_id,
                            collection: Collection::ContactCard.into(),
                            document_id: 0,
                            class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                                property: ContactField::CreatedToUpdated.into(),
                                value: u64::MAX,
                            }),
                        },
                    )
                    .ascending(),
                    |key, value| {
                        created_to_updated.push(CreatedUpdated {
                            document_id: key.deserialize_be_u32(key.len() - U32_LEN)?,
                            created: key.deserialize_be_u64(key.len() - U32_LEN - U64_LEN)?,
                            updated: value.deserialize_be_u64(0)?,
                        });

                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }

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
                            self.core.jmap.default_language,
                        ));
                    }
                    ContactCardFilter::HasMember(value) => {
                        filters.push(SearchFilter::has_keyword(ContactSearchField::Member, value));
                    }
                    ContactCardFilter::Kind(value) => {
                        filters.push(SearchFilter::eq(ContactSearchField::Kind, value));
                    }
                    ContactCardFilter::Uid(value) => {
                        filters.push(SearchFilter::eq(ContactSearchField::Uid, value))
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
                            self.core.jmap.default_language,
                        ));
                        filters.push(SearchFilter::End);
                    }
                    ContactCardFilter::CreatedBefore(before) => {
                        let before = before.timestamp() as u64;
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            created_to_updated
                                .iter()
                                .filter_map(|cu| (cu.created < before).then_some(cu.document_id)),
                        )));
                    }
                    ContactCardFilter::CreatedAfter(after) => {
                        let after = after.timestamp() as u64;
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            created_to_updated
                                .iter()
                                .filter_map(|cu| (cu.created > after).then_some(cu.document_id)),
                        )));
                    }
                    ContactCardFilter::UpdatedBefore(before) => {
                        let before = before.timestamp() as u64;
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            created_to_updated
                                .iter()
                                .filter_map(|cu| (cu.updated < before).then_some(cu.document_id)),
                        )));
                    }
                    ContactCardFilter::UpdatedAfter(after) => {
                        let after = after.timestamp() as u64;
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            created_to_updated
                                .iter()
                                .filter_map(|cu| (cu.updated > after).then_some(cu.document_id)),
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
                ContactCardComparator::Created => Ok(SearchComparator::sorted_set(
                    created_to_updated
                        .iter()
                        .enumerate()
                        .map(|(idx, u)| (u.document_id, idx as u32))
                        .collect(),
                    comparator.is_ascending,
                )),
                ContactCardComparator::Updated => {
                    let mut updated = created_to_updated.clone();
                    updated.sort_by(|a, b| a.updated.cmp(&b.updated));
                    Ok(SearchComparator::sorted_set(
                        updated
                            .iter()
                            .enumerate()
                            .map(|(idx, u)| (u.document_id, idx as u32))
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
}
