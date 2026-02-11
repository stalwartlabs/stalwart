/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::query::QueryResponseBuilder;
use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::principal::{Principal, PrincipalFilter, PrincipalType},
    types::state::State,
};
use registry::{
    schema::{
        enums::AccountType,
        prelude::{Object, Permission, Property},
    },
    types::EnumType,
};
use std::future::Future;
use store::{
    registry::RegistryQuery,
    roaring::RoaringBitmap,
    search::{SearchFilter, SearchQuery},
    write::SearchIndex,
};
use trc::AddContext;

pub trait PrincipalQuery: Sync + Send {
    fn principal_query(
        &self,
        request: QueryRequest<Principal>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl PrincipalQuery for Server {
    async fn principal_query(
        &self,
        mut request: QueryRequest<Principal>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        if !self.core.groupware.allow_directory_query
            && !access_token.has_permission(Permission::IndividualList)
        {
            return Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("The administrator has disabled directory queries.".to_string()));
        }

        let principal_ids = self
            .registry()
            .query::<RoaringBitmap>(
                RegistryQuery::new(Object::Account)
                    .equal_opt(Property::MemberTenantId, access_token.tenant_id()),
            )
            .await
            .caused_by(trc::location!())?;

        let mut filters = Vec::with_capacity(request.filter.len());
        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    PrincipalFilter::Name(name) | PrincipalFilter::Email(name) => {
                        if let Some(account_id) = self.account_id(&name).await? {
                            filters.push(SearchFilter::is_in_set(
                                RoaringBitmap::from_sorted_iter([account_id]).unwrap(),
                            ));
                        }
                    }
                    PrincipalFilter::AccountIds(ids) => {
                        filters.push(SearchFilter::is_in_set(
                            ids.into_iter()
                                .filter_map(|id| {
                                    let id = id.document_id();
                                    if principal_ids.contains(id) {
                                        Some(id)
                                    } else {
                                        None
                                    }
                                })
                                .collect::<RoaringBitmap>(),
                        ));
                    }
                    PrincipalFilter::Text(text) => {
                        filters.push(SearchFilter::is_in_set(
                            self.registry()
                                .query::<RoaringBitmap>(
                                    RegistryQuery::new(Object::Account)
                                        .equal_opt(
                                            Property::MemberTenantId,
                                            access_token.tenant_id(),
                                        )
                                        .text(text),
                                )
                                .await
                                .caused_by(trc::location!())?,
                        ));
                    }
                    PrincipalFilter::Type(principal_type) => {
                        let typ = match principal_type {
                            PrincipalType::Individual => AccountType::User,
                            PrincipalType::Group => AccountType::Group,
                            _ => {
                                filters.push(SearchFilter::is_in_set(Default::default()));
                                continue;
                            }
                        };

                        filters.push(SearchFilter::is_in_set(
                            self.registry()
                                .query::<RoaringBitmap>(
                                    RegistryQuery::new(Object::Account)
                                        .equal(Property::Type, typ.to_id())
                                        .equal_opt(
                                            Property::MemberTenantId,
                                            access_token.tenant_id(),
                                        ),
                                )
                                .await
                                .caused_by(trc::location!())?,
                        ));
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

        let results = SearchQuery::new(SearchIndex::InMemory)
            .with_filters(filters)
            .with_mask(principal_ids)
            .filter()
            .into_bitmap();

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
