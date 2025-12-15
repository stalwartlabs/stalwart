/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::query::QueryResponseBuilder;
use common::{Server, auth::AccessToken};
use directory::{Permission, QueryParams, Type, backend::internal::manage::ManageDirectory};
use http_proto::HttpSessionData;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::principal::{Principal, PrincipalFilter, PrincipalType},
    types::state::State,
};
use std::future::Future;
use store::{
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
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl PrincipalQuery for Server {
    async fn principal_query(
        &self,
        mut request: QueryRequest<Principal>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<QueryResponse> {
        if !self.core.groupware.allow_directory_query
            && !access_token.has_permission(Permission::IndividualList)
        {
            return Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("The administrator has disabled directory queries.".to_string()));
        }

        let principal_ids = self
            .store()
            .list_principals(
                None,
                access_token.tenant_id(),
                &[
                    Type::Individual,
                    Type::Group,
                    Type::Resource,
                    Type::Location,
                ],
                false,
                0,
                0,
            )
            .await
            .caused_by(trc::location!())?
            .items
            .into_iter()
            .map(|p| p.id())
            .collect::<RoaringBitmap>();

        let mut filters = Vec::with_capacity(request.filter.len());
        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    PrincipalFilter::Name(name) => {
                        if let Some(principal) = self
                            .core
                            .storage
                            .directory
                            .query(QueryParams::name(name.as_str()).with_return_member_of(false))
                            .await?
                        {
                            filters.push(SearchFilter::is_in_set(
                                RoaringBitmap::from_sorted_iter([principal.id()]).unwrap(),
                            ));
                        }
                    }
                    PrincipalFilter::Email(email) => {
                        if let Some(id) = self
                            .email_to_id(self.directory(), &email, session.session_id)
                            .await?
                        {
                            filters.push(SearchFilter::is_in_set(
                                RoaringBitmap::from_sorted_iter([id]).unwrap(),
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
                            self.store()
                                .list_principals(
                                    Some(text.as_str()),
                                    access_token.tenant.map(|t| t.id),
                                    &[],
                                    false,
                                    0,
                                    0,
                                )
                                .await?
                                .items
                                .into_iter()
                                .map(|p| p.id())
                                .collect::<RoaringBitmap>(),
                        ));
                    }
                    PrincipalFilter::Type(principal_type) => {
                        let typ = match principal_type {
                            PrincipalType::Individual => Type::Individual,
                            PrincipalType::Group => Type::Group,
                            PrincipalType::Resource => Type::Resource,
                            PrincipalType::Location => Type::Location,
                            PrincipalType::Other => Type::Other,
                        };

                        filters.push(SearchFilter::is_in_set(
                            self.store()
                                .list_principals(
                                    None,
                                    access_token.tenant.map(|t| t.id),
                                    &[typ],
                                    false,
                                    0,
                                    0,
                                )
                                .await?
                                .items
                                .into_iter()
                                .map(|p| p.id())
                                .collect::<RoaringBitmap>(),
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
