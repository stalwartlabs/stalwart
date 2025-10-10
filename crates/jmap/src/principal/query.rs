/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::JmapMethods;
use common::{Server, auth::AccessToken};
use directory::{QueryParams, Type, backend::internal::manage::ManageDirectory};
use http_proto::HttpSessionData;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::principal::{Principal, PrincipalFilter, PrincipalType},
    types::state::State,
};
use std::future::Future;
use store::{query::ResultSet, roaring::RoaringBitmap};
use types::collection::Collection;

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
        let mut result_set = ResultSet {
            account_id: request.account_id.document_id(),
            collection: Collection::Principal,
            results: RoaringBitmap::new(),
        };
        let mut is_set = true;
        let all_ids = if access_token.tenant.is_some() {
            self.store()
                .list_principals(None, access_token.tenant.map(|t| t.id), &[], false, 0, 0)
                .await?
                .items
                .into_iter()
                .map(|p| p.id())
                .collect::<RoaringBitmap>()
        } else {
            self.get_document_ids(u32::MAX, Collection::Principal)
                .await?
                .unwrap_or_default()
        };

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
                            if is_set || result_set.results.contains(principal.id()) {
                                result_set.results =
                                    RoaringBitmap::from_sorted_iter([principal.id()]).unwrap();
                            } else {
                                result_set.results = RoaringBitmap::new();
                            }
                        } else {
                            result_set.results = RoaringBitmap::new();
                        }
                        is_set = false;
                    }
                    PrincipalFilter::Email(email) => {
                        let mut ids = RoaringBitmap::new();
                        if let Some(id) = self
                            .email_to_id(self.directory(), &email, session.session_id)
                            .await?
                        {
                            ids.insert(id);
                        }
                        if is_set {
                            result_set.results = ids;
                            is_set = false;
                        } else {
                            result_set.results &= ids;
                        }
                    }
                    PrincipalFilter::AccountIds(ids) => {
                        let ids = ids
                            .into_iter()
                            .filter_map(|id| {
                                let id = id.document_id();
                                if all_ids.contains(id) { Some(id) } else { None }
                            })
                            .collect::<RoaringBitmap>();
                        if is_set {
                            result_set.results = ids;
                            is_set = false;
                        } else {
                            result_set.results &= ids;
                        }
                    }
                    PrincipalFilter::Text(text) => {
                        let ids = self
                            .store()
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
                            .collect::<RoaringBitmap>();

                        if is_set {
                            result_set.results = ids;
                            is_set = false;
                        } else {
                            result_set.results &= ids;
                        }
                    }
                    PrincipalFilter::Type(principal_type) => {
                        let typ = match principal_type {
                            PrincipalType::Individual => Type::Individual,
                            PrincipalType::Group => Type::Group,
                            PrincipalType::Resource => Type::Resource,
                            PrincipalType::Location => Type::Location,
                            PrincipalType::Other => Type::Other,
                        };

                        let ids = self
                            .store()
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
                            .collect::<RoaringBitmap>();

                        if is_set {
                            result_set.results = ids;
                            is_set = false;
                        } else {
                            result_set.results &= ids;
                        }
                    }
                    other => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(other.to_string()));
                    }
                },
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    return Err(trc::JmapEvent::UnsupportedFilter
                        .into_err()
                        .details("Logical operators are not supported"));
                }
            }
        }

        if is_set {
            result_set.results = all_ids;
        } else {
            result_set.results &= all_ids;
        }

        let (response, paginate) = self
            .build_query_response(&result_set, State::Initial, &request)
            .await?;

        if let Some(paginate) = paginate {
            self.sort(result_set, Vec::new(), paginate, response).await
        } else {
            Ok(response)
        }
    }
}
