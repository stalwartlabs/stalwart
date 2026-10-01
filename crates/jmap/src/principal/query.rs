/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, principal::get::PrincipalGet};
use common::{Server, auth::AccessToken};
use compact_str::ToCompactString;
use groupware::decode_mailto_address;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::principal::{Principal, PrincipalFilter, PrincipalType},
    request::capability::{Capability, CapabilityIds},
    types::state::State,
};
use registry::{
    schema::{
        enums::AccountType,
        prelude::{ObjectType, Property},
    },
    types::EnumImpl,
};
use std::future::Future;
use store::{
    registry::RegistryQuery,
    roaring::RoaringBitmap,
    search::{SearchFilter, SearchQuery},
    write::SearchIndex,
};
use trc::AddContext;
use utils::sanitize_email;

pub trait PrincipalQuery: Sync + Send {
    fn principal_query(
        &self,
        request: QueryRequest<Principal>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl PrincipalQuery for Server {
    async fn principal_query(
        &self,
        mut request: QueryRequest<Principal>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<QueryResponse> {
        if !self.core.groupware.allow_directory_query {
            return Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("The administrator has disabled directory queries."));
        }

        let principal_ids = if request.filter.is_empty()
            || request.filter.iter().any(|cond| {
                matches!(
                    cond,
                    Filter::Not | Filter::Property(PrincipalFilter::AccountIds(_))
                )
            }) {
            Some(
                self.registry()
                    .query::<RoaringBitmap>(
                        RegistryQuery::new(ObjectType::Account)
                            .with_tenant(access_token.tenant_id()),
                    )
                    .await
                    .caused_by(trc::location!())?,
            )
        } else {
            None
        };

        let mut filters = Vec::with_capacity(request.filter.len());
        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    PrincipalFilter::Name(name) | PrincipalFilter::Email(name) => {
                        let account_id = self.account_id_from_email(&name, false).await?;
                        filters.push(SearchFilter::is_in_set(
                            visible_principal_ids(self, access_token, account_id).await?,
                        ));
                    }
                    PrincipalFilter::CalendarAddress(address)
                        if using.contains(Capability::PrincipalsAvailability) =>
                    {
                        let account_id =
                            match sanitize_email(decode_mailto_address(&address).as_ref()) {
                                Some(address) => {
                                    self.account_id_from_email(&address, false).await?
                                }
                                None => None,
                            };
                        filters.push(SearchFilter::is_in_set(
                            visible_principal_ids(self, access_token, account_id).await?,
                        ));
                    }
                    PrincipalFilter::AccountIds(ids) => {
                        filters.push(SearchFilter::is_in_set(
                            ids.into_iter()
                                .map(|id| id.document_id())
                                .filter(|id| {
                                    principal_ids.as_ref().is_some_and(|ids| ids.contains(*id))
                                })
                                .collect::<RoaringBitmap>(),
                        ));
                    }
                    PrincipalFilter::Text(text) => {
                        filters.push(SearchFilter::is_in_set(
                            self.registry()
                                .query::<RoaringBitmap>(
                                    RegistryQuery::new(ObjectType::Account)
                                        .with_tenant(access_token.tenant_id())
                                        .text(Property::Text, text),
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
                                    RegistryQuery::new(ObjectType::Account)
                                        .equal(Property::Type, typ.to_id())
                                        .with_tenant(access_token.tenant_id()),
                                )
                                .await
                                .caused_by(trc::location!())?,
                        ));
                    }
                    other => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(other.to_compact_string()));
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

        let mask = principal_ids.unwrap_or_else(|| {
            filters
                .iter()
                .filter_map(|filter| match filter {
                    SearchFilter::DocumentSet(set) => Some(set),
                    _ => None,
                })
                .fold(RoaringBitmap::new(), |mut mask, set| {
                    mask |= set;
                    mask
                })
        });

        let results = SearchQuery::new(SearchIndex::InMemory)
            .with_filters(filters)
            .with_mask(mask)
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

async fn visible_principal_ids(
    server: &Server,
    access_token: &AccessToken,
    account_id: Option<u32>,
) -> trc::Result<RoaringBitmap> {
    Ok(match account_id {
        Some(account_id)
            if server
                .visible_principal(access_token, account_id)
                .await?
                .is_some() =>
        {
            RoaringBitmap::from_iter([account_id])
        }
        _ => RoaringBitmap::new(),
    })
}
