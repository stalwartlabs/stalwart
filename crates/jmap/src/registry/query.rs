/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        EnterpriseRegistry,
        mapping::{
            RegistryQueryResponse, account::credential_query, cluster::cluster_node_query,
            log::log_query, queued_message::queued_message_query, report::report_query,
            spam_sample::spam_sample_query, task::task_query,
        },
    },
};
use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse},
    object::registry::{Registry, RegistryComparator, RegistryFilter, RegistryFilterOperator},
    types::state::State,
};
use registry::{
    schema::{
        enums::{AccountType, Permission},
        prelude::{ObjectType, Property},
    },
    types::{
        EnumImpl,
        index::{IndexSchemaType, IndexSchemaValueType},
        ipmask::IpAddrOrMask,
    },
};
use std::str::FromStr;
use store::registry::{RegistryFilterOp, RegistryFilterValue};
use types::id::Id;

pub trait RegistryQuery: Sync + Send {
    fn registry_query(
        &self,
        object_type: ObjectType,
        request: QueryRequest<Registry>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl RegistryQuery for Server {
    async fn registry_query(
        &self,
        object_type: ObjectType,
        mut request: QueryRequest<Registry>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        // Initial assertions
        if self.registry().is_bootstrap_mode() {
            return Err(trc::JmapEvent::Forbidden.into_err().details(concat!(
                "The server is in bootstrap mode. Only the 'Bootstrap' object type ",
                "can be accessed until the bootstrap process is complete.",
            )));
        }
        self.assert_enterprise_object(object_type)?;

        match object_type {
            ObjectType::ArfExternalReport
            | ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::DmarcInternalReport
            | ObjectType::TlsInternalReport => report_query(RegistryQueryResponse {
                server: self,
                access_token,
                object_type,
                request,
            })
            .await
            .and_then(|response| response.build()),

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => {
                super::mapping::archived_item::archived_item_query(RegistryQueryResponse {
                    server: self,
                    access_token,
                    object_type,
                    request,
                })
                .await
                .and_then(|response| response.build())
            }

            #[cfg(feature = "enterprise")]
            ObjectType::Metric => super::mapping::telemetry::metric_query(RegistryQueryResponse {
                server: self,
                access_token,
                object_type,
                request,
            })
            .await
            .and_then(|response| response.build()),

            #[cfg(feature = "enterprise")]
            ObjectType::Trace => super::mapping::telemetry::trace_query(RegistryQueryResponse {
                server: self,
                access_token,
                object_type,
                request,
            })
            .await
            .and_then(|response| response.build()),
            // SPDX-SnippetEnd
            ObjectType::SpamTrainingSample => spam_sample_query(RegistryQueryResponse {
                server: self,
                access_token,
                object_type,
                request,
            })
            .await
            .and_then(|response| response.build()),

            ObjectType::QueuedMessage => queued_message_query(RegistryQueryResponse {
                server: self,
                access_token,
                object_type,
                request,
            })
            .await
            .and_then(|response| response.build()),

            ObjectType::ClusterNode => cluster_node_query(RegistryQueryResponse {
                server: self,
                access_token,
                object_type,
                request,
            })
            .await
            .and_then(|response| response.build()),

            ObjectType::ApiKey | ObjectType::AppPassword => {
                credential_query(RegistryQueryResponse {
                    server: self,
                    access_token,
                    object_type,
                    request,
                })
                .await
                .and_then(|response| response.build())
            }

            ObjectType::Task => task_query(RegistryQueryResponse {
                server: self,
                access_token,
                object_type,
                request,
            })
            .await
            .and_then(|response| response.build()),

            ObjectType::Log => log_query(RegistryQueryResponse {
                server: self,
                access_token,
                object_type,
                request,
            })
            .await
            .and_then(|response| response.build()),

            ObjectType::Action => Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("Actions cannot be queried")),

            _ => {
                let mut query = store::registry::RegistryQuery::new(object_type)
                    .with_tenant(access_token.tenant_id());
                let can_impersonate = access_token.has_permission(Permission::Impersonate);
                if !can_impersonate {
                    query = query.with_account(request.account_id.document_id());
                }
                let indexes = object_type.indexes();
                request.extract_filters(|property, op, value| match property {
                    Property::MemberTenantId if access_token.tenant_id().is_some() => true,
                    Property::AccountId if !can_impersonate => true,
                    property => {
                        let Some(index) = indexes.iter().find(|i| i.prop == property) else {
                            return false;
                        };
                        let is_pk = index.typ == IndexSchemaType::Unique;

                        let value = match (index.value, value) {
                            (IndexSchemaValueType::Keyword, serde_json::Value::String(value)) => {
                                Some(RegistryFilterValue::from(value))
                            }
                            (IndexSchemaValueType::Text, serde_json::Value::String(value)) => {
                                query.push_text(property, value);
                                return true;
                            }
                            (IndexSchemaValueType::Number, serde_json::Value::Number(value)) => {
                                value
                                    .as_i64()
                                    .map(|value| RegistryFilterValue::from(value as u64))
                            }
                            (IndexSchemaValueType::Enum, serde_json::Value::String(value))
                                if (property == Property::Type
                                    && object_type == ObjectType::Account) =>
                            {
                                AccountType::parse(&value)
                                    .map(|id| RegistryFilterValue::from(id.to_id()))
                            }
                            (IndexSchemaValueType::Boolean, serde_json::Value::Bool(value)) => {
                                Some(RegistryFilterValue::from(value))
                            }
                            (IndexSchemaValueType::Id, serde_json::Value::String(value)) => {
                                Id::from_str(&value)
                                    .ok()
                                    .map(|id| RegistryFilterValue::from(id.id()))
                            }
                            (IndexSchemaValueType::IpMask, serde_json::Value::String(value)) => {
                                IpAddrOrMask::from_str(&value)
                                    .ok()
                                    .map(|ip| RegistryFilterValue::Bytes(ip.to_index_key()))
                            }
                            _ => None,
                        };

                        if let Some(value) = value {
                            query.filters.push(store::registry::RegistryFilter {
                                property,
                                op,
                                value,
                                is_pk,
                            });

                            true
                        } else {
                            false
                        }
                    }
                })?;

                let params = request
                    .extract_parameters(self.core.jmap.query_max_results, Some(Property::Id))?;
                if let Some(limit) = params.limit {
                    query = query.with_limit(limit);
                    if let Some(anchor) = params.anchor {
                        query = query.with_anchor(anchor);
                    } else if let Some(position) = params.position {
                        query = query.with_index_start(position);
                    }
                }

                let matches = if query.has_filters() || params.sort_by == Property::Id {
                    let matches = self.registry().query::<Vec<Id>>(query).await?;
                    if matches.is_empty() {
                        return QueryResponseBuilder::new(
                            0,
                            self.core.jmap.query_max_results,
                            State::Initial,
                            &request,
                        )
                        .build();
                    }
                    matches.into()
                } else {
                    None
                };

                let results = match params.sort_by {
                    Property::Id => {
                        let mut results = matches.unwrap();
                        if !params.sort_ascending {
                            results.sort_unstable_by(|a, b| b.cmp(a));
                        }
                        results
                    }
                    property => {
                        let Some(index) = indexes
                            .iter()
                            .find(|i| i.prop == property && i.value != IndexSchemaValueType::Text)
                        else {
                            return Err(trc::JmapEvent::UnsupportedSort.into_err().details(
                                format!("Property {} is not supported for sorting", property),
                            ));
                        };

                        if index.typ == IndexSchemaType::Search {
                            self.registry()
                                .sort_by_index(
                                    object_type,
                                    index.prop,
                                    matches,
                                    params.sort_ascending,
                                )
                                .await?
                        } else {
                            self.registry()
                                .sort_by_pk(object_type, index.prop, matches, params.sort_ascending)
                                .await?
                        }
                    }
                };

                // Build response
                let mut response = QueryResponseBuilder::new(
                    results.len(),
                    self.core.jmap.query_max_results,
                    State::Initial,
                    &request,
                );

                for id in results {
                    if !response.add_id(id) {
                        break;
                    }
                }

                response.build()
            }
        }
    }
}

pub(crate) trait RegistryQueryFilters {
    fn extract_filters(
        &mut self,
        cb: impl FnMut(Property, RegistryFilterOp, serde_json::Value) -> bool,
    ) -> trc::Result<()>;

    fn extract_parameters(
        &mut self,
        max_results: usize,
        external_filter: Option<Property>,
    ) -> trc::Result<RegistryQueryParameters>;
}

pub(crate) struct RegistryQueryParameters {
    pub sort_by: Property,
    pub sort_ascending: bool,
    pub anchor: Option<u64>,
    pub position: Option<u64>,
    pub limit: Option<usize>,
}

impl RegistryQueryFilters for QueryRequest<Registry> {
    fn extract_filters(
        &mut self,
        mut cb: impl FnMut(Property, RegistryFilterOp, serde_json::Value) -> bool,
    ) -> trc::Result<()> {
        for cond in std::mem::take(&mut self.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    RegistryFilter::Property {
                        property,
                        operator,
                        value,
                    } => {
                        let operator = match operator {
                            RegistryFilterOperator::Equal => RegistryFilterOp::Equal,
                            RegistryFilterOperator::GreaterThan => RegistryFilterOp::GreaterThan,
                            RegistryFilterOperator::GreaterThanOrEqual => {
                                RegistryFilterOp::GreaterEqualThan
                            }
                            RegistryFilterOperator::LessThan => RegistryFilterOp::LowerThan,
                            RegistryFilterOperator::LessThanOrEqual => {
                                RegistryFilterOp::LowerEqualThan
                            }
                        };
                        if !cb(property, operator, value) {
                            return Err(trc::JmapEvent::UnsupportedFilter.into_err().details(
                                format!(
                                    "Filter on property {} is not supported or invalid",
                                    property
                                ),
                            ));
                        }
                    }
                    RegistryFilter::_T(other) => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(other.to_string()));
                    }
                },
                Filter::And | Filter::Close => {}
                Filter::Or | Filter::Not => {
                    return Err(trc::JmapEvent::UnsupportedFilter
                        .into_err()
                        .details("Only AND is supported in filters".to_string()));
                }
            }
        }

        Ok(())
    }

    fn extract_parameters(
        &mut self,
        max_results: usize,
        external_filter: Option<Property>,
    ) -> trc::Result<RegistryQueryParameters> {
        #[cfg(feature = "test_mode")]
        let comparator = self
            .sort
            .take()
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or_else(|| Comparator::ascending(RegistryComparator::Property(Property::Id)));
        #[cfg(not(feature = "test_mode"))]
        let comparator = self
            .sort
            .take()
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or_else(|| Comparator::descending(RegistryComparator::Property(Property::Id)));

        match comparator.property {
            RegistryComparator::Property(property) => {
                if external_filter.is_some_and(|f| f == property)
                    && !self.calculate_total.unwrap_or(false)
                    && self.anchor_offset.is_none_or(|offset| offset == 0)
                    && self.position.is_none_or(|pos| pos > 0)
                {
                    Ok(RegistryQueryParameters {
                        sort_by: property,
                        sort_ascending: comparator.is_ascending,
                        anchor: self.anchor.take().map(|anchor| anchor.id()),
                        position: self.position.take().map(|pos| pos as u64),
                        limit: self
                            .limit
                            .take()
                            .map(|limit| std::cmp::min(limit, max_results))
                            .unwrap_or(max_results)
                            .into(),
                    })
                } else {
                    Ok(RegistryQueryParameters {
                        sort_by: property,
                        sort_ascending: comparator.is_ascending,
                        anchor: None,
                        position: None,
                        limit: None,
                    })
                }
            }
            RegistryComparator::_T(other) => Err(trc::JmapEvent::UnsupportedSort
                .into_err()
                .details(format!("Property {} is not supported for sorting", other))),
        }
    }
}
