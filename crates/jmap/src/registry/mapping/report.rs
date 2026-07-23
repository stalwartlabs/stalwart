/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::RegistryQueryFilters,
    },
};
use jmap_proto::{error::set::SetError, types::state::State};
use jmap_tools::{Key, Value};
use registry::{
    jmap::IntoValue,
    schema::prelude::{Object, ObjectInner, ObjectType, Property},
    types::{EnumImpl, datetime::UTCDateTime},
};
use smtp::reporting::index::{ExternalReportIndex, InternalReportIndex};
use std::str::FromStr;
use store::{
    U64_LEN, ValueKey,
    registry::{RegistryFilter, RegistryFilterValue, RegistryQuery},
    write::{BatchBuilder, RegistryClass, ValueClass, key::KeySerializer},
};
use trc::AddContext;
use types::id::Id;

pub(crate) async fn report_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    let object_id = set.object_type.to_id();

    // Reports cannot be created
    set.fail_all_create("Reports cannot be created");

    let mut batch = BatchBuilder::new();
    if matches!(
        set.object_type,
        ObjectType::DmarcInternalReport | ObjectType::TlsInternalReport
    ) {
        let now = UTCDateTime::now();
        'outer: for (id, value) in set.update.drain(..) {
            // Extract new deliverAt value
            let mut deliver_at = None;
            for (key, value) in value.into_expanded_object() {
                match (key, value) {
                    (Key::Property(Property::DeliverAt), Value::Str(deliver_at_)) => {
                        deliver_at = UTCDateTime::from_str(deliver_at_.as_ref())
                            .ok()
                            .filter(|da| *da > now);
                        if deliver_at.is_none() {
                            set.response.not_updated.append(
                                id,
                                SetError::invalid_patch()
                                    .with_property(Property::DeliverAt)
                                    .with_description("Invalid value for property"),
                            );
                            continue 'outer;
                        }
                    }
                    (Key::Property(Property::Id), _) => {}
                    (key, _) => {
                        set.response.not_updated.append(
                            id,
                            SetError::invalid_properties().with_property(key.into_owned()),
                        );
                        continue 'outer;
                    }
                }
            }
            let Some(deliver_at) = deliver_at else {
                set.response.not_updated.append(
                    id,
                    SetError::invalid_patch()
                        .with_property(Key::Property(Property::DeliverAt))
                        .with_description("Missing required property"),
                );
                continue;
            };

            let item_id = id.id();
            let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });
            if let Some(mut report_obj) = set
                .server
                .store()
                .get_value::<Object>(ValueKey::from(key.clone()))
                .await?
            {
                match &mut report_obj.inner {
                    ObjectInner::DmarcInternalReport(report) => {
                        report.reschedule_ops(&mut batch, item_id, report_obj.revision, deliver_at);
                    }
                    ObjectInner::TlsInternalReport(report) => {
                        report.reschedule_ops(&mut batch, item_id, report_obj.revision, deliver_at);
                    }
                    _ => {}
                }
                batch.commit_point();

                set.response.updated.append(id, None);
            } else {
                set.response.not_updated.append(id, SetError::not_found());
            }
        }
    } else {
        // External reports cannot be updated
        set.fail_all_update("External reports cannot be updated");
    }

    // Process reports to destroy
    let tenant_id = set.access_token.tenant_id().map(Id::from);
    for id in set.destroy.drain(..) {
        let item_id = id.id();
        let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });
        if let Some(report) = set
            .server
            .store()
            .get_value::<Object>(ValueKey::from(key))
            .await?
            .filter(|report| {
                !set.is_tenant_filtered || report.inner.member_tenant_id() == tenant_id
            })
        {
            match &report.inner {
                ObjectInner::DmarcExternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::TlsExternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::ArfExternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::DmarcInternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::TlsInternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                _ => {}
            }
            batch.commit_point();

            set.response.destroyed.push(id);
        } else {
            set.response.not_destroyed.append(id, SetError::not_found());
        }
    }

    if !batch.is_empty() {
        set.server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(set)
}

pub(crate) async fn report_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let object_id = get.object_type.to_id();
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else if matches!(
        get.object_type,
        ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::ArfExternalReport
    ) {
        if get.is_tenant_filtered {
            get.server.registry().query::<Vec<Id>>(
                RegistryQuery::new(get.object_type)
                    .with_tenant(get.access_token.tenant_id())
                    .with_limit(get.server.core.jmap.get_max_objects),
            )
        } else {
            get.server.registry().query::<Vec<Id>>(
                RegistryQuery::new(get.object_type)
                    .greater_than(Property::ExpiresAt, 0u64)
                    .with_limit(get.server.core.jmap.get_max_objects),
            )
        }
        .await?
    } else {
        get.server
            .registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(get.object_type)
                    .filter(RegistryFilter::greater_than(
                        Property::Domain,
                        RegistryFilterValue::Bytes(vec![]),
                        true,
                    ))
                    .with_limit(get.server.core.jmap.get_max_objects),
            )
            .await?
    };

    let tenant_id = get.access_token.tenant_id().map(Id::from);
    for id in ids {
        if let Some(report) = get
            .server
            .store()
            .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id: id.id(),
            })))
            .await?
            .filter(|report| {
                !get.is_tenant_filtered || report.inner.member_tenant_id() == tenant_id
            })
        {
            get.insert(id, report.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

pub(crate) async fn report_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let mut query = store::registry::RegistryQuery::new(req.object_type)
        .with_tenant(req.access_token.tenant_id());
    let is_internal = matches!(
        req.object_type,
        ObjectType::DmarcInternalReport | ObjectType::TlsInternalReport
    );

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Domain => {
                if let serde_json::Value::String(value) = value {
                    match req.object_type {
                        ObjectType::DmarcInternalReport => {
                            query.filters.push(RegistryFilter::greater_than_or_equal(
                                property,
                                RegistryFilterValue::Bytes(
                                    KeySerializer::new(value.len() + U64_LEN)
                                        .write(value.as_str())
                                        .write(0u64)
                                        .finalize(),
                                ),
                                true,
                            ));
                            query.filters.push(RegistryFilter::less_than_or_equal(
                                property,
                                RegistryFilterValue::Bytes(
                                    KeySerializer::new(value.len() + U64_LEN)
                                        .write(value.as_str())
                                        .write(u64::MAX)
                                        .finalize(),
                                ),
                                true,
                            ));

                            true
                        }
                        ObjectType::TlsInternalReport => {
                            query
                                .filters
                                .push(RegistryFilter::equal(property, value, true));
                            true
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            Property::Text if !is_internal => {
                if let serde_json::Value::String(value) = value {
                    query.filters.push(RegistryFilter::text(property, value));
                    true
                } else {
                    false
                }
            }
            Property::MemberTenantId if !is_internal => {
                if req.access_token.tenant_id().is_none()
                    && let Some(id) = value.as_str().and_then(|s| Id::from_str(s).ok())
                {
                    query
                        .filters
                        .push(RegistryFilter::equal(property, id.id(), false));
                    true
                } else {
                    false
                }
            }
            Property::TotalFailedSessions | Property::TotalSuccessfulSessions if !is_internal => {
                if let Some(value) = value.as_u64() {
                    query.filters.push(store::registry::RegistryFilter {
                        property,
                        op,
                        value: value.into(),
                        is_pk: false,
                    });
                    true
                } else {
                    false
                }
            }
            Property::ExpiresAt if !is_internal => {
                if let Some(value) = value
                    .as_str()
                    .and_then(|value| UTCDateTime::from_str(value).ok())
                {
                    query.filters.push(store::registry::RegistryFilter {
                        property,
                        op,
                        value: (value.timestamp() as u64).into(),
                        is_pk: false,
                    });
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, Some(Property::Id))?;

    if !query.has_filters() {
        if is_internal {
            query.filters.push(RegistryFilter::greater_than(
                Property::Domain,
                RegistryFilterValue::Bytes(vec![]),
                true,
            ));
        } else {
            query.filters.push(RegistryFilter::greater_than(
                Property::ExpiresAt,
                0u64,
                false,
            ));
        }
    }
    if let Some(limit) = params.limit {
        query = query.with_limit(limit);
        if let Some(anchor) = params.anchor {
            query = query.with_anchor(anchor);
        } else if let Some(position) = params.position {
            query = query.with_index_start(position);
        }
    }

    let matches = req.server.registry().query::<Vec<Id>>(query).await?;
    let results = match params.sort_by {
        Property::Id => {
            let mut results = matches;
            if !params.sort_ascending {
                results.sort_unstable_by(|a, b| b.cmp(a));
            }
            results
        }
        Property::Domain if is_internal => {
            if !matches.is_empty() {
                req.server
                    .registry()
                    .sort_by_pk(
                        req.object_type,
                        Property::Domain,
                        Some(matches),
                        params.sort_ascending,
                    )
                    .await?
            } else {
                vec![]
            }
        }
        Property::ExpiresAt if !is_internal => {
            if !matches.is_empty() {
                req.server
                    .registry()
                    .sort_by_index(
                        req.object_type,
                        Property::ExpiresAt,
                        Some(matches),
                        params.sort_ascending,
                    )
                    .await?
            } else {
                vec![]
            }
        }
        property => {
            return Err(trc::JmapEvent::UnsupportedSort.into_err().details(format!(
                "Property {} is not supported for sorting",
                property
            )));
        }
    };

    // Build response
    let mut response = QueryResponseBuilder::new(
        results.len(),
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    for id in results {
        if !response.add_id(id) {
            break;
        }
    }

    Ok(response)
}
