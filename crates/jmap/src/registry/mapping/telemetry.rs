/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse},
        query::RegistryQueryFilters,
    },
};
use common::Server;
use jmap_proto::types::state::State;
use registry::{
    jmap::{IntoValue, JmapValue},
    schema::{
        prelude::Property,
        structs::{Metric, Trace, TraceEvent, TraceValue},
    },
    types::datetime::UTCDateTime,
};
use std::str::FromStr;
use store::{
    Deserialize, IterateParams, ValueKey,
    ahash::AHashSet,
    registry::RegistryFilterOp,
    search::{
        SearchComparator, SearchField, SearchFilter, SearchOperator, SearchQuery,
        TracingSearchField,
    },
    write::{SearchIndex, TelemetryClass, ValueClass, key::DeserializeBigEndian, now},
};
use trc::{AddContext, EventType, Key, MetricType};
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

pub(crate) async fn trace_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        get.server
            .search_store()
            .query_global(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(SearchFilter::gt(
                        SearchField::Id,
                        SnowflakeIdGenerator::from_timestamp(now() - 86400).unwrap_or_default(),
                    ))
                    .with_comparator(SearchComparator::Field {
                        field: SearchField::Id,
                        ascending: false,
                    }),
            )
            .await?
            .into_iter()
            .take(get.server.core.jmap.get_max_objects)
            .map(Id::from)
            .collect()
    };
    let has_timestamp_field =
        get.properties.is_empty() || get.properties.contains(&Property::Timestamp);
    let has_from_field = get.properties.is_empty() || get.properties.contains(&Property::From);
    let has_to_field = get.properties.is_empty() || get.properties.contains(&Property::To);
    let has_size_field = get.properties.is_empty() || get.properties.contains(&Property::Size);

    for id in ids {
        let item_id = id.id();
        if let Some(trace) = get
            .server
            .tracing_store()
            .get_value::<Trace>(ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(
                item_id,
            ))))
            .await?
        {
            let mut values = Vec::with_capacity(4);

            let mut got_timestamp = !has_timestamp_field;
            let mut got_from = !has_from_field;
            let mut got_to = !has_to_field;
            let mut got_size = !has_size_field;

            for event in trace.events.iter() {
                if !got_timestamp {
                    values.push((Property::Timestamp, event.timestamp.into_value()));
                    got_timestamp = true;
                }
                if !got_from
                    && let Some(value) = find_key_value(event, Key::From).map(value_as_string)
                {
                    values.push((Property::From, value));
                    got_from = true;
                }
                if !got_to && let Some(value) = find_key_value(event, Key::To).map(value_as_string)
                {
                    values.push((Property::To, value));
                    got_to = true;
                }
                if !got_size
                    && let Some(value) = find_key_value(event, Key::Size).map(value_as_number)
                {
                    values.push((Property::Size, value));
                    got_size = true;
                }
            }

            let mut trace = trace.into_value();
            let obj = trace.as_object_mut().unwrap();
            for (key, value) in values {
                obj.insert_unchecked(key, value);
            }

            get.insert(id, trace);
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

fn find_key_value(span: &TraceEvent, key: Key) -> Option<&TraceValue> {
    span.key_values
        .iter()
        .find_map(|kv| if kv.key == key { Some(&kv.value) } else { None })
}

fn value_as_string(value: &TraceValue) -> JmapValue<'static> {
    match value {
        TraceValue::String(s) => JmapValue::Str(s.value.clone().into()),
        TraceValue::List(values) => {
            let mut result = String::new();
            for value in values.value.iter() {
                if let TraceValue::String(s) = value {
                    if !result.is_empty() {
                        result.push_str("; ");
                    }
                    result.push_str(&s.value);
                }
            }
            JmapValue::Str(result.into())
        }
        _ => JmapValue::Null,
    }
}

fn value_as_number(value: &TraceValue) -> JmapValue<'static> {
    match value {
        TraceValue::Integer(i) => JmapValue::Number(i.value.into()),
        TraceValue::UnsignedInt(u) => JmapValue::Number(u.value.into()),
        TraceValue::Float(f) => JmapValue::Number(f.value.into_inner().into()),
        _ => JmapValue::Null,
    }
}

pub(crate) async fn metric_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        metric_ids(get.server, get.server.core.jmap.get_max_objects).await?
    };

    for id in ids {
        let item_id = id.id();
        if let Some(metric) = get
            .server
            .metrics_store()
            .get_value::<Metric>(ValueKey::from(ValueClass::Telemetry(
                TelemetryClass::Metric(item_id),
            )))
            .await?
        {
            let mut metric = metric.into_value();
            metric.as_object_mut().unwrap().insert_unchecked(
                Property::Timestamp,
                UTCDateTime::from_timestamp(SnowflakeIdGenerator::to_timestamp(item_id) as i64)
                    .into_value(),
            );

            get.insert(id, metric);
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

pub(crate) async fn trace_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let mut tracing_query = Vec::new();
    tracing_query.push(SearchFilter::And);

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Timestamp => {
                if let Some(id) = value
                    .as_str()
                    .and_then(|s| UTCDateTime::from_str(s).ok())
                    .and_then(|dt| SnowflakeIdGenerator::from_timestamp(dt.timestamp() as u64))
                {
                    let op = match op {
                        RegistryFilterOp::Equal => SearchOperator::Equal,
                        RegistryFilterOp::GreaterThan => SearchOperator::GreaterThan,
                        RegistryFilterOp::GreaterEqualThan => SearchOperator::GreaterEqualThan,
                        RegistryFilterOp::LowerThan => SearchOperator::LowerThan,
                        RegistryFilterOp::LowerEqualThan => SearchOperator::LowerEqualThan,
                        _ => return false,
                    };

                    tracing_query.push(SearchFilter::Operator {
                        field: SearchField::Id,
                        op,
                        value: id.into(),
                    });

                    true
                } else {
                    false
                }
            }
            Property::Event => {
                if let Some(typ) = value.as_str().and_then(EventType::parse) {
                    tracing_query.push(SearchFilter::eq(
                        TracingSearchField::EventType,
                        typ.to_id() as u64,
                    ));
                    true
                } else {
                    false
                }
            }
            Property::QueueId => {
                if let Some(queue_id) = value.as_str().and_then(|s| Id::from_str(s).ok()) {
                    tracing_query
                        .push(SearchFilter::eq(TracingSearchField::QueueId, queue_id.id()));
                    true
                } else {
                    false
                }
            }
            Property::Text => {
                if let Some(query) = value.as_str() {
                    let mut buf = String::with_capacity(query.len());
                    let mut in_quote = false;
                    for ch in query.chars() {
                        if ch.is_ascii_whitespace() {
                            if in_quote {
                                buf.push(' ');
                            } else if !buf.is_empty() {
                                tracing_query.push(SearchFilter::has_keyword(
                                    TracingSearchField::Keywords,
                                    buf,
                                ));
                                buf = String::new();
                            }
                        } else if ch == '"' {
                            buf.push(ch);
                            if in_quote {
                                if !buf.is_empty() {
                                    tracing_query.push(SearchFilter::has_keyword(
                                        TracingSearchField::Keywords,
                                        buf,
                                    ));
                                    buf = String::new();
                                }
                                in_quote = false;
                            } else {
                                in_quote = true;
                            }
                        } else {
                            buf.push(ch);
                        }
                    }
                    if !buf.is_empty() {
                        tracing_query
                            .push(SearchFilter::has_keyword(TracingSearchField::Keywords, buf));
                    }
                    true
                } else {
                    false
                }
            }

            _ => false,
        })?;

    if !tracing_query.iter().any(|f| {
        matches!(
            f,
            SearchFilter::Operator {
                field: SearchField::Tracing(
                    TracingSearchField::Keywords | TracingSearchField::QueueId
                ) | SearchField::Id,
                ..
            }
        )
    }) {
        tracing_query.push(SearchFilter::gt(
            SearchField::Id,
            SnowflakeIdGenerator::from_timestamp(now() - 86400).unwrap_or_default(),
        ));
    }
    tracing_query.push(SearchFilter::End);

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;

    if !matches!(params.sort_by, Property::Id | Property::Timestamp) {
        return Err(trc::JmapEvent::UnsupportedSort.into_err().details(format!(
            "Property {} is not supported for sorting",
            params.sort_by
        )));
    }

    let results = req
        .server
        .search_store()
        .query_global(
            SearchQuery::new(SearchIndex::Tracing)
                .with_filters(tracing_query)
                .with_comparator(SearchComparator::Field {
                    field: SearchField::Id,
                    ascending: params.sort_ascending,
                }),
        )
        .await?;

    // Build response
    let mut response = QueryResponseBuilder::new(
        results.len(),
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    for id in results {
        if !response.add_id(id.into()) {
            break;
        }
    }

    Ok(response)
}

pub(crate) async fn metric_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let mut ts_from = 0u64;
    let mut ts_to = u64::MAX;
    let mut metric_type = None;

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Timestamp => {
                if let Some(ts) = value.as_str().and_then(|s| UTCDateTime::from_str(s).ok()) {
                    let ts = ts.timestamp() as u64;
                    let (from, to) = match op {
                        RegistryFilterOp::Equal => (ts, ts),
                        RegistryFilterOp::GreaterThan => (ts + 1, u64::MAX),
                        RegistryFilterOp::GreaterEqualThan => (ts, u64::MAX),
                        RegistryFilterOp::LowerThan => (0, ts - 1),
                        RegistryFilterOp::LowerEqualThan => (0, ts),
                        _ => return false,
                    };

                    // Intersect with existing range
                    ts_from = ts_from.max(from);
                    ts_to = ts_to.min(to);

                    true
                } else {
                    false
                }
            }
            Property::Metric => {
                if let Some(mt) = value
                    .as_array()
                    .map(|v| {
                        v.iter()
                            .filter_map(|s| s.as_str().and_then(MetricType::parse))
                            .collect::<AHashSet<_>>()
                    })
                    .filter(|v| !v.is_empty())
                {
                    metric_type = Some(mt);
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;

    if ts_from != 0 {
        ts_from = SnowflakeIdGenerator::from_timestamp(ts_from).unwrap_or(0);
    }
    if ts_to != u64::MAX {
        ts_to = SnowflakeIdGenerator::from_timestamp(ts_to).unwrap_or(u64::MAX);
    }

    if let Some(anchor) = req.request.anchor {
        let anchor = anchor.id();
        if params.sort_ascending {
            if anchor > ts_from {
                ts_from = anchor;
            }
        } else if anchor < ts_to {
            ts_to = anchor;
        }
    }

    let from_key = ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(ts_from)));
    let to_key = ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(ts_to)));

    // Build response
    let mut response = QueryResponseBuilder::new(
        req.server.core.jmap.query_max_results + 1,
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    let mut total = 0;

    req.server
        .metrics_store()
        .iterate(
            IterateParams::new(from_key, to_key)
                .set_ascending(params.sort_ascending)
                .set_values(metric_type.is_some()),
            |key, value| {
                let id = key.deserialize_be_u64(0)?;

                if let Some(ref types) = metric_type {
                    let mt = match Metric::deserialize(value)? {
                        Metric::Counter(metric_count) => metric_count.metric,
                        Metric::Gauge(metric_count) => metric_count.metric,
                        Metric::Histogram(metric_sum) => metric_sum.metric,
                    };
                    if !types.contains(&mt) {
                        return Ok(true);
                    }
                }

                total += 1;
                if response.response.total.is_some() {
                    if !response.is_full() {
                        response.add_id(id.into());
                    }
                    Ok(true)
                } else {
                    Ok(response.add_id(id.into()))
                }
            },
        )
        .await
        .caused_by(trc::location!())?;

    if response.response.total.is_some() {
        response.response.total = Some(total);
    }

    if let Some(limit) = response.response.limit
        && total < limit
    {
        response.response.limit = None;
    }

    Ok(response)
}

async fn metric_ids(server: &Server, max_results: usize) -> trc::Result<Vec<Id>> {
    let mut events = Vec::with_capacity(8);

    let from_key = ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(0)));
    let to_key = ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(u64::MAX)));

    server
        .metrics_store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                events.push(key.deserialize_be_u64(0)?.into());

                Ok(events.len() < max_results)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| events)
}
