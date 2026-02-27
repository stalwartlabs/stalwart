/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::RegistryGetResponse;
use common::Server;
use registry::{
    jmap::IntoValue,
    schema::prelude::{Object, Property},
    types::datetime::UTCDateTime,
};
use store::{
    IterateParams, ValueKey,
    search::{SearchComparator, SearchField, SearchFilter, SearchQuery},
    write::{SearchIndex, TelemetryClass, ValueClass, key::DeserializeBigEndian, now},
};
use trc::AddContext;
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

    for id in ids {
        let item_id = id.id();
        if let Some(trace) = get
            .server
            .tracing_store()
            .get_value::<Object>(ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(
                item_id,
            ))))
            .await?
        {
            get.insert(id, trace.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
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
            .get_value::<Object>(ValueKey::from(ValueClass::Telemetry(
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
