/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::request::RequestBuilder;
use crate::{
    metrics::{HistogramSnapshot, MetricScale},
    proto::writer::{LenHint, ProtoWriter},
};
use trc::Collector;

const SCOPE_METRICS: u32 = 2;

const METRIC_NAME: u32 = 1;
const METRIC_DESCRIPTION: u32 = 2;
const METRIC_UNIT: u32 = 3;
const METRIC_GAUGE: u32 = 5;
const METRIC_SUM: u32 = 7;
const METRIC_HISTOGRAM: u32 = 9;

const DATA_POINTS: u32 = 1;
const AGGREGATION_TEMPORALITY: u32 = 2;
const SUM_IS_MONOTONIC: u32 = 3;
const TEMPORALITY_CUMULATIVE: u64 = 2;

const POINT_START_TIME: u32 = 2;
const POINT_TIME: u32 = 3;
const NUMBER_AS_DOUBLE: u32 = 4;
const NUMBER_AS_INT: u32 = 6;

const HISTOGRAM_COUNT: u32 = 4;
const HISTOGRAM_SUM: u32 = 5;
const HISTOGRAM_BUCKET_COUNTS: u32 = 6;
const HISTOGRAM_EXPLICIT_BOUNDS: u32 = 7;
const HISTOGRAM_MIN: u32 = 11;
const HISTOGRAM_MAX: u32 = 12;

const COUNTER_UNIT: &str = "{event}";

pub fn encode_metrics(
    request: &mut RequestBuilder,
    is_enterprise: bool,
    start_unix_nano: u64,
    now_unix_nano: u64,
) {
    for counter in Collector::collect_counters(is_enterprise) {
        let event = counter.id();
        let name = event.otel_metric_name();
        if name.is_empty() {
            continue;
        }
        let w = request.writer();
        let metric = begin_metric(w, name, event.description(), COUNTER_UNIT);
        let sum = w.begin(METRIC_SUM, LenHint::Small);
        let point = w.begin(DATA_POINTS, LenHint::Small);
        w.fixed64(POINT_START_TIME, start_unix_nano);
        w.fixed64(POINT_TIME, now_unix_nano);
        w.sfixed64_always(NUMBER_AS_INT, saturating_i64(counter.value()));
        w.end(point);
        w.uint64(AGGREGATION_TEMPORALITY, TEMPORALITY_CUMULATIVE);
        w.bool_always(SUM_IS_MONOTONIC, true);
        w.end(sum);
        w.end(metric);
        request.commit();
    }

    for gauge in Collector::collect_gauges(is_enterprise) {
        let metric_type = gauge.id();
        let name = metric_type.otel_name();
        if name.is_empty() {
            continue;
        }
        let unit = metric_type.otel_unit();
        let w = request.writer();
        let metric = begin_metric(w, name, metric_type.description(), unit);
        let gauge_msg = w.begin(METRIC_GAUGE, LenHint::Small);
        let point = w.begin(DATA_POINTS, LenHint::Small);
        w.fixed64(POINT_TIME, now_unix_nano);
        match MetricScale::from_otel_unit(unit) {
            MetricScale::Identity => {
                w.sfixed64_always(NUMBER_AS_INT, saturating_i64(gauge.get()));
            }
            scale => w.double_always(NUMBER_AS_DOUBLE, scale.apply(gauge.get())),
        }
        w.end(point);
        w.end(gauge_msg);
        w.end(metric);
        request.commit();
    }

    for histogram in Collector::collect_histograms(is_enterprise) {
        let metric_type = histogram.id();
        let name = metric_type.otel_name();
        if name.is_empty() {
            continue;
        }
        let unit = metric_type.otel_unit();
        let scale = MetricScale::from_otel_unit(unit);
        let snapshot = HistogramSnapshot::new(histogram);
        let w = request.writer();
        let metric = begin_metric(w, name, metric_type.description(), unit);
        let histogram_msg = w.begin(METRIC_HISTOGRAM, LenHint::Medium);
        let point = w.begin(DATA_POINTS, LenHint::Medium);
        w.fixed64(POINT_START_TIME, start_unix_nano);
        w.fixed64(POINT_TIME, now_unix_nano);
        w.fixed64_always(HISTOGRAM_COUNT, snapshot.count);
        w.double_always(HISTOGRAM_SUM, scale.apply(snapshot.sum));
        w.packed_fixed64(HISTOGRAM_BUCKET_COUNTS, snapshot.buckets.iter().copied());
        w.packed_double(
            HISTOGRAM_EXPLICIT_BOUNDS,
            snapshot.bounds.iter().map(|bound| scale.apply(*bound)),
        );
        if let Some(min) = snapshot.min {
            w.double_always(HISTOGRAM_MIN, scale.apply(min));
        }
        if let Some(max) = snapshot.max {
            w.double_always(HISTOGRAM_MAX, scale.apply(max));
        }
        w.end(point);
        w.uint64(AGGREGATION_TEMPORALITY, TEMPORALITY_CUMULATIVE);
        w.end(histogram_msg);
        w.end(metric);
        request.commit();
    }
}

#[inline(always)]
fn begin_metric(
    w: &mut ProtoWriter,
    name: &str,
    description: &str,
    unit: &str,
) -> crate::proto::writer::Nested {
    let metric = w.begin(SCOPE_METRICS, LenHint::Medium);
    w.bytes(METRIC_NAME, name.as_bytes());
    w.bytes(METRIC_DESCRIPTION, description.as_bytes());
    w.bytes(METRIC_UNIT, unit.as_bytes());
    metric
}

#[inline(always)]
fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
