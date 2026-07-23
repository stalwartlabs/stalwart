/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::telemetry::OtelMetrics;
use opentelemetry_sdk::metrics::{
    Temporality,
    data::{
        AggregatedMetrics, Gauge, GaugeDataPoint, Histogram, HistogramDataPoint, Metric,
        MetricData, ResourceMetrics, ScopeMetrics, Sum, SumDataPoint,
    },
    exporter::PushMetricExporter,
};
use std::time::SystemTime;
use trc::{Collector, TelemetryEvent};

impl OtelMetrics {
    pub async fn push_metrics(&self, is_enterprise: bool, start_time: SystemTime) {
        let mut metrics = Vec::with_capacity(256);
        let time = SystemTime::now();

        // Add counters
        for counter in Collector::collect_counters(is_enterprise) {
            metrics.push(Metric::new(
                counter.id().as_str(),
                counter.id().description(),
                "events",
                AggregatedMetrics::U64(MetricData::Sum(Sum::new(
                    vec![SumDataPoint::new(vec![], counter.value(), vec![])],
                    start_time,
                    time,
                    Temporality::Cumulative,
                    true,
                ))),
            ));
        }

        // Add gauges
        for gauge in Collector::collect_gauges(is_enterprise) {
            metrics.push(Metric::new(
                gauge.id().as_str(),
                gauge.id().description(),
                gauge.id().unit(),
                AggregatedMetrics::U64(MetricData::Gauge(Gauge::new(
                    vec![GaugeDataPoint::new(vec![], gauge.get(), vec![])],
                    Some(start_time),
                    time,
                ))),
            ));
        }

        // Add histograms
        for histogram in Collector::collect_histograms(is_enterprise) {
            metrics.push(Metric::new(
                histogram.id().as_str(),
                histogram.id().description(),
                histogram.id().unit(),
                AggregatedMetrics::U64(MetricData::Histogram(Histogram::new(
                    vec![HistogramDataPoint::new(
                        vec![],
                        histogram.count(),
                        histogram.upper_bounds_vec(),
                        histogram.buckets_vec(),
                        histogram.min(),
                        histogram.max(),
                        histogram.sum(),
                        vec![],
                    )],
                    start_time,
                    time,
                    Temporality::Cumulative,
                ))),
            ));
        }

        // Export metrics
        let rm = ResourceMetrics::new(
            self.resource.clone(),
            vec![ScopeMetrics::new(self.instrumentation.clone(), metrics)],
        );
        if let Err(err) = self.exporter.export(&rm).await {
            trc::event!(
                Telemetry(TelemetryEvent::OtelMetricsExporterError),
                Reason = err.to_string(),
            );
        }
    }

    pub fn enable_errors() {
        // TODO: Remove this when the OpenTelemetry SDK supports error handling
        /*let _ = set_error_handler(|error| {
            trc::event!(
                Telemetry(TelemetryEvent::OtelMetricsExporterError),
                Reason = error.to_string(),
            );
        });*/
    }
}
