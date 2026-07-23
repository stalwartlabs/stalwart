/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use ahash::AHashMap;
use parking_lot::Mutex;
use registry::{
    schema::structs::{Metric, MetricCount, MetricSum},
    types::ObjectImpl,
};
use std::{future::Future, sync::Arc, time::Duration};
use store::{
    Store, ValueKey,
    write::{BatchBuilder, TelemetryClass, ValueClass},
};
use trc::*;
use utils::snowflake::SnowflakeIdGenerator;

pub trait MetricsStore: Sync + Send {
    fn write_metrics(
        &self,
        timestamp: Option<u64>,
        history: SharedMetricHistory,
    ) -> impl Future<Output = trc::Result<()>> + Send;
    fn purge_metrics(&self, period: Duration) -> impl Future<Output = trc::Result<()>> + Send;
}

#[derive(Default)]
pub struct MetricsHistory {
    events: AHashMap<MetricType, u32>,
    histograms: AHashMap<MetricType, HistogramHistory>,
    id_generator: SnowflakeIdGenerator,
}

#[derive(Default)]
struct HistogramHistory {
    sum: u64,
    count: u64,
}

pub type SharedMetricHistory = Arc<Mutex<MetricsHistory>>;

impl MetricsStore for Store {
    async fn write_metrics(
        &self,
        _timestamp: Option<u64>,
        history_: SharedMetricHistory,
    ) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        {
            let mut history_guard = history_.lock();
            for event in [
                MetricType::SmtpConnectionStart,
                MetricType::ImapConnectionStart,
                MetricType::Pop3ConnectionStart,
                MetricType::ManageSieveConnectionStart,
                MetricType::HttpConnectionStart,
                MetricType::DeliveryAttemptStart,
                MetricType::QueueMessageQueued,
                MetricType::QueueAuthenticatedMessageQueued,
                MetricType::QueueDsnQueued,
                MetricType::QueueReportQueued,
                MetricType::MessageIngestHam,
                MetricType::MessageIngestSpam,
                MetricType::AuthFailed,
                MetricType::SecurityAuthenticationBan,
                MetricType::SecurityScanBan,
                MetricType::SecurityAbuseBan,
                MetricType::SecurityLoiterBan,
                MetricType::SecurityIpBlocked,
                MetricType::IncomingReportDmarcReport,
                MetricType::IncomingReportDmarcReportWithWarnings,
                MetricType::IncomingReportTlsReport,
                MetricType::IncomingReportTlsReportWithWarnings,
            ] {
                let reading = Collector::read_metric_counter(event.event_id());
                if reading > 0 {
                    let history = history_guard.events.entry(event).or_insert(0);
                    let diff = reading - *history;
                    *history = reading;

                    if diff > 0 {
                        #[cfg(not(any(feature = "dev_mode", feature = "test_mode")))]
                        let metric_id = history_guard.id_generator.generate();

                        #[cfg(any(feature = "dev_mode", feature = "test_mode"))]
                        let metric_id = _timestamp
                            .map(|timestamp| {
                                SnowflakeIdGenerator::global_id_from_timestamp(timestamp).unwrap()
                            })
                            .unwrap_or_else(|| history_guard.id_generator.generate());

                        batch.set(
                            ValueClass::Telemetry(TelemetryClass::Metric(metric_id)),
                            Metric::Counter(MetricCount {
                                count: diff as u64,
                                metric: event,
                            })
                            .to_pickled_vec(),
                        );
                    }
                }
            }

            for gauge in Collector::collect_gauges(true) {
                let metric = gauge.id();
                if matches!(metric, MetricType::QueueCount | MetricType::ServerMemory) {
                    let value = gauge.get();
                    if value > 0 {
                        #[cfg(not(any(feature = "dev_mode", feature = "test_mode")))]
                        let metric_id = history_guard.id_generator.generate();

                        #[cfg(any(feature = "dev_mode", feature = "test_mode"))]
                        let metric_id = _timestamp
                            .map(|timestamp| {
                                SnowflakeIdGenerator::global_id_from_timestamp(timestamp).unwrap()
                            })
                            .unwrap_or_else(|| history_guard.id_generator.generate());

                        batch.set(
                            ValueClass::Telemetry(TelemetryClass::Metric(metric_id)),
                            Metric::Gauge(MetricCount {
                                count: value,
                                metric,
                            })
                            .to_pickled_vec(),
                        );
                    }
                }
            }

            for histogram in Collector::collect_histograms(true) {
                let metric = histogram.id();
                if matches!(
                    metric,
                    MetricType::MessageIngestTime
                        | MetricType::MessageIngestIndexTime
                        | MetricType::DeliveryTotalTime
                        | MetricType::DeliveryAttemptTime
                        | MetricType::DnsLookupTime
                        | MetricType::StoreDataReadTime
                        | MetricType::StoreDataWriteTime
                        | MetricType::StoreBlobReadTime
                        | MetricType::StoreBlobWriteTime
                ) {
                    let history = history_guard.histograms.entry(metric).or_default();
                    let sum = histogram.sum();
                    let count = histogram.count();
                    let diff_sum = sum - history.sum;
                    let diff_count = count - history.count;
                    history.sum = sum;
                    history.count = count;
                    if diff_sum > 0 || diff_count > 0 {
                        #[cfg(not(any(feature = "dev_mode", feature = "test_mode")))]
                        let metric_id = history_guard.id_generator.generate();

                        #[cfg(any(feature = "dev_mode", feature = "test_mode"))]
                        let metric_id = _timestamp
                            .map(|timestamp| {
                                SnowflakeIdGenerator::global_id_from_timestamp(timestamp).unwrap()
                            })
                            .unwrap_or_else(|| history_guard.id_generator.generate());

                        batch.set(
                            ValueClass::Telemetry(TelemetryClass::Metric(metric_id)),
                            Metric::Histogram(MetricSum { count, metric, sum }).to_pickled_vec(),
                        );
                    }
                }
            }
        }

        if !batch.is_empty() {
            self.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }

    async fn purge_metrics(&self, period: Duration) -> trc::Result<()> {
        let until_span_id = SnowflakeIdGenerator::from_duration(period).ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate reference metric id.")
        })?;

        self.delete_range(
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(0))),
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(until_span_id))),
        )
        .await
        .caused_by(trc::location!())
    }
}

impl MetricsHistory {
    pub fn init() -> SharedMetricHistory {
        Arc::new(Mutex::new(Self::default()))
    }
}
