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

macro_rules! persisted_metrics {
    ($list:ident => [$($variant:ident),+ $(,)?]) => {
        pub const $list: &[MetricType] = &[$(MetricType::$variant),+];
    };
    ($list:ident, $matcher:ident => [$($variant:ident),+ $(,)?]) => {
        persisted_metrics!($list => [$($variant),+]);

        #[inline]
        pub fn $matcher(metric: MetricType) -> bool {
            matches!(metric, $(MetricType::$variant)|+)
        }
    };
}

persisted_metrics!(
    PERSISTED_COUNTERS => [
        SmtpConnectionStart,
        ImapConnectionStart,
        Pop3ConnectionStart,
        ManageSieveConnectionStart,
        HttpConnectionStart,
        DeliveryAttemptStart,
        QueueMessageQueued,
        QueueAuthenticatedMessageQueued,
        QueueDsnQueued,
        QueueReportQueued,
        MessageIngestHam,
        MessageIngestSpam,
        AuthFailed,
        SecurityAuthenticationBan,
        SecurityScanBan,
        SecurityAbuseBan,
        SecurityLoiterBan,
        SecurityIpBlocked,
        IncomingReportDmarcReport,
        IncomingReportDmarcReportWithWarnings,
        IncomingReportTlsReport,
        IncomingReportTlsReportWithWarnings,
        CacheHit,
        CacheMiss,
        CacheStale,
        CacheEntryTooLarge,
        CacheSwapHit,
        CacheSwapMiss,
        CacheSwapWrite,
        CacheSwapError,
        QueueBackPressure,
        LimitMemoryBudget,
        SearchIndexBatchIndexed,
        SearchIndexDocumentTruncated,
        SearchIndexPartitionRetry,
        TaskManagerTaskFailed,
        TaskManagerTaskRetry,
        TaskManagerTaskStalled,
        TaskManagerTaskExpired,
        SmtpDkim2DsnRejected,
        SmtpSpfFromPass,
        SmtpSpfFromFail,
        SmtpDkimPass,
        SmtpDkimFail,
        SmtpDkim2Pass,
        SmtpDkim2Fail,
        SmtpDmarcPass,
        SmtpDmarcFail,
    ]
);

persisted_metrics!(
    PERSISTED_GAUGES, is_persisted_gauge => [
        QueueCount,
        ServerMemory,
        ServerBufferedMemorySmtp,
        ServerBufferedMemoryRead,
        CacheMessagesSize,
        CacheMessagesLargeSize,
        CacheSize,
        SearchIndexPendingEmail,
        SearchIndexPendingCalendar,
        SearchIndexPendingContacts,
        SearchIndexPendingFile,
        SearchIndexPendingTracing,
        TaskManagerPending,
        TaskManagerDue,
    ]
);

persisted_metrics!(
    PERSISTED_HISTOGRAMS, is_persisted_histogram => [
        MessageIngestTime,
        SearchIndexIndexTime,
        DeliveryTotalTime,
        DeliveryAttemptTime,
        DnsLookupTime,
        StoreDataReadTime,
        StoreDataWriteTime,
        StoreBlobReadTime,
        StoreBlobWriteTime,
    ]
);

pub trait MetricsStore: Sync + Send {
    fn write_metrics(
        &self,
        node_id: u64,
        timestamp: Option<u64>,
        history: SharedMetricHistory,
    ) -> impl Future<Output = trc::Result<()>> + Send;
    fn purge_metrics(&self, period: Duration) -> impl Future<Output = trc::Result<()>> + Send;
}

#[derive(Default)]
pub struct MetricsHistory {
    events: AHashMap<MetricType, u64>,
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
        node_id: u64,
        _timestamp: Option<u64>,
        history_: SharedMetricHistory,
    ) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        {
            let mut history_guard = history_.lock();
            for &event in PERSISTED_COUNTERS {
                let reading = Collector::read_metric_counter(event.event_id());
                if reading > 0 {
                    let history = history_guard.events.entry(event).or_insert(0);
                    let diff = reading - *history;
                    *history = reading;

                    if diff > 0 {
                        #[cfg(not(any(feature = "dev_mode", stalwart_tests)))]
                        let metric_id = history_guard.id_generator.generate();

                        #[cfg(any(feature = "dev_mode", stalwart_tests))]
                        let metric_id = _timestamp
                            .map(|timestamp| {
                                SnowflakeIdGenerator::global_id_from_timestamp(timestamp).unwrap()
                            })
                            .unwrap_or_else(|| history_guard.id_generator.generate());

                        batch.set(
                            ValueClass::Telemetry(TelemetryClass::Metric(metric_id)),
                            Metric::Counter(MetricCount {
                                count: diff,
                                metric: event,
                                node_id,
                            })
                            .to_pickled_vec(),
                        );
                    }
                }
            }

            for gauge in Collector::collect_gauges(true) {
                let metric = gauge.id();
                if is_persisted_gauge(metric) {
                    let value = gauge.get();
                    #[cfg(not(any(feature = "dev_mode", stalwart_tests)))]
                    let metric_id = history_guard.id_generator.generate();

                    #[cfg(any(feature = "dev_mode", stalwart_tests))]
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
                            node_id,
                        })
                        .to_pickled_vec(),
                    );
                }
            }

            for histogram in Collector::collect_histograms(true) {
                let metric = histogram.id();
                if is_persisted_histogram(metric) {
                    let history = history_guard.histograms.entry(metric).or_default();
                    let sum = histogram.sum();
                    let count = histogram.count();
                    let diff_sum = sum - history.sum;
                    let diff_count = count - history.count;
                    history.sum = sum;
                    history.count = count;
                    if diff_sum > 0 || diff_count > 0 {
                        #[cfg(not(any(feature = "dev_mode", stalwart_tests)))]
                        let metric_id = history_guard.id_generator.generate();

                        #[cfg(any(feature = "dev_mode", stalwart_tests))]
                        let metric_id = _timestamp
                            .map(|timestamp| {
                                SnowflakeIdGenerator::global_id_from_timestamp(timestamp).unwrap()
                            })
                            .unwrap_or_else(|| history_guard.id_generator.generate());

                        batch.set(
                            ValueClass::Telemetry(TelemetryClass::Metric(metric_id)),
                            Metric::Histogram(MetricSum {
                                count: diff_count,
                                metric,
                                sum: diff_sum,
                                node_id,
                            })
                            .to_pickled_vec(),
                        );
                    }
                }
            }
        }

        if !batch.is_empty() {
            self.write_batch(&mut batch)
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
