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
    Server,
    telemetry::metrics::store::{
        MetricsStore, PERSISTED_COUNTERS, PERSISTED_GAUGES, PERSISTED_HISTOGRAMS,
    },
};
use registry::{
    schema::structs::{Metric, MetricCount, MetricSum},
    types::ObjectImpl,
};
use std::{f64::consts::TAU, time::Duration};
use store::{
    rand::{self, Rng, RngExt},
    write::{BatchBuilder, TelemetryClass, ValueClass},
};
use trc::*;
use utils::snowflake::SnowflakeIdGenerator;

const HISTORY_SECS: u64 = 90 * 24 * 60 * 60;
const INTERVAL_SECS: u64 = 60 * 60;
const DAY_SECS: u64 = 24 * 60 * 60;
const MIB: f64 = 1024.0 * 1024.0;
const NODE_SHARES: [f64; 2] = [0.58, 0.42];
const NODE_MEMORY_BASE: [f64; 2] = [310.0 * MIB, 240.0 * MIB];
const LAG_PROBABILITY: f64 = 0.07;
const INCIDENT_PER_MILLE: u64 = 15;

#[derive(Clone, Copy)]
struct Interval {
    load: f64,
    progress: f64,
    incident: bool,
}

#[derive(Clone, Copy)]
enum GaugeScope {
    Node,
    Cluster,
}

impl Server {
    pub async fn insert_test_metrics(&self) {
        let store = self.metrics_store();
        store.purge_metrics(Duration::from_secs(0)).await.unwrap();

        let node_ids = [self.core.network.node_id, self.core.network.node_id + 1];
        let now = store::write::now();
        let start = now - HISTORY_SECS;
        let mut rng = rand::rng();
        let mut cluster_gauges = [0u64; PERSISTED_GAUGES.len()];
        let mut lagged_gauges = [0u64; PERSISTED_GAUGES.len()];
        let mut node_drift = [[0.0f64; PERSISTED_GAUGES.len()]; NODE_SHARES.len()];
        let mut batch = BatchBuilder::new();

        let mut timestamp = start;
        while timestamp <= now {
            let interval = Interval::at(timestamp, start);

            lagged_gauges.copy_from_slice(&cluster_gauges);
            for (value, &metric) in cluster_gauges.iter_mut().zip(PERSISTED_GAUGES) {
                if let GaugeScope::Cluster = gauge_scope(metric) {
                    *value = cluster_gauge(metric, *value, interval, &mut rng);
                }
            }

            for (node_index, ((&node_id, &share), drift)) in node_ids
                .iter()
                .zip(NODE_SHARES.iter())
                .zip(node_drift.iter_mut())
                .enumerate()
            {
                for &metric in PERSISTED_COUNTERS {
                    let count = stochastic_round(
                        counter_rate(metric, interval) * interval.load * share * noise(&mut rng),
                        &mut rng,
                    );
                    if count > 0 {
                        write(
                            &mut batch,
                            timestamp,
                            Metric::Counter(MetricCount {
                                count,
                                metric,
                                node_id,
                            }),
                        );
                    }
                }

                for &metric in PERSISTED_HISTOGRAMS {
                    let (rate, mean) = histogram_profile(metric, interval);
                    let count =
                        stochastic_round(rate * interval.load * share * noise(&mut rng), &mut rng);
                    if count > 0 {
                        let sum = (count as f64 * mean * noise(&mut rng)).round().max(1.0) as u64;
                        write(
                            &mut batch,
                            timestamp,
                            Metric::Histogram(MetricSum {
                                count,
                                sum,
                                metric,
                                node_id,
                            }),
                        );
                    }
                }

                let lagging = node_index == 1 && rng.random_bool(LAG_PROBABILITY);
                for (((&metric, &current), &previous), drift) in PERSISTED_GAUGES
                    .iter()
                    .zip(cluster_gauges.iter())
                    .zip(lagged_gauges.iter())
                    .zip(drift.iter_mut())
                {
                    let count = match gauge_scope(metric) {
                        GaugeScope::Cluster if lagging => previous,
                        GaugeScope::Cluster => current,
                        GaugeScope::Node => {
                            node_gauge(metric, node_index, drift, interval, &mut rng)
                        }
                    };
                    write(
                        &mut batch,
                        timestamp,
                        Metric::Gauge(MetricCount {
                            count,
                            metric,
                            node_id,
                        }),
                    );
                }
            }

            store.write_batch(&mut batch).await.unwrap();
            batch = BatchBuilder::new();
            timestamp += INTERVAL_SECS;
        }
    }
}

impl Interval {
    fn at(timestamp: u64, start: u64) -> Self {
        let hour = (timestamp % DAY_SECS) as f64 / INTERVAL_SECS as f64;
        let diurnal = 0.55 + 0.45 * ((hour - 15.0) / 24.0 * TAU).cos();
        let weekday = (timestamp / DAY_SECS + 4) % 7;
        let weekly = if matches!(weekday, 0 | 6) { 0.6 } else { 1.0 };
        let progress = (timestamp - start) as f64 / HISTORY_SECS as f64;
        let hour_index = timestamp / INTERVAL_SECS;
        Interval {
            load: diurnal * weekly * (0.8 + 0.4 * progress),
            progress,
            incident: hour_index.wrapping_mul(2_654_435_761) % 1000 < INCIDENT_PER_MILLE,
        }
    }
}

fn counter_rate(metric: MetricType, interval: Interval) -> f64 {
    let incident = interval.incident;
    match metric {
        MetricType::SmtpConnectionStart => 900.0,
        MetricType::ImapConnectionStart => 1200.0,
        MetricType::Pop3ConnectionStart => 40.0,
        MetricType::ManageSieveConnectionStart => 15.0,
        MetricType::HttpConnectionStart => 4000.0,
        MetricType::DeliveryAttemptStart => 450.0,
        MetricType::QueueMessageQueued => 500.0,
        MetricType::QueueAuthenticatedMessageQueued => 260.0,
        MetricType::QueueDsnQueued => 12.0,
        MetricType::QueueReportQueued => 6.0,
        MetricType::MessageIngestHam => 520.0,
        MetricType::MessageIngestSpam => 140.0,
        MetricType::AuthFailed if incident => 900.0,
        MetricType::AuthFailed => 60.0,
        MetricType::SecurityAuthenticationBan if incident => 12.0,
        MetricType::SecurityAuthenticationBan => 0.4,
        MetricType::SecurityScanBan => 0.8,
        MetricType::SecurityAbuseBan => 0.2,
        MetricType::SecurityLoiterBan => 0.3,
        MetricType::SecurityIpBlocked => 25.0,
        MetricType::IncomingReportDmarcReport => 1.5,
        MetricType::IncomingReportDmarcReportWithWarnings => 0.4,
        MetricType::IncomingReportTlsReport => 1.2,
        MetricType::IncomingReportTlsReportWithWarnings => 0.2,
        MetricType::CacheHit => 120_000.0,
        MetricType::CacheMiss => 9_000.0,
        MetricType::CacheStale => 600.0,
        MetricType::CacheEntryTooLarge => 4.0,
        MetricType::CacheSwapHit => 7_000.0,
        MetricType::CacheSwapMiss => 1_400.0,
        MetricType::CacheSwapWrite => 1_500.0,
        MetricType::CacheSwapError if incident => 6.0,
        MetricType::CacheSwapError => 0.05,
        MetricType::QueueBackPressure if incident => 120.0,
        MetricType::QueueBackPressure => 0.02,
        MetricType::LimitMemoryBudget if incident => 40.0,
        MetricType::LimitMemoryBudget => 0.05,
        MetricType::SearchIndexBatchIndexed => 600.0,
        MetricType::SearchIndexDocumentTruncated => 3.0,
        MetricType::SearchIndexPartitionRetry if incident => 15.0,
        MetricType::SearchIndexPartitionRetry => 0.3,
        MetricType::TaskManagerTaskFailed if incident => 8.0,
        MetricType::TaskManagerTaskFailed => 0.4,
        MetricType::TaskManagerTaskRetry if incident => 25.0,
        MetricType::TaskManagerTaskRetry => 1.5,
        MetricType::TaskManagerTaskStalled if incident => 3.0,
        MetricType::TaskManagerTaskStalled => 0.1,
        MetricType::TaskManagerTaskExpired => 0.05,
        MetricType::SmtpDkim2DsnRejected => 1.0,
        MetricType::SmtpSpfFromPass => 560.0,
        MetricType::SmtpSpfFromFail if incident => 300.0,
        MetricType::SmtpSpfFromFail => 70.0,
        MetricType::SmtpDkimPass => 470.0,
        MetricType::SmtpDkimFail if incident => 340.0,
        MetricType::SmtpDkimFail => 160.0,
        MetricType::SmtpDkim2Pass => 45.0,
        MetricType::SmtpDkim2Fail => 4.0,
        MetricType::SmtpDmarcPass => 440.0,
        MetricType::SmtpDmarcFail if incident => 280.0,
        MetricType::SmtpDmarcFail => 60.0,
        MetricType::EncryptionAtRestEncrypted => 180.0,
        MetricType::EncryptionEncryptionSkipped if incident => 20.0,
        MetricType::EncryptionEncryptionSkipped => 1.5,
        MetricType::EncryptionGatewayEncrypted => 95.0,
        MetricType::EncryptionGatewayPlaintext => 160.0,
        MetricType::EncryptionGatewayBounced if incident => 12.0,
        MetricType::EncryptionGatewayBounced => 0.6,
        MetricType::EncryptionKeyLookup => 70.0,
        MetricType::EncryptionKeyHarvested => 9.0,
        MetricType::EncryptionKeyChange => 0.4,
        MetricType::EncryptionCrlFetchFailed if incident => 6.0,
        MetricType::EncryptionCrlFetchFailed => 0.2,
        MetricType::EncryptionDnssecBogus if incident => 4.0,
        MetricType::EncryptionDnssecBogus => 0.1,
        _ => 10.0,
    }
}

fn histogram_profile(metric: MetricType, interval: Interval) -> (f64, f64) {
    let slowdown = if interval.incident { 3.0 } else { 1.0 };
    match metric {
        MetricType::MessageIngestTime => (660.0, 35.0 * slowdown),
        MetricType::SearchIndexIndexTime => (600.0, 140.0 * slowdown),
        MetricType::DeliveryTotalTime => (450.0, 2_400.0 * slowdown),
        MetricType::DeliveryAttemptTime => (480.0, 750.0 * slowdown),
        MetricType::DnsLookupTime => (3_000.0, 18.0),
        MetricType::EncryptionKeyLookupTime => (70.0, 140.0 * slowdown),
        MetricType::StoreDataReadTime => (90_000.0, 1.6 * slowdown),
        MetricType::StoreDataWriteTime => (12_000.0, 4.5 * slowdown),
        MetricType::StoreBlobReadTime => (4_000.0, 6.0 * slowdown),
        MetricType::StoreBlobWriteTime => (900.0, 12.0 * slowdown),
        _ => (100.0, 50.0),
    }
}

fn gauge_scope(metric: MetricType) -> GaugeScope {
    match metric {
        MetricType::ServerMemory
        | MetricType::ServerBufferedMemorySmtp
        | MetricType::ServerBufferedMemoryRead
        | MetricType::CacheMessagesSize
        | MetricType::CacheMessagesLargeSize
        | MetricType::CacheSize => GaugeScope::Node,
        _ => GaugeScope::Cluster,
    }
}

fn cluster_gauge(metric: MetricType, previous: u64, interval: Interval, rng: &mut impl Rng) -> u64 {
    let (target, max, smoothing) = match metric {
        MetricType::QueueCount if interval.incident => (2_500.0, 10_000.0, 0.6),
        MetricType::QueueCount => (40.0 + 260.0 * interval.load, 10_000.0, 0.35),
        MetricType::SearchIndexPendingEmail if interval.incident => (1_800.0, 5_000.0, 0.7),
        MetricType::SearchIndexPendingEmail => (90.0 * interval.load, 5_000.0, 0.5),
        MetricType::SearchIndexPendingCalendar => (8.0 * interval.load, 500.0, 0.5),
        MetricType::SearchIndexPendingContacts => (5.0 * interval.load, 500.0, 0.5),
        MetricType::SearchIndexPendingFile => (14.0 * interval.load, 500.0, 0.5),
        MetricType::SearchIndexPendingTracing => (60.0 * interval.load, 2_000.0, 0.5),
        MetricType::TaskManagerPending if interval.incident => (180.0, 1_000.0, 0.6),
        MetricType::TaskManagerPending => (6.0 + 30.0 * interval.load, 1_000.0, 0.4),
        MetricType::TaskManagerDue => (3.0 * interval.load, 200.0, 0.5),
        _ => (20.0 * interval.load, 1_000.0, 0.5),
    };
    let next = previous as f64 * (1.0 - smoothing) + target * smoothing * noise_wide(rng);
    stochastic_round(next.min(max), rng)
}

fn node_gauge(
    metric: MetricType,
    node_index: usize,
    drift: &mut f64,
    interval: Interval,
    rng: &mut impl Rng,
) -> u64 {
    *drift = (*drift + rng.random_range(-0.04..0.04)).clamp(-0.25, 0.25);
    let node_factor = if node_index == 0 { 1.0 } else { 0.75 };
    let value = match metric {
        MetricType::ServerMemory => {
            NODE_MEMORY_BASE[node_index]
                * (1.0 + 0.35 * interval.progress + 0.15 * interval.load + *drift)
        }
        MetricType::ServerBufferedMemorySmtp => {
            if rng.random_bool(0.25 + 0.5 * interval.load) {
                rng.random_range(64.0 * 1024.0..6.0 * MIB) * interval.load * node_factor
            } else {
                0.0
            }
        }
        MetricType::ServerBufferedMemoryRead => {
            rng.random_range(0.0..2.0 * MIB) * interval.load * node_factor
        }
        MetricType::CacheMessagesSize => {
            96.0 * MIB * node_factor * (0.6 + 0.4 * interval.load + *drift)
        }
        MetricType::CacheMessagesLargeSize => {
            24.0 * MIB * node_factor * (0.5 + 0.5 * interval.load + *drift)
        }
        MetricType::CacheSize => {
            220.0
                * MIB
                * node_factor
                * (0.7 + 0.3 * interval.load + 0.2 * interval.progress + *drift)
        }
        _ => 1_000.0 * node_factor * interval.load,
    };
    value.max(0.0).round() as u64
}

fn write(batch: &mut BatchBuilder, timestamp: u64, metric: Metric) {
    batch.set(
        ValueClass::Telemetry(TelemetryClass::Metric(
            SnowflakeIdGenerator::global_id_from_timestamp(timestamp).unwrap(),
        )),
        metric.to_pickled_vec(),
    );
}

fn noise(rng: &mut impl Rng) -> f64 {
    rng.random_range(0.85..1.15)
}

fn noise_wide(rng: &mut impl Rng) -> f64 {
    rng.random_range(0.5..1.5)
}

fn stochastic_round(value: f64, rng: &mut impl Rng) -> u64 {
    (value.max(0.0) + rng.random::<f64>()).floor() as u64
}
