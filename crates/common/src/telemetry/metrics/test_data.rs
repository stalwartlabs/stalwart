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
    telemetry::metrics::store::{MetricsStore, SharedMetricHistory},
};
use std::time::Duration;
use store::rand::{self, Rng};
use trc::*;

impl Server {
    pub async fn insert_test_metrics(&self) {
        self.metrics_store()
            .purge_metrics(Duration::from_secs(0))
            .await
            .unwrap();
        let mut start_time = store::write::now() - (90 * 24 * 60 * 60);
        let timestamp = store::write::now();
        let history = SharedMetricHistory::default();

        while start_time <= timestamp {
            for event_type in [
                EventType::Smtp(SmtpEvent::ConnectionStart),
                EventType::Imap(ImapEvent::ConnectionStart),
                EventType::Pop3(Pop3Event::ConnectionStart),
                EventType::ManageSieve(ManageSieveEvent::ConnectionStart),
                EventType::Http(HttpEvent::ConnectionStart),
                EventType::Delivery(DeliveryEvent::AttemptStart),
                EventType::Queue(QueueEvent::MessageQueued),
                EventType::Queue(QueueEvent::AuthenticatedMessageQueued),
                EventType::Queue(QueueEvent::DsnQueued),
                EventType::Queue(QueueEvent::ReportQueued),
                EventType::MessageIngest(MessageIngestEvent::Ham),
                EventType::MessageIngest(MessageIngestEvent::Spam),
                EventType::Auth(AuthEvent::Failed),
                EventType::Security(SecurityEvent::AuthenticationBan),
                EventType::Security(SecurityEvent::ScanBan),
                EventType::Security(SecurityEvent::AbuseBan),
                EventType::Security(SecurityEvent::LoiterBan),
                EventType::Security(SecurityEvent::IpBlocked),
                EventType::IncomingReport(IncomingReportEvent::DmarcReport),
                EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings),
                EventType::IncomingReport(IncomingReportEvent::TlsReport),
                EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings),
            ] {
                // Generate a random value between 0 and 100
                Collector::update_event_counter(event_type, rand::rng().random_range(0..=100))
            }

            Collector::update_gauge(MetricType::QueueCount, rand::rng().random_range(0..=1000));
            Collector::update_gauge(
                MetricType::ServerMemory,
                rand::rng().random_range(100 * 1024 * 1024..=300 * 1024 * 1024),
            );
            Collector::update_gauge(MetricType::UserCount, rand::rng().random_range(100..=500));
            Collector::update_gauge(MetricType::DomainCount, rand::rng().random_range(10..=50));

            for metric_type in [
                MetricType::MessageIngestTime,
                MetricType::MessageIngestIndexTime,
                MetricType::DeliveryTotalTime,
                MetricType::DeliveryAttemptTime,
                MetricType::DnsLookupTime,
                MetricType::StoreDataReadTime,
                MetricType::StoreDataWriteTime,
                MetricType::StoreBlobReadTime,
                MetricType::StoreBlobWriteTime,
            ] {
                Collector::update_histogram(metric_type, rand::rng().random_range(2..=1000))
            }
            Collector::update_histogram(
                MetricType::DeliveryTotalTime,
                rand::rng().random_range(1000..=5000),
            );

            self.metrics_store()
                .write_metrics(start_time.into(), history.clone())
                .await
                .unwrap();
            start_time += 60 * 60;
        }
    }
}
