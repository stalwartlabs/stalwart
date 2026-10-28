/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::telemetry::OtelMetrics;
use std::time::SystemTime;
use trc::TelemetryEvent;

impl OtelMetrics {
    pub async fn push_metrics(&self, is_enterprise: bool, start_time: SystemTime) {
        match self.exporter.try_lock() {
            Ok(mut exporter) => {
                exporter
                    .push(is_enterprise, start_time, self.interval)
                    .await
            }
            Err(_) => trc::event!(
                Telemetry(TelemetryEvent::OtelMetricsExporterError),
                Details = "Previous metrics export still in progress, skipping this interval",
            ),
        }
    }
}
