/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::telemetry::OtelTracer;
use trc::{TelemetryEvent, ipc::subscriber::SubscriberBuilder};

pub(crate) fn spawn_otel_tracer(builder: SubscriberBuilder, tracer: OtelTracer) {
    if let Err(err) = tracer.spawn(builder) {
        trc::event!(
            Telemetry(TelemetryEvent::OtelExporterError),
            Details = "Failed to start the OpenTelemetry exporter",
            Reason = err.to_string(),
        );
    }
}
